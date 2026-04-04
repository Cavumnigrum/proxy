import asyncio
import base64
import hashlib
import logging
import os
import struct
from typing import Optional


class WSError(Exception):
    """Исключение для ошибок WebSocket."""
    pass


def setup_logger(name: str) -> logging.Logger:
    """Настройка логгера."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


class RawWebSocket:
    """
    Асинхронный клиент/сервер WebSocket.
    
    Потокобезопасная отправка: метод send() защищён asyncio.Lock,
    что позволяет нескольким корутинам (каналам мультиплексора)
    безопасно писать в один WS-поток без перемешивания кадров.
    """
    OP_CONT = 0x0
    OP_TEXT = 0x1
    OP_BIN = 0x2
    OP_CLOSE = 0x8
    OP_PING = 0x9
    OP_PONG = 0xA

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        is_client: bool,
    ):
        self.reader = reader
        self.writer = writer
        self.is_client = is_client
        self.closed = False
        # Блокировка для атомарной записи кадров (мультиплексор!)
        self._send_lock = asyncio.Lock()

    @classmethod
    async def connect(
        cls,
        host: str,
        port: int,
        path: str = "/",
        ssl_context=None,
    ) -> 'RawWebSocket':
        """Устанавливает WS-соединение с сервером."""
        reader, writer = await asyncio.open_connection(
            host, port, ssl=ssl_context
        )
        ws_key = base64.b64encode(os.urandom(16)).decode('utf-8')
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        writer.write(req.encode())
        await writer.drain()

        headers = []
        while True:
            line = await reader.readline()
            if line == b'\r\n' or not line:
                break
            headers.append(line.decode().strip())

        if not headers or "101" not in headers[0]:
            writer.close()
            await writer.wait_closed()
            raise WSError("Invalid WS handshake response")

        return cls(reader, writer, is_client=True)

    @classmethod
    async def accept(
        cls,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        timeout: float = 10.0,
    ) -> Optional['RawWebSocket']:
        """Принимает WS-соединение от клиента."""
        try:
            first_line_raw = await asyncio.wait_for(
                reader.readline(), timeout=timeout
            )
            if not first_line_raw:
                return None

            # Детекция TLS на plaintext порту
            if first_line_raw.startswith(b'\x16\x03'):
                logging.getLogger("server").error(
                    "TLS Client Hello на Plaintext порту! "
                    "Запустите сервер с --tls."
                )
                return None

            first_line = first_line_raw.decode('utf-8', 'ignore').strip()
            if not first_line.upper().startswith("GET"):
                return None

            headers = {}
            while True:
                line_raw = await asyncio.wait_for(
                    reader.readline(), timeout=timeout
                )
                if line_raw == b'\r\n' or not line_raw:
                    break
                line = line_raw.decode('utf-8', 'ignore').strip()
                parts = line.split(":", 1)
                if len(parts) == 2:
                    headers[parts[0].strip().lower()] = parts[1].strip()

            ws_key = headers.get("sec-websocket-key")
            if not ws_key:
                return None

            magic = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
            accept_key = base64.b64encode(
                hashlib.sha1(ws_key.encode() + magic).digest()
            ).decode()

            res = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept_key}\r\n\r\n"
            )
            writer.write(res.encode())
            await writer.drain()

            return cls(reader, writer, is_client=False)

        except asyncio.TimeoutError:
            return None
        except Exception:
            return None

    @staticmethod
    def _xor_mask(data: bytes, mask: bytes) -> bytes:
        """
        XOR-маскирование через массив байт (array модуль).
        Работает in-place, без аллокации больших int объектов.
        """
        n = len(data)
        if n == 0:
            return b""

        # Используем bytearray для in-place XOR — 
        # это быстрее int.from_bytes для больших данных,
        # так как не требует аллокации двух 128KB+ int объектов.
        result = bytearray(data)
        mask_len = len(mask)
        # Обрабатываем блоками по 8 байт (маска повторяется каждые 4)
        # Для максимальной скорости используем memoryview
        for i in range(n):
            result[i] ^= mask[i % mask_len]
        return bytes(result)

    async def send(self, data: bytes, is_text: bool = False) -> None:
        """
        Атомарная отправка WS-кадра.
        Защищена блокировкой для безопасности в мультиплексоре.
        Включает drain() для контроля backpressure.
        """
        if self.closed:
            return

        opcode = self.OP_TEXT if is_text else self.OP_BIN
        length = len(data)

        # Собираем заголовок
        header = bytearray()
        header.append(0x80 | opcode)

        mask_bit = 0x80 if self.is_client else 0x00
        if length < 126:
            header.append(mask_bit | length)
        elif length < 65536:
            header.append(mask_bit | 126)
            header.extend(struct.pack('!H', length))
        else:
            header.append(mask_bit | 127)
            header.extend(struct.pack('!Q', length))

        async with self._send_lock:
            if self.is_client:
                mask = os.urandom(4)
                header.extend(mask)
                # Пишем заголовок и данные отдельно —
                # так мы избегаем копирования 128KB в bytearray
                self.writer.write(bytes(header))
                self.writer.write(self._xor_mask(data, mask))
            else:
                # Сервер не маскирует — пишем заголовок + данные напрямую
                self.writer.write(bytes(header))
                self.writer.write(data)

            await self.writer.drain()

    async def recv(self) -> Optional[bytes]:
        """Получает WS-фрейм. Обрабатывает PING/PONG/CLOSE."""
        while not self.closed:
            try:
                hdr = await self.reader.readexactly(2)
                opcode = hdr[0] & 0x0F
                is_masked = bool(hdr[1] & 0x80)
                length = hdr[1] & 0x7F

                if length == 126:
                    raw = await self.reader.readexactly(2)
                    length = struct.unpack('!H', raw)[0]
                elif length == 127:
                    raw = await self.reader.readexactly(8)
                    length = struct.unpack('!Q', raw)[0]

                mask = await self.reader.readexactly(4) if is_masked else b''
                payload = await self.reader.readexactly(length)

                if is_masked:
                    payload = self._xor_mask(payload, mask)

                if opcode == self.OP_CLOSE:
                    await self.close()
                    return None
                elif opcode == self.OP_PING:
                    async with self._send_lock:
                        self.writer.write(bytes([0x80 | self.OP_PONG, 0]))
                        await self.writer.drain()
                    continue
                elif opcode in (self.OP_TEXT, self.OP_BIN):
                    return payload

            except (asyncio.IncompleteReadError, ConnectionError, OSError):
                self.closed = True
                return None

        return None

    async def close(self) -> None:
        """Закрывает WS-соединение."""
        if self.closed:
            return
        self.closed = True
        try:
            async with self._send_lock:
                self.writer.write(bytes([0x80 | self.OP_CLOSE, 0x00]))
                await self.writer.drain()
        except Exception:
            pass
        finally:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception:
                pass


class MuxProtocol:
    """
    Бинарный протокол мультиплексирования.
    Формат кадра: [CMD: 1 байт] [ChannelID: 4 байта BE] [Payload: N байт]
    """
    CMD_OPEN = 0x01
    CMD_DATA = 0x02
    CMD_CLOSE = 0x03

    # Предкомпилированный struct для производительности
    _HEADER = struct.Struct('!BI')

    @classmethod
    def pack(cls, cmd: int, channel_id: int, data: bytes = b'') -> bytes:
        """Упаковывает мультиплексный кадр."""
        return cls._HEADER.pack(cmd, channel_id) + data

    @classmethod
    def unpack(cls, frame: bytes):
        """Распаковывает мультиплексный кадр."""
        if len(frame) < 5:
            return None, None, None
        cmd, channel_id = cls._HEADER.unpack_from(frame, 0)
        return cmd, channel_id, frame[5:]
