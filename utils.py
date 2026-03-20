import asyncio
import base64
import hashlib
import json
import logging
import os
import struct
from typing import Optional, Tuple, Dict, Any, List

class WSError(Exception):
    """Исключение для ошибок WebSocket."""
    pass

def setup_logger(name: str) -> logging.Logger:
    """
    Настраивает и возвращает логгер.
    
    Args:
        name (str): Имя логгера.
        
    Returns:
        logging.Logger: Настроенный логгер.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger

class RawWebSocket:
    """
    Асинхронный клиент/сервер WebSocket без использования сторонних библиотек.
    Реализует базовое чтение и запись бинарных и текстовых фреймов.
    """
    OP_CONT = 0x0
    OP_TEXT = 0x1
    OP_BIN = 0x2
    OP_CLOSE = 0x8
    OP_PING = 0x9
    OP_PONG = 0xA

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, is_client: bool):
        """
        Инициализация WS-соединения.
        
        Args:
            reader (asyncio.StreamReader): Поток чтения.
            writer (asyncio.StreamWriter): Поток записи.
            is_client (bool): Является ли текущая сторона клиентом (определяет маскирование).
        """
        self.reader = reader
        self.writer = writer
        self.is_client = is_client
        self.closed = False

    @classmethod
    async def connect(cls, host: str, port: int, path: str = "/") -> 'RawWebSocket':
        """
        Устанавливает соединение с сервером по WSS.
        Оставлено без SSL для тестирования локально или через TLS Termination Proxy.
        Если требуется SSL, необходимо использовать ssl_context.
        
        Args:
            host (str): Адрес сервера.
            port (int): Порт сервера.
            path (str): Путь запроса.
            
        Returns:
            RawWebSocket: Объект соединения.
            
        Raises:
            WSError: Ошибка рукопожатия.
        """
        reader, writer = await asyncio.open_connection(host, port)
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

        # Читаем заголовки
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
    async def accept(cls, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Optional['RawWebSocket']:
        """
        Принимает WS-соединение на сервере.
        
        Args:
            reader (asyncio.StreamReader): Поток чтения.
            writer (asyncio.StreamWriter): Поток записи.
            
        Returns:
            Optional[RawWebSocket]: Соединение или None, если запрос не валиден.
        """
        headers = {}
        first_line = await reader.readline()
        if not first_line:
            return None
            
        while True:
            line = await reader.readline()
            if line == b'\r\n' or not line:
                break
            parts = line.decode('utf-8', 'ignore').strip().split(":", 1)
            if len(parts) == 2:
                headers[parts[0].strip().lower()] = parts[1].strip()

        ws_key = headers.get("sec-websocket-key")
        if not ws_key:
            return None
            
        # Генерация ответа (RFC 6455)
        magic = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        accept_key = base64.b64encode(hashlib.sha1(ws_key.encode() + magic).digest()).decode()
        
        res = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept_key}\r\n\r\n"
        )
        writer.write(res.encode())
        await writer.drain()
        
        return cls(reader, writer, is_client=False)

    def _xor_mask(self, data: bytes, mask: bytes) -> bytes:
        """
        Применяет XOR-маскирование к данным.
        
        Args:
            data (bytes): Исходные данные.
            mask (bytes): 4-байтовая маска.
            
        Returns:
            bytes: Маскированные данные.
        """
        mask_int = int.from_bytes(mask, 'big')
        n = len(data)
        # Быстрый XOR без циклов, генерируем маску нужной длины
        mask_rep = (mask * (n // 4 + 1))[:n]
        return (int.from_bytes(data, 'big') ^ int.from_bytes(mask_rep, 'big')).to_bytes(n, 'big')

    async def send(self, data: bytes, is_text: bool = False):
        """
        Отправляет фрейм данных.
        
        Args:
            data (bytes): Данные для отправки.
            is_text (bool): Флаг текстового сообщения (иначе бинарное).
        """
        if self.closed:
            return
            
        opcode = self.OP_TEXT if is_text else self.OP_BIN
        header = bytearray([0x80 | opcode])
        length = len(data)
        
        mask_bit = 0x80 if self.is_client else 0x00
        
        if length < 126:
            header.append(mask_bit | length)
        elif length < 65536:
            header.append(mask_bit | 126)
            header.extend(struct.pack('!H', length))
        else:
            header.append(mask_bit | 127)
            header.extend(struct.pack('!Q', length))
            
        if self.is_client:
            mask = os.urandom(4)
            header.extend(mask)
            self.writer.write(bytes(header) + self._xor_mask(data, mask))
        else:
            self.writer.write(bytes(header) + data)
            
        await self.writer.drain()

    async def recv(self) -> Optional[bytes]:
        """
        Получает и возвращает полезную нагрузку WS-фрейма.
        Автоматически обрабатывает PING/PONG/CLOSE.
        
        Returns:
            Optional[bytes]: Данные или None, если соединение закрыто.
        """
        while not self.closed:
            try:
                hdr = await self.reader.readexactly(2)
                opcode = hdr[0] & 0x0F
                is_masked = bool(hdr[1] & 0x80)
                length = hdr[1] & 0x7F
                
                if length == 126:
                    length = struct.unpack('!H', await self.reader.readexactly(2))[0]
                elif length == 127:
                    length = struct.unpack('!Q', await self.reader.readexactly(8))[0]
                    
                mask = await self.reader.readexactly(4) if is_masked else b''
                payload = await self.reader.readexactly(length)
                
                if is_masked:
                    payload = self._xor_mask(payload, mask)
                    
                if opcode == self.OP_CLOSE:
                    await self.close()
                    return None
                elif opcode == self.OP_PING:
                    pong_hdr = bytearray([0x80 | self.OP_PONG, 0])  # Упрощенный PONG без маски (сервер)
                    self.writer.write(bytes(pong_hdr))
                    await self.writer.drain()
                    continue
                elif opcode in (self.OP_TEXT, self.OP_BIN):
                    return payload
            except (asyncio.IncompleteReadError, ConnectionError, OSError):
                self.closed = True
                return None
                
        return None

    async def close(self):
        """Закрывает соединение."""
        if self.closed:
            return
        self.closed = True
        try:
            # Отправляем фрейм закрытия
            self.writer.write(bytes([0x80 | self.OP_CLOSE, 0x00]))
            await self.writer.drain()
        except Exception:
            pass
        finally:
            self.writer.close()
            await self.writer.wait_closed()
