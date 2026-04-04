import asyncio
import json
import os
import struct
import socket
import ssl
from typing import Dict, Any, Optional

from utils import RawWebSocket, setup_logger, MuxProtocol

logger = setup_logger("client")


class Client:
    """
    Локальный SOCKS5-прокси с мультиплексированием.
    
    Архитектура: Все SOCKS5-запросы от браузера передаются
    через ОДНО постоянное WSS-соединение к серверу.
    Каждый запрос получает уникальный channel_id.
    """

    # Размер чанка для чтения из TCP.
    # 32KB — оптимальный баланс между:
    # - накладными расходами WS-фрейма (маленький чанк = больше фреймов)
    # - задержкой XOR-маскирования (большой чанк = дольше блокировка CPU)
    # - интерлеавингом каналов (маленький чанк = лучше интерлеавинг)
    CHUNK_SIZE = 32768  # 32 KB

    def __init__(self, config_path: str = "config.json"):
        self.config = self._load_config(config_path)
        self.mode = self.config.get("mode", "wss")
        self.local_port = self.config.get("local_socks5_port", 1081)
        self.bypass_domains = set(self.config.get("bypass_domains", []))
        self.bypass_ips = set(self.config.get("bypass_ips", []))

        # Мультиплексор
        self.channels: Dict[int, asyncio.Queue] = {}
        self._next_id = 1
        self._ws: Optional[RawWebSocket] = None
        self._ws_lock = asyncio.Lock()

    @staticmethod
    def _load_config(path: str) -> Dict[str, Any]:
        """Загрузка JSON-конфигурации."""
        if not os.path.exists(path):
            raise FileNotFoundError(f"Config file {path} not found.")
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _should_bypass(self, target_host: str) -> bool:
        """Проверка обхода прокси для домена/IP."""
        for domain in self.bypass_domains:
            if target_host == domain or target_host.endswith("." + domain):
                return True
        for ip_mask in self.bypass_ips:
            if "/" in ip_mask:
                base_ip = ip_mask.split("/")[0]
                if target_host.startswith(base_ip.rsplit(".", 1)[0]):
                    return True
            elif target_host == ip_mask:
                return True
        return False

    async def _get_ws(self) -> RawWebSocket:
        """
        Возвращает активное WS-соединение или создаёт новое.
        Потокобезопасно через asyncio.Lock.
        """
        async with self._ws_lock:
            if self._ws and not self._ws.closed:
                return self._ws

            ws_host = self.config.get("server_ws_host", "127.0.0.1")
            ws_port = self.config.get("server_ws_port", 8443)
            use_tls = self.config.get("server_ws_tls", self.mode == "wss")

            logger.info(
                f"Установка туннеля к {ws_host}:{ws_port} (TLS: {use_tls})..."
            )

            ssl_context = None
            if use_tls:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

            self._ws = await RawWebSocket.connect(
                ws_host, ws_port, ssl_context=ssl_context
            )

            # Настройка сокета
            if self._ws.writer.transport:
                sock = self._ws.writer.transport.get_extra_info('socket')
                if sock:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            # Фоновый чтец
            asyncio.create_task(self._ws_reader_loop(self._ws))
            logger.info("Мультиплексный туннель активен")
            return self._ws

    async def _ws_reader_loop(self, ws: RawWebSocket) -> None:
        """
        Фоновая корутина: читает WS-кадры и раскидывает
        данные по очередям каналов.
        """
        try:
            while not ws.closed:
                frame = await ws.recv()
                if frame is None:
                    break

                cmd, channel_id, payload = MuxProtocol.unpack(frame)

                if cmd == MuxProtocol.CMD_DATA:
                    queue = self.channels.get(channel_id)
                    if queue is not None:
                        await queue.put(payload)

                elif cmd == MuxProtocol.CMD_CLOSE:
                    queue = self.channels.get(channel_id)
                    if queue is not None:
                        await queue.put(None)

        except Exception as e:
            logger.error(f"WS Reader Error: {e}")
        finally:
            # Туннель упал — закрываем все каналы
            logger.warning("Туннель закрыт, очистка каналов")
            async with self._ws_lock:
                self._ws = None
            for q in list(self.channels.values()):
                try:
                    q.put_nowait(None)
                except asyncio.QueueFull:
                    pass
            self.channels.clear()

    async def _handle_socks5(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Обработка входящего SOCKS5-подключения от браузера."""
        try:
            # 1. Приветствие
            hdr = await asyncio.wait_for(reader.readexactly(2), timeout=5.0)
            if hdr[0] != 0x05:
                writer.close()
                return
            nmethods = hdr[1]
            await reader.readexactly(nmethods)
            writer.write(b'\x05\x00')
            await writer.drain()

            # 2. Запрос CONNECT
            req = await asyncio.wait_for(reader.readexactly(4), timeout=5.0)
            ver, cmd, rsv, atyp = req
            if cmd != 0x01:
                writer.write(b'\x05\x07\x00\x01' + b'\x00' * 6)
                await writer.drain()
                writer.close()
                return

            if atyp == 0x01:  # IPv4
                target_host = socket.inet_ntoa(await reader.readexactly(4))
            elif atyp == 0x03:  # Domain
                dlen = (await reader.readexactly(1))[0]
                target_host = (await reader.readexactly(dlen)).decode()
            elif atyp == 0x04:  # IPv6
                raw_ipv6 = await reader.readexactly(16)
                target_host = socket.inet_ntop(socket.AF_INET6, raw_ipv6)
            else:
                writer.write(b'\x05\x08\x00\x01' + b'\x00' * 6)
                await writer.drain()
                writer.close()
                return

            target_port = struct.unpack(
                '!H', await reader.readexactly(2)
            )[0]

            # 3. Маршрутизация
            if self._should_bypass(target_host):
                await self._handle_direct(
                    reader, writer, target_host, target_port
                )
            else:
                await self._handle_tunnel(
                    reader, writer, target_host, target_port
                )

        except asyncio.TimeoutError:
            logger.debug("SOCKS5 handshake timeout")
            writer.close()
        except Exception as e:
            logger.debug(f"SOCKS5 error: {e}")
            try:
                writer.close()
            except Exception:
                pass

    async def _handle_direct(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: str,
        port: int,
    ) -> None:
        """Прямое подключение (Bypass) без туннеля."""
        logger.debug(f"Bypass: {host}:{port}")
        try:
            t_reader, t_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10.0
            )

            writer.write(b'\x05\x00\x00\x01' + b'\x00' * 6)
            await writer.drain()

            await self._bridge(reader, writer, t_reader, t_writer)

        except Exception as e:
            logger.debug(f"Bypass error: {e}")
            try:
                writer.write(b'\x05\x05\x00\x01' + b'\x00' * 6)
                await writer.drain()
            except Exception:
                pass
        finally:
            writer.close()

    async def _handle_tunnel(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: str,
        port: int,
    ) -> None:
        """Создаёт канал внутри мультиплексного WS-туннеля."""
        channel_id = self._next_id
        self._next_id += 1

        # Очередь с ограничением — не более 8 элементов (8 × 32KB = 256KB)
        # Это предотвращает buffer bloat и снижает jitter
        queue: asyncio.Queue = asyncio.Queue(maxsize=8)
        self.channels[channel_id] = queue

        logger.info(f"[Ch:{channel_id}] → {host}:{port}")

        try:
            ws = await self._get_ws()

            # CMD_OPEN
            info = json.dumps({"host": host, "port": port}).encode()
            await ws.send(MuxProtocol.pack(
                MuxProtocol.CMD_OPEN, channel_id, info
            ))

            # SOCKS5 OK
            writer.write(b'\x05\x00\x00\x01' + b'\x00' * 6)
            await writer.drain()

            async def tcp_to_ws() -> None:
                """Браузер → WS-туннель."""
                try:
                    while True:
                        data = await reader.read(self.CHUNK_SIZE)
                        if not data:
                            break
                        await ws.send(MuxProtocol.pack(
                            MuxProtocol.CMD_DATA, channel_id, data
                        ))
                except Exception:
                    pass
                finally:
                    try:
                        await ws.send(MuxProtocol.pack(
                            MuxProtocol.CMD_CLOSE, channel_id
                        ))
                    except Exception:
                        pass

            async def ws_to_tcp() -> None:
                """WS-туннель → Браузер."""
                try:
                    while True:
                        data = await queue.get()
                        if data is None:
                            break
                        writer.write(data)
                        await writer.drain()
                except Exception:
                    pass

            done, pending = await asyncio.wait(
                [asyncio.create_task(tcp_to_ws()),
                 asyncio.create_task(ws_to_tcp())],
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()

        except Exception as e:
            logger.error(f"[Ch:{channel_id}] Ошибка: {e}")
        finally:
            self.channels.pop(channel_id, None)
            try:
                writer.close()
            except Exception:
                pass

    async def _bridge(
        self,
        r1: asyncio.StreamReader,
        w1: asyncio.StreamWriter,
        r2: asyncio.StreamReader,
        w2: asyncio.StreamWriter,
    ) -> None:
        """Двунаправленная пересылка TCP."""
        async def fwd(
            src: asyncio.StreamReader,
            dst: asyncio.StreamWriter,
        ) -> None:
            try:
                while True:
                    data = await src.read(self.CHUNK_SIZE)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except Exception:
                pass

        done, pending = await asyncio.wait(
            [asyncio.create_task(fwd(r1, w2)),
             asyncio.create_task(fwd(r2, w1))],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        for w in (w1, w2):
            try:
                w.close()
            except Exception:
                pass

    async def start(self) -> None:
        """Запуск SOCKS5 сервера."""
        server = await asyncio.start_server(
            self._handle_socks5, '127.0.0.1', self.local_port
        )
        logger.info(
            f"SOCKS5 Proxy запущен на 127.0.0.1:{self.local_port} "
            f"(режим: {self.mode.upper()})"
        )
        async with server:
            await server.serve_forever()


if __name__ == "__main__":
    client = Client()
    try:
        asyncio.run(client.start())
    except KeyboardInterrupt:
        logger.info("Остановлен.")
