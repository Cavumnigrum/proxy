import asyncio
import argparse
import json
import os
import struct
import socket
import ssl
from typing import Dict, Any, Optional
from utils import RawWebSocket, setup_logger, MuxProtocol

logger = setup_logger("client")

class Client:
    def __init__(self, config_path: str = "config.json"):
        self.config = self._load_config(config_path)
        self.mode = self.config.get("mode", "wss")
        self.local_port = self.config.get("local_socks5_port", 1081)
        self.bypass_domains = set(self.config.get("bypass_domains", []))
        self.bypass_ips = set(self.config.get("bypass_ips", []))
        
        # Реестр каналов мультиплексора (ID -> Queue)
        self.channels: Dict[int, asyncio.Queue] = {}
        self.next_channel_id = 1
        self._ws: Optional[RawWebSocket] = None
        self._ws_lock = asyncio.Lock()
        
    def _load_config(self, path: str) -> Dict[str, Any]:
        if not os.path.exists(path): raise FileNotFoundError(f"Config file {path} not found.")
        with open(path, "r", encoding="utf-8") as f: return json.load(f)

    def _should_bypass(self, target_host: str) -> bool:
        for domain in self.bypass_domains:
            if target_host == domain or target_host.endswith("." + domain): return True
        for ip_mask in self.bypass_ips:
            if "/" in ip_mask:
                base_ip = ip_mask.split("/")[0]
                if target_host.startswith(base_ip.rsplit(".", 1)[0]): return True
            elif target_host == ip_mask: return True
        return False

    async def _get_ws(self):
        """Возвращает или создает постоянное WSS соединение."""
        async with self._ws_lock:
            if self._ws and not self._ws.closed:
                return self._ws
            
            ws_host = self.config.get("server_ws_host", "127.0.0.1")
            ws_port = self.config.get("server_ws_port", 8443)
            use_tls = self.config.get("server_ws_tls", self.mode == "wss")
            
            logger.info(f"Установка нового туннеля к {ws_host}:{ws_port} (TLS: {use_tls})...")
            
            ssl_context = None
            if use_tls:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

            self._ws = await RawWebSocket.connect(ws_host, ws_port, ssl_context=ssl_context)
            
            # Настройка сокета для скорости
            if self._ws.writer.transport:
                sock = self._ws.writer.transport.get_extra_info('socket')
                if sock:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)

            # Запускаем фоновый чтец туннеля
            asyncio.create_task(self._ws_reader_task(self._ws))
            logger.info("Мультиплексный туннель активен")
            return self._ws

    async def _ws_reader_task(self, ws: RawWebSocket):
        """Читает фреймы из WS и раскидывает по очередям каналов."""
        try:
            while not ws.closed:
                frame = await ws.recv()
                if frame is None: break
                
                cmd, channel_id, payload = MuxProtocol.unpack(frame)
                if cmd == MuxProtocol.CMD_DATA:
                    if channel_id in self.channels:
                        await self.channels[channel_id].put(payload)
                elif cmd == MuxProtocol.CMD_CLOSE:
                    if channel_id in self.channels:
                        await self.channels[channel_id].put(None)
        except Exception as e:
            logger.error(f"WS Reader Error: {e}")
        finally:
            logger.info("WS Туннель закрыт, очистка всех активных каналов")
            for q in list(self.channels.values()):
                await q.put(None)
            self.channels.clear()

    async def _handle_socks5(self, reader, writer):
        """Рукопожатие SOCKS5."""
        try:
            # 1. Hello
            hdr = await reader.readexactly(2)
            if hdr[0] != 0x05: return
            nmethods = hdr[1]
            await reader.readexactly(nmethods)
            writer.write(b'\x05\x00')
            await writer.drain()
            
            # 2. Request
            req = await reader.readexactly(4)
            ver, cmd, rsv, atyp = req
            if cmd != 0x01: return
            if atyp == 0x01: target_host = socket.inet_ntoa(await reader.readexactly(4))
            elif atyp == 0x03:
                dlen = (await reader.readexactly(1))[0]
                target_host = (await reader.readexactly(dlen)).decode()
            else: return
            target_port = struct.unpack('!H', await reader.readexactly(2))[0]
            
            # 3. Маршрутизация
            if self._should_bypass(target_host):
                await self._handle_direct(reader, writer, target_host, target_port)
            else:
                await self._handle_tunnel(reader, writer, target_host, target_port)
        except Exception as e:
            logger.debug(f"SOCKS5 error: {e}")
            writer.close()

    async def _handle_direct(self, reader, writer, host, port):
        logger.info(f"Bypass: {host}:{port}")
        try:
            t_reader, t_writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=10.0)
            writer.write(b'\x05\x00\x00\x01' + b'\x00'*6)
            await writer.drain()
            await self._bridge(reader, writer, t_reader, t_writer)
        except Exception:
            writer.write(b'\x05\x05\x00\x01' + b'\x00'*6)
            await writer.drain()

    async def _handle_tunnel(self, reader, writer, host, port):
        """Создает новый канал внутри мультиплексного WS-туннеля."""
        channel_id = self.next_channel_id
        self.next_channel_id += 1
        queue = asyncio.Queue(maxsize=100)
        self.channels[channel_id] = queue
        
        logger.info(f"[Ch:{channel_id}] Туннель к {host}:{port}")
        
        try:
            ws = await self._get_ws()
            
            # Отправляем CMD_OPEN
            info = json.dumps({"host": host, "port": port}).encode()
            await ws.send(MuxProtocol.pack(MuxProtocol.CMD_OPEN, channel_id, info))
            
            # Подтверждаем SOCKS5
            writer.write(b'\x05\x00\x00\x01' + b'\x00'*6)
            await writer.drain()
            
            async def tcp_to_ws():
                try:
                    while True:
                        data = await reader.read(131072)
                        if not data: break
                        await ws.send(MuxProtocol.pack(MuxProtocol.CMD_DATA, channel_id, data))
                        if ws.writer.transport.get_write_buffer_size() > 1024 * 1024:
                            await ws.writer.drain()
                except Exception: pass
                finally:
                    await ws.send(MuxProtocol.pack(MuxProtocol.CMD_CLOSE, channel_id))

            async def ws_to_tcp():
                try:
                    while True:
                        data = await queue.get()
                        if data is None: break
                        writer.write(data)
                        if writer.transport.get_write_buffer_size() > 1024 * 1024:
                            await writer.drain()
                except Exception: pass
                finally:
                    writer.close()

            await asyncio.gather(tcp_to_ws(), ws_to_tcp())
            
        except Exception as e:
            logger.error(f"[Ch:{channel_id}] Ошибка канала: {e}")
            writer.close()
        finally:
            self.channels.pop(channel_id, None)

    async def _bridge(self, r1, w1, r2, w2):
        async def fwd(src, dst):
            try:
                while True:
                    data = await src.read(131072)
                    if not data: break
                    dst.write(data)
                    if dst.transport.get_write_buffer_size() > 1024*1024: await dst.drain()
            except Exception: pass
            finally: dst.close()
        await asyncio.gather(fwd(r1, w2), fwd(r2, w1))

    async def start(self):
        server = await asyncio.start_server(self._handle_socks5, '127.0.0.1', self.local_port)
        logger.info(f"Client (Multi-Stream SOCKS5) запущен на 127.0.0.1:{self.local_port}")
        async with server: await server.serve_forever()

if __name__ == "__main__":
    cli = Client()
    try: asyncio.run(cli.start())
    except KeyboardInterrupt: logger.info("Стоп.")
