import asyncio
import argparse
import json
import socket
from typing import Dict, Optional
from utils import RawWebSocket, setup_logger, MuxProtocol

logger = setup_logger("server")

class Server:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.channels: Dict[int, asyncio.Queue] = {}
        self._ws: Optional[RawWebSocket] = None

    async def _target_worker(self, channel_id: int, host: str, port: int):
        """Обработка одного канала мультиплексора (соединение с целью)."""
        logger.info(f"[Ch:{channel_id}] Подключение к {host}:{port}...")
        try:
            target_reader, target_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10.0
            )
            
            # Настраиваем сокет для скорости
            if target_writer.transport:
                sock = target_writer.transport.get_extra_info('socket')
                if sock:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            logger.info(f"[Ch:{channel_id}] Соединение установлено")
            
            async def target_to_ws():
                try:
                    while True:
                        data = await target_reader.read(131072)
                        if not data: break
                        await self._ws.send(MuxProtocol.pack(MuxProtocol.CMD_DATA, channel_id, data))
                        if self._ws.writer.transport.get_write_buffer_size() > 1024*1024:
                            await self._ws.writer.drain()
                except Exception: pass
                finally:
                    await self._ws.send(MuxProtocol.pack(MuxProtocol.CMD_CLOSE, channel_id))

            async def ws_to_target():
                try:
                    queue = self.channels[channel_id]
                    while True:
                        data = await queue.get()
                        if data is None: break
                        target_writer.write(data)
                        if target_writer.transport.get_write_buffer_size() > 1024*1024:
                            await target_writer.drain()
                except Exception: pass
                finally:
                    target_writer.close()
            
            await asyncio.gather(target_to_ws(), ws_to_target())
        except Exception as e:
            logger.error(f"[Ch:{channel_id}] Ошибка подключения к {host}:{port}: {e}")
            await self._ws.send(MuxProtocol.pack(MuxProtocol.CMD_CLOSE, channel_id))
        finally:
            self.channels.pop(channel_id, None)
            logger.info(f"[Ch:{channel_id}] Канал закрыт")

    async def handle_ws(self, reader, writer):
        """Обработка мультиплексного WS-туннеля."""
        ws = await RawWebSocket.accept(reader, writer)
        if not ws:
            writer.close()
            return
        
        self._ws = ws
        logger.info("Мультиплексный туннель установлен")
        
        try:
            while True:
                frame = await ws.recv()
                if frame is None: break
                
                cmd, channel_id, payload = MuxProtocol.unpack(frame)
                if cmd == MuxProtocol.CMD_OPEN:
                    try:
                        info = json.loads(payload.decode())
                        target_host, target_port = info['host'], info['port']
                        queue = asyncio.Queue(maxsize=100)
                        self.channels[channel_id] = queue
                        asyncio.create_task(self._target_worker(channel_id, target_host, target_port))
                    except Exception as e:
                        logger.error(f"Ошибка открытия канала: {e}")
                
                elif cmd == MuxProtocol.CMD_DATA:
                    if channel_id in self.channels:
                        await self.channels[channel_id].put(payload)
                
                elif cmd == MuxProtocol.CMD_CLOSE:
                    if channel_id in self.channels:
                        await self.channels[channel_id].put(None)
                        
        except Exception as e:
            logger.error(f"Ошибка туннеля: {e}")
        finally:
            logger.info("Туннель закрыт, очистка каналов...")
            for q in list(self.channels.values()):
                await q.put(None)
            self.channels.clear()

    async def start(self):
        server = await asyncio.start_server(self.handle_ws, self.host, self.port)
        logger.info(f"Server (Multiplexed WSS) запущен на {self.host}:{self.port}")
        async with server:
            await server.serve_forever()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--tls", action="store_true", help="Use SSL/TLS (Self-signed auto-gen)")
    args = parser.parse_args()

    # Если TLS включен, создаем контекст
    ssl_context = None
    if args.tls:
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import datetime
            import ssl
            import tempfile

            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"UniversalProxy")])
            cert = (x509.CertificateBuilder()
                    .subject_name(subject).issuer_name(issuer)
                    .public_key(key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(datetime.datetime.utcnow())
                    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
                    .add_extension(x509.SubjectAlternativeName([x509.DNSName(u"localhost")]), critical=False)
                    .sign(key, hashes.SHA256()))

            with tempfile.NamedTemporaryFile(delete=False) as cert_file, \
                 tempfile.NamedTemporaryFile(delete=False) as key_file:
                cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
                key_file.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
                cert_path, key_path = cert_file.name, key_file.name

            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(cert_path, key_path)
            logger.info("Самоподписанный TLS сертификат сгенерирован")
        except Exception as e:
            logger.error(f"Не удалось создать TLS сертификат: {e}. Используем Plaintext.")

    srv = Server(args.host, args.port)
    
    # Для TLS нам нужно вызвать start_server с ssl=ssl_context вручную, 
    # так как существующий метод start() не принимает его.
    async def start_with_tls():
        server = await asyncio.start_server(srv.handle_ws, srv.host, srv.port, ssl=ssl_context)
        logger.info(f"Server (Multiplexed WSS) запущен на {srv.host}:{srv.port} (TLS: {args.tls})")
        async with server:
            await server.serve_forever()

    asyncio.run(start_with_tls())
