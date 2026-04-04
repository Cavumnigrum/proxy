import asyncio
import argparse
import json
import socket
from typing import Dict, Optional

from utils import RawWebSocket, setup_logger, MuxProtocol

logger = setup_logger("server")

# Размер чанка для чтения с целевых серверов.
# Должен совпадать с клиентом для оптимального интерлеавинга.
CHUNK_SIZE = 32768  # 32 KB


class Server:
    """
    Мультиплексный WS-сервер.
    
    Принимает одно WS-соединение от клиента.
    Каждый канал (channel_id) соответствует одному 
    SOCKS5-запросу от браузера.
    """

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.channels: Dict[int, asyncio.Queue] = {}
        self._ws: Optional[RawWebSocket] = None

    async def _target_worker(
        self, channel_id: int, host: str, port: int
    ) -> None:
        """
        Обрабатывает один канал мультиплексора.
        Устанавливает TCP-соединение с целевым сервером
        и пересылает данные в обе стороны.
        """
        logger.info(f"[Ch:{channel_id}] → {host}:{port}")
        try:
            target_reader, target_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10.0
            )

            # TCP_NODELAY для минимизации задержки
            if target_writer.transport:
                sock = target_writer.transport.get_extra_info('socket')
                if sock:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            async def target_to_ws() -> None:
                """Целевой сервер → WS-туннель (Download)."""
                try:
                    while True:
                        data = await target_reader.read(CHUNK_SIZE)
                        if not data:
                            break
                        await self._ws.send(MuxProtocol.pack(
                            MuxProtocol.CMD_DATA, channel_id, data
                        ))
                except Exception:
                    pass
                finally:
                    try:
                        await self._ws.send(MuxProtocol.pack(
                            MuxProtocol.CMD_CLOSE, channel_id
                        ))
                    except Exception:
                        pass

            async def ws_to_target() -> None:
                """WS-туннель → Целевой сервер (Upload)."""
                try:
                    queue = self.channels.get(channel_id)
                    if queue is None:
                        return
                    while True:
                        data = await queue.get()
                        if data is None:
                            break
                        target_writer.write(data)
                        await target_writer.drain()
                except Exception:
                    pass

            done, pending = await asyncio.wait(
                [asyncio.create_task(target_to_ws()),
                 asyncio.create_task(ws_to_target())],
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()

        except asyncio.TimeoutError:
            logger.warning(f"[Ch:{channel_id}] Timeout к {host}:{port}")
            try:
                await self._ws.send(MuxProtocol.pack(
                    MuxProtocol.CMD_CLOSE, channel_id
                ))
            except Exception:
                pass
        except Exception as e:
            logger.error(f"[Ch:{channel_id}] Ошибка: {e}")
            try:
                await self._ws.send(MuxProtocol.pack(
                    MuxProtocol.CMD_CLOSE, channel_id
                ))
            except Exception:
                pass
        finally:
            self.channels.pop(channel_id, None)
            try:
                target_writer.close()
            except Exception:
                pass

    async def handle_ws(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Обработка мультиплексного WS-туннеля."""
        peer = writer.get_extra_info('peername')
        peer_str = f"{peer[0]}:{peer[1]}" if peer else "Unknown"
        logger.info(f"[{peer_str}] Входящее подключение")

        ws = await RawWebSocket.accept(reader, writer)
        if not ws:
            logger.warning(f"[{peer_str}] WS handshake failed")
            writer.close()
            return

        self._ws = ws
        logger.info(f"[{peer_str}] Мультиплексный туннель установлен")

        try:
            while True:
                frame = await ws.recv()
                if frame is None:
                    break

                cmd, channel_id, payload = MuxProtocol.unpack(frame)
                if cmd is None:
                    continue

                if cmd == MuxProtocol.CMD_OPEN:
                    try:
                        info = json.loads(payload.decode())
                        target_host = info['host']
                        target_port = info['port']
                        # Очередь с ограничением: 8 × 32KB = 256KB буфер
                        queue: asyncio.Queue = asyncio.Queue(maxsize=8)
                        self.channels[channel_id] = queue
                        asyncio.create_task(
                            self._target_worker(
                                channel_id, target_host, target_port
                            )
                        )
                    except Exception as e:
                        logger.error(f"Ошибка открытия канала: {e}")

                elif cmd == MuxProtocol.CMD_DATA:
                    queue = self.channels.get(channel_id)
                    if queue is not None:
                        try:
                            queue.put_nowait(payload)
                        except asyncio.QueueFull:
                            # Если очередь заполнена — пропускаем.
                            # Это лучше чем блокировать весь мультиплексор.
                            logger.debug(
                                f"[Ch:{channel_id}] Queue full, dropped"
                            )

                elif cmd == MuxProtocol.CMD_CLOSE:
                    queue = self.channels.get(channel_id)
                    if queue is not None:
                        try:
                            queue.put_nowait(None)
                        except asyncio.QueueFull:
                            pass

        except Exception as e:
            logger.error(f"Ошибка туннеля: {e}")
        finally:
            logger.info(f"[{peer_str}] Туннель закрыт, очистка каналов")
            for q in list(self.channels.values()):
                try:
                    q.put_nowait(None)
                except asyncio.QueueFull:
                    pass
            self.channels.clear()
            self._ws = None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Universal Proxy Server (Multiplexed WSS)"
    )
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument(
        "--tls", action="store_true",
        help="Включить TLS (автогенерация самоподписанного сертификата)"
    )
    args = parser.parse_args()

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

            key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048
            )
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u"UniversalProxy")
            ])
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.utcnow())
                .not_valid_after(
                    datetime.datetime.utcnow() + datetime.timedelta(days=365)
                )
                .add_extension(
                    x509.SubjectAlternativeName([
                        x509.DNSName(u"localhost")
                    ]),
                    critical=False,
                )
                .sign(key, hashes.SHA256())
            )

            with tempfile.NamedTemporaryFile(delete=False) as cert_file, \
                 tempfile.NamedTemporaryFile(delete=False) as key_file:
                cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
                key_file.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                ))
                cert_path = cert_file.name
                key_path = key_file.name

            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(cert_path, key_path)
            logger.info("TLS сертификат сгенерирован")

        except Exception as e:
            logger.error(f"TLS ошибка: {e}. Работа в Plaintext.")

    srv = Server(args.host, args.port)

    async def run() -> None:
        """Запуск сервера с опциональным TLS."""
        server = await asyncio.start_server(
            srv.handle_ws, srv.host, srv.port, ssl=ssl_context
        )
        tls_str = "TLS" if ssl_context else "Plaintext"
        logger.info(
            f"Server (Multiplexed WSS) запущен на "
            f"{srv.host}:{srv.port} ({tls_str})"
        )
        async with server:
            await server.serve_forever()

    asyncio.run(run())
