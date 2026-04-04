import asyncio
import argparse
import json
from typing import Optional
from utils import RawWebSocket, setup_logger

logger = setup_logger("server")

class Server:
    def __init__(self, host: str, port: int):
        """
        Инициализация сервера.
        
        Args:
            host (str): Хост для прослушивания (обычно 0.0.0.0).
            port (int): Порт для прослушивания (обычно 443 или 8443).
        """
        self.host = host
        self.port = port
        
    async def handle_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        """Обрабатывает входящее подключение (WebSocket -> TCP Target)."""
        peername = client_writer.get_extra_info('peername')
        client_ip = f"{peername[0]}:{peername[1]}" if peername else "Unknown"
        logger.info(f"[{client_ip}] Входящее подключение...")
        
        ws: Optional[RawWebSocket] = None
        target_writer: Optional[asyncio.StreamWriter] = None
        
        try:
            # Принимаем WS-рукопожатие с таймаутом
            ws = await RawWebSocket.accept(client_reader, client_writer, timeout=10.0)
            if not ws:
                logger.warning(f"[{client_ip}] Неверный WS handshake (проверьте TLS/WSS настройки или наличие Proxy).")
                client_writer.close()
                return
                
            logger.info(f"[{client_ip}] WS handshake успешен. Ожидание команды...")
            
            # Читаем конфигурационный фрейм (JSON: {"host": "...", "port": ...})
            init_frame = await asyncio.wait_for(ws.recv(), timeout=5.0)
            if not init_frame:
                raise ValueError("Соединение закрыто до получения команды.")
                
            try:
                command = json.loads(init_frame.decode('utf-8'))
                target_host = command['host']
                target_port = command['port']
            except (json.JSONDecodeError, KeyError) as e:
                logger.error(f"[{client_ip}] Некорректный командный фрейм: {e}")
                await ws.send(b'{"status": "error", "msg": "Invalid command"}', is_text=True)
                return
                
            logger.info(f"[{client_ip}] Запрос туннеля к {target_host}:{target_port}")
            
            # Подключаемся к целевому хосту
            try:
                target_reader, target_writer = await asyncio.wait_for(
                    asyncio.open_connection(target_host, target_port), timeout=10.0
                )
                await ws.send(b'{"status": "ok"}', is_text=True)
                logger.info(f"[{client_ip}] Подключено к {target_host}:{target_port}")
            except Exception as e:
                logger.error(f"[{client_ip}] Ошибка подключения к {target_host}:{target_port} - {e}")
                await ws.send(json.dumps({"status": "error", "msg": str(e)}).encode('utf-8'), is_text=True)
                return

            # Мост с оптимизацией буферов
            if target_writer.transport:
                target_writer.transport.set_write_buffer_limits(high=1024 * 1024 * 2)
            if ws.writer.transport:
                ws.writer.transport.set_write_buffer_limits(high=1024 * 1024 * 2)

            async def ws_to_tcp():
                try:
                    while True:
                        data = await ws.recv()
                        if data is None:
                            break
                        target_writer.write(data)
                        if target_writer.transport.get_write_buffer_size() > 1024 * 1024:
                            await target_writer.drain()
                except Exception as e:
                    logger.debug(f"[{client_ip}] Ошибка ws->tcp: {e}")

            async def tcp_to_ws():
                try:
                    while True:
                        # Используем 128КБ буфер для отдачи
                        data = await target_reader.read(131072)
                        if not data:
                            break
                        await ws.send(data)
                        if ws.writer.transport.get_write_buffer_size() > 1024 * 1024:
                            await ws.writer.drain()
                except Exception as e:
                    logger.debug(f"[{client_ip}] Ошибка tcp->ws: {e}")

            # Запускаем двунаправленную передачу
            tasks = [asyncio.create_task(ws_to_tcp()), asyncio.create_task(tcp_to_ws())]
            _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            
            for task in pending:
                task.cancel()
                
            logger.info(f"[{client_ip}] Соединение с {target_host}:{target_port} завершено.")

        except asyncio.TimeoutError:
            logger.warning(f"[{client_ip}] Таймаут ожидания.")
        except Exception as e:
            logger.error(f"[{client_ip}] Ошибка обработки: {e}")
        finally:
            if ws:
                await ws.close()
            if target_writer:
                target_writer.close()
            
    async def start(self, use_tls: bool = False):
        """Запуск сервера."""
        ssl_context = None
        if use_tls:
            import ssl
            import tempfile
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            import datetime
            
            # Генерируем временный самоподписанный сертификат для тестирования, 
            # если пользователь не указал свои пути.
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u"universal-ws-proxy"),
            ])
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.now(datetime.timezone.utc)
            ).not_valid_after(
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
            ).sign(key, hashes.SHA256())
            
            with tempfile.NamedTemporaryFile(delete=False) as key_f:
                key_f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
                key_path = key_f.name
                
            with tempfile.NamedTemporaryFile(delete=False) as cert_f:
                cert_f.write(cert.public_bytes(serialization.Encoding.PEM))
                cert_path = cert_f.name
                
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(certfile=cert_path, keyfile=key_path)

        server = await asyncio.start_server(self.handle_client, self.host, self.port, ssl=ssl_context)
        addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        logger.info(f"Server (Universal WS Proxy) запущен на {addrs} (TLS: {use_tls})")
        
        async with server:
            await server.serve_forever()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Universal WebSocket Proxy Server")
    parser.add_argument("--host", default="0.0.0.0", help="Хост для прослушивания")
    parser.add_argument("--port", type=int, default=8443, help="Порт для прослушивания")
    parser.add_argument("--tls", action="store_true", help="Включить поддержку TLS (WSS)")
    args = parser.parse_args()
    
    srv = Server(args.host, args.port)
    try:
        asyncio.run(srv.start(use_tls=args.tls))
    except KeyboardInterrupt:
        logger.info("Сервер остановлен.")
