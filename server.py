import asyncio
import argparse
import json
import logging
from typing import Optional, Tuple
from utils import RawWebSocket, setup_logger, WSError

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
            # Принимаем WS-рукопожатие
            ws = await RawWebSocket.accept(client_reader, client_writer)
            if not ws:
                logger.warning(f"[{client_ip}] Неверный WS handshake.")
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

            # Функции моста
            async def ws_to_tcp():
                try:
                    while True:
                        data = await ws.recv()
                        if data is None:
                            break
                        target_writer.write(data)
                        await target_writer.drain()
                except Exception as e:
                    logger.debug(f"[{client_ip}] Ошибка ws->tcp: {e}")

            async def tcp_to_ws():
                try:
                    while True:
                        data = await target_reader.read(65536)
                        if not data:
                            break
                        await ws.send(data)
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
            
    async def start(self):
        """Запуск сервера."""
        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        logger.info(f"Server (Universal WS Proxy) запущен на {addrs}")
        
        async with server:
            await server.serve_forever()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Universal WebSocket Proxy Server")
    parser.add_argument("--host", default="0.0.0.0", help="Хост для прослушивания")
    parser.add_argument("--port", type=int, default=8443, help="Порт для прослушивания")
    args = parser.parse_args()
    
    srv = Server(args.host, args.port)
    try:
        asyncio.run(srv.start())
    except KeyboardInterrupt:
        logger.info("Сервер остановлен.")
