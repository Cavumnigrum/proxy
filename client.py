import asyncio
import json
import os
import struct
import socket
from typing import Dict, Any, Optional

import asyncssh

from utils import RawWebSocket, setup_logger

logger = setup_logger("client")

class Client:
    def __init__(self, config_path: str = "config.json"):
        """
        Инициализация клиента. Загрузка конфигурации.
        """
        self.config = self._load_config(config_path)
        self.mode = self.config.get("mode", "wss")
        self.local_port = self.config.get("local_socks5_port", 1080)
        self.bypass_domains = set(self.config.get("bypass_domains", []))
        # Здесь мы могли бы использовать ipaddress модуль для честной проверки подсетей,
        # но для упрощения первой итерации пока просто проверяем точные совпадения IP, 
        # либо можно написать простую логику маски.
        self.bypass_ips = set(self.config.get("bypass_ips", []))
        
        # Пул соединений для SSH и WSS
        self._ssh_conn: Optional[asyncssh.SSHClientConnection] = None
        self._ssh_lock = asyncio.Lock()
        
    def _load_config(self, path: str) -> Dict[str, Any]:
        """Загрузка JSON конфига."""
        if not os.path.exists(path):
            raise FileNotFoundError(f"Config file {path} not found.")
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
            
    def _should_bypass(self, target_host: str) -> bool:
        """
        Проверяет, нужно ли передавать трафик напрямую (обход прокси).
        
        Args:
            target_host (str): Целевой хост или IP.
            
        Returns:
            bool: True если прямой обход (direct pass), False если через туннель.
        """
        for domain in self.bypass_domains:
            if target_host == domain or target_host.endswith("." + domain):
                return True
                
        # Простая проверка прямого вхождения для IP. 
        # В идеале (production) - проверка CIDR.
        for ip_mask in self.bypass_ips:
            if "/" in ip_mask:
                # Todo: CIDR implementation
                base_ip = ip_mask.split("/")[0]
                if target_host.startswith(base_ip.rsplit(".", 1)[0]): # Грубая эвристика для /24 и /16
                     return True
            else:
                if target_host == ip_mask:
                    return True
        return False

    async def _socks5_handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Optional[tuple[str, int]]:
        """
        Выполняет рукопожатие SOCKS5.
        
        Returns:
            tuple: (target_host, target_port) или None при ошибке.
        """
        try:
            # 1. Приветствие SOCKS5
            hdr = await reader.readexactly(2)
            if hdr[0] != 0x05:
                return None
            nmethods = hdr[1]
            await reader.readexactly(nmethods)
            
            # Отвечаем No Auth
            writer.write(b'\x05\x00')
            await writer.drain()

            # 2. Запрос CONNECT
            req = await reader.readexactly(4)
            ver, cmd, rsv, atyp = req
            if cmd != 0x01: # Только CONNECT поддерживаем
                writer.write(b'\x05\x07\x00\x01' + b'\x00'*6)
                await writer.drain()
                return None

            if atyp == 0x01: # IPv4
                raw = await reader.readexactly(4)
                target_host = socket.inet_ntoa(raw)
            elif atyp == 0x03: # Domain
                dlen = (await reader.readexactly(1))[0]
                target_host = (await reader.readexactly(dlen)).decode('utf-8')
            else: # IPv6 (0x04) не поддерживаем в этой версии
                writer.write(b'\x05\x08\x00\x01' + b'\x00'*6)
                await writer.drain()
                return None

            port_raw = await reader.readexactly(2)
            target_port = struct.unpack('!H', port_raw)[0]
            
            return target_host, target_port
            
        except Exception as e:
            logger.debug(f"SOCKS5 Handshake error: {e}")
            return None

    async def _handle_direct(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, target_host: str, target_port: int, client_id: str):
        """Прямой обход (Bypass) для локальных доменов/IP."""
        logger.info(f"[{client_id}] Bypass: Прямое подключение к {target_host}:{target_port}")
        try:
            t_reader, t_writer = await asyncio.wait_for(
                asyncio.open_connection(target_host, target_port), timeout=10.0
            )
            
            # Оптимизация сокета для прямого соединения
            if t_writer.transport:
                sock = t_writer.transport.get_extra_info('socket')
                if sock:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    # Крупные буферы для обхода
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)
            
            # Успешный ответ SOCKS5
            writer.write(b'\x05\x00\x00\x01' + b'\x00'*6)
            await writer.drain()
            
            await self._bridge(reader, writer, t_reader, t_writer)
            
        except Exception as e:
            logger.error(f"[{client_id}] Bypass error to {target_host}:{target_port} - {e}")
            writer.write(b'\x05\x05\x00\x01' + b'\x00'*6)
            await writer.drain()

    async def _handle_wss(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, target_host: str, target_port: int, client_id: str):
        """Туннелирование через WSS сервер."""
        # Упрощенный парсинг параметров прокси из конфига
        # Упрощенный парсинг URL (без поддержки wss напрямую, так как мы пишем чистый raw, предполагаем либо ws либо tls terminating proxy)
        ws_host = self.config.get("server_ws_host", "127.0.0.1")
        ws_port = self.config.get("server_ws_port", 8443)
        ws_path = "/"
        use_tls = self.config.get("server_ws_tls", self.mode == "wss")
        
        logger.info(f"[{client_id}] WSS Tunnel: {target_host}:{target_port} через {ws_host}:{ws_port} (TLS: {use_tls})")
        
        try:
            # 1. Подключение к WSS
            ssl_context = None
            if use_tls:
                import ssl
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

            ws = await asyncio.wait_for(
                RawWebSocket.connect(ws_host, ws_port, ws_path, ssl_context=ssl_context),
                timeout=15.0
            )
            
            # Настройка сокета на максимальную производительность
            if ws.writer.transport:
                sock = ws.writer.transport.get_extra_info('socket')
                if sock:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)
            
            # 2. Передача команды
            cmd = json.dumps({"host": target_host, "port": target_port}).encode('utf-8')
            await ws.send(cmd, is_text=True)
            
            # 3. Чтение статуса
            status_frame = await asyncio.wait_for(ws.recv(), timeout=10.0)
            if not status_frame:
                raise ValueError("No response from server")
                
            status_data = json.loads(status_frame.decode('utf-8'))
            if status_data.get("status") != "ok":
                raise ValueError(f"Server rejected: {status_data.get('msg')}")
                
            # Успешный ответ SOCKS5 клиенту
            writer.write(b'\x05\x00\x00\x01' + b'\x00'*6)
            await writer.drain()
            
            # 4. Мост с «умным» дренажем (позволяет нескольким пакетам быть в полете)
            if writer.transport:
                writer.transport.set_write_buffer_limits(high=1024 * 1024 * 2) # 2MB
            
            async def ws_to_tcp():
                try:
                    while True:
                        data = await ws.recv()
                        if data is None:
                            break
                        writer.write(data)
                        # Drain только если буфер реально заполнен (> 1MB)
                        if writer.transport.get_write_buffer_size() > 1024 * 1024:
                            await writer.drain()
                except Exception as e:
                    logger.debug(f"[{client_id}] wss->tcp error: {e}")

            async def tcp_to_ws():
                try:
                    while True:
                        data = await reader.read(131072)
                        if not data:
                            break
                        await ws.send(data)
                        # RawWebSocket.send теперь не делает drain внутри, 
                        # поэтому делаем его здесь при необходимости
                        if ws.writer.transport.get_write_buffer_size() > 1024 * 1024:
                            await ws.writer.drain()
                except Exception as e:
                    logger.debug(f"[{client_id}] tcp->wss error: {e}")
                    
            tasks = [asyncio.create_task(ws_to_tcp()), asyncio.create_task(tcp_to_ws())]
            _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
                
            await ws.close()
            
        except Exception as e:
            if isinstance(e, asyncio.TimeoutError):
                err_msg = "TimeoutError (Сервер недоступен, проверьте firewall на VDS)"
            else:
                err_msg = str(e) or repr(e)
            logger.error(f"[{client_id}] WSS error to {target_host}:{target_port} - {err_msg}")
            writer.write(b'\x05\x05\x00\x01' + b'\x00'*6)
            await writer.drain()

    async def _get_ssh_conn(self):
        """Возвращает активное SSH соединение из пула или создает новое."""
        async with self._ssh_lock:
            if self._ssh_conn and not self._ssh_conn.is_closing():
                return self._ssh_conn
                
            ssh_host = self.config.get("ssh_host", "127.0.0.1")
            ssh_port = self.config.get("ssh_port", 22)
            ssh_user = self.config.get("ssh_user", "root")
            ssh_key = self.config.get("ssh_key", "")
            
            kwargs = {'username': ssh_user, 'known_hosts': None}
            if ssh_key:
                if os.path.exists(ssh_key):
                    kwargs['client_keys'] = [ssh_key]
                else:
                    # Если путь не существует, пробуем использовать как пароль
                    kwargs['password'] = ssh_key
            
            self._ssh_conn = await asyncssh.connect(ssh_host, port=ssh_port, **kwargs)
            return self._ssh_conn

    async def _handle_ssh(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, target_host: str, target_port: int, client_id: str):
        """Туннелирование через SSH с использованием пула соединений."""
        logger.info(f"[{client_id}] SSH Tunnel: {target_host}:{target_port}")
        
        try:
            conn = await self._get_ssh_conn()
            
            # Открытие прямого TCP-форвардинга внутри SSH (создает новый канал в существующем соединении)
            async with conn.create_connection(None, target_host, target_port) as (ssh_reader, ssh_writer):
                # SOCKS5 OK
                writer.write(b'\x05\x00\x00\x01' + b'\x00'*6)
                await writer.drain()
                
                # Мост
                await self._bridge(reader, writer, ssh_reader, ssh_writer)
                
        except Exception as e:
            logger.error(f"[{client_id}] SSH error to {target_host}:{target_port} - {e}")
            writer.write(b'\x05\x05\x00\x01' + b'\x00'*6)
            await writer.drain()
            # Очищаем пул при критической ошибке соединения
            async with self._ssh_lock:
                self._ssh_conn = None

    async def _bridge(self, r1, w1, r2, w2):
        """Двунаправленная пересылка данных с оптимизацией буферов."""
        # Увеличиваем лимиты для обоих писателей
        for w in (w1, w2):
            if w.transport:
                w.transport.set_write_buffer_limits(high=1024 * 1024 * 2)

        async def forward(src, dst):
            try:
                while True:
                    data = await src.read(131072)
                    if not data:
                        break
                    dst.write(data)
                    if dst.transport.get_write_buffer_size() > 1024 * 1024:
                        await dst.drain()
            except Exception:
                pass
                
        tasks = [asyncio.create_task(forward(r1, w2)), asyncio.create_task(forward(r2, w1))]
        _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        
        # Cleanup
        for w in (w1, w2):
            try:
                w.close()
                await w.wait_closed()
            except Exception:
                pass


    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Входная точка для локальных соединений."""
        peername = writer.get_extra_info('peername')
        client_id = f"{peername[1]}" if peername else "Unknown"
        
        target = await self._socks5_handshake(reader, writer)
        if not target:
            writer.close()
            return
            
        target_host, target_port = target
        
        if self._should_bypass(target_host):
            await self._handle_direct(reader, writer, target_host, target_port, client_id)
        else:
            if self.mode == "wss":
                await self._handle_wss(reader, writer, target_host, target_port, client_id)
            elif self.mode == "ssh":
                await self._handle_ssh(reader, writer, target_host, target_port, client_id)
            else:
                logger.error(f"[{client_id}] Неизвестный режим: {self.mode}")
                writer.close()

    async def start(self):
        """Запуск локального SOCKS5 сервера."""
        server = await asyncio.start_server(self.handle_client, '127.0.0.1', self.local_port)
        logger.info(f"Client (Universal SOCKS5) запущен на 127.0.0.1:{self.local_port} (Ожидание подключений)")
        logger.info(f"Активный режим: {self.mode.upper()}")
        
        async with server:
            await server.serve_forever()

if __name__ == "__main__":
    cli = Client()
    try:
        asyncio.run(cli.start())
    except KeyboardInterrupt:
        logger.info("Клиент остановлен.")
