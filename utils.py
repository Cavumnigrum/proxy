import asyncio
import base64
import hashlib
import json
import logging
import os
import struct
import socket
from typing import Optional, Dict

class WSError(Exception):
    """Исключение для ошибок WebSocket."""
    pass

def setup_logger(name: str) -> logging.Logger:
    """Настройка логгера."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger

class RawWebSocket:
    """Асинхронный клиент/сервер WebSocket."""
    OP_CONT = 0x0
    OP_TEXT = 0x1
    OP_BIN = 0x2
    OP_CLOSE = 0x8
    OP_PING = 0x9
    OP_PONG = 0xA

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, is_client: bool):
        self.reader = reader
        self.writer = writer
        self.is_client = is_client
        self.closed = False
        self._mask_cache = {}

    @classmethod
    async def connect(cls, host: str, port: int, path: str = "/", ssl_context=None) -> 'RawWebSocket':
        reader, writer = await asyncio.open_connection(host, port, ssl=ssl_context)
        ws_key = base64.b64encode(os.urandom(16)).decode('utf-8')
        req = (f"GET {path} HTTP/1.1\r\n"
               f"Host: {host}:{port}\r\n"
               "Upgrade: websocket\r\n"
               "Connection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {ws_key}\r\n"
               "Sec-WebSocket-Version: 13\r\n\r\n")
        writer.write(req.encode())
        await writer.drain()
        headers = []
        while True:
            line = await reader.readline()
            if line == b'\r\n' or not line: break
            headers.append(line.decode().strip())
        if not headers or "101" not in headers[0]:
            writer.close()
            await writer.wait_closed()
            raise WSError("Invalid WS handshake response")
        return cls(reader, writer, is_client=True)

    @classmethod
    async def accept(cls, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, timeout: float = 10.0) -> Optional['RawWebSocket']:
        try:
            first_line_raw = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if not first_line_raw: return None
            if first_line_raw.startswith(b'\x16\x03'):
                logging.getLogger("server").error("TLS Client Hello detected on plaintext port!")
                return None
            headers = {}
            while True:
                line_raw = await asyncio.wait_for(reader.readline(), timeout=timeout)
                if line_raw == b'\r\n' or not line_raw: break
                line = line_raw.decode('utf-8', 'ignore').strip()
                parts = line.split(":", 1)
                if len(parts) == 2: headers[parts[0].strip().lower()] = parts[1].strip()
            ws_key = headers.get("sec-websocket-key")
            if not ws_key: return None
            magic = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
            accept_key = base64.b64encode(hashlib.sha1(ws_key.encode() + magic).digest()).decode()
            res = ("HTTP/1.1 101 Switching Protocols\r\n"
                   "Upgrade: websocket\r\n"
                   "Connection: Upgrade\r\n"
                   f"Sec-WebSocket-Accept: {accept_key}\r\n\r\n")
            writer.write(res.encode())
            await writer.drain()
            return cls(reader, writer, is_client=False)
        except Exception: return None

    def _xor_mask(self, data: bytes, mask: bytes) -> bytes:
        n = len(data)
        if n == 0: return b""
        ck = (mask, n)
        if ck in self._mask_cache: mask_rep = self._mask_cache[ck]
        else:
            mask_rep = (mask * (n // 4 + 1))[:n]
            if len(self._mask_cache) < 10: self._mask_cache[ck] = mask_rep
        return (int.from_bytes(data, 'big') ^ int.from_bytes(mask_rep, 'big')).to_bytes(n, 'big')

    async def send(self, data: bytes, is_text: bool = False):
        if self.closed: return
        opcode = self.OP_TEXT if is_text else self.OP_BIN
        header = bytearray([0x80 | opcode])
        length = len(data)
        mask_bit = 0x80 if self.is_client else 0x00
        if length < 126: header.append(mask_bit | length)
        elif length < 65536:
            header.append(mask_bit | 126)
            header.extend(struct.pack('!H', length))
        else:
            header.append(mask_bit | 127)
            header.extend(struct.pack('!Q', length))
        
        full_frame = bytearray(header)
        if self.is_client:
            mask = os.urandom(4)
            full_frame.extend(mask)
            full_frame.extend(self._xor_mask(data, mask))
        else:
            full_frame.extend(data)
        
        self.writer.write(full_frame)
        # Drain is removed for performance, caller must drain if needed

    async def recv(self) -> Optional[bytes]:
        while not self.closed:
            try:
                hdr = await self.reader.readexactly(2)
                opcode = hdr[0] & 0x0F
                is_masked = bool(hdr[1] & 0x80)
                length = hdr[1] & 0x7F
                if length == 126: length = struct.unpack('!H', await self.reader.readexactly(2))[0]
                elif length == 127: length = struct.unpack('!Q', await self.reader.readexactly(8))[0]
                mask = await self.reader.readexactly(4) if is_masked else b''
                payload = await self.reader.readexactly(length)
                if is_masked: payload = self._xor_mask(payload, mask)
                if opcode == self.OP_CLOSE:
                    await self.close()
                    return None
                elif opcode == self.OP_PING:
                    self.writer.write(bytes([0x80 | self.OP_PONG, 0]))
                    await self.writer.drain()
                    continue
                elif opcode in (self.OP_TEXT, self.OP_BIN):
                    return payload
            except Exception:
                self.closed = True
                return None
        return None

    async def close(self):
        if self.closed: return
        self.closed = True
        try:
            self.writer.write(bytes([0x80 | self.OP_CLOSE, 0x00]))
            await self.writer.drain()
        except Exception: pass
        finally:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception: pass

class MuxProtocol:
    """Уровнь мультиплексирования над WebSocket."""
    CMD_OPEN = 0x01
    CMD_DATA = 0x02
    CMD_CLOSE = 0x03
    
    @staticmethod
    def pack(cmd: int, channel_id: int, data: bytes = b'') -> bytes:
        return struct.pack('!BI', cmd, channel_id) + data

    @staticmethod
    def unpack(frame: bytes):
        if len(frame) < 5: return None, None, None
        cmd, channel_id = struct.unpack('!BI', frame[:5])
        return cmd, channel_id, frame[5:]
