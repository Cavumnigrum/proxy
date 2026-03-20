import asyncio
import pytest
from utils import RawWebSocket

@pytest.mark.asyncio
async def test_websocket_handshake_and_exchange(unused_tcp_port):
    """
    Happy Path: Тестирует полный цикл соединения, рукопожатия и отправки
    как текстовых, так и бинарных данных через RawWebSocket.
    """
    host = "127.0.0.1"
    port = unused_tcp_port
    
    server_ws = None
    
    async def handle_client(reader, writer):
        nonlocal server_ws
        server_ws = await RawWebSocket.accept(reader, writer)
        if server_ws:
            # Эхо сервер
            while True:
                data = await server_ws.recv()
                if data is None:
                    break
                await server_ws.send(data)
                
    server = await asyncio.start_server(handle_client, host, port)
    
    async with server:
        # Клиент подключается
        client_ws = await RawWebSocket.connect(host, port)
        assert client_ws is not None
        
        # Отправляем текст
        test_payload = b'{"status": "hello"}'
        await client_ws.send(test_payload, is_text=True)
        
        # Получаем эхо
        resp = await client_ws.recv()
        assert resp == test_payload
        
        # Отправляем бинарный PING/PONG (проверка маскировки)
        test_bin = b'\x00\xFF\xAA\xBB'
        await client_ws.send(test_bin, is_text=False)
        resp2 = await client_ws.recv()
        assert resp2 == test_bin
        
        await client_ws.close()
        
    server.close()
    await server.wait_closed()


@pytest.mark.asyncio
async def test_websocket_invalid_handshake(unused_tcp_port):
    """
    Edge Case: Попытка подключиться к сервису, который не отвечает на WS рукопожатие.
    """
    host = "127.0.0.1"
    port = unused_tcp_port
    
    async def handle_bad_server(reader, writer):
        # Отвечаем мусором вместо HTTP 101
        writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        await writer.drain()
        writer.close()
        
    server = await asyncio.start_server(handle_bad_server, host, port)
    
    async with server:
        import utils
        with pytest.raises(utils.WSError):
            await RawWebSocket.connect(host, port)
            
    server.close()
    await server.wait_closed()
