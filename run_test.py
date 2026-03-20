import asyncio
import traceback
from server import Server
from client import Client

async def mock_remote_server(reader, writer):
    while True:
        data = await reader.read(1024)
        if not data:
            break
        writer.write(b"ECHO:" + data)
        await writer.drain()

async def start_mock():
    server = await asyncio.start_server(mock_remote_server, '127.0.0.1', 9999)
    await server.start_serving()
    
async def test_socks():
    try:
        reader, writer = await asyncio.open_connection('127.0.0.1', 1081)
        writer.write(b'\x05\x01\x00')
        await writer.drain()
        resp = await reader.readexactly(2)
        print("Auth resp:", resp)
        # connect to 127.0.0.1:9999
        writer.write(b'\x05\x01\x00\x01\x7f\x00\x00\x01\x27\x0f')
        await writer.drain()
        resp = await reader.readexactly(10)
        print("Connect resp:", resp)
        writer.write(b'hello!')
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1024), 2.0)
        print("Echoed:", data)
    except Exception as e:
        traceback.print_exc()

async def main():
    import json
    with open('test_config.json', 'w') as f:
        json.dump({
            "mode": "wss",
            "server_ws_host": "127.0.0.1",
            "server_ws_port": 8443,
            "local_socks5_port": 1081,
            "bypass_domains": [],
            "bypass_ips": []
        }, f)
    
    server = Server('127.0.0.1', 8443)
    client = Client('test_config.json')
    
    srv_task = asyncio.create_task(server.start())
    cli_task = asyncio.create_task(client.start())
    mock_task = asyncio.create_task(start_mock())
    
    await asyncio.sleep(0.5)
    await test_socks()
    
    srv_task.cancel()
    cli_task.cancel()

asyncio.run(main())
