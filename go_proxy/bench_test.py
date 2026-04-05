"""
Benchmark Go-proxy na localhost.
Target (TCP :19000) <- proxy_server (WS :19443) <- proxy_client (SOCKS5 :19081) <- bench
"""
import socket
import struct
import time
import os
import subprocess
import sys
import concurrent.futures

BLOCK = 64 * 1024
TEST_SIZE = 100 * 1024 * 1024  # 100 MB

PROXY_EXE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxy.exe")
TARGET_PORT = 19000
SERVER_PORT = 19443
CLIENT_PORT = 19081


def run_target_server(port: int):
    """TCP-server: otdaet TEST_SIZE bajt, zatem chitaet TEST_SIZE bajt."""
    import threading
    import socketserver

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            data = b'\x00' * BLOCK
            sent = 0
            while sent < TEST_SIZE:
                try:
                    self.request.sendall(data)
                    sent += BLOCK
                except Exception:
                    return

            received = 0
            while received < TEST_SIZE:
                try:
                    chunk = self.request.recv(BLOCK)
                    if not chunk:
                        break
                    received += len(chunk)
                except Exception:
                    break

    server = socketserver.ThreadingTCPServer(('127.0.0.1', port), Handler)
    server.allow_reuse_address = True
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


def socks5_connect(proxy_host: str, proxy_port: int, target_host: str, target_port: int) -> socket.socket:
    """SOCKS5 CONNECT."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((proxy_host, proxy_port))

    sock.sendall(b'\x05\x01\x00')
    resp = sock.recv(2)
    assert resp == b'\x05\x00', f"SOCKS5 hello fail: {resp!r}"

    host_b = target_host.encode()
    req = b'\x05\x01\x00\x03' + bytes([len(host_b)]) + host_b + struct.pack('!H', target_port)
    sock.sendall(req)
    resp = sock.recv(10)
    assert resp[1] == 0x00, f"SOCKS5 connect fail: {resp[1]}"

    sock.settimeout(60)
    return sock


def bench_single(proxy_port: int, target_port: int) -> tuple:
    """Single-stream download + upload test. Returns (dl_mbps, ul_mbps)."""
    sock = socks5_connect('127.0.0.1', proxy_port, '127.0.0.1', target_port)

    # Download
    received = 0
    t0 = time.perf_counter()
    while received < TEST_SIZE:
        data = sock.recv(BLOCK)
        if not data:
            break
        received += len(data)
    dl_elapsed = time.perf_counter() - t0
    dl_mbps = (received * 8) / (dl_elapsed * 1_000_000)

    # Upload
    payload = b'\x00' * BLOCK
    sent = 0
    t0 = time.perf_counter()
    while sent < TEST_SIZE:
        n = sock.send(payload)
        sent += n
    ul_elapsed = time.perf_counter() - t0
    ul_mbps = (sent * 8) / (ul_elapsed * 1_000_000)

    sock.close()
    return dl_mbps, ul_mbps


def bench_parallel_download(proxy_port: int, n: int) -> list:
    """N parallel download streams through proxy."""
    base_port = 19100
    servers = []
    for i in range(n):
        srv = run_target_server(base_port + i)
        servers.append((srv, base_port + i))

    def dl_stream(port: int) -> float:
        sock = socks5_connect('127.0.0.1', proxy_port, '127.0.0.1', port)
        received = 0
        t0 = time.perf_counter()
        while received < TEST_SIZE:
            data = sock.recv(BLOCK)
            if not data:
                break
            received += len(data)
        elapsed = time.perf_counter() - t0
        sock.close()
        return (received * 8) / (elapsed * 1_000_000)

    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
        futures = {pool.submit(dl_stream, port): port for _, port in servers}
        results = []
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    for srv, _ in servers:
        srv.shutdown()

    return results


def main():
    print("=== Go Proxy Benchmark (localhost) ===")
    print(f"Test size: {TEST_SIZE // (1024*1024)} MB")
    print()

    # 1. Target
    target_srv = run_target_server(TARGET_PORT)
    print(f"[OK] Target TCP :{ TARGET_PORT}")

    # 2. Go proxy server
    srv_proc = subprocess.Popen(
        [PROXY_EXE, "-mode", "server", "-listen", f"127.0.0.1:{SERVER_PORT}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == 'win32' else 0,
    )
    time.sleep(0.5)
    print(f"[OK] Proxy server :{SERVER_PORT} (PID {srv_proc.pid})")

    # 3. Go proxy client
    cli_proc = subprocess.Popen(
        [PROXY_EXE, "-mode", "client",
         "-listen", f"127.0.0.1:{CLIENT_PORT}",
         "-server", f"ws://127.0.0.1:{SERVER_PORT}/ws"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == 'win32' else 0,
    )
    time.sleep(0.5)
    print(f"[OK] Proxy client SOCKS5 :{CLIENT_PORT} (PID {cli_proc.pid})")
    print()

    try:
        # Single stream
        print("--- Single Stream ---")
        dl, ul = bench_single(CLIENT_PORT, TARGET_PORT)
        print(f"  Download: {dl:>8.1f} Mbps")
        print(f"  Upload:   {ul:>8.1f} Mbps")
        print()

        # Parallel download (4 streams)
        print("--- 4 Parallel Downloads ---")
        results = bench_parallel_download(CLIENT_PORT, 4)
        total = sum(results)
        per = [f"{r:.0f}" for r in results]
        print(f"  Per-stream: {per} Mbps")
        print(f"  Total:      {total:>8.1f} Mbps")
        print()

        # Parallel download (8 streams)
        print("--- 8 Parallel Downloads ---")
        results = bench_parallel_download(CLIENT_PORT, 8)
        total = sum(results)
        per = [f"{r:.0f}" for r in results]
        print(f"  Per-stream: {per} Mbps")
        print(f"  Total:      {total:>8.1f} Mbps")

    finally:
        print()
        print("Cleanup...")
        srv_proc.terminate()
        cli_proc.terminate()
        target_srv.shutdown()
        try:
            srv_proc.wait(timeout=3)
            cli_proc.wait(timeout=3)
        except Exception:
            srv_proc.kill()
            cli_proc.kill()
        print("Done.")


if __name__ == "__main__":
    main()
