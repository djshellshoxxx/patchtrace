"""Loopback slow-drip HTTP server for deadline and cancellation tests (no external network)."""
from __future__ import annotations

import socket
import threading
from collections.abc import Callable


def drip_server(total: int, gap: float) -> tuple[str, Callable[[], None]]:
    """Serve `total` bytes one at a time, `gap` seconds apart. Returns (url, close)."""
    srv = socket.socket()
    srv.bind(('127.0.0.1', 0))
    srv.listen(4)
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            srv.settimeout(0.1)
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            with conn:
                try:
                    conn.recv(4096)
                    conn.sendall(f'HTTP/1.1 200 OK\r\nContent-Length: {total}\r\n\r\n'.encode())
                    for _ in range(total):
                        if stop.wait(gap):
                            break
                        conn.sendall(b'x')
                except OSError:
                    pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    def close() -> None:
        stop.set()
        thread.join(2)
        srv.close()
    return f'http://127.0.0.1:{srv.getsockname()[1]}/drip', close
