"""The KEV offline fixture preserves socket's type for cold standard-library imports."""
from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path


def test_guard_allows_cold_ssl_import_but_refuses_socket_and_lookup():
    code = textwrap.dedent(f'''
        import importlib, socket, sys
        sys.path.insert(0, {str(Path(__file__).resolve().parent)!r})
        from kev_helpers import socket_guard
        saved_type, saved_init = socket.socket, socket.socket.__init__
        sys.modules.pop('ssl', None)
        fixture = socket_guard()
        next(fixture)
        try:
            ssl = importlib.import_module('ssl')
            assert socket.socket is saved_type
            assert issubclass(ssl.SSLSocket, saved_type)
            for attempt in (lambda: socket.socket(), lambda: saved_type(),
                            lambda: socket.create_connection(('example.invalid', 443)),
                            lambda: socket.getaddrinfo('example.invalid', 443)):
                try:
                    attempt()
                except AssertionError as exc:
                    assert str(exc) == 'KEV tests must not open sockets'
                else:
                    raise AssertionError('the offline guard admitted an operation')
        finally:
            fixture.close()
        assert socket.socket is saved_type
        assert socket.socket.__init__ is saved_init
    ''')
    result = subprocess.run([sys.executable, '-I', '-c', code], capture_output=True,
                            text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
