from __future__ import annotations

import socket
import threading
import time

from fixinspector.fix.framing import FixFramer


class FakeFixSessionHarness:
    """Real socket-pair fake client/server around ProxyEngine._serve_connection."""

    def __init__(self, engine) -> None:
        self.engine = engine
        self.client, proxy_client = socket.socketpair()
        proxy_upstream, self.server = socket.socketpair()
        self._proxy_client = proxy_client
        self._proxy_upstream = proxy_upstream
        self.client.settimeout(0.05)
        self.server.settimeout(0.05)
        self._client_framer = FixFramer()
        self._server_framer = FixFramer()
        self._thread = threading.Thread(
            target=engine._serve_connection,
            args=(proxy_client, proxy_upstream),
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def send_client(self, raw: bytes) -> None:
        self.client.sendall(raw)

    def send_server(self, raw: bytes) -> None:
        self.server.sendall(raw)

    def receive_server(self, count: int, timeout: float = 2.0) -> list[bytes]:
        return self._receive(self.server, self._server_framer, count, timeout)

    def receive_client(self, count: int, timeout: float = 2.0) -> list[bytes]:
        return self._receive(self.client, self._client_framer, count, timeout)

    @staticmethod
    def _receive(peer: socket.socket, framer: FixFramer, count: int, timeout: float) -> list[bytes]:
        messages: list[bytes] = []
        deadline = time.monotonic() + timeout
        while len(messages) < count and time.monotonic() < deadline:
            try:
                data = peer.recv(65536)
            except socket.timeout:
                continue
            if not data:
                break
            messages.extend(frame.raw for frame in framer.feed_frames(data))
        return messages

    def receive_server_bytes(self, timeout: float = 2.0) -> bytes:
        deadline = time.monotonic() + timeout
        result = bytearray()
        while time.monotonic() < deadline:
            try:
                data = self.server.recv(65536)
            except socket.timeout:
                if result:
                    break
                continue
            if not data:
                break
            result.extend(data)
            if result:
                break
        return bytes(result)

    def close(self) -> None:
        self.engine._stop.set()
        for peer in (self.client, self.server):
            try:
                peer.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            peer.close()
        self._thread.join(timeout=2)
        for peer in (self._proxy_client, self._proxy_upstream):
            try:
                peer.close()
            except OSError:
                pass

    def __enter__(self) -> "FakeFixSessionHarness":
        self.start()
        return self

    def __exit__(self, _kind, _value, _traceback) -> None:
        self.close()
