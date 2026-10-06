"""Plaintext local listener creation."""

from __future__ import annotations

import socket


def create_listener(host: str, port: int, backlog: int = 1) -> socket.socket:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(backlog)
        listener.settimeout(1.0)
        return listener
    except BaseException:
        listener.close()
        raise
