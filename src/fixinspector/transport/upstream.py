"""Upstream TCP/TLS connection lifecycle."""

from __future__ import annotations

import socket

from .tls import TLSNegotiated, TLSSettings, build_client_context


PLAIN_TCP_VERIFICATION = "Not applicable (Plain TCP)"


def transport_label(transport: str) -> str:
    if transport == "plain_tcp":
        return "Plain TCP"
    if transport == "tls":
        return "TLS"
    raise ValueError("Upstream transport must be 'plain_tcp' or 'tls'")


def connect_upstream(
    host: str,
    port: int,
    sni: str,
    tls_settings: TLSSettings | None,
    timeout: float = 10.0,
    *,
    transport: str = "tls",
) -> tuple[socket.socket, TLSNegotiated]:
    """Connect with the selected transport; TLS never falls back to plaintext."""
    transport_label(transport)
    if transport == "plain_tcp":
        raw = socket.create_connection((host, port), timeout=timeout)
        try:
            raw.settimeout(0.1)
        except BaseException:
            raw.close()
            raise
        return raw, TLSNegotiated(verification=PLAIN_TCP_VERIFICATION)

    if tls_settings is None:
        raise ValueError("TLS settings are required for TLS upstream transport")
    context = build_client_context(tls_settings)
    server_hostname = (sni or host) if tls_settings.verify else (sni or None)
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        wrapped = context.wrap_socket(raw, server_hostname=server_hostname)
    except BaseException:
        raw.close()
        raise
    wrapped.settimeout(0.1)
    cipher_info = wrapped.cipher()
    negotiated = TLSNegotiated(
        verification=tls_settings.verification_label,
        version=wrapped.version() or "",
        cipher=cipher_info[0] if cipher_info else "",
    )
    return wrapped, negotiated
