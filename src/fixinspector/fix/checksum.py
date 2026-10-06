"""FIX CheckSum calculation and verification."""

from __future__ import annotations

SOH = b"\x01"


def checksum_value(prefix: bytes) -> int:
    return sum(prefix) % 256


def checksum_bytes(prefix: bytes) -> bytes:
    return f"{checksum_value(prefix):03d}".encode("ascii")


def checksum_field_start(raw: bytes) -> int:
    marker = raw.rfind(SOH + b"10=")
    if marker >= 0:
        return marker + 1
    if raw.startswith(b"10="):
        return 0
    return -1


def checksum_ok(raw: bytes) -> bool:
    marker = checksum_field_start(raw)
    if marker < 0:
        return False
    end = raw.find(SOH, marker)
    if end < 0:
        return False
    value = raw[marker + 3 : end]
    if len(value) != 3 or not value.isdigit():
        return False
    return checksum_value(raw[:marker]) == int(value)

__all__ = ["checksum_bytes", "checksum_field_start", "checksum_ok", "checksum_value"]
