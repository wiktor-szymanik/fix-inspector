"""Structured FIX serialization with framing repair."""

from __future__ import annotations

from collections.abc import Iterable

from .checksum import checksum_bytes
from .fields import FixField

SOH = b"\x01"


def serialize_structured(fields: Iterable[FixField]) -> bytes:
    ordered = list(fields)
    begin = next((field for field in ordered if field.tag == "8"), None)
    if begin is None:
        raise ValueError("Missing BeginString (tag 8)")

    body_fields = [field for field in ordered if field.tag not in {"8", "9", "10"}]
    if not body_fields or body_fields[0].tag != "35":
        raise ValueError("MsgType (tag 35) must be the first body field")

    body_parts: list[bytes] = []
    for field in body_fields:
        try:
            tag = field.tag.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError(f"FIX tag must be ASCII: {field.tag!r}") from exc
        if not tag.isdigit():
            raise ValueError(f"FIX tag must be numeric: {field.tag!r}")
        body_parts.append(tag + b"=" + bytes(field.value) + SOH)
    body = b"".join(body_parts)
    prefix = b"8=" + begin.value + SOH + b"9=" + str(len(body)).encode("ascii") + SOH + body
    return prefix + b"10=" + checksum_bytes(prefix) + SOH

__all__ = ["serialize_structured"]
