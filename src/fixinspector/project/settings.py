"""JSON helpers for project UI and dictionary configuration."""

from __future__ import annotations

import base64
from collections.abc import Mapping
import json
from typing import Any


def encode_bytes(value: bytes | bytearray | memoryview) -> str:
    return base64.b64encode(bytes(value)).decode("ascii")


def decode_bytes(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def dumps_state(value: Mapping[str, Any]) -> str:
    return json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def loads_state(value: str) -> dict[str, Any]:
    decoded = json.loads(value)
    if not isinstance(decoded, dict):
        raise ValueError("Project state must be a JSON object")
    return decoded


__all__ = ["decode_bytes", "dumps_state", "encode_bytes", "loads_state"]
