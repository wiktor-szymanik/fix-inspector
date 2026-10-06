"""Lossless flat FIX message model."""

from __future__ import annotations

from dataclasses import dataclass, field

from .fields import FixField


@dataclass(slots=True)
class FixMessage:
    raw: bytes
    fields: list[FixField]
    msg_type: str = "?"
    encoding: str = "ascii"
    issues: list[str] = field(default_factory=list)

    def values(self, tag: str) -> list[bytes]:
        return [item.value for item in self.fields if item.tag == str(tag)]

    def first(self, tag: str, default: bytes | None = None) -> bytes | None:
        for item in self.fields:
            if item.tag == str(tag):
                return item.value
        return default

__all__ = ["FixMessage"]
