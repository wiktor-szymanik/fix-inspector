from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass(slots=True)
class FixField:
    tag: str
    value: bytes


@dataclass(slots=True)
class FixMessage:
    raw: bytes
    fields: list[FixField]
    msg_type: str = "?"
    encoding: str = "ascii"

    def values(self, tag: str) -> list[bytes]:
        return [f.value for f in self.fields if f.tag == tag]

    def first(self, tag: str, default: Optional[bytes] = None) -> Optional[bytes]:
        for item in self.fields:
            if item.tag == tag:
                return item.value
        return default


@dataclass(slots=True)
class TrafficRecord:
    record_id: int
    direction: str
    raw: bytes
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "FORWARDED"
    msg_type: str = "?"
    modified: bool = False


@dataclass(slots=True)
class ValidationIssue:
    level: str
    text: str
