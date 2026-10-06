from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(slots=True)
class TrafficRecord:
    """One observed wire record with immutable original and effective bytes."""

    record_id: int
    direction: str
    original_raw: bytes
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "RECEIVED"
    msg_type: str = "?"
    sequence_number: int | None = None
    effective_raw: bytes | None = None
    modified: bool = False
    source: str = "CLIENT"
    framing_error: str | None = None
    bookmarked: bool = False
    note: str = ""
    session_key: str = ""
    fault_action: str = ""
    fault_rule: str = ""
    fault_reason: str = ""
    duplicate_of_record_id: int | None = None

    @property
    def raw(self) -> bytes:
        """Compatibility view used by the UI shell."""
        return self.effective_raw if self.effective_raw is not None else self.original_raw

    @raw.setter
    def raw(self, value: bytes) -> None:
        self.effective_raw = bytes(value)
        self.modified = self.effective_raw != self.original_raw
