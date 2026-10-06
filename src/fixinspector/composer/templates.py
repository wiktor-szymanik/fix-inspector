"""Project-scoped Composer templates."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(slots=True)
class ComposerTemplate:
    template_id: str
    name: str
    msg_type: str
    raw: bytes
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


__all__ = ["ComposerTemplate"]
