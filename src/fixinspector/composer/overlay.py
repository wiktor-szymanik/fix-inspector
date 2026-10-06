"""Optional documentation-derived business/security hints for Composer."""

from __future__ import annotations

import json
from pathlib import Path


class BusinessSecurityOverlay:
    def __init__(self, data: dict[str, object] | None = None, *, source_path: str = "") -> None:
        self.data = data or {}
        self.source_path = source_path

    @classmethod
    def load(cls, path: str | Path) -> "BusinessSecurityOverlay":
        source = Path(path)
        value = json.loads(source.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("Overlay root must be a JSON object")
        messages = value.get("messages", {})
        if not isinstance(messages, dict):
            raise ValueError("Overlay 'messages' must be a JSON object")
        return cls(value, source_path=str(source))

    def _message(self, msg_type: str) -> dict[str, object]:
        messages = self.data.get("messages", {})
        value = messages.get(str(msg_type), {}) if isinstance(messages, dict) else {}
        return value if isinstance(value, dict) else {}

    def _field(self, msg_type: str, tag: str) -> dict[str, object]:
        fields = self._message(msg_type).get("fields", {})
        value = fields.get(str(tag), {}) if isinstance(fields, dict) else {}
        return value if isinstance(value, dict) else {}

    def message_hint(self, msg_type: str) -> str:
        return str(self._message(msg_type).get("hint", ""))

    def field_hint(self, msg_type: str, tag: str) -> str:
        return str(self._field(msg_type, tag).get("hint", ""))

    def security_hint(self, msg_type: str, tag: str) -> str:
        return str(self._field(msg_type, tag).get("security", ""))


__all__ = ["BusinessSecurityOverlay"]
