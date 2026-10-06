"""Composer templates and safe injection orchestration."""

from __future__ import annotations

import base64
from collections.abc import Callable
from datetime import datetime, timezone
import itertools

from ..session.injection import InjectionMode, InjectionRequest
from .model import ComposerForm
from .overlay import BusinessSecurityOverlay
from .templates import ComposerTemplate


class ComposerController:
    """Uses the transport-owned InjectionController; it is not a session engine."""

    def __init__(self, dictionary, queue_sender: Callable[..., InjectionRequest]) -> None:
        self.dictionary = dictionary
        self._queue_sender = queue_sender
        self.overlay = BusinessSecurityOverlay()
        self._templates: dict[str, ComposerTemplate] = {}
        self._ids = itertools.count(1)
        self._requests: dict[int, InjectionRequest] = {}
        self._listeners: list[Callable[[InjectionRequest], None]] = []

    def set_dictionary(self, dictionary) -> None:
        self.dictionary = dictionary

    def set_overlay(self, overlay: BusinessSecurityOverlay) -> None:
        self.overlay = overlay

    def build_form(self, msg_type: str) -> ComposerForm:
        return ComposerForm.from_dictionary(self.dictionary, msg_type, self.overlay)

    def save_template(self, name: str, msg_type: str, raw: bytes, template_id: str = "") -> ComposerTemplate:
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("Template name is required")
        now = datetime.now(timezone.utc)
        if template_id and template_id in self._templates:
            item = self._templates[template_id]
            item.name = clean_name
            item.msg_type = str(msg_type)
            item.raw = bytes(raw)
            item.updated_at = now
            return item
        item_id = f"C{next(self._ids)}"
        item = ComposerTemplate(item_id, clean_name, str(msg_type), bytes(raw), now, now)
        self._templates[item_id] = item
        return item

    def template(self, template_id: str) -> ComposerTemplate | None:
        return self._templates.get(template_id)

    def templates(self) -> tuple[ComposerTemplate, ...]:
        return tuple(self._templates.values())

    def delete_template(self, template_id: str) -> None:
        self._templates.pop(template_id, None)

    def queue(self, raw: bytes, *, template_id: str = "") -> InjectionRequest:
        request = self._queue_sender(
            bytes(raw),
            InjectionMode.CLONE_EDIT,
            source="COMPOSER",
            repeater_item_id=f"composer:{template_id}" if template_id else "composer",
        )
        self.handle_injection_event(request)
        return request

    def handle_injection_event(self, request: InjectionRequest) -> None:
        if request.source != "COMPOSER":
            return
        self._requests[request.injection_id] = request.snapshot()
        for listener in tuple(self._listeners):
            listener(request.snapshot())

    def add_listener(self, listener: Callable[[InjectionRequest], None]) -> None:
        self._listeners.append(listener)

    def requests(self) -> tuple[InjectionRequest, ...]:
        return tuple(self._requests.values())

    def to_state(
        self,
        redact: Callable[[bytes], bytes],
        redact_text: Callable[[str], str] = lambda value: value,
    ) -> dict[str, object]:
        return {
            "overlay_path": self.overlay.source_path,
            "templates": [
                {
                    "template_id": item.template_id,
                    "name": redact_text(item.name),
                    "msg_type": item.msg_type,
                    "raw": base64.b64encode(redact(item.raw)).decode("ascii"),
                    "created_at": item.created_at.isoformat(),
                    "updated_at": item.updated_at.isoformat(),
                }
                for item in self.templates()
            ],
        }

    def restore_state(self, state: object) -> None:
        if not isinstance(state, dict):
            return
        templates: dict[str, ComposerTemplate] = {}
        greatest = 0
        values = state.get("templates", [])
        if isinstance(values, list):
            for value in values:
                if not isinstance(value, dict):
                    continue
                try:
                    template_id = str(value["template_id"])
                    item = ComposerTemplate(
                        template_id,
                        str(value["name"]),
                        str(value["msg_type"]),
                        base64.b64decode(str(value["raw"]), validate=True),
                        datetime.fromisoformat(str(value["created_at"])),
                        datetime.fromisoformat(str(value["updated_at"])),
                    )
                except (KeyError, TypeError, ValueError):
                    continue
                templates[template_id] = item
                if template_id.startswith("C") and template_id[1:].isdigit():
                    greatest = max(greatest, int(template_id[1:]))
        self._templates = templates
        self._ids = itertools.count(greatest + 1)
        overlay_path = str(state.get("overlay_path", ""))
        if overlay_path:
            try:
                self.overlay = BusinessSecurityOverlay.load(overlay_path)
            except (OSError, ValueError):
                self.overlay = BusinessSecurityOverlay(source_path=overlay_path)


__all__ = ["ComposerController", "ComposerTemplate"]
