"""Saved item orchestration over the shared session InjectionController."""

from __future__ import annotations

import base64
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime
import itertools
import threading

from ..fix.parser import parse_message
from ..records import TrafficRecord
from ..session.injection import AutoUpdatePolicy, InjectionMode, InjectionRequest, SESSION_AWARE_POLICY
from .model import RepeaterItem, RepeaterRun


class RepeaterController:
    def __init__(
        self,
        queue_sender: Callable[..., InjectionRequest],
        *,
        dictionary=None,
    ) -> None:
        self._queue_sender = queue_sender
        self.dictionary = dictionary
        self._ids = itertools.count(1)
        self._items: dict[str, RepeaterItem] = {}
        self._listeners: list[Callable[[RepeaterItem, InjectionRequest], None]] = []
        self._lock = threading.RLock()

    def create_from_record(self, record: TrafficRecord) -> RepeaterItem:
        item_number = next(self._ids)
        item_id = f"R{item_number}"
        parsed = parse_message(record.raw, self.dictionary)
        title = f"{item_id} · {parsed.msg_type} · History #{record.record_id}"
        mode = InjectionMode.CLONE_EDIT if self.dictionary and self.dictionary.is_admin(parsed.msg_type) else InjectionMode.BUSINESS_REPLAY
        item = RepeaterItem(item_id, title, record.record_id, bytes(record.raw), bytes(record.raw), mode)
        with self._lock:
            self._items[item_id] = item
        return item

    def queue(
        self,
        item_id: str,
        raw: bytes,
        mode: InjectionMode | str,
        auto_update: AutoUpdatePolicy = SESSION_AWARE_POLICY,
    ) -> InjectionRequest:
        selected_mode = mode if isinstance(mode, InjectionMode) else InjectionMode(str(mode))
        with self._lock:
            item = self._items[item_id]
            item.working_raw = bytes(raw)
            item.mode = selected_mode
            item.auto_update = auto_update
            source_record_id = item.source_record_id
            original_raw = item.original_raw
        if selected_mode is not InjectionMode.EXACT_RAW:
            original = parse_message(original_raw, self.dictionary)
            edited = parse_message(raw, self.dictionary)
            identity_tags = ("49", "56", "50", "57", "142", "143")
            if any(original.values(tag) != edited.values(tag) for tag in identity_tags):
                auto_update = replace(auto_update, session_identity=False)
        request = self._queue_sender(
            bytes(raw),
            selected_mode,
            source="REPEATER",
            repeater_item_id=item_id,
            source_record_id=source_record_id,
            auto_update=auto_update,
        )
        self.handle_injection_event(request)
        return request

    def handle_injection_event(self, request: InjectionRequest) -> None:
        if not request.repeater_item_id:
            return
        with self._lock:
            item = self._items.get(request.repeater_item_id)
            if item is None:
                return
            item.update_from_request(request)
            listeners = tuple(self._listeners)
        for listener in listeners:
            listener(item, request)

    def add_listener(self, listener: Callable[[RepeaterItem, InjectionRequest], None]) -> None:
        with self._lock:
            self._listeners.append(listener)

    def item(self, item_id: str) -> RepeaterItem | None:
        with self._lock:
            return self._items.get(item_id)

    def items(self) -> tuple[RepeaterItem, ...]:
        with self._lock:
            return tuple(self._items.values())

    def remove(self, item_id: str) -> None:
        with self._lock:
            self._items.pop(item_id, None)

    def to_state(self, redact: Callable[[bytes], bytes]) -> list[dict[str, object]]:
        with self._lock:
            items = tuple(self._items.values())
        return [
            {
                "item_id": item.item_id,
                "title": item.title,
                "source_record_id": item.source_record_id,
                "original_raw": base64.b64encode(redact(item.original_raw)).decode("ascii"),
                "working_raw": base64.b64encode(redact(item.working_raw)).decode("ascii"),
                "mode": item.mode.value,
                "auto_update": {
                    "body_length": item.auto_update.body_length,
                    "msg_seq_num": item.auto_update.msg_seq_num,
                    "sending_time": item.auto_update.sending_time,
                    "checksum": item.auto_update.checksum,
                },
                "created_at": item.created_at.isoformat(),
                "runs": [
                    {
                        "injection_id": run.injection_id,
                        "mode": run.mode.value,
                        "queued_at": run.queued_at.isoformat(),
                        "status": run.status,
                        "result_record_id": run.result_record_id,
                        "sequence_number": run.sequence_number,
                        "detail": run.detail,
                    }
                    for run in item.runs
                ],
            }
            for item in items
        ]

    def restore_state(self, state: object) -> None:
        if not isinstance(state, list):
            return
        restored: dict[str, RepeaterItem] = {}
        greatest = 0
        for value in state:
            if not isinstance(value, dict):
                continue
            try:
                item_id = str(value["item_id"])
                original = base64.b64decode(str(value["original_raw"]), validate=True)
                working = base64.b64decode(str(value["working_raw"]), validate=True)
                policy_value = value.get("auto_update", {})
                if not isinstance(policy_value, dict):
                    policy_value = {}
                item = RepeaterItem(
                    item_id=item_id,
                    title=str(value.get("title", item_id)),
                    source_record_id=int(value.get("source_record_id", 0)),
                    original_raw=original,
                    working_raw=working,
                    mode=InjectionMode(str(value.get("mode", InjectionMode.BUSINESS_REPLAY.value))),
                    auto_update=AutoUpdatePolicy(
                        bool(policy_value.get("body_length", True)),
                        bool(policy_value.get("msg_seq_num", True)),
                        bool(policy_value.get("sending_time", True)),
                        bool(policy_value.get("checksum", True)),
                    ),
                    created_at=datetime.fromisoformat(str(value["created_at"])),
                )
                for run_value in value.get("runs", []):
                    if not isinstance(run_value, dict):
                        continue
                    item.runs.append(
                        RepeaterRun(
                            int(run_value["injection_id"]),
                            InjectionMode(str(run_value["mode"])),
                            datetime.fromisoformat(str(run_value["queued_at"])),
                            str(run_value["status"]),
                            int(run_value["result_record_id"])
                            if run_value.get("result_record_id") is not None
                            else None,
                            int(run_value["sequence_number"])
                            if run_value.get("sequence_number") is not None
                            else None,
                            str(run_value.get("detail", "")),
                        )
                    )
                restored[item_id] = item
                if item_id.startswith("R") and item_id[1:].isdigit():
                    greatest = max(greatest, int(item_id[1:]))
            except (KeyError, TypeError, ValueError):
                continue
        with self._lock:
            self._items = restored
            self._ids = itertools.count(greatest + 1)


__all__ = ["RepeaterController"]
