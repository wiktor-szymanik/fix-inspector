"""Saved Sender items and their asynchronous run timeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..session.injection import AutoUpdatePolicy, InjectionMode, InjectionRequest, SESSION_AWARE_POLICY


@dataclass(frozen=True, slots=True)
class RepeaterRun:
    injection_id: int
    mode: InjectionMode
    queued_at: datetime
    status: str
    result_record_id: int | None = None
    sequence_number: int | None = None
    detail: str = ""

    @classmethod
    def from_request(cls, request: InjectionRequest) -> "RepeaterRun":
        return cls(
            request.injection_id,
            request.mode,
            request.queued_at,
            request.status.value,
            request.result_record_id,
            request.slot_sequence_number,
            request.detail,
        )


@dataclass(slots=True)
class RepeaterItem:
    item_id: str
    title: str
    source_record_id: int
    original_raw: bytes
    working_raw: bytes
    mode: InjectionMode = InjectionMode.BUSINESS_REPLAY
    auto_update: AutoUpdatePolicy = SESSION_AWARE_POLICY
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    runs: list[RepeaterRun] = field(default_factory=list)

    def update_from_request(self, request: InjectionRequest) -> None:
        run = RepeaterRun.from_request(request)
        if self.runs:
            current = self.runs[-1]
            if (
                current.injection_id == run.injection_id
                and current.status == run.status
                and current.result_record_id == run.result_record_id
                and current.detail == run.detail
            ):
                return
        self.runs.append(run)


__all__ = ["RepeaterItem", "RepeaterRun"]
