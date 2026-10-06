"""Bounded live-History policy; durable project traffic remains on disk."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from ..records import TrafficRecord

UNRESOLVED_STATUSES = frozenset({"HELD", "QUEUED"})


@dataclass(frozen=True, slots=True)
class HistoryRetentionPolicy:
    max_live_records: int = 10_000

    def __post_init__(self) -> None:
        if not 100 <= int(self.max_live_records) <= 1_000_000:
            raise ValueError("Live History limit must be between 100 and 1,000,000")

    def eviction_ids(
        self,
        records: Mapping[int, TrafficRecord] | Iterable[TrafficRecord],
    ) -> tuple[int, ...]:
        ordered = list(records.values() if isinstance(records, Mapping) else records)
        excess = len(ordered) - self.max_live_records
        if excess <= 0:
            return ()
        candidates = [
            record.record_id
            for record in ordered
            if record.status not in UNRESOLVED_STATUSES
        ]
        return tuple(candidates[:excess])


__all__ = ["HistoryRetentionPolicy", "UNRESOLVED_STATUSES"]
