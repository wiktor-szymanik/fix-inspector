"""Sequence-safe held-message queue independent of sockets and GUI."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from enum import Enum
import time


class QueueDisposition(str, Enum):
    FORWARD = "FORWARD"
    HELD = "HELD"
    QUEUED = "QUEUED"


@dataclass(slots=True)
class PendingMessage:
    record_id: int
    sequence_number: int | None
    raw: bytes
    interceptable: bool
    disposition: QueueDisposition
    manual_only: bool = False
    held_since: float | None = None
    deadline: float | None = None


@dataclass(frozen=True, slots=True)
class ReleasedMessage:
    record_id: int
    sequence_number: int | None
    raw: bytes | None
    status: str


@dataclass(frozen=True, slots=True)
class QueueResolution:
    released: tuple[ReleasedMessage, ...] = ()
    promoted_record_id: int | None = None
    destructive_gap: bool = False


@dataclass(frozen=True, slots=True)
class OrderedQueueSnapshot:
    held_count: int
    queued_count: int
    held_record_id: int | None
    held_sequence_number: int | None
    deadline: float | None


class OrderedHoldQueue:
    """Pause one FIX direction without allowing later traffic to overtake it.

    Queue order is wire arrival order. Sequence numbers are retained for
    diagnostics but never used to sort, because sorting malformed/duplicate
    sequence numbers would destroy the exact observed wire order.
    """

    def __init__(self, timeout_seconds: float = 0.0) -> None:
        self._items: deque[PendingMessage] = deque()
        self._timeout_seconds = max(0.0, float(timeout_seconds))

    def submit(
        self,
        record_id: int,
        sequence_number: int | None,
        raw: bytes,
        interceptable: bool,
        now: float | None = None,
        manual_only: bool = False,
    ) -> QueueDisposition:
        current_time = time.monotonic() if now is None else now
        if not self._items and not interceptable:
            return QueueDisposition.FORWARD
        if not self._items:
            item = PendingMessage(
                record_id,
                sequence_number,
                bytes(raw),
                True,
                QueueDisposition.HELD,
                bool(manual_only),
            )
            self._mark_held(item, current_time)
            self._items.append(item)
            return QueueDisposition.HELD

        self._items.append(
            PendingMessage(
                record_id,
                sequence_number,
                bytes(raw),
                bool(interceptable),
                QueueDisposition.QUEUED,
                bool(manual_only),
            )
        )
        return QueueDisposition.QUEUED

    def resolve(
        self,
        record_id: int,
        action: str,
        replacement: bytes | None = None,
        now: float | None = None,
        automatic: bool = False,
    ) -> QueueResolution:
        if not self._items or self._items[0].disposition is not QueueDisposition.HELD:
            raise KeyError(f"No held message with record id {record_id}")
        head = self._items[0]
        if head.record_id != record_id:
            raise ValueError(f"Record {record_id} is queued behind held record {head.record_id}")
        normalized_action = action.strip().lower()
        if normalized_action not in {"forward", "drop"}:
            raise ValueError(f"Unknown intercept action: {action}")

        current_time = time.monotonic() if now is None else now
        self._items.popleft()
        released: list[ReleasedMessage] = []
        destructive_gap = normalized_action == "drop"
        if destructive_gap:
            released.append(ReleasedMessage(head.record_id, head.sequence_number, None, "DROPPED"))
        else:
            outbound = bytes(replacement) if replacement is not None else head.raw
            status = "AUTO-FWD" if automatic else "FORWARDED"
            released.append(ReleasedMessage(head.record_id, head.sequence_number, outbound, status))

        promoted: int | None = None
        while self._items:
            next_item = self._items[0]
            if next_item.interceptable:
                next_item.disposition = QueueDisposition.HELD
                self._mark_held(next_item, current_time)
                promoted = next_item.record_id
                break
            self._items.popleft()
            released.append(
                ReleasedMessage(
                    next_item.record_id,
                    next_item.sequence_number,
                    next_item.raw,
                    "FORWARDED",
                )
            )
        return QueueResolution(tuple(released), promoted, destructive_gap)

    def expire(self, now: float | None = None) -> QueueResolution | None:
        if not self._items:
            return None
        head = self._items[0]
        if head.disposition is not QueueDisposition.HELD or head.deadline is None:
            return None
        current_time = time.monotonic() if now is None else now
        if current_time < head.deadline:
            return None
        return self.resolve(head.record_id, "forward", now=current_time, automatic=True)

    def resolve_all(self, action: str) -> QueueResolution:
        """Resolve the current snapshot wholesale without intermediate promotion."""
        normalized_action = action.strip().lower()
        if normalized_action not in {"forward", "drop"}:
            raise ValueError(f"Unknown intercept action: {action}")
        released = []
        while self._items:
            item = self._items.popleft()
            released.append(
                ReleasedMessage(
                    item.record_id,
                    item.sequence_number,
                    None if normalized_action == "drop" else item.raw,
                    "DROPPED" if normalized_action == "drop" else "FORWARDED",
                )
            )
        return QueueResolution(
            tuple(released),
            None,
            destructive_gap=normalized_action == "drop" and bool(released),
        )

    def set_timeout(self, timeout_seconds: float, now: float | None = None) -> None:
        self._timeout_seconds = max(0.0, float(timeout_seconds))
        if not self._items or self._items[0].disposition is not QueueDisposition.HELD:
            return
        head = self._items[0]
        current_time = time.monotonic() if now is None else now
        held_since = head.held_since if head.held_since is not None else current_time
        head.deadline = (
            held_since + self._timeout_seconds
            if self._timeout_seconds > 0 and not head.manual_only
            else None
        )

    def snapshot(self) -> OrderedQueueSnapshot:
        head = self._items[0] if self._items else None
        held = bool(head and head.disposition is QueueDisposition.HELD)
        return OrderedQueueSnapshot(
            held_count=1 if held else 0,
            queued_count=max(0, len(self._items) - (1 if held else 0)),
            held_record_id=head.record_id if held else None,
            held_sequence_number=head.sequence_number if held else None,
            deadline=head.deadline if held else None,
        )

    def contains(self, record_id: int) -> bool:
        return any(item.record_id == record_id for item in self._items)

    def pending_record_ids(self) -> tuple[int, ...]:
        return tuple(item.record_id for item in self._items)

    def _mark_held(self, item: PendingMessage, now: float) -> None:
        item.held_since = now
        item.deadline = (
            now + self._timeout_seconds
            if self._timeout_seconds > 0 and not item.manual_only
            else None
        )
