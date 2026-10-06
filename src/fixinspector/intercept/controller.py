"""Thread-safe interception policy and ordered queue orchestration."""

from __future__ import annotations

from dataclasses import dataclass
import threading

from ..session.ordered_queue import (
    OrderedHoldQueue,
    OrderedQueueSnapshot,
    QueueDisposition,
    QueueResolution,
)
from .rules import InterceptPolicy

DIRECTIONS = ("C→S", "S→C")


@dataclass(frozen=True, slots=True)
class InterceptSnapshot:
    held_count: int
    queued_count: int
    client_to_server: OrderedQueueSnapshot
    server_to_client: OrderedQueueSnapshot


class InterceptController:
    def __init__(self, dictionary) -> None:
        self._dictionary = dictionary
        self._policy = InterceptPolicy()
        self._timeout_seconds = 0.0
        self._queues = {direction: OrderedHoldQueue() for direction in DIRECTIONS}
        self._record_direction: dict[int, str] = {}
        self._lock = threading.RLock()

    def set_dictionary(self, dictionary) -> None:
        with self._lock:
            self._dictionary = dictionary

    def configure(
        self,
        client_to_server: bool,
        server_to_client: bool = False,
        timeout_seconds: float | None = None,
        *,
        client_to_server_admin: bool = False,
        server_to_client_admin: bool = False,
    ) -> None:
        with self._lock:
            self._policy.hold_client_to_server = bool(client_to_server)
            self._policy.hold_server_to_client = bool(server_to_client)
            self._policy.hold_client_to_server_admin = bool(client_to_server_admin)
            self._policy.hold_server_to_client_admin = bool(server_to_client_admin)
            if timeout_seconds is not None:
                self._timeout_seconds = max(0.0, float(timeout_seconds))
                for ordered_queue in self._queues.values():
                    ordered_queue.set_timeout(self._timeout_seconds)

    def submit(
        self,
        record_id: int,
        direction: str,
        msg_type: str,
        sequence_number: int | None,
        raw: bytes,
        now: float | None = None,
        force_hold: bool | None = None,
        manual_only: bool = False,
    ) -> QueueDisposition:
        if direction not in self._queues:
            raise ValueError(f"Unknown FIX direction: {direction}")
        with self._lock:
            interceptable = (
                self._policy.should_hold(direction, msg_type, self._dictionary)
                if force_hold is None
                else bool(force_hold)
            )
            disposition = self._queues[direction].submit(
                record_id,
                sequence_number,
                raw,
                interceptable,
                now,
                manual_only,
            )
            if disposition is not QueueDisposition.FORWARD:
                self._record_direction[record_id] = direction
            return disposition

    def resolve(
        self,
        record_id: int,
        action: str,
        replacement: bytes | None = None,
        now: float | None = None,
    ) -> tuple[str, QueueResolution]:
        with self._lock:
            direction = self._record_direction.get(record_id)
            if direction is None:
                raise KeyError(f"Record {record_id} is not held or queued")
            resolution = self._queues[direction].resolve(record_id, action, replacement, now)
            self._remove_released(resolution)
            return direction, resolution

    def resolve_all(
        self,
        direction: str,
        action: str,
        now: float | None = None,
    ) -> QueueResolution:
        """Resolve every message currently queued in one direction, in wire order."""
        if direction not in self._queues:
            raise ValueError(f"Unknown FIX direction: {direction}")
        with self._lock:
            ordered_queue = self._queues[direction]
            resolution = ordered_queue.resolve_all(action)
            self._remove_released(resolution)
            return resolution

    def expire(self, now: float | None = None) -> list[tuple[str, QueueResolution]]:
        expired: list[tuple[str, QueueResolution]] = []
        with self._lock:
            for direction in DIRECTIONS:
                resolution = self._queues[direction].expire(now)
                if resolution is None:
                    continue
                self._remove_released(resolution)
                expired.append((direction, resolution))
        return expired

    def expire_direction(
        self,
        direction: str,
        now: float | None = None,
    ) -> QueueResolution | None:
        if direction not in self._queues:
            raise ValueError(f"Unknown FIX direction: {direction}")
        with self._lock:
            resolution = self._queues[direction].expire(now)
            if resolution is not None:
                self._remove_released(resolution)
            return resolution

    def snapshot(self) -> InterceptSnapshot:
        with self._lock:
            client_to_server = self._queues["C→S"].snapshot()
            server_to_client = self._queues["S→C"].snapshot()
            return InterceptSnapshot(
                client_to_server.held_count + server_to_client.held_count,
                client_to_server.queued_count + server_to_client.queued_count,
                client_to_server,
                server_to_client,
            )

    def contains(self, record_id: int) -> bool:
        with self._lock:
            return record_id in self._record_direction

    def direction_for(self, record_id: int) -> str | None:
        with self._lock:
            return self._record_direction.get(record_id)

    def pending_record_ids(self, direction: str | None = None) -> tuple[int, ...]:
        with self._lock:
            if direction is not None:
                if direction not in self._queues:
                    raise ValueError(f"Unknown FIX direction: {direction}")
                return self._queues[direction].pending_record_ids()
            return tuple(
                record_id
                for current_direction in DIRECTIONS
                for record_id in self._queues[current_direction].pending_record_ids()
            )

    def reset(self) -> tuple[int, ...]:
        with self._lock:
            pending = tuple(self._record_direction)
            self._queues = {
                direction: OrderedHoldQueue(self._timeout_seconds)
                for direction in DIRECTIONS
            }
            self._record_direction.clear()
            return pending

    def _remove_released(self, resolution: QueueResolution) -> None:
        for released in resolution.released:
            self._record_direction.pop(released.record_id, None)


__all__ = ["InterceptController", "InterceptSnapshot", "QueueDisposition", "QueueResolution"]
