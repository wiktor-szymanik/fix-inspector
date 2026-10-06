"""Thread-safe effective-wire journal for virtualized outbound sequence slots."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import threading


@dataclass(frozen=True, slots=True)
class SubstitutionEntry:
    journal_id: int
    session_key: str
    sequence_number: int
    original_record_id: int
    original_client_raw: bytes
    effective_server_raw: bytes
    injection_id: int
    injection_source: str
    repeater_item_id: str
    substituted_at: datetime
    recovery_replay_count: int = 0
    last_recovered_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class JournalSnapshot:
    substitution_count: int
    recovery_replay_count: int
    last_sequence_number: int | None
    last_session_key: str


class SubstitutionJournal:
    def __init__(self) -> None:
        self._entries: list[SubstitutionEntry] = []
        self._by_session_sequence: dict[tuple[str, int], int] = {}
        self._next_id = 1
        self._lock = threading.RLock()

    def record(
        self,
        *,
        session_key: str,
        sequence_number: int,
        original_record_id: int,
        original_client_raw: bytes,
        effective_server_raw: bytes,
        injection_id: int,
        injection_source: str,
        repeater_item_id: str = "",
        substituted_at: datetime | None = None,
    ) -> SubstitutionEntry:
        timestamp = substituted_at or datetime.now(timezone.utc)
        with self._lock:
            entry = SubstitutionEntry(
                self._next_id,
                session_key,
                int(sequence_number),
                int(original_record_id),
                bytes(original_client_raw),
                bytes(effective_server_raw),
                int(injection_id),
                str(injection_source),
                str(repeater_item_id),
                timestamp,
            )
            self._next_id += 1
            self._entries.append(entry)
            self._by_session_sequence[(session_key, int(sequence_number))] = len(self._entries) - 1
            return entry

    def lookup(self, session_key: str, sequence_number: int) -> SubstitutionEntry | None:
        with self._lock:
            index = self._by_session_sequence.get((session_key, int(sequence_number)))
            return self._entries[index] if index is not None else None

    def entries_for_range(
        self,
        session_key: str,
        begin_sequence: int,
        end_sequence: int | None,
    ) -> tuple[SubstitutionEntry, ...]:
        with self._lock:
            return tuple(
                entry
                for entry in self._entries
                if entry.session_key == session_key
                and entry.sequence_number >= begin_sequence
                and (end_sequence is None or entry.sequence_number <= end_sequence)
            )

    def mark_recovery_replay(
        self,
        session_key: str,
        sequence_number: int,
        at: datetime | None = None,
    ) -> SubstitutionEntry | None:
        with self._lock:
            index = self._by_session_sequence.get((session_key, int(sequence_number)))
            if index is None:
                return None
            current = self._entries[index]
            updated = replace(
                current,
                recovery_replay_count=current.recovery_replay_count + 1,
                last_recovered_at=at or datetime.now(timezone.utc),
            )
            self._entries[index] = updated
            return updated

    def entries(self) -> tuple[SubstitutionEntry, ...]:
        with self._lock:
            return tuple(self._entries)

    def snapshot(self) -> JournalSnapshot:
        with self._lock:
            last = self._entries[-1] if self._entries else None
            return JournalSnapshot(
                len(self._entries),
                sum(entry.recovery_replay_count for entry in self._entries),
                last.sequence_number if last else None,
                last.session_key if last else "",
            )


__all__ = ["JournalSnapshot", "SubstitutionEntry", "SubstitutionJournal"]
