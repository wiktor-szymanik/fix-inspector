"""Narrow recovery policy that replays journaled effective history safely."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import threading

from ..fix.fields import FixField
from ..fix.parser import parse_message
from ..fix.serializer import serialize_structured
from .injection import utc_sending_time
from .substitution_journal import SubstitutionEntry, SubstitutionJournal


@dataclass(frozen=True, slots=True)
class ResendRange:
    begin_sequence: int
    end_sequence: int | None

    def contains(self, sequence: int) -> bool:
        return sequence >= self.begin_sequence and (
            self.end_sequence is None or sequence <= self.end_sequence
        )


@dataclass(frozen=True, slots=True)
class RecoveryDecision:
    effective_raw: bytes
    entry: SubstitutionEntry
    detail: str


@dataclass(frozen=True, slots=True)
class RecoverySnapshot:
    pending_range_count: int
    effective_replay_count: int
    conflict_count: int
    last_detail: str


def build_effective_recovery_replay(
    effective_raw: bytes,
    *,
    at: datetime | None = None,
    dictionary=None,
) -> bytes:
    message = parse_message(effective_raw, dictionary)
    if message.issues or message.first("8") is None or message.first("35") is None:
        raise ValueError("Journaled effective message cannot be safely structured for recovery")
    original_sending_time = message.first("52")
    fields: list[FixField] = []
    inserted_possdup = False
    inserted_orig_time = False
    for field in message.fields:
        if field.tag in {"9", "10"}:
            continue
        if field.tag == "43":
            fields.append(FixField("43", b"Y"))
            inserted_possdup = True
            continue
        if field.tag == "52":
            if not inserted_possdup:
                fields.append(FixField("43", b"Y"))
                inserted_possdup = True
            fields.append(FixField("52", utc_sending_time(at)))
            if original_sending_time is not None:
                fields.append(FixField("122", bytes(original_sending_time)))
                inserted_orig_time = True
            continue
        if field.tag == "122":
            if not inserted_orig_time and original_sending_time is not None:
                fields.append(FixField("122", bytes(original_sending_time)))
                inserted_orig_time = True
            continue
        fields.append(FixField(field.tag, bytes(field.value)))
    if not inserted_possdup:
        fields.insert(2 if len(fields) >= 2 else len(fields), FixField("43", b"Y"))
    fields.append(FixField("10", b"000"))
    return serialize_structured(fields)


class RecoveryController:
    """Observe ResendRequest and only virtualize known original Heartbeat resends."""

    def __init__(self, *, dictionary=None) -> None:
        self.dictionary = dictionary
        self._ranges: dict[str, list[ResendRange]] = {}
        self._effective_replays = 0
        self._conflicts = 0
        self._last_detail = ""
        self._lock = threading.RLock()

    def set_dictionary(self, dictionary) -> None:
        with self._lock:
            self.dictionary = dictionary

    def observe_server(self, session_key: str, raw: bytes) -> ResendRange | None:
        message = parse_message(raw, self.dictionary)
        if message.msg_type != "2":
            return None
        begin = self._integer(message.first("7"))
        end_value = self._integer(message.first("16"))
        if begin is None:
            return None
        end = None if end_value in {None, 0} else end_value
        requested = ResendRange(begin, end)
        with self._lock:
            self._ranges.setdefault(session_key, []).append(requested)
            self._last_detail = f"Server requested recovery {begin}–{end if end is not None else '∞'}"
        return requested

    def rewrite_client_if_needed(
        self,
        session_key: str,
        original_raw: bytes,
        journal: SubstitutionJournal,
        *,
        at: datetime | None = None,
    ) -> RecoveryDecision | None:
        message = parse_message(original_raw, self.dictionary)
        sequence = self._integer(message.first("34"))
        if sequence is None:
            return None
        entry = journal.lookup(session_key, sequence)
        if entry is None:
            return None
        with self._lock:
            in_requested_range = any(
                requested.contains(sequence) for requested in self._ranges.get(session_key, [])
            )
        possdup = message.first("43") == b"Y"
        if message.msg_type != "0":
            if in_requested_range or possdup:
                with self._lock:
                    self._conflicts += 1
                    self._last_detail = (
                        f"SeqNum {sequence} has journaled effective history, but external resend "
                        f"is MsgType {message.msg_type}; genuine non-Heartbeat traffic was not replaced"
                    )
            return None
        if not (in_requested_range or possdup):
            return None
        effective = build_effective_recovery_replay(
            entry.effective_server_raw,
            at=at or datetime.now(timezone.utc),
            dictionary=self.dictionary,
        )
        return RecoveryDecision(effective, entry, f"Prepared effective recovery for SeqNum {sequence}")

    def mark_effective_replay_sent(
        self,
        session_key: str,
        sequence: int,
        journal: SubstitutionJournal,
        *,
        at: datetime | None = None,
    ) -> SubstitutionEntry | None:
        updated = journal.mark_recovery_replay(session_key, sequence, at)
        with self._lock:
            self._effective_replays += 1
            self._last_detail = f"Replayed effective injected history for SeqNum {sequence}"
            self._ranges[session_key] = [
                requested
                for requested in self._ranges.get(session_key, [])
                if not (
                    requested.begin_sequence == sequence
                    and requested.end_sequence == sequence
                )
            ]
        return updated

    def snapshot(self) -> RecoverySnapshot:
        with self._lock:
            return RecoverySnapshot(
                sum(len(ranges) for ranges in self._ranges.values()),
                self._effective_replays,
                self._conflicts,
                self._last_detail,
            )

    def clear_active_ranges(self) -> None:
        with self._lock:
            self._ranges.clear()

    @staticmethod
    def _integer(value: bytes | None) -> int | None:
        if value is None:
            return None
        try:
            return int(value)
        except ValueError:
            return None


__all__ = [
    "RecoveryController",
    "RecoveryDecision",
    "RecoverySnapshot",
    "ResendRange",
    "build_effective_recovery_replay",
]
