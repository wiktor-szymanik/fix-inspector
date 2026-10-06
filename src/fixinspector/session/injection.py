"""Shared safe-slot and explicit destructive replay queue."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
import itertools
import threading

from ..fix.fields import FixField
from ..fix.checksum import checksum_bytes
from ..fix.parser import parse_message
from ..fix.serializer import serialize_structured


class InjectionMode(str, Enum):
    BUSINESS_REPLAY = "Business Replay"
    CLONE_EDIT = "Clone/Edit"
    EXACT_RAW = "Exact Raw Replay"


class InjectionStatus(str, Enum):
    # Persisted Sender runs retain these identifiers; UI formats their punctuation.
    QUEUED = "Queued \u2014 waiting for safe active-session slot"
    RAW_QUEUED = "Queued \u2014 session-destructive exact raw replay"
    INJECTED = "Injected in outbound Heartbeat slot"
    RAW_REPLAYED = "Exact raw replay sent \u2014 session-destructive"
    RECOVERY_REPLAYED = "Effective injected message replayed for recovery"
    CANCELLED = "Cancelled \u2014 active session disconnected"
    FAILED = "Failed"


@dataclass(frozen=True, slots=True)
class AutoUpdatePolicy:
    """Fields that Inspector may virtualize for one outbound test message."""

    body_length: bool = True
    msg_seq_num: bool = True
    sending_time: bool = True
    checksum: bool = True
    session_identity: bool = True

    @property
    def is_session_aware(self) -> bool:
        return self == SESSION_AWARE_POLICY

    @property
    def is_raw_manual(self) -> bool:
        return not any(
            (self.body_length, self.msg_seq_num, self.sending_time, self.checksum)
        )


SESSION_AWARE_POLICY = AutoUpdatePolicy()
RAW_MANUAL_POLICY = AutoUpdatePolicy(False, False, False, False, False)


@dataclass(slots=True)
class InjectionRequest:
    injection_id: int
    mode: InjectionMode
    template_raw: bytes
    source: str
    repeater_item_id: str
    source_record_id: int | None
    queued_at: datetime
    status: InjectionStatus
    result_record_id: int | None = None
    slot_sequence_number: int | None = None
    effective_raw: bytes | None = None
    detail: str = ""
    auto_update: AutoUpdatePolicy = SESSION_AWARE_POLICY

    def snapshot(self) -> "InjectionRequest":
        return replace(self)


@dataclass(frozen=True, slots=True)
class SafeSlotClaim:
    request: InjectionRequest
    sequence_number: int
    effective_raw: bytes


SESSION_HEADER_TAGS = frozenset(
    {
        "8", "9", "10", "35", "34", "49", "56", "50", "57", "52",
        "97", "142", "143", "144", "145", "115", "116",
        "128", "129", "347", "369", "370", "1128",
    }
)


def utc_sending_time(at: datetime | None = None) -> bytes:
    current = (at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return current.strftime("%Y%m%d-%H:%M:%S.%f")[:-3].encode("ascii")


def build_safe_injection(
    template_raw: bytes,
    heartbeat_raw: bytes,
    *,
    at: datetime | None = None,
    dictionary=None,
    auto_update: AutoUpdatePolicy = SESSION_AWARE_POLICY,
) -> bytes:
    """Overlay business fields onto a genuine current-session Heartbeat slot."""
    template = parse_message(template_raw, dictionary)
    heartbeat = parse_message(heartbeat_raw, dictionary)
    if heartbeat.issues or heartbeat.msg_type != "0":
        raise ValueError("Safe injection requires a complete outbound Heartbeat")
    if heartbeat.first("112") is not None:
        raise ValueError("A TestRequest response Heartbeat is not a harmless safe slot")
    if heartbeat.first("43") == b"Y":
        raise ValueError("A recovery/PossDup Heartbeat is not a new safe slot")
    sequence = heartbeat.first("34")
    sender = heartbeat.first("49")
    target = heartbeat.first("56")
    begin = heartbeat.first("8")
    msg_type = template.first("35")
    if None in (sequence, sender, target, begin, msg_type):
        raise ValueError("Heartbeat/template lacks required session header fields")

    fields = [FixField("8", bytes(begin)), FixField("9", b"0"), FixField("35", bytes(msg_type))]
    appl_ver = template.first("1128") or heartbeat.first("1128")
    if appl_ver is not None:
        fields.append(FixField("1128", bytes(appl_ver)))
    template_sequences = template.values("34")
    effective_sequences = [bytes(sequence)] if auto_update.msg_seq_num else [
        bytes(value) for value in template_sequences
    ]
    if not effective_sequences:
        effective_sequences = [bytes(sequence)]
    fields.extend(FixField("34", value) for value in effective_sequences)
    for tag in ("49", "56", "50", "57", "142", "143"):
        values = heartbeat.values(tag) if auto_update.session_identity else template.values(tag)
        fields.extend(FixField(tag, bytes(value)) for value in values)
    template_times = template.values("52")
    effective_times = [utc_sending_time(at)] if auto_update.sending_time else [
        bytes(value) for value in template_times
    ]
    if effective_times:
        fields.extend(FixField("52", value) for value in effective_times)
    for tag in ("115", "116", "128", "129", "144", "145", "347"):
        for value in template.values(tag):
            fields.append(FixField(tag, bytes(value)))
    fields.extend(
        FixField(field.tag, bytes(field.value))
        for field in template.fields
        if field.tag not in SESSION_HEADER_TAGS
    )
    fields.append(FixField("10", b"000"))
    effective = serialize_structured(fields)
    return _apply_framing_policy(effective, template, auto_update)


def apply_auto_updates(
    template_raw: bytes,
    auto_update: AutoUpdatePolicy,
    *,
    sequence_number: int = 1,
    at: datetime | None = None,
    dictionary=None,
) -> bytes:
    """Apply a Sender auto-update profile without changing unrelated fields.

    The raw/manual profile is byte-exact. Other profiles preserve ordered and
    duplicate body fields; selected structural fields are intentionally repaired.
    """
    policy = auto_update
    if policy.is_raw_manual:
        return bytes(template_raw)
    template = parse_message(template_raw, dictionary)
    if template.first("8") is None or template.first("35") is None:
        raise ValueError("Message lacks BeginString (8) or MsgType (35)")
    fields = [FixField(field.tag, bytes(field.value)) for field in template.fields]
    if policy.msg_seq_num:
        _replace_or_insert_field(fields, "34", str(int(sequence_number)).encode("ascii"), after="35")
    if policy.sending_time:
        _replace_or_insert_field(fields, "52", utc_sending_time(at), after="34")
    effective = serialize_structured(fields)
    return _apply_framing_policy(effective, template, policy)


def _replace_or_insert_field(
    fields: list[FixField], tag: str, value: bytes, *, after: str
) -> None:
    for index, field in enumerate(fields):
        if field.tag == tag:
            fields[index] = FixField(tag, bytes(value))
            return
    insert_at = next((index + 1 for index, field in enumerate(fields) if field.tag == after), len(fields))
    fields.insert(insert_at, FixField(tag, bytes(value)))


def _apply_framing_policy(effective: bytes, template, policy: AutoUpdatePolicy) -> bytes:
    raw = bytes(effective)
    if not policy.body_length:
        original_body_length = template.first("9")
        if original_body_length is not None:
            raw = _replace_wire_value(raw, "9", original_body_length)
    if policy.checksum:
        checksum_marker = raw.rfind(b"\x0110=")
        if checksum_marker >= 0:
            raw = _replace_wire_value(raw, "10", checksum_bytes(raw[: checksum_marker + 1]))
    else:
        original_checksum = template.first("10")
        if original_checksum is not None:
            raw = _replace_wire_value(raw, "10", original_checksum)
    return raw


def _replace_wire_value(raw: bytes, tag: str, value: bytes) -> bytes:
    marker = tag.encode("ascii") + b"="
    start = 0 if raw.startswith(marker) else raw.find(b"\x01" + marker)
    if start < 0:
        return raw
    value_start = start + len(marker) if start == 0 else start + 1 + len(marker)
    value_end = raw.find(b"\x01", value_start)
    if value_end < 0:
        return raw
    return raw[:value_start] + bytes(value) + raw[value_end:]


class InjectionController:
    def __init__(
        self,
        *,
        dictionary=None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.dictionary = dictionary
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._ids = itertools.count(1)
        self._safe_queue: deque[int] = deque()
        self._raw_queue: deque[int] = deque()
        self._requests: dict[int, InjectionRequest] = {}
        self._listener: Callable[[InjectionRequest], None] | None = None
        self._lock = threading.RLock()

    def set_dictionary(self, dictionary) -> None:
        with self._lock:
            self.dictionary = dictionary

    def set_listener(self, listener: Callable[[InjectionRequest], None] | None) -> None:
        with self._lock:
            self._listener = listener

    def reserve_ids_through(self, injection_id: int) -> None:
        with self._lock:
            if self._safe_queue or self._raw_queue:
                raise RuntimeError("Cannot reserve injection IDs while requests are queued")
            highest_existing = max(self._requests, default=0)
            self._ids = itertools.count(max(1, highest_existing + 1, int(injection_id) + 1))

    def queue(
        self,
        raw: bytes,
        mode: InjectionMode | str,
        *,
        source: str = "REPEATER",
        repeater_item_id: str = "",
        source_record_id: int | None = None,
        auto_update: AutoUpdatePolicy = SESSION_AWARE_POLICY,
    ) -> InjectionRequest:
        selected_mode = mode if isinstance(mode, InjectionMode) else InjectionMode(str(mode))
        status = InjectionStatus.RAW_QUEUED if selected_mode is InjectionMode.EXACT_RAW else InjectionStatus.QUEUED
        with self._lock:
            request = InjectionRequest(
                next(self._ids),
                selected_mode,
                bytes(raw),
                str(source),
                str(repeater_item_id),
                source_record_id,
                self._clock(),
                status,
                auto_update=auto_update,
            )
            self._requests[request.injection_id] = request
            (self._raw_queue if selected_mode is InjectionMode.EXACT_RAW else self._safe_queue).append(
                request.injection_id
            )
            snapshot = request.snapshot()
        self._notify(snapshot)
        return snapshot

    def claim_safe_slot(self, heartbeat_raw: bytes) -> SafeSlotClaim | None:
        heartbeat = parse_message(heartbeat_raw, self.dictionary)
        if (
            heartbeat.msg_type != "0"
            or heartbeat.issues
            or heartbeat.first("112") is not None
            or heartbeat.first("43") == b"Y"
        ):
            return None
        sequence_raw = heartbeat.first("34")
        if sequence_raw is None:
            return None
        try:
            sequence = int(sequence_raw)
        except ValueError:
            return None
        while True:
            with self._lock:
                if not self._safe_queue:
                    return None
                request = self._requests[self._safe_queue.popleft()]
            try:
                effective = build_safe_injection(
                    request.template_raw,
                    heartbeat_raw,
                    at=self._clock(),
                    dictionary=self.dictionary,
                    auto_update=request.auto_update,
                )
            except (TypeError, ValueError) as exc:
                self.mark_failed(request.injection_id, str(exc))
                continue
            return SafeSlotClaim(request.snapshot(), sequence, effective)

    def claim_exact_raw(self) -> InjectionRequest | None:
        with self._lock:
            if not self._raw_queue:
                return None
            return self._requests[self._raw_queue.popleft()].snapshot()

    def mark_injected(self, claim: SafeSlotClaim, record_id: int) -> InjectionRequest:
        return self._mark(
            claim.request.injection_id,
            InjectionStatus.INJECTED,
            record_id=record_id,
            sequence=claim.sequence_number,
            effective_raw=claim.effective_raw,
        )

    def mark_raw_replayed(self, injection_id: int, record_id: int, sequence: int | None) -> InjectionRequest:
        return self._mark(
            injection_id,
            InjectionStatus.RAW_REPLAYED,
            record_id=record_id,
            sequence=sequence,
        )

    def mark_recovery_replayed(self, injection_id: int, record_id: int, sequence: int) -> InjectionRequest:
        return self._mark(
            injection_id,
            InjectionStatus.RECOVERY_REPLAYED,
            record_id=record_id,
            sequence=sequence,
        )

    def mark_failed(self, injection_id: int, detail: str) -> InjectionRequest:
        return self._mark(injection_id, InjectionStatus.FAILED, detail=detail)

    def cancel_pending(self) -> tuple[InjectionRequest, ...]:
        with self._lock:
            pending = tuple(self._safe_queue) + tuple(self._raw_queue)
            self._safe_queue.clear()
            self._raw_queue.clear()
        return tuple(self._mark(injection_id, InjectionStatus.CANCELLED) for injection_id in pending)

    def cancel(self, injection_id: int) -> bool:
        """Cancel one still-waiting owner request without disturbing other tool queues."""
        key = int(injection_id)
        with self._lock:
            removed = False
            for pending in (self._safe_queue, self._raw_queue):
                try:
                    pending.remove(key)
                    removed = True
                except ValueError:
                    continue
        if removed:
            self._mark(key, InjectionStatus.CANCELLED)
        return removed

    def request(self, injection_id: int) -> InjectionRequest | None:
        with self._lock:
            request = self._requests.get(int(injection_id))
            return request.snapshot() if request else None

    def requests(self) -> tuple[InjectionRequest, ...]:
        with self._lock:
            return tuple(request.snapshot() for request in self._requests.values())

    def waiting_count(self) -> int:
        with self._lock:
            return len(self._safe_queue)

    def destructive_waiting_count(self) -> int:
        with self._lock:
            return len(self._raw_queue)

    def _mark(
        self,
        injection_id: int,
        status: InjectionStatus,
        *,
        record_id: int | None = None,
        sequence: int | None = None,
        effective_raw: bytes | None = None,
        detail: str = "",
    ) -> InjectionRequest:
        with self._lock:
            request = self._requests[int(injection_id)]
            request.status = status
            if record_id is not None:
                request.result_record_id = record_id
            if sequence is not None:
                request.slot_sequence_number = sequence
            if effective_raw is not None:
                request.effective_raw = bytes(effective_raw)
            request.detail = detail
            snapshot = request.snapshot()
        self._notify(snapshot)
        return snapshot

    def _notify(self, request: InjectionRequest) -> None:
        listener = self._listener
        if listener is not None:
            listener(request.snapshot())


__all__ = [
    "AutoUpdatePolicy",
    "InjectionController",
    "InjectionMode",
    "InjectionRequest",
    "InjectionStatus",
    "SafeSlotClaim",
    "RAW_MANUAL_POLICY",
    "SESSION_AWARE_POLICY",
    "apply_auto_updates",
    "build_safe_injection",
    "utc_sending_time",
]
