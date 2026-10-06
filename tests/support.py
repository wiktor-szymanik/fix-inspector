from __future__ import annotations

import time
import queue
import socket
from collections.abc import Callable, Iterable

from fixinspector.fix.fields import FixField
from fixinspector.fix.serializer import serialize_structured


def fix_message(
    msg_type: str = "D",
    seq_num: int = 1,
    extra_fields: Iterable[tuple[str, bytes]] = (),
) -> bytes:
    fields = [
        FixField("8", b"FIXT.1.1"),
        FixField("9", b"0"),
        FixField("35", msg_type.encode("ascii")),
        FixField("34", str(seq_num).encode("ascii")),
        FixField("49", b"CLIENT"),
        FixField("56", b"SERVER"),
        FixField("52", b"20260901-10:00:00.000"),
    ]
    fields.extend(FixField(tag, value) for tag, value in extra_fields)
    fields.append(FixField("10", b"000"))
    return serialize_structured(fields)


def body_length_ok(raw: bytes) -> bool:
    first_soh = raw.find(b"\x01")
    tag9_end = raw.find(b"\x01", first_soh + 1)
    checksum_start = raw.rfind(b"10=")
    if first_soh < 0 or tag9_end < 0 or checksum_start < 0:
        return False
    try:
        declared = int(raw[first_soh + 3 : tag9_end])
    except ValueError:
        return False
    return checksum_start - (tag9_end + 1) == declared


def wait_until(predicate: Callable[[], bool], timeout: float = 1.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.005)
    return predicate()


class ScriptedSocket:
    def __init__(self, chunks: Iterable[bytes]) -> None:
        self._chunks = iter(chunks)

    def recv(self, _size: int) -> bytes:
        return next(self._chunks, b"")

    def settimeout(self, _timeout: float) -> None:
        return None


class RecordingSocket:
    def __init__(self) -> None:
        self.sent: list[bytes] = []

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)


class ControllableSocket:
    """Socket double that stays open while the test resolves held messages."""

    _CLOSE = object()

    def __init__(self) -> None:
        self._chunks: queue.Queue[bytes | object] = queue.Queue()
        self._timeout = 0.1

    def push(self, data: bytes) -> None:
        self._chunks.put(bytes(data))

    def close_input(self) -> None:
        self._chunks.put(self._CLOSE)

    def recv(self, _size: int) -> bytes:
        try:
            item = self._chunks.get(timeout=self._timeout)
        except queue.Empty as exc:
            raise socket.timeout from exc
        if item is self._CLOSE:
            return b""
        return item

    def settimeout(self, timeout: float) -> None:
        self._timeout = timeout
