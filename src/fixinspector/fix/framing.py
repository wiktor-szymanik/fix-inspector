"""BodyLength-aware FIX stream framing with malformed-input recovery."""

from __future__ import annotations

from dataclasses import dataclass

SOH = b"\x01"
SOH_SYMBOL = "␁"
BEGIN_PREFIX = b"8=FIX"


@dataclass(frozen=True, slots=True)
class FramedMessage:
    raw: bytes
    error: str | None = None

    @property
    def valid_framing(self) -> bool:
        return self.error is None


class FixFramer:
    """Extract messages independently of TCP read boundaries.

    Valid frames are delimited strictly through tags 8/9/10. When a malformed
    frame is followed by another BeginString, the malformed bytes are emitted
    as a record and the stream resynchronizes. ``flush`` exposes a truncated
    final frame instead of silently discarding it.
    """

    def __init__(self, max_buffer_bytes: int = 4 * 1024 * 1024) -> None:
        self.buffer = b""
        self.max_buffer_bytes = max(1024, int(max_buffer_bytes))

    def feed(self, data: bytes) -> list[bytes]:
        return [frame.raw for frame in self.feed_frames(data)]

    def feed_frames(self, data: bytes) -> list[FramedMessage]:
        self.buffer += bytes(data)
        framed: list[FramedMessage] = []

        while self.buffer:
            begin = self.buffer.find(BEGIN_PREFIX)
            if begin < 0:
                keep = len(BEGIN_PREFIX) - 1
                if len(self.buffer) > self.max_buffer_bytes:
                    emit_length = max(1, len(self.buffer) - keep)
                    framed.append(
                        FramedMessage(self.buffer[:emit_length], "No FIX BeginString before buffer limit")
                    )
                    self.buffer = self.buffer[emit_length:]
                    continue
                break
            if begin > 0:
                framed.append(FramedMessage(self.buffer[:begin], "Bytes before FIX BeginString"))
                self.buffer = self.buffer[begin:]
                continue

            first_soh = self.buffer.find(SOH)
            if first_soh < 0:
                break
            tag9_start = first_soh + 1
            if len(self.buffer) < tag9_start + 2:
                break
            if not self.buffer.startswith(b"9=", tag9_start):
                recovered = self._recover_malformed("BodyLength (9) is not the second field")
                if recovered is None:
                    break
                framed.append(recovered)
                continue

            tag9_end = self.buffer.find(SOH, tag9_start)
            if tag9_end < 0:
                break
            body_length_bytes = self.buffer[tag9_start + 2 : tag9_end]
            try:
                body_length = int(body_length_bytes)
                if body_length < 0:
                    raise ValueError
            except ValueError:
                recovered = self._recover_malformed("BodyLength (9) is not a non-negative integer")
                if recovered is None:
                    break
                framed.append(recovered)
                continue

            body_start = tag9_end + 1
            checksum_start = body_start + body_length
            if checksum_start > self.max_buffer_bytes:
                recovered = self._recover_malformed("BodyLength (9) exceeds framing buffer limit")
                if recovered is None:
                    break
                framed.append(recovered)
                continue
            if len(self.buffer) <= checksum_start:
                next_begin = self.buffer.find(BEGIN_PREFIX, body_start)
                if next_begin > 0:
                    framed.append(
                        FramedMessage(
                            self.buffer[:next_begin],
                            "BodyLength (9) extends into the next FIX message",
                        )
                    )
                    self.buffer = self.buffer[next_begin:]
                    continue
                break
            if not self.buffer.startswith(b"10=", checksum_start):
                recovered = self._recover_malformed("BodyLength (9) does not locate CheckSum (10)")
                if recovered is None:
                    break
                framed.append(recovered)
                continue

            checksum_end = self.buffer.find(SOH, checksum_start)
            if checksum_end < 0:
                break
            checksum_value = self.buffer[checksum_start + 3 : checksum_end]
            end = checksum_end + 1
            error = None
            if len(checksum_value) != 3 or not checksum_value.isdigit():
                error = "CheckSum (10) must contain exactly three decimal digits"
            framed.append(FramedMessage(self.buffer[:end], error))
            self.buffer = self.buffer[end:]

        return framed

    def flush(self) -> list[FramedMessage]:
        """Expose any truncated/malformed bytes remaining when a stream closes."""
        if not self.buffer:
            return []
        raw = self.buffer
        self.buffer = b""
        return [FramedMessage(raw, "Connection closed with an incomplete FIX frame")]

    def _recover_malformed(self, reason: str) -> FramedMessage | None:
        next_begin = self.buffer.find(BEGIN_PREFIX, len(BEGIN_PREFIX))
        if next_begin > 0:
            raw = self.buffer[:next_begin]
            self.buffer = self.buffer[next_begin:]
            return FramedMessage(raw, reason)

        checksum_end = self._checksum_field_end()
        if checksum_end is None:
            if len(self.buffer) > self.max_buffer_bytes:
                raw = self.buffer[: self.max_buffer_bytes]
                self.buffer = self.buffer[self.max_buffer_bytes :]
                return FramedMessage(raw, reason + "; framing buffer limit reached")
            return None
        raw = self.buffer[:checksum_end]
        self.buffer = self.buffer[checksum_end:]
        return FramedMessage(raw, reason)

    def _checksum_field_end(self) -> int | None:
        search_from = 0
        while True:
            marker = self.buffer.find(SOH + b"10=", search_from)
            if marker < 0:
                return None
            field_start = marker + 1
            end = self.buffer.find(SOH, field_start)
            if end < 0:
                return None
            if end + 1 == len(self.buffer) or self.buffer.startswith(BEGIN_PREFIX, end + 1):
                return end + 1
            search_from = end + 1


__all__ = ["FramedMessage", "FixFramer", "SOH", "SOH_SYMBOL"]
