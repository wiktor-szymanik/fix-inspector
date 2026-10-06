"""Offline, fail-soft decoding independent of transport/session state."""

from __future__ import annotations

from dataclasses import dataclass
import re

from ..fix.dictionary import FixDictionary
from ..fix.framing import FixFramer
from ..fix.message import FixMessage
from ..fix.parser import parse_message
from ..fix.serializer import serialize_structured
from ..fix.validation import ValidationIssue, validate_message

_ESCAPED_SOH = re.compile(r"\\x0*1", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class DecodedFrame:
    raw: bytes
    message: FixMessage
    framing_error: str | None
    validation: tuple[ValidationIssue, ...]

    @property
    def issues(self) -> tuple[str, ...]:
        result = []
        if self.framing_error:
            result.append(f"FRAMING: {self.framing_error}")
        result.extend(f"{item.level}: {item.text}" for item in self.validation)
        return tuple(result)


def normalize_pasted_fix(text: str) -> bytes:
    """Accept SOH, visible delimiters, pipes, and common prefixed log lines."""

    normalized = _ESCAPED_SOH.sub("\x01", text)
    normalized = normalized.replace("<SOH>", "\x01").replace("<soh>", "\x01")
    normalized = normalized.replace("^A", "\x01").replace("␁", "\x01").replace("|", "\x01")
    parts: list[str] = []
    for line in normalized.splitlines() or [normalized]:
        begin = line.find("8=FIX")
        parts.append(line[begin:] if begin >= 0 else line)
    return "".join(parts).encode("utf-8", errors="surrogatepass")


class OfflineDecoder:
    def __init__(self, dictionary=None, *, max_input_bytes: int = 8 * 1024 * 1024) -> None:
        self.dictionary = dictionary or FixDictionary()
        self.max_input_bytes = max(64 * 1024, int(max_input_bytes))

    def decode_text(self, text: str) -> list[DecodedFrame]:
        raw = normalize_pasted_fix(text)
        return self.decode_bytes(raw)

    def decode_bytes(self, raw: bytes) -> list[DecodedFrame]:
        payload = bytes(raw)
        if len(payload) > self.max_input_bytes:
            raise ValueError(
                f"Decoder input is {len(payload):,} bytes; limit is {self.max_input_bytes:,} bytes"
            )
        framer = FixFramer(max_buffer_bytes=self.max_input_bytes)
        frames = framer.feed_frames(payload)
        frames.extend(framer.flush())
        result: list[DecodedFrame] = []
        for frame in frames:
            message = parse_message(frame.raw, self.dictionary)
            result.append(
                DecodedFrame(
                    frame.raw,
                    message,
                    frame.error,
                    tuple(validate_message(message, self.dictionary)),
                )
            )
        return result

    def repair(self, frame: DecodedFrame | bytes) -> bytes:
        message = frame.message if isinstance(frame, DecodedFrame) else parse_message(frame, self.dictionary)
        return serialize_structured(message.fields)


__all__ = ["DecodedFrame", "OfflineDecoder", "normalize_pasted_fix"]
