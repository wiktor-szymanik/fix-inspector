"""Fields secret policy used at persistence and export boundaries."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from ..fix.checksum import checksum_bytes
from ..fix.fields import FixField
from ..fix.parser import parse_message

DEFAULT_SECRET_TAGS = frozenset({"553"})
REDACTED_VALUE = b"<REDACTED>"


def normalize_secret_tags(tags: Iterable[str] = ()) -> frozenset[str]:
    """Return validated tags while always retaining Username (553)."""
    normalized = {str(tag).strip() for tag in tags}
    normalized.discard("")
    invalid = sorted(tag for tag in normalized if not tag.isdigit() or int(tag) <= 0)
    if invalid:
        raise ValueError(f"Secret tags must be positive integers: {', '.join(invalid)}")
    return frozenset(normalized | DEFAULT_SECRET_TAGS)


@dataclass(frozen=True, slots=True)
class SecretRedactionPolicy:
    """A project-scoped policy. Tag 553 cannot be disabled."""

    secret_tags: frozenset[str] = field(default_factory=lambda: DEFAULT_SECRET_TAGS)

    def __post_init__(self) -> None:
        object.__setattr__(self, "secret_tags", normalize_secret_tags(self.secret_tags))

    @classmethod
    def from_text(cls, text: str) -> "SecretRedactionPolicy":
        return cls(frozenset(part.strip() for part in text.replace(";", ",").split(",") if part.strip()))

    @property
    def additional_tags(self) -> frozenset[str]:
        return self.secret_tags - DEFAULT_SECRET_TAGS

    def redact(self, raw: bytes, dictionary=None) -> bytes:
        return redact_sensitive(raw, dictionary, self.secret_tags)

    def redact_text(self, text: str) -> str:
        result = text
        for tag in self.secret_tags:
            result = re.sub(
                rf"(?<!\d)({re.escape(tag)}\s*=\s*)[^\x01␁|,;\r\n]*",
                rf"\1<REDACTED>",
                result,
                flags=re.IGNORECASE,
            )
        return result


def redact_sensitive(
    raw: bytes,
    dictionary=None,
    secret_tags: Iterable[str] = DEFAULT_SECRET_TAGS,
) -> bytes:
    secrets = normalize_secret_tags(secret_tags)
    message = parse_message(raw, dictionary)
    if not any(item.tag in secrets for item in message.fields):
        return bytes(raw)
    redacted = [
        FixField(field.tag, REDACTED_VALUE if field.tag in secrets else field.value)
        for field in message.fields
    ]
    try:
        if message.issues:
            raise ValueError("Malformed message requires conservative raw redaction")
        if len(redacted) < 3 or redacted[0].tag != "8" or redacted[1].tag != "9" or redacted[-1].tag != "10":
            raise ValueError("Non-canonical framing requires conservative raw redaction")
        body = b"".join(
            field.tag.encode("ascii") + b"=" + bytes(field.value) + b"\x01"
            for field in redacted[2:-1]
        )
        prefix = (
            b"8="
            + redacted[0].value
            + b"\x01"
            + b"9="
            + str(len(body)).encode("ascii")
            + b"\x01"
            + body
        )
        return prefix + b"10=" + checksum_bytes(prefix) + b"\x01"
    except (TypeError, ValueError):
        result = raw
        for tag in secrets:
            escaped = re.escape(tag.encode("ascii", errors="ignore"))
            result = re.sub(
                rb"(?:(?<=\x01)|^)" + escaped + rb"=[^\x01]*",
                tag.encode("ascii") + b"=<REDACTED>",
                result,
            )
        return result

__all__ = [
    "DEFAULT_SECRET_TAGS",
    "REDACTED_VALUE",
    "SecretRedactionPolicy",
    "normalize_secret_tags",
    "redact_sensitive",
]
