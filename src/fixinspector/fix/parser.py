"""Fail-soft FIX semantic parsing and raw-editor conversion."""

from __future__ import annotations

from typing import Protocol

from .fields import FixField
from .message import FixMessage

SOH = b"\x01"
SOH_SYMBOL = "␁"


class _FieldDefinition(Protocol):
    field_type: str


class DictionaryLookup(Protocol):
    def field(self, tag: str) -> _FieldDefinition | None: ...


def _message_encoding(fields: list[FixField]) -> str:
    for field in fields:
        if field.tag != "347":
            continue
        value = field.value.decode("ascii", errors="ignore").upper()
        if value in {"ISO-8859-2", "ISO8859-2"}:
            return "iso8859_2"
        if value in {"UTF-8", "UTF8"}:
            return "utf-8"
    return "ascii"


def parse_message(raw: bytes, dictionary: DictionaryLookup | None = None) -> FixMessage:
    fields: list[FixField] = []
    issues: list[str] = []
    index = 0
    previous_length: int | None = None

    while index < len(raw):
        equals = raw.find(b"=", index)
        if equals < 0:
            issues.append(f"Missing '=' at byte {index}")
            break
        tag_bytes = raw[index:equals]
        if not tag_bytes or not tag_bytes.isdigit():
            issues.append(f"Invalid tag at byte {index}")
            break
        tag = tag_bytes.decode("ascii")
        value_start = equals + 1
        definition = dictionary.field(tag) if dictionary else None
        field_type = definition.field_type.upper() if definition else ""

        if field_type in {"DATA", "XMLDATA"} and previous_length is not None:
            value_end = value_start + previous_length
            if value_end > len(raw):
                issues.append(f"Truncated length-delimited field {tag}")
                value_end = len(raw)
            value = raw[value_start:value_end]
            index = value_end
            if index < len(raw) and raw[index : index + 1] == SOH:
                index += 1
            elif index < len(raw):
                issues.append(f"Missing SOH after length-delimited field {tag}")
        else:
            delimiter = raw.find(SOH, value_start)
            if delimiter < 0:
                value = raw[value_start:]
                index = len(raw)
                issues.append(f"Missing SOH after tag {tag}")
            else:
                value = raw[value_start:delimiter]
                index = delimiter + 1

        fields.append(FixField(tag=tag, value=value))
        if field_type == "LENGTH":
            try:
                previous_length = int(value)
            except ValueError:
                previous_length = None
                issues.append(f"Invalid LENGTH value in tag {tag}")
        else:
            previous_length = None

    encoding = _message_encoding(fields)
    msg_type = "?"
    for field in fields:
        if field.tag == "35":
            msg_type = field.value.decode("ascii", errors="replace")
            break
    return FixMessage(raw=raw, fields=fields, msg_type=msg_type, encoding=encoding, issues=issues)


def decode_value(value: bytes, encoding: str = "ascii") -> str:
    try:
        return value.decode(encoding)
    except (LookupError, UnicodeDecodeError):
        return value.decode("latin-1", errors="replace")


def encode_value(text: str, encoding: str = "ascii") -> bytes:
    try:
        return text.encode(encoding)
    except (LookupError, UnicodeEncodeError):
        return text.encode("utf-8")


def raw_to_editor_text(raw: bytes) -> str:
    output: list[str] = []
    for byte in raw:
        if byte == 0x01:
            output.append(SOH_SYMBOL)
        elif 32 <= byte <= 126:
            output.append(chr(byte))
        else:
            output.append(f"\\x{byte:02x}")
    return "".join(output)


def editor_text_to_raw(text: str) -> bytes:
    output = bytearray()
    index = 0
    while index < len(text):
        if text.startswith(SOH_SYMBOL, index):
            output.append(0x01)
            index += len(SOH_SYMBOL)
            continue
        if text.startswith("<SOH>", index):
            output.append(0x01)
            index += 5
            continue
        if text.startswith("\\x", index) and index + 4 <= len(text):
            candidate = text[index + 2 : index + 4]
            if all(character in "0123456789abcdefABCDEF" for character in candidate):
                output.append(int(candidate, 16))
                index += 4
                continue
        code = ord(text[index])
        if code > 0x7F:
            raise ValueError("Raw editor accepts ASCII plus \\xNN escapes only")
        output.append(code)
        index += 1
    return bytes(output)

__all__ = [
    "decode_value",
    "editor_text_to_raw",
    "encode_value",
    "parse_message",
    "raw_to_editor_text",
]
