from __future__ import annotations

import re
from typing import Iterable

from .dictionary import FixDictionary
from .model import FixField, FixMessage

SOH = b"\x01"
SOH_SYMBOL = "␁"


class FixFramer:
    """Extract complete FIX messages using tag 9 BodyLength.

    Framing by BodyLength avoids the common error of treating every SOH as a
    message boundary. This also keeps framing valid when a DATA/XMLDATA field
    contains SOH bytes internally.
    """

    def __init__(self) -> None:
        self.buffer = b""

    def feed(self, data: bytes) -> list[bytes]:
        self.buffer += data
        messages: list[bytes] = []

        while True:
            start = self.buffer.find(b"8=FIX")
            if start < 0:
                # Keep a small suffix in case BeginString is split between reads.
                self.buffer = self.buffer[-16:]
                break
            if start > 0:
                self.buffer = self.buffer[start:]

            first_soh = self.buffer.find(SOH)
            if first_soh < 0:
                break

            tag9_start = first_soh + 1
            # Tag 9 may be split between TCP reads. Do not discard a valid
            # BeginString until we have enough bytes to decide.
            if len(self.buffer) < tag9_start + 2:
                break
            if not self.buffer.startswith(b"9=", tag9_start):
                self.buffer = self.buffer[first_soh + 1 :]
                continue

            tag9_end = self.buffer.find(SOH, tag9_start)
            if tag9_end < 0:
                break

            try:
                body_length = int(self.buffer[tag9_start + 2 : tag9_end])
            except ValueError:
                self.buffer = self.buffer[tag9_end + 1 :]
                continue

            body_start = tag9_end + 1
            checksum_start = body_start + body_length
            if len(self.buffer) <= checksum_start:
                break
            if not self.buffer.startswith(b"10=", checksum_start):
                # Keep the data; this may be an intentionally malformed frame.
                # The proxy is optimized for valid QuickFIX/J traffic. Raw parser
                # mutation can still be performed after interception.
                break

            end = self.buffer.find(SOH, checksum_start)
            if end < 0:
                break
            end += 1

            messages.append(self.buffer[:end])
            self.buffer = self.buffer[end:]

        return messages


def _message_encoding(raw_fields: list[FixField]) -> str:
    for field in raw_fields:
        if field.tag == "347":
            value = field.value.decode("ascii", errors="ignore").upper()
            if value in {"ISO-8859-2", "ISO8859-2"}:
                return "iso8859_2"
            if value in {"UTF-8", "UTF8"}:
                return "utf-8"
    return "ascii"


def parse_message(raw: bytes, dictionary: FixDictionary | None = None) -> FixMessage:
    fields: list[FixField] = []
    i = 0
    previous_length: int | None = None

    while i < len(raw):
        eq = raw.find(b"=", i)
        if eq < 0:
            break
        tag_bytes = raw[i:eq]
        if not tag_bytes or not tag_bytes.isdigit():
            break
        tag = tag_bytes.decode("ascii")
        value_start = eq + 1

        definition = dictionary.field(tag) if dictionary else None
        field_type = definition.field_type if definition else ""

        if field_type in {"DATA", "XMLDATA"} and previous_length is not None:
            value_end = value_start + previous_length
            if value_end > len(raw):
                value_end = len(raw)
            value = raw[value_start:value_end]
            i = value_end
            if i < len(raw) and raw[i : i + 1] == SOH:
                i += 1
        else:
            soh = raw.find(SOH, value_start)
            if soh < 0:
                value = raw[value_start:]
                i = len(raw)
            else:
                value = raw[value_start:soh]
                i = soh + 1

        fields.append(FixField(tag=tag, value=value))

        if field_type == "LENGTH":
            try:
                previous_length = int(value)
            except ValueError:
                previous_length = None
        else:
            previous_length = None

    encoding = _message_encoding(fields)
    msg_type = "?"
    for field in fields:
        if field.tag == "35":
            msg_type = field.value.decode("ascii", errors="replace")
            break

    return FixMessage(raw=raw, fields=fields, msg_type=msg_type, encoding=encoding)


def decode_value(value: bytes, encoding: str = "ascii") -> str:
    try:
        return value.decode(encoding)
    except UnicodeDecodeError:
        try:
            return value.decode("latin-1")
        except UnicodeDecodeError:
            return value.hex()


def encode_value(text: str, encoding: str = "ascii") -> bytes:
    try:
        return text.encode(encoding)
    except UnicodeEncodeError:
        return text.encode("utf-8")


def serialize_structured(fields: Iterable[FixField]) -> bytes:
    fields = list(fields)
    begin = next((f for f in fields if f.tag == "8"), None)
    if begin is None:
        raise ValueError("Missing BeginString (tag 8)")

    body_fields = [f for f in fields if f.tag not in {"8", "9", "10"}]
    if not body_fields or body_fields[0].tag != "35":
        raise ValueError("MsgType (tag 35) must be the first body field")

    body = b"".join(
        f.tag.encode("ascii") + b"=" + f.value + SOH
        for f in body_fields
    )
    prefix = (
        b"8=" + begin.value + SOH
        + b"9=" + str(len(body)).encode("ascii") + SOH
        + body
    )
    checksum = sum(prefix) % 256
    return prefix + b"10=" + f"{checksum:03d}".encode("ascii") + SOH


def checksum_ok(raw: bytes) -> bool:
    marker = raw.rfind(b"10=")
    if marker < 0:
        return False
    soh = raw.find(SOH, marker)
    if soh < 0:
        return False
    try:
        expected = int(raw[marker + 3 : soh])
    except ValueError:
        return False
    return sum(raw[:marker]) % 256 == expected


def redact_sensitive(raw: bytes, dictionary: FixDictionary | None = None) -> bytes:
    message = parse_message(raw, dictionary)
    redacted: list[FixField] = []
    for field in message.fields:
        if field.tag == "553":
            redacted.append(FixField(field.tag, b"<REDACTED>"))
        else:
            redacted.append(field)
    try:
        return serialize_structured(redacted)
    except Exception:
        # Display-only fallback for deliberately malformed raw messages.
        return re.sub(rb"(?:(?<=\x01)|^)553=[^\x01]*", b"553=<REDACTED>", raw)


def raw_to_editor_text(raw: bytes) -> str:
    out: list[str] = []
    for byte in raw:
        if byte == 0x01:
            out.append(SOH_SYMBOL)
        elif 32 <= byte <= 126:
            out.append(chr(byte))
        else:
            out.append(f"\\x{byte:02x}")
    return "".join(out)


def editor_text_to_raw(text: str) -> bytes:
    output = bytearray()
    i = 0
    while i < len(text):
        if text.startswith(SOH_SYMBOL, i):
            output.append(0x01)
            i += len(SOH_SYMBOL)
            continue
        if text.startswith("<SOH>", i):
            output.append(0x01)
            i += 5
            continue
        if text.startswith("\\x", i) and i + 4 <= len(text):
            candidate = text[i + 2 : i + 4]
            if all(c in "0123456789abcdefABCDEF" for c in candidate):
                output.append(int(candidate, 16))
                i += 4
                continue
        ch = text[i]
        code = ord(ch)
        if code > 0x7F:
            raise ValueError("Raw editor accepts ASCII plus \\xNN escapes only")
        output.append(code)
        i += 1
    return bytes(output)
