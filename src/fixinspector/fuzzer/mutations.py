"""Finite, dictionary-aware FIX mutation generation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ..fix.fields import FixField
from ..fix.parser import parse_message
from ..fix.serializer import serialize_structured
from ..session.injection import SESSION_HEADER_TAGS


MAX_CAMPAIGN_CASES = 250
MAX_TESTER_VALUES = 250
MAX_LONG_STRING_BYTES = 4096


class MutationSafety(str, Enum):
    SAFE_SESSION = "Safe-session"
    SESSION_DESTRUCTIVE = "Session-destructive"


class MutationKind(str, Enum):
    VALID_ENUM = "Valid enum values"
    INVALID_ENUM = "Invalid enum value"
    EMPTY = "Empty field"
    REMOVE_FIELD = "Remove selected field"
    DUPLICATE_FIELD = "Duplicate selected field"
    NUMERIC_BOUNDARIES = "Numeric boundaries"
    LONG_STRINGS = "Long strings"
    UNICODE_CONTROL = "Unicode/control values"
    TESTER_VALUES = "Tester-supplied values"
    HISTORY_VALUES = "Interesting History values"
    REMOVE_REQUIRED = "Remove required field"
    DUPLICATE_IDENTITY = "Duplicate selected identity field"
    ADD_UNKNOWN_TAG = "Add unknown tag"
    REUSE_BUSINESS_ID = "Reuse business IDs"
    OLD_FUTURE_TIMESTAMPS = "Old/future timestamps"
    MALFORM_BODY_LENGTH = "Malformed BodyLength"
    MALFORM_CHECKSUM = "Malformed CheckSum"


DESTRUCTIVE_KINDS = frozenset({MutationKind.MALFORM_BODY_LENGTH, MutationKind.MALFORM_CHECKSUM})
FIELD_KINDS = frozenset(
    {
        MutationKind.VALID_ENUM,
        MutationKind.INVALID_ENUM,
        MutationKind.EMPTY,
        MutationKind.REMOVE_FIELD,
        MutationKind.DUPLICATE_FIELD,
        MutationKind.NUMERIC_BOUNDARIES,
        MutationKind.LONG_STRINGS,
        MutationKind.UNICODE_CONTROL,
        MutationKind.TESTER_VALUES,
        MutationKind.HISTORY_VALUES,
        MutationKind.DUPLICATE_IDENTITY,
        MutationKind.REUSE_BUSINESS_ID,
    }
)
IDENTITY_TAGS = frozenset({"1", "11", "17", "37", "41", "48", "55", "710", "721"})


@dataclass(frozen=True, slots=True)
class MutationSpec:
    kind: MutationKind
    tag: str = ""
    values: tuple[bytes, ...] = ()
    unknown_tag: str = "9999"
    long_lengths: tuple[int, ...] = (256, 1024)


@dataclass(slots=True)
class MutationCase:
    case_id: int
    kind: MutationKind
    description: str
    safety: MutationSafety
    raw: bytes
    tag: str = ""


class MutationPlanner:
    def __init__(self, dictionary=None) -> None:
        self.dictionary = dictionary

    def set_dictionary(self, dictionary) -> None:
        self.dictionary = dictionary

    def generate(
        self,
        baseline_raw: bytes,
        specs: list[MutationSpec] | tuple[MutationSpec, ...],
        *,
        case_limit: int,
    ) -> list[MutationCase]:
        limit = int(case_limit)
        if not 1 <= limit <= MAX_CAMPAIGN_CASES:
            raise ValueError(f"Case limit must be between 1 and {MAX_CAMPAIGN_CASES}")
        message = parse_message(baseline_raw, self.dictionary)
        if message.msg_type == "?":
            raise ValueError("Baseline must contain MsgType (35)")
        fields = [FixField(item.tag, bytes(item.value)) for item in message.fields]
        result: list[MutationCase] = []
        for spec in specs:
            for description, safety, raw, tag in self._generate_spec(message, fields, spec):
                result.append(MutationCase(len(result) + 1, spec.kind, description, safety, raw, tag))
                if len(result) >= limit:
                    return result
        return result

    def _generate_spec(self, message, fields: list[FixField], spec: MutationSpec):
        kind = spec.kind
        if kind in FIELD_KINDS:
            tag = str(spec.tag)
            if not tag or tag in SESSION_HEADER_TAGS:
                return
            indexes = [index for index, item in enumerate(fields) if item.tag == tag]
            if not indexes:
                return
            index = indexes[0]
            definition = self.dictionary.field(tag) if self.dictionary else None
            if kind is MutationKind.VALID_ENUM:
                for value in (definition.enums if definition else {}):
                    yield self._replace_case(fields, index, value.encode("utf-8"), kind, tag, "dictionary enum")
            elif kind is MutationKind.INVALID_ENUM:
                value = _invalid_enum_value(definition.enums if definition else {}, definition.field_type if definition else "")
                yield self._replace_case(fields, index, value, kind, tag, "value outside enum set")
            elif kind is MutationKind.EMPTY:
                yield self._replace_case(fields, index, b"", kind, tag, "empty value")
            elif kind is MutationKind.REMOVE_FIELD:
                mutated = fields[:index] + fields[index + 1 :]
                yield (f"Remove first occurrence of tag {tag}", MutationSafety.SAFE_SESSION, _serialize(mutated), tag)
            elif kind in {MutationKind.DUPLICATE_FIELD, MutationKind.DUPLICATE_IDENTITY}:
                if kind is MutationKind.DUPLICATE_IDENTITY and tag not in IDENTITY_TAGS:
                    return
                mutated = fields[: index + 1] + [FixField(tag, bytes(fields[index].value))] + fields[index + 1 :]
                yield (f"Duplicate first occurrence of tag {tag}", MutationSafety.SAFE_SESSION, _serialize(mutated), tag)
            elif kind is MutationKind.NUMERIC_BOUNDARIES:
                for value in _numeric_values(definition.field_type if definition else ""):
                    yield self._replace_case(fields, index, value, kind, tag, "numeric boundary")
            elif kind is MutationKind.LONG_STRINGS:
                if definition and definition.field_type in {
                    "INT", "LENGTH", "NUMINGROUP", "SEQNUM", "TAGNUM", "FLOAT", "QTY", "PRICE",
                    "PRICEOFFSET", "AMT", "PERCENTAGE", "UTCTIMESTAMP", "UTCDATEONLY", "UTCTIMEONLY",
                }:
                    return
                for requested in spec.long_lengths:
                    length = max(1, min(int(requested), MAX_LONG_STRING_BYTES))
                    yield self._replace_case(fields, index, b"A" * length, kind, tag, f"bounded long value ({length} bytes)")
            elif kind is MutationKind.UNICODE_CONTROL:
                if definition and definition.field_type in {
                    "INT", "LENGTH", "NUMINGROUP", "SEQNUM", "TAGNUM", "FLOAT", "QTY", "PRICE",
                    "PRICEOFFSET", "AMT", "PERCENTAGE", "DATA", "XMLDATA",
                }:
                    return
                for label, value in (
                    ("Unicode", "Zażółć☃".encode("utf-8")),
                    ("control bytes", b"A\x00B\tC\r\nD"),
                ):
                    yield self._replace_case(fields, index, value, kind, tag, label)
            elif kind in {MutationKind.TESTER_VALUES, MutationKind.HISTORY_VALUES, MutationKind.REUSE_BUSINESS_ID}:
                if kind is MutationKind.REUSE_BUSINESS_ID and tag not in IDENTITY_TAGS:
                    return
                for value_index, value in enumerate(spec.values[:MAX_TESTER_VALUES], start=1):
                    label = (
                        "tester value"
                        if kind is MutationKind.TESTER_VALUES
                        else "History value"
                        if kind is MutationKind.HISTORY_VALUES
                        else "reused business ID"
                    )
                    yield self._replace_case(fields, index, bytes(value), kind, tag, f"{label} #{value_index}")
            return

        if kind is MutationKind.REMOVE_REQUIRED:
            definition = self.dictionary.message(message.msg_type) if self.dictionary else None
            required = definition.required_tags if definition else set()
            for tag in definition.tag_paths if definition else ():
                if tag not in required or tag in SESSION_HEADER_TAGS:
                    continue
                index = next((i for i, item in enumerate(fields) if item.tag == tag), None)
                if index is None:
                    continue
                yield (
                    f"Remove required tag {tag}",
                    MutationSafety.SAFE_SESSION,
                    _serialize(fields[:index] + fields[index + 1 :]),
                    tag,
                )
        elif kind is MutationKind.ADD_UNKNOWN_TAG:
            tag = str(spec.unknown_tag).strip()
            if not tag.isdigit() or int(tag) <= 0:
                raise ValueError("Unknown tag must be a positive integer")
            if tag in SESSION_HEADER_TAGS:
                raise ValueError(
                    f"Tag {tag} is session/header state and cannot be added as a safe-session unknown tag"
                )
            if self.dictionary and self.dictionary.field(tag) is not None:
                raise ValueError(f"Tag {tag} is present in the loaded dictionary; choose an unknown tag")
            index = max(0, len(fields) - 1)
            mutated = fields[:index] + [FixField(tag, b"FUZZ-UNKNOWN")] + fields[index:]
            yield (f"Add unknown tag {tag}", MutationSafety.SAFE_SESSION, _serialize(mutated), tag)
        elif kind is MutationKind.OLD_FUTURE_TIMESTAMPS:
            candidates = [
                (index, item.tag)
                for index, item in enumerate(fields)
                if item.tag not in SESSION_HEADER_TAGS
                and self.dictionary
                and self.dictionary.field(item.tag)
                and self.dictionary.field(item.tag).field_type in {"UTCTIMESTAMP", "UTCDATEONLY", "UTCTIMEONLY"}
            ]
            if candidates:
                index, tag = candidates[0]
            else:
                index, tag = max(0, len(fields) - 1), "60"
                fields = fields[:index] + [FixField(tag, b"")] + fields[index:]
            for label, value in (
                ("old timestamp", b"19700101-00:00:00.000"),
                ("future timestamp", b"20991231-23:59:59.999"),
            ):
                yield self._replace_case(fields, index, value, kind, tag, label)
        elif kind is MutationKind.MALFORM_BODY_LENGTH:
            raw = _serialize(fields)
            yield (
                "Malformed BodyLength (9) - exact raw",
                MutationSafety.SESSION_DESTRUCTIVE,
                _malform_body_length(raw),
                "9",
            )
        elif kind is MutationKind.MALFORM_CHECKSUM:
            raw = _serialize(fields)
            yield (
                "Malformed CheckSum (10) - exact raw",
                MutationSafety.SESSION_DESTRUCTIVE,
                _malform_checksum(raw),
                "10",
            )

    @staticmethod
    def _replace_case(
        fields: list[FixField],
        index: int,
        value: bytes,
        kind: MutationKind,
        tag: str,
        label: str,
    ):
        mutated = list(fields)
        mutated[index] = FixField(tag, bytes(value))
        return (f"{kind.value}: tag {tag} - {label}", MutationSafety.SAFE_SESSION, _serialize(mutated), tag)


def _serialize(fields: list[FixField]) -> bytes:
    return serialize_structured(FixField(item.tag, bytes(item.value)) for item in fields)


def _invalid_enum_value(enums: dict[str, str], field_type: str) -> bytes:
    candidates = ["~", "?", "INVALID", "-999999"] if field_type in {"CHAR", "BOOLEAN"} else ["INVALID", "~", "-999999"]
    return next(value.encode("utf-8") for value in candidates if value not in enums)


def _numeric_values(field_type: str) -> tuple[bytes, ...]:
    if field_type in {"FLOAT", "QTY", "PRICE", "PRICEOFFSET", "AMT", "PERCENTAGE"}:
        return (b"-1.7976931348623157E308", b"-0.0000001", b"0", b"0.0000001", b"1.7976931348623157E308")
    if field_type in {"INT", "LENGTH", "NUMINGROUP", "SEQNUM", "TAGNUM", "DAYOFMONTH"}:
        return (b"-2147483648", b"-1", b"0", b"1", b"2147483647", b"9223372036854775807")
    return ()


def _malform_body_length(raw: bytes) -> bytes:
    first = raw.find(b"\x01")
    end = raw.find(b"\x01", first + 1)
    if first < 0 or end < 0 or not raw[first + 1 : end].startswith(b"9="):
        raise ValueError("Cannot locate BodyLength (9) in baseline")
    return raw[: first + 1] + b"9=999999" + raw[end:]


def _malform_checksum(raw: bytes) -> bytes:
    start = raw.rfind(b"\x0110=")
    if start < 0:
        raise ValueError("Cannot locate CheckSum (10) in baseline")
    return raw[: start + 1] + b"10=999\x01"


__all__ = [
    "DESTRUCTIVE_KINDS",
    "FIELD_KINDS",
    "IDENTITY_TAGS",
    "MAX_CAMPAIGN_CASES",
    "MAX_LONG_STRING_BYTES",
    "MutationCase",
    "MutationKind",
    "MutationPlanner",
    "MutationSafety",
    "MutationSpec",
]
