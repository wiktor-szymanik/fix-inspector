"""Compiled History filters with lossless duplicate-tag semantics."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Callable, Iterable

from ..fix.parser import decode_value, parse_message, raw_to_editor_text
from ..records import TrafficRecord
from ..presentation import display_direction


class FilterSyntaxError(ValueError):
    pass


_TOKEN = re.compile(
    r"\s*(?:(?P<lpar>\()|(?P<rpar>\))|(?P<op>!=|>=|<=|!~|=|>|<|~)|"
    r"(?P<quoted>\"(?:\\.|[^\"])*\"|'(?:\\.|[^'])*')|(?P<word>[^\s()=!<>~]+))"
)

_TAG_ALIASES = {
    "account": "1",
    "clordid": "11",
    "origclordid": "41",
    "orderid": "37",
    "msgseqnum": "34",
    "seq": "34",
    "refseqnum": "45",
    "posreqid": "710",
    "businessrejectrefid": "379",
    "refmsgtype": "372",
    "refordid": "1080",
}


@dataclass(slots=True)
class HistoryDocument:
    record: TrafficRecord
    fields: dict[str, list[str]]
    message_name: str = ""
    readable_raw: str = ""

    @classmethod
    def from_record(cls, record: TrafficRecord, dictionary=None) -> "HistoryDocument":
        parsed = parse_message(record.raw, dictionary)
        fields: dict[str, list[str]] = {}
        for item in parsed.fields:
            fields.setdefault(item.tag, []).append(decode_value(item.value, parsed.encoding))
        name = dictionary.message_name(record.msg_type) if dictionary else record.msg_type
        return cls(record, fields, name, raw_to_editor_text(record.raw))

    def values(self, property_name: str) -> list[str]:
        key = property_name.casefold()
        tag = _resolve_tag(key)
        if tag is not None:
            return self.fields.get(tag, [])
        record = self.record
        if key in {"direction", "dir"}:
            return [record.direction, display_direction(record.direction)]
        common = {
            "id": str(record.record_id),
            "msgtype": record.msg_type,
            "type": record.msg_type,
            "message": self.message_name,
            "name": self.message_name,
            "status": record.status,
            "state": record.status,
            "source": record.source,
            "modified": str(record.modified).lower(),
            "bookmarked": str(record.bookmarked).lower(),
            "bookmark": str(record.bookmarked).lower(),
            "note": record.note,
            "raw": self.readable_raw,
        }
        value = common.get(key)
        return [] if value is None else [value]


def _resolve_tag(name: str) -> str | None:
    if name in _TAG_ALIASES:
        return _TAG_ALIASES[name]
    if name.isdigit():
        return name
    for prefix in ("tag.", "tag:"):
        if name.startswith(prefix) and name[len(prefix) :].isdigit():
            return name[len(prefix) :]
    if name.startswith("[") and name.endswith("]") and name[1:-1].isdigit():
        return name[1:-1]
    return None


def _unquote(token: str) -> str:
    if len(token) >= 2 and token[0] == token[-1] and token[0] in {'"', "'"}:
        body = token[1:-1]
        return re.sub(r"\\(.)", r"\1", body)
    return token


def _compare_one(actual: str, operator: str, expected: str) -> bool:
    if operator in {"~", "!~"}:
        found = expected.casefold() in actual.casefold()
        return found if operator == "~" else not found
    if operator in {"=", "!="}:
        equal = actual.casefold() == expected.casefold()
        return equal if operator == "=" else not equal
    try:
        left: float | str = float(actual)
        right: float | str = float(expected)
    except ValueError:
        left = actual.casefold()
        right = expected.casefold()
    return {
        ">": left > right,
        ">=": left >= right,
        "<": left < right,
        "<=": left <= right,
    }[operator]


Predicate = Callable[[HistoryDocument], bool]


class _Parser:
    def __init__(self, source: str) -> None:
        self.tokens: list[str] = []
        position = 0
        while position < len(source):
            match = _TOKEN.match(source, position)
            if not match:
                raise FilterSyntaxError(f"Unexpected input at column {position + 1}")
            self.tokens.append(match.group(match.lastgroup or ""))
            position = match.end()
        self.index = 0

    def peek(self) -> str | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def take(self) -> str:
        token = self.peek()
        if token is None:
            raise FilterSyntaxError("Unexpected end of expression")
        self.index += 1
        return token

    def parse(self) -> Predicate:
        if not self.tokens:
            return lambda _document: True
        result = self.parse_or()
        if self.peek() is not None:
            raise FilterSyntaxError(f"Unexpected token {self.peek()!r}")
        return result

    def parse_or(self) -> Predicate:
        left = self.parse_and()
        while (self.peek() or "").casefold() == "or":
            self.take()
            right = self.parse_and()
            previous = left
            left = lambda document, a=previous, b=right: a(document) or b(document)
        return left

    def parse_and(self) -> Predicate:
        left = self.parse_not()
        while (self.peek() or "").casefold() == "and":
            self.take()
            right = self.parse_not()
            previous = left
            left = lambda document, a=previous, b=right: a(document) and b(document)
        return left

    def parse_not(self) -> Predicate:
        if (self.peek() or "").casefold() == "not":
            self.take()
            inner = self.parse_not()
            return lambda document: not inner(document)
        return self.parse_primary()

    def parse_primary(self) -> Predicate:
        if self.peek() == "(":
            self.take()
            inner = self.parse_or()
            if self.take() != ")":
                raise FilterSyntaxError("Missing closing parenthesis")
            return inner
        property_name = self.take()
        if property_name in {")", "("} or property_name.casefold() in {"and", "or"}:
            raise FilterSyntaxError(f"Expected property, got {property_name!r}")
        operator = self.take()
        if operator not in {"=", "!=", ">", ">=", "<", "<=", "~", "!~"}:
            raise FilterSyntaxError(f"Expected comparison operator after {property_name!r}")
        value = _unquote(self.take())
        if value in {"(", ")"}:
            raise FilterSyntaxError("Expected a comparison value")

        def predicate(document: HistoryDocument) -> bool:
            values = document.values(property_name)
            if not values:
                return False
            if operator in {"!=", "!~"}:
                return all(_compare_one(item, operator, value) for item in values)
            return any(_compare_one(item, operator, value) for item in values)

        return predicate


def compile_filter(expression: str) -> Predicate:
    """Compile a boolean expression once for efficient repeated row evaluation."""
    return _Parser(expression.strip()).parse()


def matches_text(document: HistoryDocument, needle: str) -> bool:
    value = needle.strip().casefold()
    if not value:
        return True
    haystack: Iterable[str] = (
        str(document.record.record_id),
        document.record.direction,
        display_direction(document.record.direction),
        document.record.msg_type,
        document.message_name,
        document.record.status,
        document.record.source,
        document.record.note,
        document.readable_raw,
    )
    return any(value in item.casefold() for item in haystack)


__all__ = ["FilterSyntaxError", "HistoryDocument", "compile_filter", "matches_text"]
