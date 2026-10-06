"""Structural, dictionary, and current tested-API validation hints."""

from __future__ import annotations

from dataclasses import dataclass

from .checksum import checksum_ok
from .dictionary import FixDictionary
from .message import FixMessage
from .parser import decode_value


@dataclass(slots=True)
class ValidationIssue:
    level: str
    text: str


def _first_text(message: FixMessage, tag: str) -> str | None:
    value = message.first(tag)
    return decode_value(value, message.encoding) if value is not None else None


def validate_message(message: FixMessage, dictionary: FixDictionary) -> list[ValidationIssue]:
    issues = [ValidationIssue("WARN", issue) for issue in message.issues]
    tags = [field.tag for field in message.fields]
    tag_set = set(tags)
    if len(tags) < 4 or tags[:3] != ["8", "9", "35"] or tags[-1] != "10":
        issues.append(ValidationIssue("WARN", "Expected FIX order: 8, 9, 35, ..., 10"))
    if not checksum_ok(message.raw):
        issues.append(ValidationIssue("WARN", "CheckSum (10) does not match current raw message"))

    definition = dictionary.message(message.msg_type)
    if definition:
        for tag in sorted(definition.required_tags, key=lambda value: int(value) if value.isdigit() else 999999):
            if tag in tag_set:
                continue
            field_definition = dictionary.field(tag)
            name = field_definition.name if field_definition else tag
            issues.append(ValidationIssue("WARN", f"Missing required field {name} ({tag})"))

    for field in message.fields:
        field_definition = dictionary.field(field.tag)
        if not field_definition or not field_definition.enums:
            continue
        value = decode_value(field.value, message.encoding)
        if value not in field_definition.enums:
            issues.append(
                ValidationIssue(
                    "INFO",
                    f"{field_definition.name} ({field.tag}) uses value {value!r} not listed in dictionary enums",
                )
            )

    msg_type = message.msg_type
    order_type = _first_text(message, "40")
    time_in_force = _first_text(message, "59")
    exchange = _first_text(message, "10717")
    if msg_type == "D":
        if "55" not in tag_set and not {"48", "22"}.issubset(tag_set):
            issues.append(ValidationIssue("WARN", "NewOrderSingle requires Symbol (55) OR SecurityID (48)+SecurityIDSource (22)"))
        if order_type in {"2", "4", "P"} and "44" not in tag_set:
            issues.append(ValidationIssue("WARN", f"OrdType={order_type} requires Price (44) according to supplied documentation"))
        if order_type in {"3", "4"} and "99" not in tag_set:
            issues.append(ValidationIssue("WARN", f"OrdType={order_type} requires StopPx (99) according to supplied documentation"))
        if time_in_force == "6" and not ({"126", "432"} & tag_set):
            issues.append(ValidationIssue("WARN", "TimeInForce=6 requires ExpireTime (126) or ExpireDate (432)"))
    if msg_type == "H" and "55" not in tag_set and not {"48", "22"}.issubset(tag_set):
        issues.append(ValidationIssue("WARN", "OrderStatusRequest requires Symbol (55) OR SecurityID (48)+SecurityIDSource (22)"))
    if msg_type in {"D", "F", "H"} and exchange and exchange not in {"GPW", "WGPW"}:
        if "15" not in tag_set or "120" not in tag_set:
            issues.append(ValidationIssue("WARN", "Foreign exchange request should include Currency (15) and SettlCurrency (120)"))
    return issues

__all__ = ["ValidationIssue", "validate_message"]
