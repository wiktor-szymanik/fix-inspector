from __future__ import annotations

from .dictionary import FixDictionary
from .model import FixMessage, ValidationIssue
from .codec import decode_value, checksum_ok


def _first_text(message: FixMessage, tag: str) -> str | None:
    value = message.first(tag)
    if value is None:
        return None
    return decode_value(value, message.encoding)


def validate_message(message: FixMessage, dictionary: FixDictionary) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    tags = [f.tag for f in message.fields]
    tag_set = set(tags)

    if len(tags) < 4 or tags[0] != "8" or tags[1] != "9" or tags[2] != "35" or tags[-1] != "10":
        issues.append(ValidationIssue("WARN", "Expected FIX order: 8, 9, 35, ..., 10"))

    if not checksum_ok(message.raw):
        issues.append(ValidationIssue("WARN", "CheckSum (10) does not match current raw message"))

    msg_def = dictionary.message(message.msg_type)
    if msg_def:
        for required_tag in sorted(msg_def.required_tags, key=lambda t: int(t) if t.isdigit() else 999999):
            if required_tag not in tag_set:
                field_def = dictionary.field(required_tag)
                name = field_def.name if field_def else required_tag
                issues.append(ValidationIssue("WARN", f"Missing required field {name} ({required_tag})"))

    for field in message.fields:
        definition = dictionary.field(field.tag)
        if not definition or not definition.enums:
            continue
        value = decode_value(field.value, message.encoding)
        if value not in definition.enums:
            issues.append(
                ValidationIssue(
                    "INFO",
                    f"{definition.name} ({field.tag}) uses value {value!r} not listed in dictionary enums",
                )
            )

    # Business rules directly supported by the provided clientAPI documentation.
    msg_type = message.msg_type
    ord_type = _first_text(message, "40")
    tif = _first_text(message, "59")
    exchange = _first_text(message, "10717")

    if msg_type == "D":  # NewOrderSingle
        if "55" not in tag_set and not {"48", "22"}.issubset(tag_set):
            issues.append(ValidationIssue("WARN", "NewOrderSingle requires Symbol (55) OR SecurityID (48)+SecurityIDSource (22)"))
        if ord_type in {"2", "4", "P"} and "44" not in tag_set:
            issues.append(ValidationIssue("WARN", f"OrdType={ord_type} requires Price (44) according to supplied documentation"))
        if ord_type in {"3", "4"} and "99" not in tag_set:
            issues.append(ValidationIssue("WARN", f"OrdType={ord_type} requires StopPx (99) according to supplied documentation"))
        if tif == "6" and not ({"126", "432"} & tag_set):
            issues.append(ValidationIssue("WARN", "TimeInForce=6 requires ExpireTime (126) or ExpireDate (432)"))

    if msg_type == "H":
        if "55" not in tag_set and not {"48", "22"}.issubset(tag_set):
            issues.append(ValidationIssue("WARN", "OrderStatusRequest requires Symbol (55) OR SecurityID (48)+SecurityIDSource (22)"))

    if msg_type in {"D", "F", "H"} and exchange and exchange not in {"GPW", "WGPW"}:
        if "15" not in tag_set or "120" not in tag_set:
            issues.append(ValidationIssue("WARN", "Foreign exchange request should include Currency (15) and SettlCurrency (120)"))

    return issues
