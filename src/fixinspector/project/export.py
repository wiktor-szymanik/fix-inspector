"""Traffic exports. All public entry points redact configured tags by default."""

from __future__ import annotations

from collections.abc import Iterable
import json
from pathlib import Path

from ..fix.parser import decode_value, parse_message, raw_to_editor_text
from ..records import TrafficRecord
from ..presentation import display_direction, display_direction_text
from .redaction import SecretRedactionPolicy

EXPORT_FORMATS = frozenset({"readable", "raw", "json", "markdown"})


def _redacted_raw(record: TrafficRecord, policy: SecretRedactionPolicy, dictionary) -> bytes:
    return policy.redact(record.raw, dictionary)


def _field_rows(raw: bytes, dictionary) -> list[dict[str, str]]:
    parsed = parse_message(raw, dictionary)
    rows: list[dict[str, str]] = []
    for field in parsed.fields:
        definition = dictionary.field(field.tag) if dictionary else None
        value = decode_value(field.value, parsed.encoding)
        rows.append(
            {
                "tag": field.tag,
                "name": definition.name if definition else "",
                "value": value,
                "meaning": definition.enums.get(value, "") if definition else "",
            }
        )
    return rows


def export_records(
    records: Iterable[TrafficRecord],
    export_format: str,
    *,
    dictionary=None,
    policy: SecretRedactionPolicy | None = None,
) -> bytes:
    """Serialize selected traffic. Returns bytes for safe raw and text file writes."""
    kind = export_format.casefold()
    if kind not in EXPORT_FORMATS:
        raise ValueError(f"Unsupported export format: {export_format}")
    active_policy = policy or SecretRedactionPolicy()
    selected = list(records)
    redacted = [(record, _redacted_raw(record, active_policy, dictionary)) for record in selected]
    if kind == "raw":
        return b"".join(raw for _record, raw in redacted)

    if kind == "json":
        payload = []
        for record, raw in redacted:
            payload.append(
                {
                    "id": record.record_id,
                    "timestamp": record.timestamp.isoformat(),
                    "direction": display_direction(record.direction),
                    "status": record.status,
                    "source": record.source,
                    "msg_type": record.msg_type,
                    "sequence_number": record.sequence_number,
                    "bookmarked": record.bookmarked,
                    "note": active_policy.redact_text(record.note),
                    "modified": record.modified,
                    "fault": {
                        "action": record.fault_action,
                        "rule": active_policy.redact_text(record.fault_rule),
                        "reason": display_direction_text(active_policy.redact_text(record.fault_reason)),
                        "duplicate_of_record_id": record.duplicate_of_record_id,
                    },
                    "raw": raw_to_editor_text(raw),
                    "fields": _field_rows(raw, dictionary),
                }
            )
        return (json.dumps(payload, indent=2, ensure_ascii=False) + "\n").encode("utf-8")

    chunks: list[str] = []
    for record, raw in redacted:
        name = dictionary.message_name(record.msg_type) if dictionary else record.msg_type
        fields = _field_rows(raw, dictionary)
        if kind == "readable":
            chunks.append(
                f"#{record.record_id} {record.timestamp.isoformat()} {display_direction(record.direction)} "
                f"{name} ({record.msg_type}) [{record.status}]"
            )
            chunks.extend(
                f"  {row['tag']} {row['name']}: {row['value']}"
                + (f" ({row['meaning']})" if row["meaning"] else "")
                for row in fields
            )
            if record.note:
                chunks.append(f"  Note: {active_policy.redact_text(record.note)}")
            if record.fault_action:
                chunks.append(
                    f"  Fault: {record.fault_action}; rule={active_policy.redact_text(record.fault_rule) or '-'}; "
                    f"reason={display_direction_text(active_policy.redact_text(record.fault_reason))}"
                )
            chunks.append("")
        else:
            chunks.append(f"## #{record.record_id} {display_direction(record.direction)} - {name}")
            chunks.append("")
            chunks.append(
                f"- Time: `{record.timestamp.isoformat()}`\n- Status: `{record.status}`\n"
                f"- MsgType: `{record.msg_type}`\n- SeqNum: `{record.sequence_number or ''}`"
            )
            if record.note:
                chunks.append(f"- Note: {active_policy.redact_text(record.note)}")
            if record.fault_action:
                chunks.append(
                    f"- Fault: `{record.fault_action}`; Rule: "
                    f"{active_policy.redact_text(record.fault_rule) or '-'}; Reason: "
                    f"{display_direction_text(active_policy.redact_text(record.fault_reason))}"
                )
            chunks.extend(["", "| Tag | Name | Value | Meaning |", "|---:|---|---|---|"])
            for row in fields:
                escaped = [row[key].replace("|", "\\|").replace("\n", " ") for key in ("tag", "name", "value", "meaning")]
                chunks.append("| " + " | ".join(escaped) + " |")
            chunks.append("")
    return "\n".join(chunks).encode("utf-8")


def write_export(
    path: str | Path,
    records: Iterable[TrafficRecord],
    export_format: str,
    *,
    dictionary=None,
    policy: SecretRedactionPolicy | None = None,
) -> None:
    Path(path).write_bytes(export_records(records, export_format, dictionary=dictionary, policy=policy))


__all__ = ["EXPORT_FORMATS", "export_records", "write_export"]
