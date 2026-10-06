"""Asynchronous correlated-outcome classification for finite fuzz cases."""

from __future__ import annotations

from dataclasses import dataclass

from ..fix.parser import parse_message
from ..records import TrafficRecord


@dataclass(frozen=True, slots=True)
class ClassifiedOutcome:
    classification: str
    summary: str
    record_ids: tuple[int, ...]


def eligible_outcome_records(
    sent_record_id: int,
    records: list[TrafficRecord] | tuple[TrafficRecord, ...],
) -> list[TrafficRecord]:
    """Keep only later server traffic when classifying a sent fuzz case."""
    return sorted(
        (
            record
            for record in records
            if record.direction == "S→C" and record.record_id > int(sent_record_id)
        ),
        key=lambda item: item.record_id,
    )


def classify_outcome(records: list[TrafficRecord] | tuple[TrafficRecord, ...], dictionary=None) -> ClassifiedOutcome:
    ordered = sorted(records, key=lambda item: item.record_id)
    ids = tuple(item.record_id for item in ordered)
    if not ordered:
        return ClassifiedOutcome("NO_CORRELATED_TRAFFIC", "No traffic correlated within the configured window", ())
    parsed = [(item, parse_message(item.raw, dictionary)) for item in ordered]
    rejects = [(item, message) for item, message in parsed if message.msg_type in {"3", "9", "j", "J"}]
    if rejects:
        types = ", ".join(f"#{item.record_id} {message.msg_type}" for item, message in rejects)
        return ClassifiedOutcome("REJECT", f"Correlated reject/business-reject traffic: {types}", ids)
    executions = [(item, message) for item, message in parsed if message.msg_type == "8"]
    if executions:
        states = []
        for item, message in executions:
            value = message.first("39") or message.first("150") or b"?"
            states.append(f"#{item.record_id} state={value.decode('utf-8', errors='replace')}")
        return ClassifiedOutcome("EXECUTION_REPORT", "; ".join(states), ids)
    return ClassifiedOutcome(
        "CORRELATED_TRAFFIC",
        ", ".join(f"#{item.record_id} {message.msg_type}" for item, message in parsed),
        ids,
    )


__all__ = ["ClassifiedOutcome", "classify_outcome", "eligible_outcome_records"]
