"""Identifier extraction and scored additive correlation strategies."""

from __future__ import annotations

from dataclasses import dataclass

from ..fix.message import FixMessage


@dataclass(frozen=True, slots=True)
class CorrelationIdentifier:
    namespace: str
    value: str
    score: int
    reason: str
    references: bool = False


def _values(message: FixMessage, tag: str) -> list[str]:
    return [value.decode(message.encoding, errors="replace") for value in message.values(tag) if value]


def identifiers_for(message: FixMessage) -> list[CorrelationIdentifier]:
    identifiers: list[CorrelationIdentifier] = []
    for value in _values(message, "34"):
        identifiers.append(CorrelationIdentifier("MsgSeqNum", value, 100, "MsgSeqNum"))
    for value in _values(message, "45"):
        identifiers.append(CorrelationIdentifier("MsgSeqNum", value, 100, "RefSeqNum → MsgSeqNum", True))
    for tag, namespace, score in (
        ("710", "PosReqID", 95),
        ("11", "ClOrdID", 90),
        ("37", "OrderID", 88),
        ("1080", "OrderID", 86),
    ):
        for value in _values(message, tag):
            identifiers.append(CorrelationIdentifier(namespace, value, score, namespace))
    for value in _values(message, "41"):
        identifiers.append(CorrelationIdentifier("ClOrdID", value, 92, "OrigClOrdID → ClOrdID", True))
    for value in _values(message, "379"):
        identifiers.append(
            CorrelationIdentifier("ClOrdID", value, 85, "BusinessRejectRefID → ClOrdID", True)
        )
        identifiers.append(
            CorrelationIdentifier("BusinessID", value, 80, "BusinessRejectRefID", True)
        )
    return identifiers


__all__ = ["CorrelationIdentifier", "identifiers_for"]
