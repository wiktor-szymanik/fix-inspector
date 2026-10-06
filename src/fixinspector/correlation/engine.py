"""Additive, non-synchronous correlation index for History/Related views."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from ..fix.parser import parse_message
from ..records import TrafficRecord
from .lifecycle import CorrelationLink
from .strategies import CorrelationIdentifier, identifiers_for


class CorrelationEngine:
    def __init__(self, dictionary=None) -> None:
        self.dictionary = dictionary
        self._records: dict[int, TrafficRecord] = {}
        self._identifiers: dict[int, list[CorrelationIdentifier]] = {}
        self._index: dict[tuple[str, str], set[int]] = defaultdict(set)

    def clear(self) -> None:
        self._records.clear()
        self._identifiers.clear()
        self._index.clear()

    def add(self, record: TrafficRecord) -> None:
        if record.record_id in self._records:
            self.remove(record.record_id)
        identifiers = identifiers_for(parse_message(record.raw, self.dictionary))
        self._records[record.record_id] = record
        self._identifiers[record.record_id] = identifiers
        for item in identifiers:
            self._index[(item.namespace, item.value)].add(record.record_id)

    def remove(self, record_id: int) -> None:
        for item in self._identifiers.pop(record_id, []):
            ids = self._index.get((item.namespace, item.value))
            if ids is not None:
                ids.discard(record_id)
                if not ids:
                    self._index.pop((item.namespace, item.value), None)
        self._records.pop(record_id, None)

    def rebuild(self, records: Iterable[TrafficRecord]) -> None:
        self.clear()
        for record in records:
            self.add(record)

    def related(self, record_id: int) -> list[CorrelationLink]:
        source_items = self._identifiers.get(record_id, [])
        evidence: dict[int, dict[str, int]] = defaultdict(dict)
        for source in source_items:
            for candidate_id in self._index.get((source.namespace, source.value), set()):
                if candidate_id == record_id:
                    continue
                source_record = self._records[record_id]
                candidate_record = self._records[candidate_id]
                if (
                    source_record.session_key
                    and candidate_record.session_key
                    and source_record.session_key != candidate_record.session_key
                ):
                    continue
                for candidate in self._identifiers.get(candidate_id, []):
                    if candidate.namespace != source.namespace or candidate.value != source.value:
                        continue
                    if source.namespace == "MsgSeqNum" and not (source.references or candidate.references):
                        continue
                    if (
                        source.namespace == "MsgSeqNum"
                        and source_record.direction == candidate_record.direction
                    ):
                        continue
                    reason = (
                        source.reason
                        if source.references
                        else candidate.reason
                        if candidate.references
                        else source.reason
                    )
                    evidence[candidate_id][reason] = max(source.score, candidate.score)
        links = [
            CorrelationLink(
                source_id=record_id,
                target_id=target_id,
                score=min(100, max(scores.values()) + min(10, 2 * (len(scores) - 1))),
                reasons=tuple(sorted(scores)),
            )
            for target_id, scores in evidence.items()
        ]
        return sorted(links, key=lambda item: (-item.score, item.target_id))

    def record(self, record_id: int) -> TrafficRecord | None:
        return self._records.get(record_id)


__all__ = ["CorrelationEngine"]
