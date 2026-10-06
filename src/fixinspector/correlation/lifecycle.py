"""Immutable views returned by the correlation engine."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CorrelationLink:
    source_id: int
    target_id: int
    score: int
    reasons: tuple[str, ...]


__all__ = ["CorrelationLink"]
