"""Finite campaign and per-case result models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from .mutations import MutationCase, MutationKind, MutationSafety


class CampaignStatus(str, Enum):
    # Keep historical serialized identifiers; presentation supplies ASCII punctuation.
    DRAFT = "Draft"
    READY = "Ready"
    RUNNING = "Running"
    WAITING_SLOT = "Waiting for safe active-session slot"
    WAITING_OUTCOME = "Waiting for correlated traffic"
    PAUSED_USER = "Paused by tester"
    PAUSED_DISCONNECTED = "Paused \u2014 upstream disconnected"
    STOPPED = "Stopped"
    COMPLETED = "Completed"


class CaseStatus(str, Enum):
    PLANNED = "Planned"
    QUEUED = "Queued"
    WAITING_OUTCOME = "Waiting for correlated traffic"
    COMPLETED = "Completed"
    FAILED = "Failed"
    SKIPPED = "Skipped \u2014 destructive opt-in disabled"
    INTERRUPTED = "Interrupted"


@dataclass(slots=True)
class CampaignCase:
    case_id: int
    kind: MutationKind
    description: str
    safety: MutationSafety
    raw: bytes
    tag: str = ""
    status: CaseStatus = CaseStatus.PLANNED
    injection_id: int | None = None
    sent_record_id: int | None = None
    sequence_number: int | None = None
    queued_at: datetime | None = None
    sent_at: datetime | None = None
    completed_at: datetime | None = None
    correlated_record_ids: list[int] = field(default_factory=list)
    outcome_classification: str = ""
    outcome_summary: str = ""
    session_state: str = ""
    notes: str = ""

    @classmethod
    def from_mutation(cls, value: MutationCase) -> "CampaignCase":
        return cls(value.case_id, value.kind, value.description, value.safety, value.raw, value.tag)


@dataclass(slots=True)
class FuzzerCampaign:
    campaign_id: str
    title: str
    source_kind: str
    source_id: str
    baseline_raw: bytes
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    cases: list[CampaignCase] = field(default_factory=list)
    case_limit: int = 10
    interval_seconds: float = 1.0
    outcome_window_seconds: float = 1.0
    destructive_opt_in: bool = False
    status: CampaignStatus = CampaignStatus.DRAFT
    current_index: int = 0

    @property
    def current_case(self) -> CampaignCase | None:
        return self.cases[self.current_index] if 0 <= self.current_index < len(self.cases) else None

    @property
    def completed_count(self) -> int:
        return sum(
            item.status in {CaseStatus.COMPLETED, CaseStatus.FAILED, CaseStatus.SKIPPED, CaseStatus.INTERRUPTED}
            for item in self.cases
        )


__all__ = [
    "CampaignCase",
    "CampaignStatus",
    "CaseStatus",
    "FuzzerCampaign",
]
