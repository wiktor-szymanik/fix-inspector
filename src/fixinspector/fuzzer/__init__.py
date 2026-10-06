"""Controlled, finite manual-security-testing Fuzzer."""

from .campaign import CampaignCase, CampaignStatus, CaseStatus, FuzzerCampaign
from .classifier import ClassifiedOutcome, classify_outcome, eligible_outcome_records
from .executor import FuzzerController
from .mutations import (
    DESTRUCTIVE_KINDS,
    FIELD_KINDS,
    MAX_CAMPAIGN_CASES,
    MutationCase,
    MutationKind,
    MutationPlanner,
    MutationSafety,
    MutationSpec,
)

__all__ = [
    "CampaignCase",
    "CampaignStatus",
    "CaseStatus",
    "ClassifiedOutcome",
    "DESTRUCTIVE_KINDS",
    "FIELD_KINDS",
    "FuzzerCampaign",
    "FuzzerController",
    "MAX_CAMPAIGN_CASES",
    "MutationCase",
    "MutationKind",
    "MutationPlanner",
    "MutationSafety",
    "MutationSpec",
    "classify_outcome",
    "eligible_outcome_records",
]
