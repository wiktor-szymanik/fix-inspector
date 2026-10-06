"""Non-blocking sequential executor over the shared InjectionController."""

from __future__ import annotations

import base64
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
import itertools
import threading

from ..fix.parser import parse_message
from ..records import TrafficRecord
from ..session.injection import InjectionMode, InjectionRequest, InjectionStatus
from .campaign import CampaignCase, CampaignStatus, CaseStatus, FuzzerCampaign
from .classifier import classify_outcome
from .mutations import MAX_CAMPAIGN_CASES, MutationKind, MutationPlanner, MutationSafety, MutationSpec


MIN_CASE_INTERVAL_SECONDS = 0.25
MAX_CASE_INTERVAL_SECONDS = 60.0
MIN_OUTCOME_WINDOW_SECONDS = 0.25
MAX_OUTCOME_WINDOW_SECONDS = 60.0


class FuzzerController:
    """Owns finite campaign state only; the transport owns sequencing/session injection."""

    def __init__(
        self,
        dictionary,
        queue_sender: Callable[..., InjectionRequest],
        cancel_sender: Callable[[int], bool] | None = None,
        outcome_provider: Callable[[int], list[TrafficRecord]] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.dictionary = dictionary
        self.planner = MutationPlanner(dictionary)
        self._queue_sender = queue_sender
        self._cancel_sender = cancel_sender or (lambda _injection_id: False)
        self._outcome_provider = outcome_provider or (lambda _record_id: [])
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._campaigns: dict[str, FuzzerCampaign] = {}
        self._ids = itertools.count(1)
        self._active_id = ""
        self._connected = False
        self._next_case_at: datetime | None = None
        self._listeners: list[Callable[[FuzzerCampaign], None]] = []
        self._lock = threading.RLock()

    def set_dictionary(self, dictionary) -> None:
        with self._lock:
            self.dictionary = dictionary
            self.planner.set_dictionary(dictionary)

    def add_listener(self, listener: Callable[[FuzzerCampaign], None]) -> None:
        with self._lock:
            self._listeners.append(listener)

    def create_campaign(self, source_kind: str, source_id: str, baseline_raw: bytes, title: str = "") -> FuzzerCampaign:
        message = parse_message(baseline_raw, self.dictionary)
        if message.msg_type == "?":
            raise ValueError("Fuzzer baseline must contain MsgType (35)")
        if self.dictionary and self.dictionary.is_admin(message.msg_type):
            raise ValueError("Session/admin messages cannot be used as safe Fuzzer baselines")
        with self._lock:
            campaign_id = f"F{next(self._ids)}"
            campaign = FuzzerCampaign(
                campaign_id,
                title.strip() or f"{campaign_id} · {source_kind} {source_id} · {message.msg_type}",
                str(source_kind),
                str(source_id),
                bytes(baseline_raw),
                created_at=self._clock(),
            )
            self._campaigns[campaign_id] = campaign
        self._notify(campaign)
        return campaign

    def plan(
        self,
        campaign_id: str,
        specs: list[MutationSpec],
        *,
        case_limit: int,
        interval_seconds: float,
        outcome_window_seconds: float,
        destructive_opt_in: bool = False,
    ) -> FuzzerCampaign:
        interval = float(interval_seconds)
        outcome_window = float(outcome_window_seconds)
        if not MIN_CASE_INTERVAL_SECONDS <= interval <= MAX_CASE_INTERVAL_SECONDS:
            raise ValueError(
                f"Case interval must be between {MIN_CASE_INTERVAL_SECONDS} and {MAX_CASE_INTERVAL_SECONDS} seconds"
            )
        if not MIN_OUTCOME_WINDOW_SECONDS <= outcome_window <= MAX_OUTCOME_WINDOW_SECONDS:
            raise ValueError(
                f"Outcome window must be between {MIN_OUTCOME_WINDOW_SECONDS} and {MAX_OUTCOME_WINDOW_SECONDS} seconds"
            )
        with self._lock:
            campaign = self._campaigns[campaign_id]
            if campaign.status in {
                CampaignStatus.RUNNING,
                CampaignStatus.WAITING_SLOT,
                CampaignStatus.WAITING_OUTCOME,
            }:
                raise RuntimeError("Cannot replace a plan while its campaign is running")
            generated = self.planner.generate(campaign.baseline_raw, specs, case_limit=case_limit)
            campaign.cases = [CampaignCase.from_mutation(item) for item in generated]
            campaign.case_limit = int(case_limit)
            campaign.interval_seconds = interval
            campaign.outcome_window_seconds = outcome_window
            campaign.destructive_opt_in = bool(destructive_opt_in)
            campaign.current_index = 0
            campaign.status = CampaignStatus.READY if campaign.cases else CampaignStatus.DRAFT
        self._notify(campaign)
        return campaign

    def start(self, campaign_id: str) -> None:
        with self._lock:
            campaign = self._campaigns[campaign_id]
            if not campaign.cases:
                raise ValueError("Generate at least one finite test case before starting")
            if campaign.status in {CampaignStatus.STOPPED, CampaignStatus.COMPLETED}:
                raise RuntimeError("Stopped/completed campaigns are immutable; create a new campaign from the baseline")
            if self._active_id and self._active_id != campaign_id:
                active = self._campaigns.get(self._active_id)
                if active and active.status not in {CampaignStatus.COMPLETED, CampaignStatus.STOPPED}:
                    raise RuntimeError("Only one low-rate Fuzzer campaign can execute at a time")
            self._active_id = campaign_id
            if not self._connected:
                campaign.status = CampaignStatus.PAUSED_DISCONNECTED
            else:
                campaign.status = (
                    CampaignStatus.WAITING_OUTCOME
                    if campaign.current_case
                    and campaign.current_case.status is CaseStatus.WAITING_OUTCOME
                    else CampaignStatus.RUNNING
                )
                self._next_case_at = self._clock()
        self._notify(campaign)

    def pause(self, campaign_id: str) -> None:
        with self._lock:
            campaign = self._campaigns[campaign_id]
            current = campaign.current_case
            if current and current.status is CaseStatus.QUEUED and current.injection_id is not None:
                if self._cancel_sender(current.injection_id):
                    current.status = CaseStatus.PLANNED
                    current.injection_id = None
            campaign.status = CampaignStatus.PAUSED_USER
        self._notify(campaign)

    def stop(self, campaign_id: str) -> None:
        with self._lock:
            campaign = self._campaigns[campaign_id]
            current = campaign.current_case
            if current and current.status is CaseStatus.QUEUED and current.injection_id is not None:
                self._cancel_sender(current.injection_id)
                current.status = CaseStatus.INTERRUPTED
                current.completed_at = self._clock()
            elif current and current.status is CaseStatus.WAITING_OUTCOME:
                self._collect_outcome(campaign, current)
                current.status = CaseStatus.INTERRUPTED
                current.outcome_classification = current.outcome_classification or "STOPPED"
                current.outcome_summary = current.outcome_summary or "Stopped during correlation window"
                current.completed_at = self._clock()
            campaign.status = CampaignStatus.STOPPED
            if self._active_id == campaign_id:
                self._active_id = ""
        self._notify(campaign)

    def set_connected(self, connected: bool) -> None:
        with self._lock:
            changed = self._connected != bool(connected)
            self._connected = bool(connected)
            campaign = self._campaigns.get(self._active_id)
            if campaign is None:
                return
            previous_status = campaign.status
            if not self._connected and campaign.status in {
                CampaignStatus.RUNNING,
                CampaignStatus.WAITING_SLOT,
                CampaignStatus.WAITING_OUTCOME,
            }:
                current = campaign.current_case
                if current and current.status is CaseStatus.QUEUED and current.injection_id is not None:
                    if self._cancel_sender(current.injection_id):
                        current.status = CaseStatus.PLANNED
                        current.injection_id = None
                campaign.status = CampaignStatus.PAUSED_DISCONNECTED
            elif changed and self._connected and campaign.status is CampaignStatus.PAUSED_DISCONNECTED:
                # Reconnection never silently resumes authorized testing.
                campaign.status = CampaignStatus.PAUSED_USER
        if changed or campaign.status is not previous_status:
            self._notify(campaign)

    def tick(self, at: datetime | None = None) -> None:
        now = at or self._clock()
        with self._lock:
            campaign = self._campaigns.get(self._active_id)
            if campaign is None or not self._connected:
                return
            current = campaign.current_case
            if current is None:
                campaign.status = CampaignStatus.COMPLETED
                self._active_id = ""
                notify = campaign
            elif campaign.status is CampaignStatus.WAITING_OUTCOME:
                self._collect_outcome(campaign, current)
                if current.sent_at is None or now < current.sent_at + timedelta(seconds=campaign.outcome_window_seconds):
                    return
                outcome = classify_outcome(
                    self._outcome_provider(current.sent_record_id) if current.sent_record_id is not None else [],
                    self.dictionary,
                )
                current.correlated_record_ids = list(outcome.record_ids)
                current.outcome_classification = outcome.classification
                current.outcome_summary = outcome.summary
                current.status = CaseStatus.COMPLETED
                current.completed_at = now
                campaign.current_index += 1
                campaign.status = CampaignStatus.RUNNING
                self._next_case_at = now + timedelta(seconds=campaign.interval_seconds)
                notify = campaign
            elif campaign.status is CampaignStatus.RUNNING:
                if self._next_case_at is not None and now < self._next_case_at:
                    return
                if current.safety is MutationSafety.SESSION_DESTRUCTIVE and not campaign.destructive_opt_in:
                    current.status = CaseStatus.SKIPPED
                    current.outcome_classification = "SKIPPED"
                    current.outcome_summary = "Session-destructive mutation requires explicit opt-in"
                    current.completed_at = now
                    campaign.current_index += 1
                    self._next_case_at = now + timedelta(seconds=campaign.interval_seconds)
                    notify = campaign
                else:
                    mode = (
                        InjectionMode.EXACT_RAW
                        if current.safety is MutationSafety.SESSION_DESTRUCTIVE
                        else InjectionMode.CLONE_EDIT
                    )
                    owner = f"fuzzer:{campaign.campaign_id}:{current.case_id}"
                    request = self._queue_sender(
                        current.raw,
                        mode,
                        source="FUZZER",
                        repeater_item_id=owner,
                    )
                    current.injection_id = request.injection_id
                    current.queued_at = request.queued_at
                    current.status = CaseStatus.QUEUED
                    campaign.status = CampaignStatus.WAITING_SLOT
                    notify = campaign
            else:
                return
        self._notify(notify)

    def handle_injection_event(self, request: InjectionRequest) -> None:
        if request.source != "FUZZER" or not request.repeater_item_id.startswith("fuzzer:"):
            return
        parts = request.repeater_item_id.split(":")
        if len(parts) != 3:
            return
        campaign_id, case_text = parts[1], parts[2]
        try:
            case_id = int(case_text)
        except ValueError:
            return
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if campaign is None:
                return
            current = next((item for item in campaign.cases if item.case_id == case_id), None)
            if current is None:
                return
            current.injection_id = request.injection_id
            if request.status in {InjectionStatus.QUEUED, InjectionStatus.RAW_QUEUED}:
                current.status = CaseStatus.QUEUED
                current.queued_at = request.queued_at
                campaign.status = CampaignStatus.WAITING_SLOT
            elif request.status in {InjectionStatus.INJECTED, InjectionStatus.RAW_REPLAYED}:
                current.status = CaseStatus.WAITING_OUTCOME
                current.sent_record_id = request.result_record_id
                current.sequence_number = request.slot_sequence_number
                current.sent_at = self._clock()
                current.session_state = "Connected"
                if campaign.status is CampaignStatus.STOPPED:
                    current.status = CaseStatus.INTERRUPTED
                    current.outcome_classification = "STOPPED_AFTER_SEND"
                    current.outcome_summary = "Case completed transport send while Stop was racing the active slot"
                    current.completed_at = self._clock()
                elif campaign.status not in {CampaignStatus.PAUSED_USER, CampaignStatus.PAUSED_DISCONNECTED}:
                    campaign.status = CampaignStatus.WAITING_OUTCOME
            elif request.status is InjectionStatus.FAILED:
                current.status = CaseStatus.FAILED
                current.outcome_classification = "SEND_FAILED"
                current.outcome_summary = request.detail
                current.completed_at = self._clock()
                campaign.current_index = max(campaign.current_index, campaign.cases.index(current) + 1)
                campaign.status = CampaignStatus.RUNNING if self._connected else CampaignStatus.PAUSED_DISCONNECTED
                self._next_case_at = self._clock() + timedelta(seconds=campaign.interval_seconds)
            elif request.status is InjectionStatus.CANCELLED:
                if campaign.status is CampaignStatus.STOPPED:
                    current.status = CaseStatus.INTERRUPTED
                else:
                    current.status = CaseStatus.PLANNED
                    current.injection_id = None
                    campaign.status = CampaignStatus.PAUSED_DISCONNECTED if not self._connected else CampaignStatus.PAUSED_USER
        self._notify(campaign)

    def _collect_outcome(self, campaign: FuzzerCampaign, current: CampaignCase) -> None:
        if current.sent_record_id is None:
            return
        records = self._outcome_provider(current.sent_record_id)
        current.correlated_record_ids = [item.record_id for item in records]
        if records:
            outcome = classify_outcome(records, self.dictionary)
            current.outcome_classification = outcome.classification
            current.outcome_summary = outcome.summary

    def campaign(self, campaign_id: str) -> FuzzerCampaign | None:
        with self._lock:
            return self._campaigns.get(campaign_id)

    def campaigns(self) -> tuple[FuzzerCampaign, ...]:
        with self._lock:
            return tuple(self._campaigns.values())

    def active_campaign(self) -> FuzzerCampaign | None:
        with self._lock:
            return self._campaigns.get(self._active_id)

    def to_state(
        self,
        redact: Callable[[bytes], bytes],
        redact_text: Callable[[str], str] = lambda value: value,
    ) -> list[dict[str, object]]:
        with self._lock:
            campaigns = tuple(self._campaigns.values())
        return [_campaign_to_state(item, redact, redact_text) for item in campaigns]

    def restore_state(self, state: object) -> None:
        if not isinstance(state, list):
            return
        restored: dict[str, FuzzerCampaign] = {}
        greatest = 0
        for value in state:
            try:
                campaign = _campaign_from_state(value)
            except (KeyError, TypeError, ValueError):
                continue
            restored[campaign.campaign_id] = campaign
            if campaign.campaign_id.startswith("F") and campaign.campaign_id[1:].isdigit():
                greatest = max(greatest, int(campaign.campaign_id[1:]))
        with self._lock:
            self._campaigns = restored
            self._ids = itertools.count(greatest + 1)
            self._active_id = ""

    def _notify(self, campaign: FuzzerCampaign) -> None:
        listeners = tuple(self._listeners)
        for listener in listeners:
            listener(campaign)


def _campaign_to_state(campaign, redact, redact_text) -> dict[str, object]:
    return {
        "campaign_id": campaign.campaign_id,
        "title": redact_text(campaign.title),
        "source_kind": campaign.source_kind,
        "source_id": campaign.source_id,
        "baseline_raw": base64.b64encode(redact(campaign.baseline_raw)).decode("ascii"),
        "created_at": campaign.created_at.isoformat(),
        "case_limit": campaign.case_limit,
        "interval_seconds": campaign.interval_seconds,
        "outcome_window_seconds": campaign.outcome_window_seconds,
        "destructive_opt_in": campaign.destructive_opt_in,
        "status": campaign.status.value,
        "current_index": campaign.current_index,
        "cases": [
            {
                "case_id": item.case_id,
                "kind": item.kind.value,
                "description": redact_text(item.description),
                "safety": item.safety.value,
                "raw": base64.b64encode(redact(item.raw)).decode("ascii"),
                "tag": item.tag,
                "status": item.status.value,
                "injection_id": item.injection_id,
                "sent_record_id": item.sent_record_id,
                "sequence_number": item.sequence_number,
                "queued_at": item.queued_at.isoformat() if item.queued_at else None,
                "sent_at": item.sent_at.isoformat() if item.sent_at else None,
                "completed_at": item.completed_at.isoformat() if item.completed_at else None,
                "correlated_record_ids": item.correlated_record_ids,
                "outcome_classification": redact_text(item.outcome_classification),
                "outcome_summary": redact_text(item.outcome_summary),
                "session_state": item.session_state,
                "notes": redact_text(item.notes),
            }
            for item in campaign.cases
        ],
    }


def _campaign_from_state(value: object) -> FuzzerCampaign:
    if not isinstance(value, dict):
        raise TypeError("Campaign state must be an object")
    status = CampaignStatus(str(value.get("status", CampaignStatus.DRAFT.value)))
    if status in {CampaignStatus.RUNNING, CampaignStatus.WAITING_SLOT, CampaignStatus.WAITING_OUTCOME}:
        status = CampaignStatus.PAUSED_USER
    cases: list[CampaignCase] = []
    for raw_case in value.get("cases", []):
        if not isinstance(raw_case, dict):
            continue
        case_status = CaseStatus(str(raw_case.get("status", CaseStatus.PLANNED.value)))
        if case_status in {CaseStatus.QUEUED, CaseStatus.WAITING_OUTCOME}:
            case_status = CaseStatus.INTERRUPTED
        cases.append(
            CampaignCase(
                int(raw_case["case_id"]),
                MutationKind(str(raw_case["kind"])),
                str(raw_case["description"]),
                MutationSafety(str(raw_case["safety"])),
                base64.b64decode(str(raw_case["raw"]), validate=True),
                str(raw_case.get("tag", "")),
                case_status,
                int(raw_case["injection_id"]) if raw_case.get("injection_id") is not None else None,
                int(raw_case["sent_record_id"]) if raw_case.get("sent_record_id") is not None else None,
                int(raw_case["sequence_number"]) if raw_case.get("sequence_number") is not None else None,
                _parse_optional_time(raw_case.get("queued_at")),
                _parse_optional_time(raw_case.get("sent_at")),
                _parse_optional_time(raw_case.get("completed_at")),
                [int(item) for item in raw_case.get("correlated_record_ids", [])],
                str(raw_case.get("outcome_classification", "")),
                str(raw_case.get("outcome_summary", "")),
                str(raw_case.get("session_state", "")),
                str(raw_case.get("notes", "")),
            )
        )
    return FuzzerCampaign(
        str(value["campaign_id"]),
        str(value["title"]),
        str(value["source_kind"]),
        str(value["source_id"]),
        base64.b64decode(str(value["baseline_raw"]), validate=True),
        datetime.fromisoformat(str(value["created_at"])),
        cases,
        min(MAX_CAMPAIGN_CASES, max(1, int(value.get("case_limit", 10)))),
        max(MIN_CASE_INTERVAL_SECONDS, float(value.get("interval_seconds", 1.0))),
        max(MIN_OUTCOME_WINDOW_SECONDS, float(value.get("outcome_window_seconds", 1.0))),
        False,  # Explicit destructive authorization is never restored across app/project sessions.
        status,
        min(len(cases), max(0, int(value.get("current_index", 0)))),
    )


def _parse_optional_time(value) -> datetime | None:
    return datetime.fromisoformat(str(value)) if value else None


__all__ = [
    "FuzzerController",
    "MAX_CASE_INTERVAL_SECONDS",
    "MAX_OUTCOME_WINDOW_SECONDS",
    "MIN_CASE_INTERVAL_SECONDS",
    "MIN_OUTCOME_WINDOW_SECONDS",
]
