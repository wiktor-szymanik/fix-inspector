from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from fixinspector.fix.dictionary import FixDictionary
from fixinspector.fuzzer import (
    CampaignStatus,
    CaseStatus,
    FuzzerController,
    MutationKind,
    MutationSpec,
    eligible_outcome_records,
)
from fixinspector.project.redaction import SecretRedactionPolicy
from fixinspector.records import TrafficRecord
from fixinspector.session.injection import InjectionMode, InjectionRequest, InjectionStatus

from tests.support import fix_message


class MutableClock:
    def __init__(self) -> None:
        self.now = datetime(2026, 9, 1, 10, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


class FuzzerCampaignTests(unittest.TestCase):
    def test_outcome_candidates_exclude_older_and_client_side_correlation(self) -> None:
        candidates = [
            TrafficRecord(9, "S→C", fix_message("8", 1), msg_type="8"),
            TrafficRecord(11, "C→S", fix_message("D", 2), msg_type="D"),
            TrafficRecord(12, "S→C", fix_message("3", 3), msg_type="3"),
        ]
        self.assertEqual(
            [12],
            [item.record_id for item in eligible_outcome_records(10, candidates)],
        )

    def make_controller(self, outcomes=None):
        clock = MutableClock()
        queued = []
        cancelled = []

        def sender(raw, mode, **values):
            request = InjectionRequest(
                len(queued) + 1,
                mode,
                raw,
                values["source"],
                values["repeater_item_id"],
                None,
                clock(),
                InjectionStatus.RAW_QUEUED if mode is InjectionMode.EXACT_RAW else InjectionStatus.QUEUED,
            )
            queued.append(request)
            return request

        controller = FuzzerController(
            FixDictionary(),
            sender,
            lambda injection_id: not cancelled.append(injection_id),
            outcomes or (lambda _record_id: []),
            clock,
        )
        return controller, clock, queued, cancelled

    def test_campaign_is_strictly_sequential_and_low_rate(self) -> None:
        reject = TrafficRecord(90, "S→C", fix_message("3", 40, [("45", b"1")]), msg_type="3")
        controller, clock, queued, _cancelled = self.make_controller(lambda _record_id: [reject])
        campaign = controller.create_campaign("History", "#1", fix_message("D", extra_fields=[("11", b"A")]))
        controller.plan(
            campaign.campaign_id,
            [MutationSpec(MutationKind.EMPTY, "11"), MutationSpec(MutationKind.DUPLICATE_FIELD, "11")],
            case_limit=2,
            interval_seconds=0.5,
            outcome_window_seconds=0.5,
        )
        controller.set_connected(True)
        controller.start(campaign.campaign_id)
        controller.tick()
        self.assertEqual(1, len(queued))
        controller.tick()
        self.assertEqual(1, len(queued), "second case must not queue while first awaits a safe slot")

        sent = queued[0].snapshot()
        sent.status = InjectionStatus.INJECTED
        sent.result_record_id = 10
        sent.slot_sequence_number = 50
        controller.handle_injection_event(sent)
        clock.advance(0.49)
        controller.tick()
        self.assertEqual(1, len(queued))
        clock.advance(0.01)
        controller.tick()
        self.assertEqual(CaseStatus.COMPLETED, campaign.cases[0].status)
        self.assertEqual("REJECT", campaign.cases[0].outcome_classification)
        controller.tick()
        self.assertEqual(1, len(queued), "minimum configured interval still applies")
        clock.advance(0.5)
        controller.tick()
        self.assertEqual(2, len(queued))

    def test_disconnect_pauses_and_reconnect_never_silently_resumes(self) -> None:
        controller, _clock, queued, cancelled = self.make_controller()
        campaign = controller.create_campaign("Composer", "C1", fix_message("D", extra_fields=[("11", b"A")]))
        controller.plan(
            campaign.campaign_id,
            [MutationSpec(MutationKind.EMPTY, "11")],
            case_limit=1,
            interval_seconds=1,
            outcome_window_seconds=1,
        )
        controller.set_connected(True)
        controller.start(campaign.campaign_id)
        controller.tick()
        self.assertEqual(1, len(queued))

        controller.set_connected(False)

        self.assertEqual(CampaignStatus.PAUSED_DISCONNECTED, campaign.status)
        self.assertEqual([queued[0].injection_id], cancelled)
        self.assertEqual(CaseStatus.PLANNED, campaign.cases[0].status)
        controller.set_connected(True)
        self.assertEqual(CampaignStatus.PAUSED_USER, campaign.status)
        controller.tick()
        self.assertEqual(1, len(queued))

    def test_disconnect_during_outcome_window_does_not_resend_case_on_resume(self) -> None:
        controller, _clock, queued, _cancelled = self.make_controller()
        campaign = controller.create_campaign("History", "#1", fix_message("D", extra_fields=[("11", b"A")]))
        controller.plan(
            campaign.campaign_id,
            [MutationSpec(MutationKind.EMPTY, "11")],
            case_limit=1,
            interval_seconds=1,
            outcome_window_seconds=1,
        )
        controller.set_connected(True)
        controller.start(campaign.campaign_id)
        controller.tick()
        sent = queued[0].snapshot()
        sent.status = InjectionStatus.INJECTED
        sent.result_record_id = 10
        controller.handle_injection_event(sent)

        controller.set_connected(False)
        controller.set_connected(True)
        controller.start(campaign.campaign_id)
        controller.tick()

        self.assertEqual(1, len(queued))
        self.assertEqual(CampaignStatus.WAITING_OUTCOME, campaign.status)

    def test_destructive_case_is_skipped_without_explicit_opt_in(self) -> None:
        controller, clock, queued, _cancelled = self.make_controller()
        campaign = controller.create_campaign("History", "#1", fix_message("D", extra_fields=[("11", b"A")]))
        controller.plan(
            campaign.campaign_id,
            [MutationSpec(MutationKind.MALFORM_CHECKSUM)],
            case_limit=1,
            interval_seconds=0.25,
            outcome_window_seconds=0.25,
            destructive_opt_in=False,
        )
        controller.set_connected(True)
        controller.start(campaign.campaign_id)
        controller.tick()

        self.assertEqual([], queued)
        self.assertEqual(CaseStatus.SKIPPED, campaign.cases[0].status)
        clock.advance(0.25)
        controller.tick()
        self.assertEqual(CampaignStatus.COMPLETED, campaign.status)

    def test_late_send_event_cannot_restart_a_stopped_campaign(self) -> None:
        controller, _clock, queued, _cancelled = self.make_controller()
        campaign = controller.create_campaign("History", "#1", fix_message("D", extra_fields=[("11", b"A")]))
        controller.plan(
            campaign.campaign_id,
            [MutationSpec(MutationKind.EMPTY, "11")],
            case_limit=1,
            interval_seconds=1,
            outcome_window_seconds=1,
        )
        controller.set_connected(True)
        controller.start(campaign.campaign_id)
        controller.tick()
        controller.stop(campaign.campaign_id)
        late = queued[0].snapshot()
        late.status = InjectionStatus.INJECTED
        late.result_record_id = 10

        controller.handle_injection_event(late)

        self.assertEqual(CampaignStatus.STOPPED, campaign.status)
        self.assertEqual(CaseStatus.INTERRUPTED, campaign.cases[0].status)
        with self.assertRaises(RuntimeError):
            controller.start(campaign.campaign_id)

    def test_campaign_state_redacts_secrets_and_does_not_resume_running_work(self) -> None:
        controller, _clock, _queued, _cancelled = self.make_controller()
        baseline = fix_message("D", extra_fields=[("11", b"A"), ("553", b"CAMPAIGN-SECRET")])
        campaign = controller.create_campaign("History", "#1", baseline)
        controller.plan(
            campaign.campaign_id,
            [MutationSpec(MutationKind.EMPTY, "11")],
            case_limit=1,
            interval_seconds=1,
            outcome_window_seconds=1,
        )
        campaign.status = CampaignStatus.RUNNING
        campaign.cases[0].outcome_summary = "553=CAMPAIGN-SECRET"
        policy = SecretRedactionPolicy()

        state = controller.to_state(policy.redact, policy.redact_text)
        serialized = repr(state).encode()
        self.assertNotIn(b"CAMPAIGN-SECRET", serialized)

        restored, _clock2, _queued2, _cancelled2 = self.make_controller()
        restored.restore_state(state)
        loaded = restored.campaign(campaign.campaign_id)
        self.assertEqual(CampaignStatus.PAUSED_USER, loaded.status)
        self.assertIn("<REDACTED>", loaded.cases[0].outcome_summary)
        self.assertIn(b"553=<REDACTED>", loaded.baseline_raw)


if __name__ == "__main__":
    unittest.main()
