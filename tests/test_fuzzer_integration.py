from __future__ import annotations

from datetime import timedelta
import unittest

from fixinspector.fix.dictionary import FixDictionary
from fixinspector.fix.parser import parse_message
from fixinspector.fuzzer import CampaignStatus, FuzzerController, MutationKind, MutationSpec
from fixinspector.transport.connection import ProxyEngine

from tests.fake_session import FakeFixSessionHarness
from tests.support import fix_message, wait_until


class FuzzerInjectionIntegrationTests(unittest.TestCase):
    def test_safe_case_uses_shared_heartbeat_slot_and_preserves_genuine_business(self) -> None:
        records = []
        engine = ProxyEngine(FixDictionary(), records.append, lambda _rid, _status: None, lambda _text: None)
        controller = FuzzerController(
            engine.dictionary,
            engine.queue_injection,
            engine.cancel_injection,
        )
        engine.set_injection_listener(controller.handle_injection_event)
        campaign = controller.create_campaign(
            "History",
            "#1",
            fix_message("D", 1, [("11", b"BASELINE")]),
        )
        controller.plan(
            campaign.campaign_id,
            [MutationSpec(MutationKind.EMPTY, "11")],
            case_limit=1,
            interval_seconds=0.25,
            outcome_window_seconds=0.25,
        )
        controller.set_connected(True)

        with FakeFixSessionHarness(engine) as session:
            controller.start(campaign.campaign_id)
            controller.tick()
            genuine = fix_message("F", 80, [("41", b"GENUINE-CANCEL")])
            heartbeat = fix_message("0", 81)
            session.send_client(genuine + heartbeat)
            received = session.receive_server(2)
            self.assertTrue(wait_until(lambda: campaign.cases[0].sent_at is not None))

        self.assertEqual(genuine, received[0])
        mutated = parse_message(received[1])
        self.assertEqual("D", mutated.msg_type)
        self.assertEqual(b"81", mutated.first("34"))
        self.assertEqual(b"", mutated.first("11"))
        self.assertEqual("FUZZER", records[-1].source)
        self.assertEqual(1, engine.substitution_journal.snapshot().substitution_count)

        controller.tick(campaign.cases[0].sent_at + timedelta(seconds=0.25))
        controller.tick(campaign.cases[0].sent_at + timedelta(seconds=0.5))
        self.assertEqual(CampaignStatus.COMPLETED, campaign.status)


if __name__ == "__main__":
    unittest.main()
