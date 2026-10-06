from __future__ import annotations

from datetime import datetime, timezone
import unittest

from fixinspector.fix.checksum import checksum_ok
from fixinspector.fix.parser import parse_message
from fixinspector.session.injection import (
    InjectionController,
    InjectionMode,
    InjectionStatus,
    build_safe_injection,
)

from tests.support import body_length_ok, fix_message


FIXED_TIME = datetime(2026, 9, 1, 12, 34, 56, 789000, tzinfo=timezone.utc)


class InjectionControllerTests(unittest.TestCase):
    def test_safe_builder_uses_heartbeat_identity_slot_and_current_time(self) -> None:
        template = fix_message(
            "D",
            4,
            [("11", b"REPLAY-1"), ("58", b"first"), ("58", b"second")],
        )
        heartbeat = fix_message(
            "0",
            77,
            [("50", b"CURRENT-SUB")],
        )
        effective = build_safe_injection(template, heartbeat, at=FIXED_TIME)
        message = parse_message(effective)

        self.assertEqual("D", message.msg_type)
        self.assertEqual(b"77", message.first("34"))
        self.assertEqual(b"CLIENT", message.first("49"))
        self.assertEqual(b"SERVER", message.first("56"))
        self.assertEqual(b"CURRENT-SUB", message.first("50"))
        self.assertEqual(b"20260901-12:34:56.789", message.first("52"))
        self.assertEqual([b"first", b"second"], message.values("58"))
        self.assertTrue(body_length_ok(effective))
        self.assertTrue(checksum_ok(effective))

    def test_only_plain_new_heartbeat_claims_safe_request(self) -> None:
        controller = InjectionController(clock=lambda: FIXED_TIME)
        request = controller.queue(fix_message("D", 1), InjectionMode.BUSINESS_REPLAY)

        self.assertEqual(InjectionStatus.QUEUED, request.status)
        self.assertIsNone(controller.claim_safe_slot(fix_message("D", 8)))
        self.assertIsNone(
            controller.claim_safe_slot(fix_message("0", 9, [("112", b"TEST-REQUEST")]))
        )
        self.assertIsNone(controller.claim_safe_slot(fix_message("0", 9, [("43", b"Y")])))
        claim = controller.claim_safe_slot(fix_message("0", 10))
        self.assertIsNotNone(claim)
        self.assertEqual(10, claim.sequence_number)

    def test_invalid_template_fails_without_wasting_slot_for_next_request(self) -> None:
        controller = InjectionController(clock=lambda: FIXED_TIME)
        first = controller.queue(b"not-fix", InjectionMode.CLONE_EDIT)
        second = controller.queue(fix_message("D", 2), InjectionMode.CLONE_EDIT)

        claim = controller.claim_safe_slot(fix_message("0", 20))

        self.assertEqual(second.injection_id, claim.request.injection_id)
        self.assertEqual(InjectionStatus.FAILED, controller.request(first.injection_id).status)

    def test_cancel_one_owner_does_not_disturb_other_waiting_tools(self) -> None:
        controller = InjectionController(clock=lambda: FIXED_TIME)
        repeater = controller.queue(
            fix_message("D", 1, [("11", b"REPEATER")]),
            InjectionMode.CLONE_EDIT,
            source="REPEATER",
        )
        fuzzer = controller.queue(
            fix_message("D", 1, [("11", b"FUZZER")]),
            InjectionMode.CLONE_EDIT,
            source="FUZZER",
        )

        self.assertTrue(controller.cancel(fuzzer.injection_id))
        self.assertEqual(InjectionStatus.CANCELLED, controller.request(fuzzer.injection_id).status)
        claim = controller.claim_safe_slot(fix_message("0", 21))
        self.assertEqual(repeater.injection_id, claim.request.injection_id)


if __name__ == "__main__":
    unittest.main()
