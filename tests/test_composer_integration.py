from __future__ import annotations

import unittest

from fixinspector.composer import ComposerController
from fixinspector.fix.dictionary import FixDictionary
from fixinspector.fix.parser import parse_message
from fixinspector.session.injection import InjectionStatus
from fixinspector.transport.connection import ProxyEngine

from tests.fake_session import FakeFixSessionHarness
from tests.support import fix_message, wait_until


class ComposerInjectionIntegrationTests(unittest.TestCase):
    def test_composer_uses_same_safe_slot_controller_and_never_replaces_business(self) -> None:
        records = []
        engine = ProxyEngine(FixDictionary(), records.append, lambda _rid, _status: None, lambda _text: None)
        controller = ComposerController(engine.dictionary, engine.queue_injection)
        engine.set_injection_listener(controller.handle_injection_event)
        template = fix_message("D", 1, [("11", b"COMPOSED-1"), ("55", b"TEST")])

        with FakeFixSessionHarness(engine) as session:
            request = controller.queue(template)
            genuine = fix_message("F", 70, [("41", b"GENUINE")])
            heartbeat = fix_message("0", 71)
            session.send_client(genuine + heartbeat)
            received = session.receive_server(2)

        self.assertEqual(genuine, received[0])
        effective = parse_message(received[1])
        self.assertEqual("D", effective.msg_type)
        self.assertEqual(b"71", effective.first("34"))
        self.assertEqual(b"COMPOSED-1", effective.first("11"))
        self.assertTrue(wait_until(lambda: controller.requests()[-1].status is InjectionStatus.INJECTED))
        self.assertEqual(request.injection_id, controller.requests()[-1].injection_id)
        self.assertEqual("COMPOSER", records[-1].source)
        self.assertEqual(1, engine.substitution_journal.snapshot().substitution_count)


if __name__ == "__main__":
    unittest.main()
