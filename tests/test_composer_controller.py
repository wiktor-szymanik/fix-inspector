from __future__ import annotations

import base64
from datetime import datetime, timezone
import unittest

from fixinspector.composer import ComposerController
from fixinspector.fix.dictionary import FixDictionary
from fixinspector.project.redaction import SecretRedactionPolicy
from fixinspector.session.injection import InjectionMode, InjectionRequest, InjectionStatus

from tests.support import fix_message


class ComposerControllerTests(unittest.TestCase):
    def test_templates_round_trip_with_tag_553_redacted_at_project_boundary(self) -> None:
        queued = []

        def sender(raw, mode, **values):
            queued.append((raw, mode, values))
            return InjectionRequest(
                1,
                InjectionMode.CLONE_EDIT,
                raw,
                values["source"],
                values["repeater_item_id"],
                None,
                datetime.now(timezone.utc),
                InjectionStatus.QUEUED,
            )

        controller = ComposerController(FixDictionary(), sender)
        raw = fix_message("D", extra_fields=[("11", b"C-1"), ("553", b"TOP-SECRET")])
        saved = controller.save_template("Attack template", "D", raw)
        state = controller.to_state(lambda value: SecretRedactionPolicy().redact(value))

        persisted_raw = base64.b64decode(state["templates"][0]["raw"])
        self.assertNotIn(b"TOP-SECRET", persisted_raw)
        self.assertIn(b"553=<REDACTED>", persisted_raw)

        restored = ComposerController(FixDictionary(), sender)
        restored.restore_state(state)
        self.assertEqual(saved.name, restored.template(saved.template_id).name)
        self.assertEqual(persisted_raw, restored.template(saved.template_id).raw)

    def test_template_name_is_text_redacted_at_project_boundary(self) -> None:
        controller = ComposerController(FixDictionary(), lambda *_args, **_values: None)
        controller.save_template("Credential 553=name-secret", "D", fix_message("D"))
        policy = SecretRedactionPolicy()

        state = controller.to_state(policy.redact, policy.redact_text)

        self.assertEqual("Credential 553=<REDACTED>", state["templates"][0]["name"])

    def test_composer_queues_only_through_supplied_shared_controller(self) -> None:
        calls = []

        def sender(raw, mode, **values):
            calls.append((raw, mode, values))
            return InjectionRequest(
                7,
                InjectionMode.CLONE_EDIT,
                raw,
                values["source"],
                values["repeater_item_id"],
                None,
                datetime.now(timezone.utc),
                InjectionStatus.QUEUED,
            )

        controller = ComposerController(FixDictionary(), sender)
        raw = fix_message("D", extra_fields=[("11", b"C-2")])

        request = controller.queue(raw, template_id="C1")

        self.assertEqual(1, len(calls))
        self.assertIs(InjectionMode.CLONE_EDIT, calls[0][1])
        self.assertEqual("COMPOSER", calls[0][2]["source"])
        self.assertEqual(InjectionStatus.QUEUED, request.status)


if __name__ == "__main__":
    unittest.main()
