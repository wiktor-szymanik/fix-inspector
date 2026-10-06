from __future__ import annotations

import unittest

from fixinspector.fix.checksum import checksum_ok
from fixinspector.fix.parser import parse_message
from fixinspector.project.redaction import DEFAULT_SECRET_TAGS, redact_sensitive

from tests.support import fix_message


class SecretHandlingBaselineTests(unittest.TestCase):
    def test_tag_553_is_a_default_secret(self) -> None:
        self.assertEqual(frozenset({"553"}), DEFAULT_SECRET_TAGS)

    def test_redacts_every_duplicate_tag_553_and_repairs_valid_framing(self) -> None:
        raw = fix_message(
            msg_type="A",
            extra_fields=[("553", b"primary-secret"), ("553", b"secondary-secret")],
        )

        redacted = redact_sensitive(raw)

        self.assertNotIn(b"primary-secret", redacted)
        self.assertNotIn(b"secondary-secret", redacted)
        self.assertEqual([b"<REDACTED>", b"<REDACTED>"], parse_message(redacted).values("553"))
        self.assertTrue(checksum_ok(redacted))

    def test_fallback_redacts_tag_553_in_malformed_raw_message(self) -> None:
        malformed = b"35=A\x01553=do-not-log-this\x0158=truncated"

        redacted = redact_sensitive(malformed)

        self.assertEqual(b"35=A\x01553=<REDACTED>\x0158=truncated", redacted)
        self.assertNotIn(b"do-not-log-this", redacted)

    def test_raw_without_secret_is_returned_byte_exact_even_if_framing_is_invalid(self) -> None:
        raw = b"8=FIXT.1.1\x019=999\x0135=D\x0158=duplicate\x0158=duplicate\x0110=000\x01"
        self.assertEqual(raw, redact_sensitive(raw))

    def test_redaction_keeps_duplicate_non_secret_fields_in_wire_order(self) -> None:
        raw = fix_message(
            msg_type="A",
            extra_fields=[("58", b"first"), ("553", b"secret"), ("58", b"second")],
        )
        redacted = redact_sensitive(raw)
        message = parse_message(redacted)
        self.assertEqual([b"first", b"second"], message.values("58"))
        self.assertEqual(
            ["8", "9", "35", "34", "49", "56", "52", "58", "553", "58", "10"],
            [field.tag for field in message.fields],
        )


if __name__ == "__main__":
    unittest.main()
