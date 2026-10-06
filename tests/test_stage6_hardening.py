from __future__ import annotations

import logging
from pathlib import Path
import ssl
import tempfile
import unittest

from fixinspector.app_logging import SecretRedactingFormatter, configure_logging, shutdown_logging
from fixinspector.decoder import OfflineDecoder, normalize_pasted_fix
from fixinspector.fix.checksum import checksum_ok
from fixinspector.fix.dictionary import FixDictionary
from fixinspector.fix.framing import FixFramer
from fixinspector.history import HistoryRetentionPolicy
from fixinspector.project import ProjectDatabase, SecretRedactionPolicy
from fixinspector.records import TrafficRecord
from fixinspector.transport.connection import ProxyConfig
from fixinspector.transport.tls import TLSSettings, build_client_context

from tests.support import fix_message


from tests.tls_fixture import localhost_certificate

CERTIFICATE = localhost_certificate()


class TLSHardeningTests(unittest.TestCase):
    def test_verified_system_trust_is_the_default(self) -> None:
        self.assertTrue(ProxyConfig().verify_upstream)
        settings = TLSSettings()
        context = build_client_context(settings)
        self.assertEqual(ssl.CERT_REQUIRED, context.verify_mode)
        self.assertTrue(context.check_hostname)
        self.assertIn("system trust", settings.verification_label)

    def test_custom_ca_is_loaded_and_reported(self) -> None:
        settings = TLSSettings(True, str(CERTIFICATE))
        context = build_client_context(settings)
        self.assertEqual(ssl.CERT_REQUIRED, context.verify_mode)
        self.assertIn(CERTIFICATE.name, settings.verification_label)

    def test_missing_custom_ca_is_rejected_before_connect(self) -> None:
        with self.assertRaisesRegex(ValueError, "Custom CA file"):
            TLSSettings(True, str(CERTIFICATE.with_name("missing-ca.pem")))

    def test_testing_only_disabled_mode_is_explicit(self) -> None:
        settings = TLSSettings(False)
        context = build_client_context(settings)
        self.assertEqual(ssl.CERT_NONE, context.verify_mode)
        self.assertFalse(context.check_hostname)
        self.assertIn("testing only", settings.verification_label)


class MalformedAndDecoderTests(unittest.TestCase):
    def test_framer_bounds_non_fix_garbage_and_exposes_raw(self) -> None:
        framer = FixFramer(max_buffer_bytes=1024)
        frames = framer.feed_frames(b"x" * 2048)
        self.assertGreaterEqual(len(frames), 1)
        self.assertEqual(b"x" * 2044, frames[0].raw)
        self.assertIn("buffer limit", frames[0].error or "")
        self.assertLessEqual(len(framer.buffer), len(b"8=FIX") - 1)

    def test_decoder_accepts_pipes_log_prefixes_and_multiple_messages(self) -> None:
        first = fix_message("D", 1, [("11", b"A"), ("11", b"B")])
        second = fix_message("8", 2, [("37", b"ORDER")])
        pasted = (
            "2026-09-01 INFO outbound "
            + first.replace(b"\x01", b"|").decode("ascii")
            + "\n2026-09-01 INFO inbound "
            + second.replace(b"\x01", b"|").decode("ascii")
        )
        frames = OfflineDecoder(FixDictionary()).decode_text(pasted)
        self.assertEqual(["D", "8"], [frame.message.msg_type for frame in frames])
        self.assertEqual([b"A", b"B"], frames[0].message.values("11"))

    def test_decoder_retains_malformed_raw_and_can_repair_framing(self) -> None:
        valid = fix_message("D", 3, [("11", b"ABC")])
        malformed = valid[:-4] + b"XYZ\x01"
        frame = OfflineDecoder(FixDictionary()).decode_bytes(malformed)[0]
        self.assertEqual(malformed, frame.raw)
        self.assertIsNotNone(frame.framing_error)
        repaired = OfflineDecoder(FixDictionary()).repair(frame)
        self.assertTrue(checksum_ok(repaired))
        self.assertNotEqual(malformed, repaired)

    def test_decoder_input_normalization_supports_common_soh_forms(self) -> None:
        for delimiter in ("|", "␁", "^A", "<SOH>", "\\x01"):
            self.assertEqual(b"8=FIX.4.4\x0135=0\x01", normalize_pasted_fix(f"8=FIX.4.4{delimiter}35=0{delimiter}"))


class RetentionAndLoggingTests(unittest.TestCase):
    def test_retention_caps_completed_records_but_never_evicts_unresolved(self) -> None:
        records = {
            index: TrafficRecord(
                index,
                "C→S",
                fix_message("D", index),
                status="HELD" if index == 1 else "FORWARDED",
            )
            for index in range(1, 106)
        }
        self.assertEqual((2, 3, 4, 5, 6), HistoryRetentionPolicy(100).eviction_ids(records))

    def test_bounded_load_does_not_truncate_durable_project_on_save(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            path = Path(directory) / "bounded.fixproj"
            with ProjectDatabase(path) as project:
                project.save_records(
                    TrafficRecord(index, "C→S", fix_message("D", index))
                    for index in range(1, 111)
                )
                window = project.load_records(limit=100)
                self.assertEqual((11, 110), (window[0].record_id, window[-1].record_id))
                project.save_records(window)
                self.assertEqual(110, project.record_count())

    def test_log_formatter_redacts_default_additional_and_bytes_repr(self) -> None:
        formatter = SecretRedactingFormatter(SecretRedactionPolicy(frozenset({"553", "925"})))
        record = logging.LogRecord(
            "fixinspector.test",
            logging.WARNING,
            __file__,
            1,
            "raw=%r note=%s",
            (b"8=FIX.4.4\x01553=wire-secret\x01925=pin\x01", "553=text-secret|"),
            None,
        )
        rendered = formatter.format(record)
        self.assertNotIn("wire-secret", rendered)
        self.assertNotIn("text-secret", rendered)
        self.assertNotIn("pin", rendered)
        self.assertIn("553=<REDACTED>", rendered)
        self.assertIn("925=<REDACTED>", rendered)

    def test_rotating_log_is_local_and_redacted(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            path = Path(directory) / "app.log"
            try:
                configure_logging(SecretRedactionPolicy(), path=path)
                logger = logging.getLogger("fixinspector.stage6")
                logger.warning("diagnostic %s", "553=never-store-this|")
                for handler in logging.getLogger("fixinspector").handlers:
                    handler.flush()
                payload = path.read_text(encoding="utf-8")
                self.assertNotIn("never-store-this", payload)
                self.assertIn("553=<REDACTED>", payload)
            finally:
                shutdown_logging()


if __name__ == "__main__":
    unittest.main()
