"""Cosmetic resource resolution and stable persisted status identifiers."""

from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from fixinspector.app_resources import application_icon_path
from fixinspector.presentation import display_status


class ApplicationResourceTests(unittest.TestCase):
    def test_source_resource_is_anchored_to_module_not_working_directory(self):
        expected = Path(__file__).resolve().parents[1] / "resources/app.ico"
        with patch("pathlib.Path.cwd", return_value=Path("unrelated-working-directory")):
            self.assertEqual(expected, application_icon_path())
            self.assertTrue(application_icon_path().is_file())

    def test_frozen_resource_uses_pyinstaller_resource_root(self):
        root = Path("frozen-bundle") / "_internal"
        with patch.object(sys, "frozen", True, create=True), patch.object(sys, "_MEIPASS", str(root), create=True):
            self.assertEqual(root / "resources/app.ico", application_icon_path())

    def test_display_labels_do_not_change_serialized_statuses(self):
        from fixinspector.fuzzer.campaign import CampaignStatus, CaseStatus
        from fixinspector.session.injection import InjectionStatus

        legacy = {
            CampaignStatus.PAUSED_DISCONNECTED: "Paused \u2014 upstream disconnected",
            CaseStatus.SKIPPED: "Skipped \u2014 destructive opt-in disabled",
            InjectionStatus.QUEUED: "Queued \u2014 waiting for safe active-session slot",
            InjectionStatus.RAW_QUEUED: "Queued \u2014 session-destructive exact raw replay",
            InjectionStatus.RAW_REPLAYED: "Exact raw replay sent \u2014 session-destructive",
            InjectionStatus.CANCELLED: "Cancelled \u2014 active session disconnected",
        }
        for status, saved_value in legacy.items():
            self.assertEqual(saved_value, status.value)
            self.assertIs(status, type(status)(saved_value))
            self.assertEqual(saved_value.replace("\u2014", "-"), display_status(status.value))
