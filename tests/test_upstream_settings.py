from __future__ import annotations

from contextlib import ExitStack
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


@unittest.skipUnless(importlib.util.find_spec("PySide6"), "PySide6 is not installed")
class UpstreamSettingsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtWidgets import QApplication

        cls.application = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from PySide6.QtCore import QSettings
        from fixinspector.gui import main_window

        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.directory = Path(
            self.stack.enter_context(tempfile.TemporaryDirectory(dir=Path.cwd()))
        )
        self.settings_path = self.directory / "fix_inspector.ini"
        self.main_window = main_window
        self.settings = lambda: QSettings(str(self.settings_path), QSettings.Format.IniFormat)
        self.stack.enter_context(
            patch.object(
                main_window._v03_gui.QStandardPaths,
                "writableLocation",
                return_value=str(self.directory),
            )
        )
        self.stack.enter_context(
            patch.object(main_window.MainWindow, "_settings", lambda _window: self.settings())
        )
        self.stack.enter_context(patch.object(main_window, "configure_logging", return_value=None))
        self.stack.enter_context(patch.object(main_window, "current_log_path", return_value=None))
        self.windows = []
        self.addCleanup(self._close_windows)

    def _close_windows(self) -> None:
        for window in reversed(self.windows):
            window.close()
            window.deleteLater()
        self.application.processEvents()

    def _window(self):
        window = self.main_window.MainWindow()
        self.windows.append(window)
        return window

    def _save_initial_settings(self, values: dict[str, object]) -> None:
        settings = self.settings()
        for name, value in values.items():
            settings.setValue(name, value)
        settings.sync()

    def _select_transport(self, window, transport: str) -> None:
        index = window.upstream_transport.findData(transport)
        self.assertGreaterEqual(index, 0, transport)
        window.upstream_transport.setCurrentIndex(index)
        self.application.processEvents()

    @staticmethod
    def _valid_endpoints(window) -> None:
        window.listen_host.setText("127.0.0.1")
        window.listen_port.setText("4582")
        window.upstream_host.setText("fix.example.invalid")
        window.upstream_port.setText("4581")

    def test_empty_settings_default_to_verified_tls_and_required_group_labels(self) -> None:
        from PySide6.QtWidgets import QGroupBox

        window = self._window()
        self.assertEqual("tls", window.upstream_transport.currentData())
        self.assertTrue(window.verify_tls.isChecked())
        self.assertEqual(
            {"plain_tcp", "tls"},
            {
                window.upstream_transport.itemData(index)
                for index in range(window.upstream_transport.count())
            },
        )
        titles = {group.title() for group in window.findChildren(QGroupBox)}
        self.assertTrue(
            {
                "Proxy endpoints",
                "FIX dictionaries",
                "Interception and session controls",
                "History and secrets",
            }.issubset(titles),
            titles,
        )

    def test_legacy_settings_keep_tls_and_saved_verification_disabled(self) -> None:
        self._save_initial_settings(
            {
                "proxy/upstream_host": "legacy.example.invalid",
                "proxy/upstream_sni": "saved.example.invalid",
                "proxy/verify_tls": False,
                "proxy/ca_file": "saved-ca.pem",
            }
        )
        window = self._window()
        self.assertEqual("tls", window.upstream_transport.currentData())
        self.assertFalse(window.verify_tls.isChecked())
        self.assertEqual("saved.example.invalid", window.upstream_sni.text())
        self.assertEqual("saved-ca.pem", window.ca_file.text())
        self.assertIn("DISABLED", window.tls_warning.text())

    def test_tcp_disables_tls_controls_and_preserves_values_when_switched_back(self) -> None:
        window = self._window()
        window.upstream_sni.setText("tls.example.invalid")
        window.verify_tls.setChecked(False)
        window.ca_file.setText(str(self.directory / "saved-ca.pem"))
        controls = (window.upstream_sni, window.verify_tls, window.ca_file, window.ca_browse)

        self._select_transport(window, "plain_tcp")
        self.assertTrue(all(not control.isEnabled() for control in controls))
        self.assertEqual("tls.example.invalid", window.upstream_sni.text())
        self.assertFalse(window.verify_tls.isChecked())
        self.assertEqual(str(self.directory / "saved-ca.pem"), window.ca_file.text())
        self.assertNotIn("verification is DISABLED", window.tls_warning.text())

        self._select_transport(window, "tls")
        self.assertTrue(all(control.isEnabled() for control in controls))
        self.assertEqual("tls.example.invalid", window.upstream_sni.text())
        self.assertFalse(window.verify_tls.isChecked())
        self.assertEqual(str(self.directory / "saved-ca.pem"), window.ca_file.text())
        self.assertIn("DISABLED", window.tls_warning.text())

    def test_running_panel_restores_transport_specific_control_enablement(self) -> None:
        window = self._window()
        self._select_transport(window, "plain_tcp")
        window.proxy_endpoints.set_running(True)
        self.assertFalse(window.upstream_transport.isEnabled())
        self.assertFalse(window.upstream_host.isEnabled())
        self.assertFalse(window.ca_browse.isEnabled())
        window.proxy_endpoints.set_running(False)
        self.assertTrue(window.upstream_transport.isEnabled())
        self.assertTrue(window.upstream_host.isEnabled())
        self.assertFalse(window.ca_browse.isEnabled())
        self._select_transport(window, "tls")
        self.assertTrue(window.ca_browse.isEnabled())

    def test_route_tracks_endpoint_edits_and_transport(self) -> None:
        window = self._window()
        self._valid_endpoints(window)
        self.application.processEvents()
        tls_route = window.route_summary.text()
        self.assertIn("127.0.0.1:4582", tls_route)
        self.assertIn("fix.example.invalid:4581", tls_route)
        self.assertIn("TLS", tls_route)

        self._select_transport(window, "plain_tcp")
        tcp_route = window.route_summary.text()
        self.assertNotEqual(tls_route, tcp_route)
        self.assertIn("TCP", tcp_route)
        self.assertNotIn("TLS", tcp_route)
        window.upstream_host.setText("changed.example.invalid")
        window.upstream_port.setText("5001")
        window.listen_port.setText("5000")
        self.application.processEvents()
        self.assertIn("127.0.0.1:5000", window.route_summary.text())
        self.assertIn("changed.example.invalid:5001", window.route_summary.text())

    def test_settings_round_trip_keeps_tcp_and_disabled_tls_values(self) -> None:
        window = self._window()
        self._valid_endpoints(window)
        window.upstream_sni.setText("retained.example.invalid")
        window.verify_tls.setChecked(False)
        ca_file = str(self.directory / "retained-ca.pem")
        window.ca_file.setText(ca_file)
        self._select_transport(window, "plain_tcp")
        window._save_settings()

        persisted = self.settings()
        persisted.sync()
        self.assertEqual("plain_tcp", persisted.value("proxy/upstream_transport"))
        self.assertEqual("retained.example.invalid", persisted.value("proxy/upstream_sni"))
        self.assertEqual(ca_file, persisted.value("proxy/ca_file"))
        restored = self._window()
        self.assertEqual("plain_tcp", restored.upstream_transport.currentData())
        self.assertFalse(restored.verify_tls.isChecked())
        self.assertEqual("retained.example.invalid", restored.upstream_sni.text())
        self.assertEqual(ca_file, restored.ca_file.text())
        self.assertFalse(restored.ca_browse.isEnabled())

    def test_plain_start_ignores_tls_ca_and_needs_no_dictionaries_or_tls_prompt(self) -> None:
        window = self._window()
        self._valid_endpoints(window)
        self._select_transport(window, "plain_tcp")
        window.transport_dict.clear()
        window.app_dict.clear()
        window.ca_file.setText(str(self.directory / "missing-ca.pem"))
        for verify in (True, False):
            with self.subTest(verify=verify):
                window.verify_tls.setChecked(verify)
                with (
                    patch.object(window.engine, "start") as start,
                    patch.object(self.main_window.QMessageBox, "critical") as critical,
                    patch.object(self.main_window.QMessageBox, "warning") as warning,
                ):
                    window._start_proxy()
                    start.assert_called_once()
                    config = start.call_args.args[0]
                    self.assertEqual("plain_tcp", config.upstream_transport)
                    self.assertEqual(verify, config.verify_upstream)
                    self.assertEqual(str(self.directory / "missing-ca.pem"), config.ca_file)
                    critical.assert_not_called()
                    warning.assert_not_called()
                window._set_proxy_running(False)

    def test_invalid_endpoints_are_rejected_before_proxy_start(self) -> None:
        window = self._window()
        self._select_transport(window, "plain_tcp")
        cases = (
            ("listen_host", ""),
            ("upstream_host", ""),
            ("upstream_host", "bad host"),
            ("listen_port", ""),
            ("listen_port", "not-a-port"),
            ("listen_port", "0"),
            ("upstream_port", "65536"),
        )
        for attribute, value in cases:
            with self.subTest(attribute=attribute, value=value):
                self._valid_endpoints(window)
                getattr(window, attribute).setText(value)
                with (
                    patch.object(window.engine, "start") as start,
                    patch.object(self.main_window.QMessageBox, "critical") as critical,
                ):
                    window._start_proxy()
                    start.assert_not_called()
                    critical.assert_called_once()

    def test_tls_keeps_ca_validation_and_explicit_unverified_confirmation(self) -> None:
        window = self._window()
        self._valid_endpoints(window)
        self._select_transport(window, "tls")
        window.verify_tls.setChecked(True)
        window.ca_file.setText(str(self.directory / "missing-ca.pem"))
        with (
            patch.object(window.engine, "start") as start,
            patch.object(self.main_window.QMessageBox, "critical") as critical,
            patch.object(self.main_window.QMessageBox, "warning") as warning,
        ):
            window._start_proxy()
            start.assert_not_called()
            critical.assert_called_once()
            warning.assert_not_called()

        window.verify_tls.setChecked(False)
        with (
            patch.object(window.engine, "start") as start,
            patch.object(self.main_window.QMessageBox, "critical") as critical,
        ):
            window._start_proxy()
            start.assert_not_called()
            critical.assert_called_once()
        window.ca_file.clear()
        buttons = self.main_window.QMessageBox.StandardButton
        for answer in (buttons.Cancel, buttons.Yes):
            with self.subTest(answer=answer):
                with (
                    patch.object(window.engine, "start") as start,
                    patch.object(self.main_window.QMessageBox, "critical") as critical,
                    patch.object(self.main_window.QMessageBox, "warning", return_value=answer) as warning,
                ):
                    window._start_proxy()
                    warning.assert_called_once()
                    critical.assert_not_called()
                    if answer == buttons.Yes:
                        start.assert_called_once()
                        self.assertEqual("tls", start.call_args.args[0].upstream_transport)
                    else:
                        start.assert_not_called()

    def test_repeater_receives_same_transport_settings_without_opening_a_socket(self) -> None:
        from fixinspector.session.injection import AutoUpdatePolicy
        from tests.support import fix_message

        window = self._window()
        self._valid_endpoints(window)
        window.upstream_sni.setText("retained.example.invalid")
        raw = fix_message("A", 1)
        manual = AutoUpdatePolicy(False, False, False, False)
        for transport in ("plain_tcp", "tls"):
            with self.subTest(transport=transport):
                self._select_transport(window, transport)
                expected = window._current_proxy_config()
                with patch.object(self.main_window, "IsolatedRepeaterConnection") as connection:
                    connection.return_value.running = False
                    window._send_repeater_new_connection(transport, raw, manual)
                    connection.assert_called_once()
                    actual = connection.call_args.args[0]
                    self.assertEqual(expected, actual)
                    self.assertEqual(transport, actual.upstream_transport)
                    connection.return_value.send_logon.assert_called_once_with(raw)


if __name__ == "__main__":
    unittest.main()
