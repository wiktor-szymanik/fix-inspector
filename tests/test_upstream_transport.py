from __future__ import annotations

from pathlib import Path
import socket
import ssl
import threading
import unittest
from unittest.mock import Mock, patch

from fixinspector.fix.dictionary import FixDictionary
from fixinspector.transport.connection import ProxyConfig, ProxyEngine
from fixinspector.transport.tls import TLSSettings
from fixinspector.transport.upstream import PLAIN_TCP_VERIFICATION, connect_upstream

from tests.support import fix_message, wait_until


MISSING_CA = str(Path(__file__).parent / "fixtures" / "missing-transport-ca.pem")


def _engine(records=None, statuses=None) -> ProxyEngine:
    return ProxyEngine(
        FixDictionary(),
        (records if records is not None else []).append,
        lambda _record_id, _status: None,
        (statuses if statuses is not None else []).append,
    )


def _available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class UpstreamConnectorTests(unittest.TestCase):
    def test_plain_tcp_does_not_build_or_read_tls_settings(self) -> None:
        raw = Mock(spec=socket.socket)
        for settings in (None, object()):
            with self.subTest(settings=settings), patch(
                "fixinspector.transport.upstream.socket.create_connection", return_value=raw
            ) as create, patch(
                "fixinspector.transport.upstream.build_client_context"
            ) as context:
                connected, negotiated = connect_upstream(
                    "127.0.0.1", 4581, "ignored.example.test", settings, 2.5,
                    transport="plain_tcp",
                )
                self.assertIs(raw, connected)
                self.assertEqual(PLAIN_TCP_VERIFICATION, negotiated.verification)
                self.assertEqual(("", ""), (negotiated.version, negotiated.cipher))
                create.assert_called_once_with(("127.0.0.1", 4581), timeout=2.5)
                raw.settimeout.assert_called_with(0.1)
                context.assert_not_called()

    def test_tls_default_preserves_sni_verification_and_metadata(self) -> None:
        for verify, sni, expected_hostname in (
            (True, "", "127.0.0.1"),
            (True, "localhost", "localhost"),
            (False, "", None),
            (False, "localhost", "localhost"),
        ):
            with self.subTest(verify=verify, sni=sni):
                raw = Mock(spec=socket.socket)
                wrapped = Mock(spec=ssl.SSLSocket)
                wrapped.version.return_value = "TLSv1.3"
                wrapped.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
                settings = TLSSettings(verify=verify)
                with patch(
                    "fixinspector.transport.upstream.socket.create_connection", return_value=raw
                ) as create, patch(
                    "fixinspector.transport.upstream.build_client_context"
                ) as build:
                    build.return_value.wrap_socket.return_value = wrapped
                    connected, negotiated = connect_upstream("127.0.0.1", 4581, sni, settings)
                    self.assertIs(wrapped, connected)
                    build.assert_called_once_with(settings)
                    create.assert_called_once_with(("127.0.0.1", 4581), timeout=10.0)
                    build.return_value.wrap_socket.assert_called_once_with(
                        raw, server_hostname=expected_hostname
                    )
                    self.assertEqual(settings.verification_label, negotiated.verification)
                    self.assertEqual("TLSv1.3", negotiated.version)
                    self.assertEqual("TLS_AES_256_GCM_SHA384", negotiated.cipher)

    def test_failed_tls_handshake_closes_socket_without_plaintext_fallback(self) -> None:
        raw = Mock(spec=socket.socket)
        with patch(
            "fixinspector.transport.upstream.socket.create_connection", return_value=raw
        ) as create, patch("fixinspector.transport.upstream.build_client_context") as build:
            build.return_value.wrap_socket.side_effect = ssl.SSLError("local handshake failed")
            with self.assertRaises(ssl.SSLError):
                connect_upstream("127.0.0.1", 4581, "localhost", TLSSettings())
            raw.close.assert_called_once_with()
            create.assert_called_once()

    def test_invalid_transport_and_missing_tls_settings_fail_before_socket_creation(self) -> None:
        with patch("fixinspector.transport.upstream.socket.create_connection") as create:
            with self.assertRaisesRegex(ValueError, "Upstream transport"):
                connect_upstream("127.0.0.1", 4581, "", None, transport="unknown")
            with self.assertRaisesRegex(ValueError, "TLS settings are required"):
                connect_upstream("127.0.0.1", 4581, "", None)
            create.assert_not_called()


class ProxyTransportConfigTests(unittest.TestCase):
    def test_defaults_and_existing_positional_arguments_keep_tls(self) -> None:
        self.assertEqual("tls", ProxyConfig().upstream_transport)
        config = ProxyConfig("127.0.0.1", 1234, "localhost", 5678, "localhost", False, "", False)
        self.assertEqual("tls", config.upstream_transport)
        self.assertFalse(config.verify_upstream)
        self.assertFalse(config.tls13_only)

    def test_plain_config_start_and_preview_never_construct_tls_settings(self) -> None:
        with patch("fixinspector.transport.connection.TLSSettings") as tls_settings, patch(
            "fixinspector.transport.connection.threading.Thread"
        ) as thread:
            engine = _engine()
            config = ProxyConfig(
                upstream_host="127.0.0.1", upstream_transport="plain_tcp", ca_file=MISSING_CA
            )
            engine.set_tls_preview(True, MISSING_CA, transport="plain_tcp")
            engine.start(config)
            tls_settings.assert_not_called()
            thread.return_value.start.assert_called_once_with()
            self.assertEqual(PLAIN_TCP_VERIFICATION, engine.diagnostics().tls_verification)

    def test_tls_configuration_still_rejects_nonexistent_ca(self) -> None:
        with self.assertRaisesRegex(ValueError, "Custom CA file"):
            ProxyConfig(upstream_host="127.0.0.1", ca_file=MISSING_CA)

    def test_plain_preview_clears_stale_tls_protocol_and_cipher(self) -> None:
        engine = _engine()
        engine._tls_version = "TLSv1.3"
        engine._tls_cipher = "TLS_AES_256_GCM_SHA384"
        engine.set_tls_preview(True, MISSING_CA, transport="plain_tcp")
        snapshot = engine.diagnostics()
        self.assertEqual(PLAIN_TCP_VERIFICATION, snapshot.tls_verification)
        self.assertEqual(("", ""), (snapshot.tls_version, snapshot.tls_cipher))
        engine.set_tls_preview(True)
        self.assertEqual("Verified (system trust)", engine.diagnostics().tls_verification)

    def test_invalid_hosts_ports_and_transport_are_rechecked_before_start(self) -> None:
        cases = (
            ("upstream_host", "", "Upstream host is required"),
            ("upstream_host", " \t", "Upstream host is required"),
            ("listen_host", "", "Listener host is required"),
            ("upstream_host", "local host", "whitespace"),
            ("listen_port", 0, "Listener port"),
            ("upstream_port", 65536, "Upstream port"),
            ("upstream_port", None, "Upstream port"),
            ("upstream_port", 12.5, "Upstream port"),
            ("upstream_port", True, "Upstream port"),
            ("upstream_transport", "unknown", "Upstream transport"),
        )
        for field, value, message in cases:
            with self.subTest(field=field, value=value):
                config = ProxyConfig(upstream_host="127.0.0.1")
                setattr(config, field, value)
                engine = _engine()
                with patch("fixinspector.transport.connection.threading.Thread") as thread:
                    with self.assertRaisesRegex(ValueError, message):
                        engine.start(config)
                    thread.assert_not_called()
                    self.assertFalse(engine.running)

    def test_unknown_transport_is_rejected_at_configuration(self) -> None:
        with self.assertRaisesRegex(ValueError, "Upstream transport"):
            ProxyConfig(upstream_transport="automatic")


class _PlainServer:
    """A loopback-only endpoint; accepts no FIX operations beyond byte echoing."""

    def __init__(self, expected_bytes: int, response: bytes) -> None:
        self.expected_bytes = expected_bytes
        self.response = response
        self.received = b""
        self.errors: list[Exception] = []
        self.release = threading.Event()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(("127.0.0.1", 0))
        self.port = int(self.socket.getsockname()[1])
        self.socket.settimeout(4)
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self.socket.listen(1)
        self.thread.start()

    def _run(self) -> None:
        try:
            connection, _address = self.socket.accept()
            with connection:
                connection.settimeout(4)
                while len(self.received) < self.expected_bytes:
                    chunk = connection.recv(65536)
                    if not chunk:
                        break
                    self.received += chunk
                connection.sendall(self.response[:7])
                connection.sendall(self.response[7:])
                self.release.wait(4)
        except Exception as exc:
            self.errors.append(exc)
        finally:
            self.socket.close()

    def close(self) -> None:
        self.release.set()
        self.socket.close()
        if self.thread.ident is not None:
            self.thread.join(timeout=5)


class PlainTransportIntegrationTests(unittest.TestCase):
    def _stop(self, engine: ProxyEngine) -> None:
        engine.stop()
        if engine._accept_thread is not None:
            engine._accept_thread.join(timeout=3)
        self.assertFalse(engine.running)

    def test_plain_proxy_bidirectional_framing_and_restart(self) -> None:
        records = []
        statuses = []
        engine = _engine(records, statuses)
        listener_port = _available_port()
        for attempt in range(2):
            request = fix_message("0", 1) + fix_message("0", 2)
            response = fix_message("0", 3)
            server = _PlainServer(len(request), response)
            server.start()
            try:
                engine.start(ProxyConfig(
                    listen_port=listener_port, upstream_host="127.0.0.1",
                    upstream_port=server.port, upstream_transport="plain_tcp", ca_file=MISSING_CA,
                ))
                self.assertTrue(wait_until(
                    lambda: engine.diagnostics().listener_state.startswith("Listening"), timeout=3
                ))
                with socket.create_connection(("127.0.0.1", listener_port), timeout=3) as client:
                    client.sendall(request[:3])
                    client.sendall(request[3:19])
                    client.sendall(request[19:])
                    received = b""
                    while len(received) < len(response):
                        chunk = client.recv(65536)
                        if not chunk:
                            break
                        received += chunk
                    self.assertEqual(response, received)
                    self.assertTrue(wait_until(lambda: len(records) == 3 * (attempt + 1)))
                    snapshot = engine.diagnostics()
                    self.assertTrue(snapshot.upstream_state.startswith("Connected "))
                    self.assertEqual(PLAIN_TCP_VERIFICATION, snapshot.tls_verification)
                    self.assertEqual(("", ""), (snapshot.tls_version, snapshot.tls_cipher))
                    self.assertEqual(request, server.received)
            finally:
                self._stop(engine)
                server.close()
            self.assertFalse(server.thread.is_alive())
            self.assertEqual([], server.errors)
        self.assertEqual(["C→S", "C→S", "S→C"] * 2, [record.direction for record in records])
        self.assertTrue(any("Plain TCP connected" in status for status in statuses))

    def test_refused_plain_connection_is_fail_soft_and_next_client_can_connect(self) -> None:
        request = fix_message("0", 1)
        server = _PlainServer(len(request), request)
        statuses = []
        engine = _engine(statuses=statuses)
        listener_port = _available_port()
        try:
            engine.start(ProxyConfig(
                listen_port=listener_port, upstream_host="127.0.0.1",
                upstream_port=server.port, upstream_transport="plain_tcp",
            ))
            self.assertTrue(wait_until(
                lambda: engine.diagnostics().listener_state.startswith("Listening"), timeout=3
            ))
            with socket.create_connection(("127.0.0.1", listener_port), timeout=3) as client:
                self.assertEqual(b"", client.recv(1024))
            self.assertTrue(wait_until(lambda: any(
                status.startswith("Connection error: Plain TCP:") for status in statuses
            )))
            self.assertTrue(engine.running)
            self.assertTrue(engine.diagnostics().last_transport_error)
            server.start()
            with socket.create_connection(("127.0.0.1", listener_port), timeout=3) as client:
                client.sendall(request)
                received = b""
                while len(received) < len(request):
                    chunk = client.recv(65536)
                    if not chunk:
                        break
                    received += chunk
                self.assertEqual(request, received)
        finally:
            self._stop(engine)
            server.close()
        self.assertEqual([], server.errors)


if __name__ == "__main__":
    unittest.main()
