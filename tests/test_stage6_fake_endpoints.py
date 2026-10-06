from __future__ import annotations

from pathlib import Path
import socket
import ssl
import threading
import time
import unittest

from fixinspector.fix.dictionary import FixDictionary
from fixinspector.transport.connection import ProxyConfig, ProxyEngine

from tests.support import fix_message, wait_until


from tests.tls_fixture import localhost_certificate

CERTIFICATE = localhost_certificate()


def _available_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])
    finally:
        probe.close()


class FakeTLSServer:
    def __init__(self, expected_bytes: int, response: bytes) -> None:
        self.expected_bytes = expected_bytes
        self.response = response
        self.received = b""
        self.errors: list[BaseException] = []
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", 0))
        self.port = int(self.socket.getsockname()[1])
        self.socket.listen(1)
        self.socket.settimeout(4)
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def _run(self) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(CERTIFICATE)
        try:
            raw, _address = self.socket.accept()
            with context.wrap_socket(raw, server_side=True) as connection:
                connection.settimeout(4)
                while len(self.received) < self.expected_bytes:
                    chunk = connection.recv(65536)
                    if not chunk:
                        break
                    self.received += chunk
                connection.sendall(self.response[:7])
                connection.sendall(self.response[7:])
                time.sleep(0.05)
        except BaseException as exc:  # noqa: BLE001 - surfaced by the assertion
            self.errors.append(exc)
        finally:
            self.socket.close()


class FullFakeEndpointIntegrationTests(unittest.TestCase):
    def test_real_listener_verified_tls_custom_ca_fragmentation_and_malformed_capture(self) -> None:
        valid = fix_message("D", 11, [("11", b"CLIENT-ORDER")])
        malformed = fix_message("D", 10, [("11", b"MALFORMED")])
        malformed = malformed[:-4] + b"XYZ\x01"
        response = fix_message("8", 20, [("11", b"CLIENT-ORDER"), ("37", b"SERVER-ORDER")])
        server = FakeTLSServer(len(malformed + valid), response)
        server.start()

        records = []
        statuses = []
        engine = ProxyEngine(
            FixDictionary(),
            records.append,
            lambda record_id, status: statuses.append((record_id, status)),
            statuses.append,
        )
        listener_port = _available_port()
        engine.start(
            ProxyConfig(
                listen_host="127.0.0.1",
                listen_port=listener_port,
                upstream_host="127.0.0.1",
                upstream_port=server.port,
                upstream_sni="localhost",
                verify_upstream=True,
                ca_file=str(CERTIFICATE),
            )
        )
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(4)
        try:
            self.assertTrue(wait_until(lambda: engine.diagnostics().listener_state.startswith("Listening")))
            client.connect(("127.0.0.1", listener_port))
            payload = malformed + valid
            client.sendall(payload[:3])
            client.sendall(payload[3:19])
            client.sendall(payload[19:])
            received = b""
            while len(received) < len(response):
                received += client.recv(65536)
            self.assertTrue(wait_until(lambda: len(records) == 3))
        finally:
            client.close()
            engine.stop()
            server.thread.join(timeout=5)

        self.assertFalse(server.thread.is_alive())
        self.assertEqual([], server.errors)
        self.assertEqual(malformed + valid, server.received)
        self.assertEqual(response, received)
        self.assertEqual(malformed, records[0].original_raw)
        self.assertIsNotNone(records[0].framing_error)
        self.assertEqual(["D", "D", "8"], [record.msg_type for record in records])
        snapshot = engine.diagnostics()
        self.assertEqual(3, snapshot.observed_record_count)
        self.assertEqual(1, snapshot.malformed_record_count)
        self.assertIn("custom CA", snapshot.tls_verification)


if __name__ == "__main__":
    unittest.main()
