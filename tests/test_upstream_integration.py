"""Real loopback transport checks; no external FIX endpoint or XML dictionary."""

from __future__ import annotations

from pathlib import Path
import socket
import ssl
import threading
import unittest

from fixinspector.fix.dictionary import FixDictionary
from fixinspector.fix.fields import FixField
from fixinspector.fix.serializer import serialize_structured
from fixinspector.transport.connection import ProxyConfig, ProxyDiagnostics, ProxyEngine

from tests.support import fix_message, wait_until


from tests.tls_fixture import localhost_certificate

CERTIFICATE = localhost_certificate()
SOCKET_TIMEOUT = 4.0


def _available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _server_message(
    msg_type: str, seq_num: int, extra_fields: list[tuple[str, bytes]]
) -> bytes:
    return serialize_structured(
        [
            FixField("8", b"FIXT.1.1"),
            FixField("9", b"0"),
            FixField("35", msg_type.encode("ascii")),
            FixField("34", str(seq_num).encode("ascii")),
            FixField("49", b"SERVER"),
            FixField("56", b"CLIENT"),
            FixField("52", b"20260901-10:00:00.000"),
            *(FixField(tag, value) for tag, value in extra_fields),
            FixField("10", b"000"),
        ]
    )


def _exchanges() -> list[tuple[bytes, bytes]]:
    logon_fields = [("98", b"0"), ("108", b"30"), ("1137", b"9")]
    order_fields = [
        ("11", b"LOOPBACK-ORDER"),
        ("21", b"1"),
        ("55", b"TEST"),
        ("54", b"1"),
        ("60", b"20260901-10:00:00.000"),
        ("40", b"2"),
        ("38", b"1"),
        ("44", b"1"),
    ]
    report_fields = [
        ("11", b"LOOPBACK-ORDER"),
        ("37", b"LOOPBACK-SERVER-ORDER"),
        ("17", b"LOOPBACK-EXECUTION"),
        ("150", b"0"),
        ("39", b"0"),
        ("55", b"TEST"),
        ("54", b"1"),
        ("151", b"1"),
        ("14", b"0"),
        ("6", b"0"),
    ]
    return [
        (fix_message("A", 1, logon_fields), _server_message("A", 1, logon_fields)),
        (fix_message("D", 2, order_fields), _server_message("8", 2, report_fields)),
    ]


class _LoopbackPeer:
    """One local connection with bounded reads and explicit cleanup."""

    def __init__(self, transport: str, exchanges: list[tuple[bytes, bytes]]) -> None:
        self.exchanges = exchanges
        self.received = b""
        self.errors: list[Exception] = []
        self.finished = threading.Event()
        self._stop = threading.Event()
        self._connection: socket.socket | None = None
        self._context: ssl.SSLContext | None = None
        if transport == "tls":
            self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self._context.minimum_version = ssl.TLSVersion.TLSv1_3
            self._context.maximum_version = ssl.TLSVersion.TLSv1_3
            self._context.load_cert_chain(CERTIFICATE)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.port = int(self.listener.getsockname()[1])
        self.listener.listen(1)
        self.listener.settimeout(SOCKET_TIMEOUT)
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self._stop.set()
        for connection in (self._connection, self.listener):
            if connection is not None:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection.close()
        self.thread.join(timeout=SOCKET_TIMEOUT + 1)
        if self.thread.is_alive():
            raise AssertionError("Loopback peer did not stop")

    def _run(self) -> None:
        raw: socket.socket | None = None
        try:
            raw, _address = self.listener.accept()
            raw.settimeout(SOCKET_TIMEOUT)
            self._connection = raw
            if self._context is not None:
                self._connection = self._context.wrap_socket(raw, server_side=True)
            connection = self._connection
            with connection:
                for expected, response in self.exchanges:
                    received = b""
                    while len(received) < len(expected):
                        chunk = connection.recv(len(expected) - len(received))
                        if not chunk:
                            raise EOFError("Proxy closed before the complete FIX message")
                        received += chunk
                        self.received += chunk
                    if received != expected:
                        raise AssertionError("Proxy changed the upstream FIX bytes")
                    connection.sendall(response[:7])
                    connection.sendall(response[7:])
                self.finished.set()
                # Keep diagnostics connected until the test explicitly cleans up.
                self._stop.wait(SOCKET_TIMEOUT)
        except Exception as exc:  # noqa: BLE001 - assertions inspect thread failures
            if not self._stop.is_set():
                self.errors.append(exc)
        finally:
            if raw is not None:
                raw.close()
            self.listener.close()
            self.finished.set()


class UpstreamTransportIntegrationTests(unittest.TestCase):
    def make_engine(self):
        dictionary = FixDictionary()
        self.assertEqual({}, dictionary.fields_by_tag)
        self.assertEqual({}, dictionary.messages)
        records = []
        statuses = []
        engine = ProxyEngine(
            dictionary,
            records.append,
            lambda _record_id, _status: None,
            statuses.append,
        )
        self.addCleanup(self.stop_engine, engine)
        return engine, records, statuses

    def stop_engine(self, engine: ProxyEngine) -> None:
        engine.stop()
        self.assertTrue(wait_until(lambda: not engine.running, timeout=3))
        self.assertEqual("Stopped", engine.diagnostics().listener_state)

    def make_peer(self, transport: str) -> _LoopbackPeer:
        peer = _LoopbackPeer(transport, _exchanges())
        self.addCleanup(peer.close)
        peer.start()
        return peer

    def start_engine(
        self,
        engine: ProxyEngine,
        upstream_port: int,
        transport: str,
        *,
        listener_port: int | None = None,
        sni: str = "localhost",
        ca_file: str = str(CERTIFICATE),
    ) -> int:
        port = listener_port if listener_port is not None else _available_port()
        engine.start(
            ProxyConfig(
                listen_host="127.0.0.1",
                listen_port=port,
                upstream_host="127.0.0.1",
                upstream_port=upstream_port,
                upstream_sni=sni,
                verify_upstream=True,
                ca_file=ca_file,
                upstream_transport=transport,
            )
        )
        self.assertTrue(
            wait_until(
                lambda: engine.diagnostics().listener_state.startswith("Listening"),
                timeout=2,
            ),
            engine.diagnostics(),
        )
        return port

    def exchange_messages(self, listener_port: int, engine: ProxyEngine) -> ProxyDiagnostics:
        with socket.create_connection(("127.0.0.1", listener_port), timeout=SOCKET_TIMEOUT) as client:
            for outbound, expected in _exchanges():
                client.sendall(outbound[:3])
                client.sendall(outbound[3:19])
                client.sendall(outbound[19:])
                received = b""
                while len(received) < len(expected):
                    chunk = client.recv(len(expected) - len(received))
                    if not chunk:
                        self.fail("Proxy closed before the complete downstream FIX message")
                    received += chunk
                self.assertEqual(expected, received)
            return engine.diagnostics()

    def assert_forwarded_history(self, engine, records, peer) -> None:
        self.assertTrue(
            wait_until(
                lambda: len(records) == 4 and all(record.status == "FORWARDED" for record in records),
                timeout=2,
            )
        )
        self.assertTrue(peer.finished.wait(timeout=2))
        self.assertEqual([], peer.errors)
        self.assertEqual(b"".join(request for request, _response in _exchanges()), peer.received)
        for direction, index in (("C→S", 0), ("S→C", 1)):
            expected = [exchange[index] for exchange in _exchanges()]
            direction_records = [record for record in records if record.direction == direction]
            self.assertEqual(expected, [record.original_raw for record in direction_records])
            self.assertEqual(expected, [record.raw for record in direction_records])
            self.assertEqual(["FORWARDED", "FORWARDED"], [record.status for record in direction_records])
            self.assertEqual([1, 2], [record.sequence_number for record in direction_records])
        self.assertEqual(["A", "D"], [r.msg_type for r in records if r.direction == "C→S"])
        self.assertEqual(["A", "8"], [r.msg_type for r in records if r.direction == "S→C"])
        self.assertEqual({}, engine.dictionary.fields_by_tag)
        self.assertEqual({}, engine.dictionary.messages)
        snapshot = engine.diagnostics()
        self.assertEqual(4, snapshot.observed_record_count)
        self.assertEqual(0, snapshot.malformed_record_count)
        self.assertEqual(30, snapshot.heartbeat_interval)
        self.assertEqual("", snapshot.last_transport_error)

    def test_plain_tcp_forwards_logon_and_application_without_dictionaries(self) -> None:
        peer = self.make_peer("plain_tcp")
        engine, records, _statuses = self.make_engine()
        port = self.start_engine(engine, peer.port, "plain_tcp")

        snapshot = self.exchange_messages(port, engine)

        self.assert_forwarded_history(engine, records, peer)
        self.assertEqual("", snapshot.tls_version)
        self.assertEqual("", snapshot.tls_cipher)
        self.assertIn("Plain TCP", snapshot.tls_verification)

    def test_verified_tls_custom_ca_forwards_logon_and_application_without_dictionaries(self) -> None:
        peer = self.make_peer("tls")
        engine, records, statuses = self.make_engine()
        port = self.start_engine(engine, peer.port, "tls")

        snapshot = self.exchange_messages(port, engine)

        self.assert_forwarded_history(engine, records, peer)
        self.assertIn("custom CA", snapshot.tls_verification)
        self.assertEqual("TLSv1.3", snapshot.tls_version)
        self.assertTrue(snapshot.tls_cipher)
        self.assertTrue(any("TLS connected" in status for status in statuses))

    def assert_tls_rejected(self, *, sni: str, ca_file: str) -> None:
        peer = self.make_peer("tls")
        engine, records, _statuses = self.make_engine()
        port = self.start_engine(engine, peer.port, "tls", sni=sni, ca_file=ca_file)
        with socket.create_connection(("127.0.0.1", port), timeout=SOCKET_TIMEOUT) as client:
            # FIX bytes buffered before the upstream handshake must not escape.
            client.sendall(_exchanges()[0][0])
            self.assertTrue(
                wait_until(lambda: bool(engine.diagnostics().last_transport_error), timeout=3)
            )
            try:
                received = client.recv(4096)
            except (ConnectionResetError, ConnectionAbortedError):
                received = b""
            self.assertEqual(b"", received)
        self.assertTrue(peer.finished.wait(timeout=2))
        self.assertEqual(b"", peer.received)
        self.assertEqual([], records)
        self.assertTrue(peer.errors)
        # Windows may surface a rejected client handshake as a connection reset
        # at the server; the proxy-side certificate error below is authoritative.
        self.assertTrue(all(
            isinstance(error, (ssl.SSLError, ConnectionResetError, ConnectionAbortedError))
            for error in peer.errors
        ), peer.errors)
        snapshot = engine.diagnostics()
        self.assertIn("CERTIFICATE_VERIFY_FAILED", snapshot.last_transport_error)
        self.assertEqual("Disconnected", snapshot.upstream_state)
        self.assertTrue(engine.running)
        self.assertTrue(snapshot.listener_state.startswith("Listening"))

    def test_tls_rejects_wrong_hostname_even_with_trusted_custom_ca(self) -> None:
        self.assert_tls_rejected(sni="wrong-host.invalid", ca_file=str(CERTIFICATE))

    def test_tls_rejects_untrusted_local_certificate(self) -> None:
        self.assert_tls_rejected(sni="localhost", ca_file="")

    def test_failed_upstream_allows_listener_stop_and_same_port_restart(self) -> None:
        for transport in ("plain_tcp", "tls"):
            with self.subTest(transport=transport):
                # Reserving a port without listen() gives a local refused connection.
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as refused:
                    refused.bind(("127.0.0.1", 0))
                    engine, records, _statuses = self.make_engine()
                    port = self.start_engine(engine, int(refused.getsockname()[1]), transport)
                    with socket.create_connection(("127.0.0.1", port), timeout=SOCKET_TIMEOUT):
                        self.assertTrue(
                            wait_until(
                                lambda: bool(engine.diagnostics().last_transport_error),
                                timeout=3,
                            )
                        )
                        self.assertTrue(engine.running)
                        self.assertEqual([], records)
                    self.stop_engine(engine)

                peer = self.make_peer(transport)
                self.start_engine(engine, peer.port, transport, listener_port=port)
                self.assertEqual("", engine.diagnostics().last_transport_error)
                self.exchange_messages(port, engine)
                self.assert_forwarded_history(engine, records, peer)
                self.stop_engine(engine)
                peer.close()


if __name__ == "__main__":
    unittest.main()
