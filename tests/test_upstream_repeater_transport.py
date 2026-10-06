from __future__ import annotations

from unittest.mock import Mock, patch
import unittest

from fixinspector.fix.dictionary import FixDictionary
from fixinspector.repeater.connection import IsolatedRepeaterConnection
from fixinspector.transport.connection import ProxyConfig
from fixinspector.transport.tls import TLSNegotiated
from fixinspector.transport.upstream import PLAIN_TCP_VERIFICATION
from tests.support import fix_message


class RepeaterTransportCompatibilityTests(unittest.TestCase):
    def test_isolated_transport_uses_tcp_and_ignores_saved_tls_configuration(self) -> None:
        upstream = Mock()
        response = fix_message("A", 1)
        upstream.recv.side_effect = [response, b""]
        connector = Mock(return_value=(upstream, TLSNegotiated(PLAIN_TCP_VERIFICATION)))
        records, statuses = [], []
        ids = iter((1, 2))
        config = ProxyConfig(
            upstream_host="127.0.0.1", upstream_transport="plain_tcp",
            upstream_sni="ignored", ca_file="does-not-exist.pem",
        )
        connection = IsolatedRepeaterConnection(
            config, dictionary=FixDictionary(), next_record_id=lambda: next(ids),
            on_record=records.append, on_status=statuses.append, connector=connector,
        )
        raw = fix_message("A", 1)
        with patch("fixinspector.repeater.connection.TLSSettings") as tls:
            connection._run(raw)
            tls.assert_not_called()
        connector.assert_called_once_with("127.0.0.1", 4581, "ignored", None, transport="plain_tcp")
        upstream.sendall.assert_called_once_with(raw)
        self.assertEqual([raw, response], [record.raw for record in records])
        self.assertTrue(any("open - Plain TCP" in status for status in statuses))
        upstream.close.assert_called_once_with()
