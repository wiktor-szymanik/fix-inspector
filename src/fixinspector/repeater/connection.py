"""Isolated one-off transport for Sender Logon protocol tests."""

from __future__ import annotations

from collections.abc import Callable
import logging
import socket
import threading
import uuid

from ..fix.framing import FixFramer, FramedMessage
from ..fix.parser import parse_message
from ..records import TrafficRecord
from ..transport.connection import ProxyConfig
from ..transport.tls import TLSSettings
from ..transport.upstream import connect_upstream, transport_label

LOGGER = logging.getLogger(__name__)


class IsolatedRepeaterConnection:
    """A raw TCP/TLS exchange isolated from the main proxy connection manager.

    It deliberately does not implement logon state, heartbeats, resend, or logout.
    The tester owns the exact outbound Logon bytes and closes this transport
    independently.
    """

    def __init__(
        self,
        config: ProxyConfig,
        *,
        dictionary,
        next_record_id: Callable[[], int],
        on_record: Callable[[TrafficRecord], None],
        on_status: Callable[[str], None],
        connector: Callable = connect_upstream,
    ) -> None:
        self.config = config
        self.dictionary = dictionary
        self._next_record_id = next_record_id
        self._on_record = on_record
        self._on_status = on_status
        self._connector = connector
        self._socket = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self.session_key = f"repeater-{uuid.uuid4().hex}"

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive() and not self._stop.is_set())

    def send_logon(self, raw: bytes) -> None:
        message = parse_message(bytes(raw), self.dictionary)
        if message.msg_type != "A":
            raise ValueError("Send on new connection is available only for Logon (35=A)")
        with self._lock:
            if self.running:
                raise RuntimeError("This Sender test connection is already open")
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._run,
                args=(bytes(raw),),
                name="repeater-logon-transport",
                daemon=True,
            )
            self._thread.start()

    def close(self) -> None:
        self._stop.set()
        current = self._socket
        if current is not None:
            try:
                current.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                current.close()
            except OSError:
                pass
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1.0)

    def _run(self, raw: bytes) -> None:
        framer = FixFramer()
        try:
            label = transport_label(self.config.upstream_transport)
            self._on_status(f"Connecting isolated Sender transport using {label}…")
            tls = TLSSettings(
                self.config.verify_upstream,
                self.config.ca_file,
                self.config.tls13_only,
            ) if self.config.upstream_transport == "tls" else None
            # Keep the existing positional TLS connector contract; plain TCP
            # explicitly opts into the shared connector's alternative transport.
            options = {"transport": "plain_tcp"} if tls is None else {}
            current, negotiated = self._connector(
                self.config.upstream_host,
                self.config.upstream_port,
                self.config.upstream_sni,
                tls,
                **options,
            )
            self._socket = current
            if self._stop.is_set():
                current.close()
                return
            current.sendall(raw)
            self._emit_record(FramedMessage(raw), "C→S", "NEW-CONNECTION-SENT")
            self._on_status(
                f"Isolated Sender connection open - {negotiated.version or label}"
            )
            LOGGER.info(
                "Isolated Sender Logon sent upstream=%s:%s transport=%s verification=%s",
                self.config.upstream_host,
                self.config.upstream_port,
                label,
                negotiated.verification,
            )
            while not self._stop.is_set():
                try:
                    data = current.recv(65536)
                except socket.timeout:
                    continue
                if not data:
                    break
                for frame in framer.feed_frames(data):
                    self._emit_record(frame, "S→C", "NEW-CONNECTION-RECEIVED")
            for frame in framer.flush():
                self._emit_record(frame, "S→C", "NEW-CONNECTION-RECEIVED")
            self._on_status("Isolated Sender connection closed")
        except BaseException as exc:  # noqa: BLE001 - surface transport failures to the UI
            if not self._stop.is_set():
                LOGGER.error("Isolated Sender connection failed: %s", exc)
                self._on_status(f"Isolated Sender connection failed: {exc}")
        finally:
            current = self._socket
            self._socket = None
            if current is not None:
                try:
                    current.close()
                except OSError:
                    pass
            self._stop.set()

    def _emit_record(self, frame: FramedMessage, direction: str, status: str) -> None:
        parsed = parse_message(frame.raw, self.dictionary)
        try:
            sequence = int(parsed.first("34")) if parsed.first("34") is not None else None
        except ValueError:
            sequence = None
        self._on_record(
            TrafficRecord(
                record_id=self._next_record_id(),
                direction=direction,
                original_raw=bytes(frame.raw),
                status=status,
                msg_type=parsed.msg_type,
                sequence_number=sequence,
                source="REPEATER",
                framing_error=frame.error or ("; ".join(parsed.issues) or None),
                session_key=self.session_key,
            )
        )


__all__ = ["IsolatedRepeaterConnection"]
