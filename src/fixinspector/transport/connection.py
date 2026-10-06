"""Bidirectional FIX proxy connection pipeline."""

from __future__ import annotations

from dataclasses import dataclass
import itertools
import logging
from pathlib import Path
import queue
import socket
import ssl
import threading
from typing import Callable
import uuid

from ..fix.framing import FixFramer, FramedMessage
from ..fix.parser import parse_message
from ..intercept.controller import InterceptController
from ..intercept.proxy_behaviour import (
    DisconnectEvent,
    DisconnectSide,
    FaultAction,
    FaultDecision,
    ProxyBehaviourController,
)
from ..records import TrafficRecord
from ..session.ordered_queue import QueueDisposition, QueueResolution
from ..session.injection import (
    AutoUpdatePolicy,
    InjectionController,
    InjectionMode,
    InjectionRequest,
    SESSION_AWARE_POLICY,
    SafeSlotClaim,
)
from ..session.recovery import RecoveryController
from ..session.substitution_journal import SubstitutionJournal
from ..session.tracker import SessionTracker
from .listener import create_listener
from .tls import TLSSettings
from .upstream import PLAIN_TCP_VERIFICATION, connect_upstream, transport_label

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class ProxyConfig:
    listen_host: str = "127.0.0.1"
    listen_port: int = 4582
    upstream_host: str = ""
    upstream_port: int = 4581
    upstream_sni: str = ""
    verify_upstream: bool = True
    ca_file: str = ""
    tls13_only: bool = True
    upstream_transport: str = "tls"

    def __post_init__(self) -> None:
        self._validate_ports()
        transport_label(self.upstream_transport)
        if self.upstream_transport == "tls":
            TLSSettings(self.verify_upstream, self.ca_file, self.tls13_only)

    def validate_endpoints(self) -> None:
        """Validate connection inputs when starting, allowing blank saved defaults."""
        for name, host in (("Listener", self.listen_host), ("Upstream", self.upstream_host)):
            if not isinstance(host, str) or not host.strip():
                raise ValueError(f"{name} host is required")
            if any(character.isspace() for character in host):
                raise ValueError(f"{name} host must not contain whitespace")
        self._validate_ports()
        transport_label(self.upstream_transport)

    def _validate_ports(self) -> None:
        self.listen_port = self._validated_port(self.listen_port, "Listener")
        self.upstream_port = self._validated_port(self.upstream_port, "Upstream")

    @staticmethod
    def _validated_port(value: int, name: str) -> int:
        message = f"{name} port must be between 1 and 65535"
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise ValueError(message)
        try:
            port = int(value)
        except ValueError as exc:
            raise ValueError(message) from exc
        if not 1 <= port <= 65535:
            raise ValueError(message)
        return port


@dataclass(frozen=True, slots=True)
class ProxyDiagnostics:
    listener_state: str
    upstream_state: str
    tls_verification: str
    tls_version: str
    tls_cipher: str
    client_to_server_sequence: int | None
    server_to_client_sequence: int | None
    heartbeat_interval: int | None
    client_session_id: str
    server_session_id: str
    held_count: int
    queued_count: int
    client_held_count: int
    client_queued_count: int
    server_held_count: int
    server_queued_count: int
    paused_client_sequence: int | None
    injection_waiting_count: int
    destructive_replay_waiting_count: int
    substitution_count: int
    recovery_replay_count: int
    recovery_pending_range_count: int
    recovery_conflict_count: int
    last_substituted_sequence: int | None
    recovery_detail: str
    observed_record_count: int
    malformed_record_count: int
    outstanding_wire_record_count: int
    last_transport_error: str


@dataclass(frozen=True, slots=True)
class _ControlAction:
    record_id: int
    action: str
    raw: bytes | None


class ProxyEngine:
    """Transport orchestrator; session ownership remains with the external client."""

    def __init__(
        self,
        dictionary,
        on_record: Callable[[TrafficRecord], None],
        on_record_status: Callable[[int, str], None],
        on_status: Callable[[str], None],
    ) -> None:
        self.dictionary = dictionary
        self.on_record = on_record
        self.on_record_status = on_record_status
        self.on_status = on_status

        self.intercept = InterceptController(dictionary)
        self.proxy_behaviour = ProxyBehaviourController(dictionary)
        self.session_tracker = SessionTracker()
        self.injection = InjectionController(dictionary=dictionary)
        self.substitution_journal = SubstitutionJournal()
        self.recovery = RecoveryController(dictionary=dictionary)
        self._config: ProxyConfig | None = None
        self._server_socket: socket.socket | None = None
        self._client_socket: socket.socket | None = None
        self._upstream_socket: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._connection_abort = threading.Event()
        self._ids = itertools.count(1)
        self._wire_records: dict[int, TrafficRecord] = {}
        self._fault_decisions: dict[int, FaultDecision] = {}
        self._records_lock = threading.RLock()
        self._active_session_key = f"offline-{uuid.uuid4().hex}"
        self._connection_serial = 0
        self._control_queues: dict[str, queue.Queue[_ControlAction]] = {
            "C→S": queue.Queue(),
            "S→C": queue.Queue(),
        }
        self._state_lock = threading.Lock()
        self._listener_state = "Stopped"
        self._upstream_state = "Disconnected"
        self._tls_verification = "DISABLED - testing only"
        self._tls_version = ""
        self._tls_cipher = ""
        self._observed_record_count = 0
        self._malformed_record_count = 0
        self._last_transport_error = ""

    def set_tls_preview(self, verify: bool, ca_file: str = "", transport: str = "tls") -> None:
        """Reflect stopped Configuration state in persistent diagnostics."""
        if self.running:
            return
        transport_label(transport)
        if transport == "plain_tcp":
            label = PLAIN_TCP_VERIFICATION
        elif verify:
            label = f"Verified (custom CA: {Path(ca_file).name})" if ca_file else "Verified (system trust)"
        else:
            label = "DISABLED - testing only"
        with self._state_lock:
            self._tls_verification = label
            self._tls_version = ""
            self._tls_cipher = ""

    @property
    def running(self) -> bool:
        return bool(self._accept_thread and self._accept_thread.is_alive())

    @property
    def _pending(self) -> dict[int, str]:
        """Read-only compatibility view used by Stage 0 characterization tests."""
        snapshot = self.intercept.snapshot()
        pending: dict[int, str] = {}
        for queue_snapshot in (snapshot.client_to_server, snapshot.server_to_client):
            if queue_snapshot.held_record_id is not None:
                pending[queue_snapshot.held_record_id] = "HELD"
        return pending

    def set_dictionary(self, dictionary) -> None:
        self.dictionary = dictionary
        self.intercept.set_dictionary(dictionary)
        self.proxy_behaviour.set_dictionary(dictionary)
        self.injection.set_dictionary(dictionary)
        self.recovery.set_dictionary(dictionary)

    def set_injection_listener(
        self,
        listener: Callable[[InjectionRequest], None] | None,
    ) -> None:
        self.injection.set_listener(listener)

    def queue_injection(
        self,
        raw: bytes,
        mode: InjectionMode | str,
        *,
        source: str = "REPEATER",
        repeater_item_id: str = "",
        source_record_id: int | None = None,
        auto_update: AutoUpdatePolicy = SESSION_AWARE_POLICY,
    ) -> InjectionRequest:
        return self.injection.queue(
            raw,
            mode,
            source=source,
            repeater_item_id=repeater_item_id,
            source_record_id=source_record_id,
            auto_update=auto_update,
        )

    def next_record_id(self) -> int:
        """Reserve a History ID for an isolated, Inspector-owned transport."""
        with self._records_lock:
            return next(self._ids)

    def cancel_injection(self, injection_id: int) -> bool:
        return self.injection.cancel(injection_id)

    def reserve_record_ids_through(self, record_id: int) -> None:
        """Advance IDs after loading a stopped project's historical records."""
        if self.running:
            raise RuntimeError("Cannot change record IDs while proxy is running")
        self._ids = itertools.count(max(1, int(record_id) + 1))

    def set_intercept(
        self,
        c2s: bool,
        s2c: bool = False,
        timeout_seconds: float | None = None,
        *,
        c2s_admin: bool = False,
        s2c_admin: bool = False,
    ) -> None:
        self.intercept.configure(
            c2s,
            s2c,
            timeout_seconds,
            client_to_server_admin=c2s_admin,
            server_to_client_admin=s2c_admin,
        )

    def start(self, config: ProxyConfig) -> None:
        if self.running:
            raise RuntimeError("Proxy is already running")
        config.validate_endpoints()
        label = transport_label(config.upstream_transport)
        verification = (
            TLSSettings(config.verify_upstream, config.ca_file, config.tls13_only).verification_label
            if config.upstream_transport == "tls"
            else PLAIN_TCP_VERIFICATION
        )
        self._config = config
        self._stop.clear()
        with self._state_lock:
            self._listener_state = "Starting"
            self._upstream_state = "Disconnected"
            self._tls_verification = verification
            self._tls_version = ""
            self._tls_cipher = ""
            self._last_transport_error = ""
        LOGGER.info(
            "Proxy starting listener=%s:%s upstream=%s:%s transport=%s verification=%s",
            config.listen_host,
            config.listen_port,
            config.upstream_host,
            config.upstream_port,
            label,
            self._tls_verification,
        )
        self._accept_thread = threading.Thread(target=self._run, name="fix-listener", daemon=True)
        self._accept_thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._connection_abort.set()
        for current_socket in (self._client_socket, self._upstream_socket, self._server_socket):
            if current_socket is None:
                continue
            try:
                current_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                current_socket.close()
            except OSError:
                pass
        for record_id in self.intercept.reset():
            self.on_record_status(record_id, "DISCONNECTED")
        self.injection.cancel_pending()
        self.recovery.clear_active_ranges()
        self._clear_control_queues()
        self.session_tracker.reset()
        with self._records_lock:
            self._wire_records.clear()
            self._fault_decisions.clear()
        with self._state_lock:
            self._listener_state = "Stopped"
            self._upstream_state = "Disconnected"
            self._tls_version = ""
            self._tls_cipher = ""
        self.on_status("Stopped")
        LOGGER.info("Proxy stopped")

    def resolve_intercept(self, record_id: int, action: str, raw: bytes | None = None) -> None:
        direction = self.intercept.direction_for(record_id)
        if direction is None:
            return
        self._control_queues[direction].put(_ControlAction(record_id, action, raw))

    def resolve_all_intercept(self, direction: str, action: str) -> None:
        """Resolve the complete current direction queue in wire order."""
        if direction not in self._control_queues:
            raise ValueError(f"Unknown FIX direction: {direction}")
        normalized = action.strip().lower()
        if normalized not in {"forward", "drop"}:
            raise ValueError(f"Unknown intercept action: {action}")
        self._control_queues[direction].put(_ControlAction(0, f"{normalized}_all", None))

    def pending_records(self, direction: str | None = None) -> tuple[TrafficRecord, ...]:
        ids = self.intercept.pending_record_ids(direction)
        with self._records_lock:
            return tuple(self._wire_records[record_id] for record_id in ids if record_id in self._wire_records)

    def reset_proxy_behaviour(self) -> tuple[int, ...]:
        """Restore safe policy and discard every message in the current pause queue."""
        pending = self.intercept.reset()
        self.proxy_behaviour.reset()
        self._clear_control_queues()
        with self._records_lock:
            for record_id in pending:
                record = self._wire_records.pop(record_id, None)
                self._fault_decisions.pop(record_id, None)
                if record is not None:
                    record.fault_action = "DROP"
                    record.fault_reason = "RESET PROXY BEHAVIOUR discarded paused queue"
        for record_id in pending:
            self.on_record_status(record_id, "DROPPED")
        return pending

    def disconnect(self, side: DisconnectSide | str, *, reason: str = "Manual disconnect") -> None:
        selected = side if isinstance(side, DisconnectSide) else DisconnectSide(str(side).upper())
        self._connection_abort.set()
        targets = []
        if selected in {DisconnectSide.CLIENT, DisconnectSide.BOTH}:
            targets.append(("client", self._client_socket))
        if selected in {DisconnectSide.SERVER, DisconnectSide.BOTH}:
            targets.append(("server", self._upstream_socket))
        for _label, current_socket in targets:
            if current_socket is None:
                continue
            try:
                current_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                current_socket.close()
            except OSError:
                pass
        summary = f"{selected.value.title()} side connection disconnected: {reason}"
        self.proxy_behaviour.record_event(kind="DISCONNECT", summary=summary)
        self.on_status(summary)

    def diagnostics(self) -> ProxyDiagnostics:
        session = self.session_tracker.snapshot()
        intercept = self.intercept.snapshot()
        journal = self.substitution_journal.snapshot()
        recovery = self.recovery.snapshot()
        with self._records_lock:
            outstanding_wire_records = len(self._wire_records)
        with self._state_lock:
            return ProxyDiagnostics(
                self._listener_state,
                self._upstream_state,
                self._tls_verification,
                self._tls_version,
                self._tls_cipher,
                session.client_to_server_sequence,
                session.server_to_client_sequence,
                session.heartbeat_interval,
                session.client_session_id,
                session.server_session_id,
                intercept.held_count,
                intercept.queued_count,
                intercept.client_to_server.held_count,
                intercept.client_to_server.queued_count,
                intercept.server_to_client.held_count,
                intercept.server_to_client.queued_count,
                intercept.client_to_server.held_sequence_number,
                self.injection.waiting_count(),
                self.injection.destructive_waiting_count(),
                journal.substitution_count,
                journal.recovery_replay_count,
                recovery.pending_range_count,
                recovery.conflict_count,
                journal.last_sequence_number,
                recovery.last_detail,
                self._observed_record_count,
                self._malformed_record_count,
                outstanding_wire_records,
                self._last_transport_error,
            )

    def _run(self) -> None:
        config = self._config
        assert config is not None
        label = transport_label(config.upstream_transport)
        try:
            server = create_listener(config.listen_host, config.listen_port)
            self._server_socket = server
            with self._state_lock:
                self._listener_state = f"Listening {config.listen_host}:{config.listen_port}"
            LOGGER.info("[Proxy] Listening on %s:%s", config.listen_host, config.listen_port)
            self.on_status(f"Listening on {config.listen_host}:{config.listen_port}")
            while not self._stop.is_set():
                try:
                    client, address = server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self._stop.is_set():
                        break
                    raise
                self._client_socket = client
                client.settimeout(0.1)
                self.proxy_behaviour.record_event(
                    kind="CONNECT", summary="Client connected to proxy"
                )
                self.on_status(f"Client connected from {address[0]}:{address[1]}")
                LOGGER.info("[Proxy] Client connected from %s:%s", address[0], address[1])
                upstream_connected = False
                try:
                    with self._state_lock:
                        self._upstream_state = "Connecting"
                    connecting = (
                        f"[Upstream] Connecting to {config.upstream_host}:{config.upstream_port} "
                        f"using {label}"
                    )
                    LOGGER.info("%s", connecting)
                    self.on_status(connecting)
                    upstream, negotiated = connect_upstream(
                        config.upstream_host,
                        config.upstream_port,
                        config.upstream_sni,
                        (
                            TLSSettings(config.verify_upstream, config.ca_file, config.tls13_only)
                            if config.upstream_transport == "tls"
                            else None
                        ),
                        transport=config.upstream_transport,
                    )
                    self._upstream_socket = upstream
                    upstream_connected = True
                    with self._state_lock:
                        self._upstream_state = f"Connected {config.upstream_host}:{config.upstream_port}"
                        self._tls_verification = negotiated.verification
                        self._tls_version = negotiated.version
                        self._tls_cipher = negotiated.cipher
                    self.on_status(f"{label} connected to {config.upstream_host}:{config.upstream_port}")
                    LOGGER.info("[Upstream] %s", "TLS established" if label == "TLS" else "Connected (Plain TCP)")
                    if negotiated.version:
                        LOGGER.info("[Upstream] Protocol: %s", negotiated.version)
                        self.on_status(f"[Upstream] Protocol: {negotiated.version}")
                    self.proxy_behaviour.record_event(
                        kind="CONNECT", summary=f"Upstream FIX server connected over {label}"
                    )
                    self._serve_connection(client, upstream)
                except Exception as exc:  # noqa: BLE001 - transport failures are reported to the UI
                    if not self._stop.is_set():
                        operation = (
                            "TLS handshake failed"
                            if not upstream_connected and isinstance(exc, ssl.SSLError)
                            else f"{label} connection failed"
                        )
                        with self._state_lock:
                            self._last_transport_error = f"{operation}: {exc}"
                        LOGGER.error("[Upstream] %s: %s", operation, exc)
                        self.on_status(f"Connection error: {label}: {operation}: {exc}")
                finally:
                    for current_socket in (client, self._upstream_socket):
                        if current_socket is not None:
                            try:
                                current_socket.close()
                            except OSError:
                                pass
                    self._client_socket = None
                    self._upstream_socket = None
                    for record_id in self.intercept.reset():
                        self.on_record_status(record_id, "DISCONNECTED")
                    self._clear_control_queues()
                    with self._records_lock:
                        self._wire_records.clear()
                        self._fault_decisions.clear()
                    with self._state_lock:
                        self._upstream_state = "Disconnected"
                        self._tls_version = ""
                        self._tls_cipher = ""
                    if not self._stop.is_set():
                        self.proxy_behaviour.record_event(
                            kind="DISCONNECT", summary="Client connection ended; listener remains active"
                        )
                        self.on_status("Client disconnected; listening for next connection")
        except Exception as exc:  # noqa: BLE001
            if not self._stop.is_set():
                with self._state_lock:
                    self._listener_state = "Error"
                    self._last_transport_error = str(exc)
                LOGGER.error("Listener error: %s", exc)
                self.on_status(f"Listener error: {exc}")
        finally:
            with self._state_lock:
                if self._stop.is_set():
                    self._listener_state = "Stopped"

    def _serve_connection(self, client: socket.socket, upstream: socket.socket) -> None:
        self._connection_abort.clear()
        with self._state_lock:
            self._connection_serial += 1
            self._active_session_key = (
                f"connection-{self._connection_serial}-{uuid.uuid4().hex}"
            )
        self.recovery.clear_active_ranges()
        errors: queue.Queue[BaseException] = queue.Queue()
        threads = [
            threading.Thread(target=self._pipe, args=(client, upstream, "C→S", errors), daemon=True),
            threading.Thread(target=self._pipe, args=(upstream, client, "S→C", errors), daemon=True),
        ]
        for worker in threads:
            worker.start()
        try:
            while not self._stop.is_set() and all(worker.is_alive() for worker in threads):
                try:
                    error = errors.get(timeout=0.1)
                except queue.Empty:
                    continue
                raise error
        finally:
            self._connection_abort.set()
            for current_socket in (client, upstream):
                try:
                    current_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            for worker in threads:
                worker.join(timeout=0.5)
            self.injection.cancel_pending()
            self.recovery.clear_active_ranges()

    def _pipe(
        self,
        source,
        destination,
        direction: str,
        errors: queue.Queue[BaseException],
    ) -> None:
        framer = FixFramer()
        try:
            source.settimeout(0.1)
            while not self._stop.is_set() and not self._connection_abort.is_set():
                if direction == "C→S":
                    self._process_exact_replays(destination)
                self._process_controls(direction, destination)
                expired = self.intercept.expire_direction(direction)
                if expired is not None:
                    self._apply_resolution(destination, expired, direction)
                try:
                    data = source.recv(65536)
                except socket.timeout:
                    continue
                if not data:
                    for frame in framer.flush():
                        self._handle_frame(frame, destination, direction)
                    return
                for frame in framer.feed_frames(data):
                    self._handle_frame(frame, destination, direction)
        except BaseException as exc:  # noqa: BLE001
            if not self._stop.is_set() and not self._connection_abort.is_set():
                errors.put(exc)

    def _handle_frame(self, frame: FramedMessage, destination, direction: str) -> None:
        parsed = parse_message(frame.raw, self.dictionary)
        if direction == "C→S":
            observed_session_key = self._session_key(parsed)
            if observed_session_key:
                # FIX session identity is stable across TCP reconnects. Keep
                # journal/recovery awareness tied to that identity rather than
                # to the transient socket connection UUID.
                self._active_session_key = observed_session_key
        sequence_number = self._sequence_number(parsed.first("34"))
        self.session_tracker.observe(direction, parsed)
        if direction == "S→C":
            self.recovery.observe_server(self._active_session_key, frame.raw)
        record_id = next(self._ids)
        decision = self.proxy_behaviour.evaluate(direction, parsed)
        if decision.action is FaultAction.DROP:
            disposition = QueueDisposition.FORWARD
            status = "DROPPED"
        else:
            disposition = self.intercept.submit(
                record_id,
                direction,
                parsed.msg_type,
                sequence_number,
                frame.raw,
                force_hold=True if decision.action is FaultAction.PAUSE else None,
                manual_only=decision.action is FaultAction.PAUSE,
            )
            if disposition is not QueueDisposition.FORWARD:
                status = disposition.value
            elif decision.action is FaultAction.DELAY:
                status = "DELAYED"
            elif decision.action is FaultAction.DUPLICATE:
                status = "DUPLICATED"
            else:
                status = "FORWARDED"
        fault_action = "" if decision.action is FaultAction.NORMAL else decision.action.value
        fault_reason = "" if decision.action is FaultAction.NORMAL else decision.reason
        if disposition is QueueDisposition.QUEUED and decision.action is FaultAction.NORMAL:
            pending_ids = self.intercept.pending_record_ids(direction)
            with self._records_lock:
                fault_backpressure = any(
                    self._fault_decisions.get(pending_id, FaultDecision()).action
                    is FaultAction.PAUSE
                    for pending_id in pending_ids
                    if pending_id != record_id
                )
            if fault_backpressure:
                fault_action = FaultAction.PAUSE.value
                fault_reason = "Queued behind an earlier fault-paused message"
        record = TrafficRecord(
            record_id=record_id,
            direction=direction,
            original_raw=frame.raw,
            status=status,
            msg_type=parsed.msg_type,
            sequence_number=sequence_number,
            source="CLIENT" if direction == "C→S" else "SERVER",
            framing_error=frame.error,
            session_key=self._active_session_key,
            fault_action=fault_action,
            fault_rule=decision.matched_rule,
            fault_reason=fault_reason,
        )
        if status != "DROPPED":
            with self._records_lock:
                self._wire_records[record_id] = record
                if disposition is not QueueDisposition.FORWARD:
                    self._fault_decisions[record_id] = decision
        with self._state_lock:
            self._observed_record_count += 1
            if frame.error or parsed.issues:
                self._malformed_record_count += 1
        self.on_record(record)
        if decision.action is not FaultAction.NORMAL:
            self.proxy_behaviour.record_event(
                direction=direction,
                kind=decision.action.value,
                summary=self._event_summary(record, decision, status),
                record_id=record_id,
                msg_type=parsed.msg_type,
            )
        if status == "DROPPED":
            self._fire_disconnects(direction, DisconnectEvent.DROPPED)
            self._fire_disconnects(direction, DisconnectEvent.RECEIVED)
            return
        if disposition is QueueDisposition.FORWARD:
            final_status = self._forward_fault_record(
                destination,
                record,
                frame.raw,
                direction,
                status,
                decision,
            )
            if final_status != status:
                self.on_record_status(record.record_id, final_status)
            with self._records_lock:
                self._wire_records.pop(record_id, None)
                self._fault_decisions.pop(record_id, None)
            if final_status != "DISCONNECTED":
                self._fire_disconnects(direction, DisconnectEvent.FORWARDED)
        self._fire_disconnects(direction, DisconnectEvent.RECEIVED)

    def _process_controls(self, direction: str, destination) -> None:
        controls = self._control_queues[direction]
        while True:
            try:
                control = controls.get_nowait()
            except queue.Empty:
                return
            try:
                if control.action in {"forward_all", "drop_all"}:
                    resolved_direction = direction
                    resolution = self.intercept.resolve_all(
                        direction, control.action.removesuffix("_all")
                    )
                else:
                    resolved_direction, resolution = self.intercept.resolve(
                        control.record_id,
                        control.action,
                        control.raw,
                    )
            except (KeyError, ValueError) as exc:
                self.on_status(f"Intercept resolution error: {exc}")
                continue
            if resolved_direction != direction:
                self.on_status(f"Intercept resolution direction mismatch for #{control.record_id}")
                continue
            self._apply_resolution(destination, resolution, direction)

    def _apply_resolution(
        self,
        destination,
        resolution: QueueResolution,
        direction: str = "C→S",
    ) -> None:
        for released in resolution.released:
            status = released.status
            with self._records_lock:
                record = self._wire_records.get(released.record_id)
                decision = self._fault_decisions.pop(released.record_id, FaultDecision())
            if released.raw is not None:
                if record is not None:
                    ordinary_status = (
                        "RELEASED_FROM_QUEUE"
                        if record.fault_action == FaultAction.PAUSE.value
                        else released.status
                    )
                    status = self._forward_fault_record(
                        destination,
                        record,
                        released.raw,
                        direction,
                        ordinary_status,
                        decision,
                    )
                else:
                    destination.sendall(released.raw)
                if status != "DISCONNECTED":
                    self._fire_disconnects(direction, DisconnectEvent.FORWARDED)
            else:
                if record is not None and record.fault_action == FaultAction.PAUSE.value:
                    record.fault_reason = f"{record.fault_reason}; manually dropped from pause queue".strip("; ")
                self.proxy_behaviour.record_event(
                    direction=direction,
                    kind="DROP",
                    summary=f"{direction} queued record #{released.record_id} dropped",
                    record_id=released.record_id,
                    msg_type=record.msg_type if record is not None else "",
                )
                self._fire_disconnects(direction, DisconnectEvent.DROPPED)
            if record is not None:
                record.status = status
            self.on_record_status(released.record_id, status)
            with self._records_lock:
                self._wire_records.pop(released.record_id, None)
        if resolution.promoted_record_id is not None:
            with self._records_lock:
                promoted = self._wire_records.get(resolution.promoted_record_id)
                if promoted is not None:
                    promoted.status = "HELD"
            self.on_record_status(resolution.promoted_record_id, "HELD")

    def _forward_fault_record(
        self,
        destination,
        record: TrafficRecord,
        raw: bytes,
        direction: str,
        ordinary_status: str,
        decision: FaultDecision,
    ) -> str:
        if self._stop.is_set() or (
            decision.delay_ms > 0
            and self._connection_abort.wait(decision.delay_ms / 1_000.0)
        ):
            return "DISCONNECTED"
        if direction == "C→S":
            final_status = self._send_client_record(destination, record, raw, ordinary_status)
        else:
            destination.sendall(raw)
            final_status = ordinary_status

        if decision.duplicate_copies:
            exact_wire_raw = bytes(record.raw if direction == "C→S" else raw)
            for _copy in range(decision.duplicate_copies):
                destination.sendall(exact_wire_raw)
                duplicate_message = parse_message(exact_wire_raw, self.dictionary)
                duplicate_id = next(self._ids)
                duplicate = TrafficRecord(
                    record_id=duplicate_id,
                    direction=direction,
                    original_raw=exact_wire_raw,
                    status="FAULT-INJECTED DUPLICATE",
                    msg_type=duplicate_message.msg_type,
                    sequence_number=self._sequence_number(
                        duplicate_message.first("34")
                    ),
                    source="FAULT-INJECTION",
                    session_key=self._active_session_key,
                    fault_action=FaultAction.DUPLICATE.value,
                    fault_rule=decision.matched_rule,
                    fault_reason=decision.reason,
                    duplicate_of_record_id=record.record_id,
                )
                with self._state_lock:
                    self._observed_record_count += 1
                self.on_record(duplicate)
                self.proxy_behaviour.record_event(
                    direction=direction,
                    kind="DUPLICATE",
                    summary=(
                        f"{direction} 35={duplicate.msg_type} emitted exact duplicate "
                        f"of record #{record.record_id}"
                    ),
                    record_id=duplicate_id,
                    msg_type=duplicate.msg_type,
                )
        return final_status

    def _fire_disconnects(self, direction: str, event: DisconnectEvent) -> None:
        for side in self.proxy_behaviour.consume_disconnects(direction, event):
            self.disconnect(
                side,
                reason=f"one-shot trigger after {direction} message {event.value.lower()}",
            )

    @staticmethod
    def _event_summary(
        record: TrafficRecord,
        decision: FaultDecision,
        status: str,
    ) -> str:
        rule = f' by rule "{decision.matched_rule}"' if decision.matched_rule else ""
        detail = f" ({decision.delay_ms} ms)" if decision.delay_ms else ""
        return f"{record.direction} 35={record.msg_type} {status.lower()}{rule}{detail}"

    def _send_client_record(
        self,
        destination,
        record: TrafficRecord,
        original_raw: bytes,
        ordinary_status: str,
    ) -> str:
        recovery = self.recovery.rewrite_client_if_needed(
            self._active_session_key,
            original_raw,
            self.substitution_journal,
        )
        if recovery is not None:
            destination.sendall(recovery.effective_raw)
            self.recovery.mark_effective_replay_sent(
                self._active_session_key,
                recovery.entry.sequence_number,
                self.substitution_journal,
            )
            self._set_effective_record(
                record,
                recovery.effective_raw,
                "RECOVERY-REPLAY",
                recovery.entry.injection_source,
            )
            return "RECOVERY-REPLAY"

        claim = self.injection.claim_safe_slot(original_raw)
        if claim is None:
            destination.sendall(original_raw)
            return ordinary_status
        try:
            destination.sendall(claim.effective_raw)
        except BaseException as exc:  # noqa: BLE001 - preserve transport failure semantics
            self.injection.mark_failed(claim.request.injection_id, str(exc))
            raise
        self.substitution_journal.record(
            session_key=self._active_session_key,
            sequence_number=claim.sequence_number,
            original_record_id=record.record_id,
            original_client_raw=original_raw,
            effective_server_raw=claim.effective_raw,
            injection_id=claim.request.injection_id,
            injection_source=claim.request.source,
            repeater_item_id=claim.request.repeater_item_id,
        )
        self._set_effective_record(record, claim.effective_raw, "INJECTED", claim.request.source)
        self.injection.mark_injected(claim, record.record_id)
        return "INJECTED"

    def _process_exact_replays(self, destination) -> None:
        while True:
            request = self.injection.claim_exact_raw()
            if request is None:
                return
            try:
                destination.sendall(request.template_raw)
            except BaseException as exc:  # noqa: BLE001
                self.injection.mark_failed(request.injection_id, str(exc))
                raise
            parsed = parse_message(request.template_raw, self.dictionary)
            sequence = self._sequence_number(parsed.first("34"))
            record_id = next(self._ids)
            record = TrafficRecord(
                record_id=record_id,
                direction="C→S",
                original_raw=request.template_raw,
                status="EXACT-RAW-REPLAY",
                msg_type=parsed.msg_type,
                sequence_number=sequence,
                source=request.source,
                framing_error="; ".join(parsed.issues) or None,
                session_key=self._active_session_key,
            )
            with self._state_lock:
                self._observed_record_count += 1
                if parsed.issues:
                    self._malformed_record_count += 1
            self.on_record(record)
            self.injection.mark_raw_replayed(request.injection_id, record_id, sequence)

    def _set_effective_record(
        self,
        record: TrafficRecord,
        effective_raw: bytes,
        status: str,
        source: str,
    ) -> None:
        parsed = parse_message(effective_raw, self.dictionary)
        record.raw = effective_raw
        record.status = status
        record.source = source
        record.msg_type = parsed.msg_type
        record.sequence_number = self._sequence_number(parsed.first("34"))

    def _clear_control_queues(self) -> None:
        for controls in self._control_queues.values():
            while True:
                try:
                    controls.get_nowait()
                except queue.Empty:
                    break

    @staticmethod
    def _sequence_number(value: bytes | None) -> int | None:
        if value is None:
            return None
        try:
            return int(value)
        except ValueError:
            return None

    @staticmethod
    def _session_key(message) -> str:
        begin = message.first("8")
        sender = message.first("49")
        target = message.first("56")
        if begin is None or sender is None or target is None:
            return ""
        components = [begin, sender, target, message.first("50") or b"", message.first("57") or b""]
        return "fix:" + ":".join(bytes(value).hex() for value in components)


__all__ = ["ProxyConfig", "ProxyDiagnostics", "ProxyEngine"]
