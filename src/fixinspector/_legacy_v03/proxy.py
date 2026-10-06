from __future__ import annotations

from dataclasses import dataclass
import itertools
import queue
import socket
import ssl
import threading
from typing import Callable

from .codec import FixFramer, parse_message
from .dictionary import FixDictionary
from .model import TrafficRecord


@dataclass(slots=True)
class ProxyConfig:
    listen_host: str = "127.0.0.1"
    listen_port: int = 4582
    upstream_host: str = ""
    upstream_port: int = 4581
    upstream_sni: str = ""
    verify_upstream: bool = False
    ca_file: str = ""
    tls13_only: bool = True


@dataclass(slots=True)
class _Pending:
    event: threading.Event
    action: str = "forward"
    raw: bytes | None = None


class ProxyEngine:
    def __init__(
        self,
        dictionary: FixDictionary,
        on_record: Callable[[TrafficRecord], None],
        on_record_status: Callable[[int, str], None],
        on_status: Callable[[str], None],
    ) -> None:
        self.dictionary = dictionary
        self.on_record = on_record
        self.on_record_status = on_record_status
        self.on_status = on_status

        self._config: ProxyConfig | None = None
        self._server_socket: socket.socket | None = None
        self._client_socket: socket.socket | None = None
        self._upstream_socket: ssl.SSLSocket | None = None
        self._accept_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._pending: dict[int, _Pending] = {}
        self._pending_lock = threading.Lock()
        self._ids = itertools.count(1)
        self._intercept_c2s = False
        self._intercept_s2c = False
        self._intercept_timeout_seconds = 7.0
        self._settings_lock = threading.Lock()

    @property
    def running(self) -> bool:
        return bool(self._accept_thread and self._accept_thread.is_alive())

    def set_dictionary(self, dictionary: FixDictionary) -> None:
        self.dictionary = dictionary

    def set_intercept(
        self,
        c2s: bool,
        s2c: bool = False,
        timeout_seconds: float | None = None,
    ) -> None:
        with self._settings_lock:
            self._intercept_c2s = bool(c2s)
            self._intercept_s2c = bool(s2c)
            if timeout_seconds is not None:
                self._intercept_timeout_seconds = max(0.0, float(timeout_seconds))

    def _intercept_timeout(self) -> float:
        with self._settings_lock:
            return self._intercept_timeout_seconds

    def start(self, config: ProxyConfig) -> None:
        if self.running:
            raise RuntimeError("Proxy is already running")
        if not config.upstream_host:
            raise ValueError("Upstream host is required")
        self._config = config
        self._stop.clear()
        self._accept_thread = threading.Thread(target=self._run, name="fix-proxy", daemon=True)
        self._accept_thread.start()

    def stop(self) -> None:
        self._stop.set()
        for sock in (self._client_socket, self._upstream_socket, self._server_socket):
            if sock:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    sock.close()
                except OSError:
                    pass
        with self._pending_lock:
            for pending in self._pending.values():
                pending.action = "drop"
                pending.event.set()
            self._pending.clear()
        self.on_status("Stopped")

    def resolve_intercept(self, record_id: int, action: str, raw: bytes | None = None) -> None:
        with self._pending_lock:
            pending = self._pending.get(record_id)
            if not pending:
                return
            pending.action = action
            pending.raw = raw
            pending.event.set()

    def _run(self) -> None:
        config = self._config
        assert config is not None

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket = server
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((config.listen_host, config.listen_port))
        server.listen(1)
        server.settimeout(1.0)
        self.on_status(f"Listening on {config.listen_host}:{config.listen_port}")

        while not self._stop.is_set():
            try:
                client, address = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            self._client_socket = client
            self.on_status(f"Client connected from {address[0]}:{address[1]}")
            try:
                upstream = self._connect_upstream(config)
                self._upstream_socket = upstream
                self.on_status(f"TLS connected to {config.upstream_host}:{config.upstream_port}")
                self._serve_connection(client, upstream)
            except Exception as exc:  # noqa: BLE001 - surface transport failures to UI
                self.on_status(f"Connection error: {exc}")
            finally:
                for sock in (client, self._upstream_socket):
                    if sock:
                        try:
                            sock.close()
                        except OSError:
                            pass
                self._client_socket = None
                self._upstream_socket = None
                if not self._stop.is_set():
                    self.on_status("Client disconnected; listening for next connection")

    def _connect_upstream(self, config: ProxyConfig) -> ssl.SSLSocket:
        if config.verify_upstream:
            context = ssl.create_default_context(cafile=config.ca_file or None)
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            server_hostname = config.upstream_sni or config.upstream_host
        else:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            server_hostname = config.upstream_sni or None

        if config.tls13_only:
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.maximum_version = ssl.TLSVersion.TLSv1_3

        raw = socket.create_connection((config.upstream_host, config.upstream_port), timeout=10)
        wrapped = context.wrap_socket(raw, server_hostname=server_hostname)
        wrapped.settimeout(1.0)
        return wrapped

    def _serve_connection(self, client: socket.socket, upstream: ssl.SSLSocket) -> None:
        client.settimeout(1.0)
        errors: queue.Queue[BaseException] = queue.Queue()

        threads = [
            threading.Thread(
                target=self._pipe,
                args=(client, upstream, "C→S", errors),
                daemon=True,
            ),
            threading.Thread(
                target=self._pipe,
                args=(upstream, client, "S→C", errors),
                daemon=True,
            ),
        ]
        for thread in threads:
            thread.start()

        while not self._stop.is_set() and any(t.is_alive() for t in threads):
            try:
                exc = errors.get(timeout=0.25)
            except queue.Empty:
                continue
            raise exc

    def _should_intercept(self, direction: str, msg_type: str) -> bool:
        with self._settings_lock:
            enabled = self._intercept_c2s if direction == "C→S" else self._intercept_s2c
        if not enabled:
            return False
        # Default behavior: only application/business messages are held.
        return not self.dictionary.is_admin(msg_type)

    def _pipe(
        self,
        source: socket.socket,
        destination: socket.socket,
        direction: str,
        errors: queue.Queue[BaseException],
    ) -> None:
        framer = FixFramer()
        try:
            while not self._stop.is_set():
                try:
                    data = source.recv(65536)
                except socket.timeout:
                    continue
                if not data:
                    return

                messages = framer.feed(data)
                for raw in messages:
                    parsed = parse_message(raw, self.dictionary)
                    record_id = next(self._ids)
                    intercept = self._should_intercept(direction, parsed.msg_type)
                    status = "HELD" if intercept else "FORWARDED"
                    record = TrafficRecord(
                        record_id=record_id,
                        direction=direction,
                        raw=raw,
                        status=status,
                        msg_type=parsed.msg_type,
                    )
                    self.on_record(record)

                    if not intercept:
                        destination.sendall(raw)
                        continue

                    pending = _Pending(event=threading.Event(), raw=raw)
                    with self._pending_lock:
                        self._pending[record_id] = pending

                    timeout_seconds = self._intercept_timeout()
                    resolved = pending.event.wait(timeout=timeout_seconds if timeout_seconds > 0 else None)
                    timed_out = not resolved
                    if timed_out:
                        # FIX messages share one ordered MsgSeqNum stream. Holding an
                        # application message indefinitely would also prevent later
                        # session traffic from being forwarded without creating a
                        # sequence gap. Auto-forward is therefore a safety valve.
                        pending.action = "forward"
                        pending.raw = raw

                    with self._pending_lock:
                        self._pending.pop(record_id, None)

                    if self._stop.is_set():
                        return
                    if pending.action == "drop":
                        self.on_record_status(record_id, "DROPPED")
                        continue

                    outbound = pending.raw if pending.raw is not None else raw
                    destination.sendall(outbound)
                    self.on_record_status(record_id, "AUTO-FWD" if timed_out else "FORWARDED")
        except BaseException as exc:  # noqa: BLE001
            if not self._stop.is_set():
                errors.put(exc)
