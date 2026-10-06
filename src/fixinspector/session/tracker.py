"""Passive observed-session diagnostics; never owns the FIX session."""

from __future__ import annotations

from dataclasses import dataclass
import threading

from ..fix.message import FixMessage
from ..fix.parser import decode_value


@dataclass(frozen=True, slots=True)
class SessionSnapshot:
    client_to_server_sequence: int | None
    server_to_client_sequence: int | None
    heartbeat_interval: int | None
    client_session_id: str
    server_session_id: str


class SessionTracker:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._c2s_sequence: int | None = None
        self._s2c_sequence: int | None = None
        self._heartbeat: int | None = None
        self._client_session_id = ""
        self._server_session_id = ""

    def observe(self, direction: str, message: FixMessage) -> None:
        sequence = self._integer(message, "34")
        sender = self._text(message, "49")
        target = self._text(message, "56")
        with self._lock:
            if direction == "C→S":
                if sequence is not None:
                    self._c2s_sequence = sequence
                if sender or target:
                    self._client_session_id = f"{sender or '?'}→{target or '?'}"
                if message.msg_type == "A":
                    heartbeat = self._integer(message, "108")
                    if heartbeat is not None:
                        self._heartbeat = heartbeat
            else:
                if sequence is not None:
                    self._s2c_sequence = sequence
                if sender or target:
                    self._server_session_id = f"{sender or '?'}→{target or '?'}"

    def snapshot(self) -> SessionSnapshot:
        with self._lock:
            return SessionSnapshot(
                self._c2s_sequence,
                self._s2c_sequence,
                self._heartbeat,
                self._client_session_id,
                self._server_session_id,
            )

    def reset(self) -> None:
        with self._lock:
            self._c2s_sequence = None
            self._s2c_sequence = None
            self._heartbeat = None
            self._client_session_id = ""
            self._server_session_id = ""

    @staticmethod
    def _text(message: FixMessage, tag: str) -> str:
        value = message.first(tag)
        return decode_value(value, message.encoding) if value is not None else ""

    @staticmethod
    def _integer(message: FixMessage, tag: str) -> int | None:
        value = message.first(tag)
        if value is None:
            return None
        try:
            return int(value)
        except ValueError:
            return None
