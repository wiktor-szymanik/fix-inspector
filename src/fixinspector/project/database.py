"""Transactional, local-only SQLite project persistence."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Iterator

from ..records import TrafficRecord
from .redaction import SecretRedactionPolicy

SCHEMA_VERSION = 3


class ProjectDatabase:
    """Own a FIX Inspector project file and enforce redaction before writes."""

    def __init__(
        self,
        path: str | Path,
        *,
        policy: SecretRedactionPolicy | None = None,
        dictionary=None,
    ) -> None:
        self.path = Path(path)
        self.policy = policy or SecretRedactionPolicy()
        self.dictionary = dictionary
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._connection = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=FULL")
            version = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
            if version > SCHEMA_VERSION:
                raise RuntimeError(
                    f"Project schema {version} is newer than supported schema {SCHEMA_VERSION}"
                )
            self._create_schema()
        except sqlite3.DatabaseError as exc:
            raise RuntimeError(f"Could not open project database: {exc}") from exc

    def __enter__(self) -> "ProjectDatabase":
        return self

    def __exit__(self, _kind, _value, _traceback) -> None:
        self.close()

    @property
    def is_open(self) -> bool:
        return self._connection is not None

    def close(self) -> None:
        if self._connection is not None:
            self._connection.commit()
            self._connection.close()
            self._connection = None  # type: ignore[assignment]

    def _create_schema(self) -> None:
        with self.transaction():
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS project_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS traffic (
                    record_id INTEGER PRIMARY KEY,
                    captured_at TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    session_key TEXT NOT NULL DEFAULT '',
                    original_raw BLOB NOT NULL,
                    effective_raw BLOB,
                    status TEXT NOT NULL,
                    msg_type TEXT NOT NULL,
                    sequence_number INTEGER,
                    modified INTEGER NOT NULL DEFAULT 0,
                    source TEXT NOT NULL,
                    framing_error TEXT,
                    bookmarked INTEGER NOT NULL DEFAULT 0,
                    note TEXT NOT NULL DEFAULT '',
                    fault_action TEXT NOT NULL DEFAULT '',
                    fault_rule TEXT NOT NULL DEFAULT '',
                    fault_reason TEXT NOT NULL DEFAULT '',
                    duplicate_of_record_id INTEGER
                );
                CREATE INDEX IF NOT EXISTS traffic_captured_at ON traffic(captured_at);
                CREATE INDEX IF NOT EXISTS traffic_msg_type ON traffic(msg_type);
                CREATE INDEX IF NOT EXISTS traffic_sequence ON traffic(sequence_number);
                CREATE TABLE IF NOT EXISTS project_state (
                    key TEXT PRIMARY KEY,
                    json_value TEXT NOT NULL
                );
                """
            )
            # Schema 1 projects predate per-connection correlation scoping.
            # Add the column in place; an empty value keeps their historical
            # correlation behavior without inventing a session identity.
            traffic_columns = {
                str(row[1]) for row in self._connection.execute("PRAGMA table_info(traffic)")
            }
            if "session_key" not in traffic_columns:
                self._connection.execute(
                    "ALTER TABLE traffic ADD COLUMN session_key TEXT NOT NULL DEFAULT ''"
                )
            for column, definition in (
                ("fault_action", "TEXT NOT NULL DEFAULT ''"),
                ("fault_rule", "TEXT NOT NULL DEFAULT ''"),
                ("fault_reason", "TEXT NOT NULL DEFAULT ''"),
                ("duplicate_of_record_id", "INTEGER"),
            ):
                if column not in traffic_columns:
                    self._connection.execute(
                        f"ALTER TABLE traffic ADD COLUMN {column} {definition}"
                    )
            self._connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            self._connection.execute(
                "INSERT OR REPLACE INTO project_meta(key, value) VALUES('format', 'FIX Inspector Project')"
            )
            self._connection.execute(
                "INSERT OR REPLACE INTO project_meta(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )

    @contextmanager
    def transaction(self) -> Iterator[None]:
        try:
            with self._connection:
                yield
        except sqlite3.DatabaseError as exc:
            raise RuntimeError(f"Project database operation failed: {exc}") from exc

    def _row_values(self, record: TrafficRecord) -> tuple[Any, ...]:
        original = self.policy.redact(record.original_raw, self.dictionary)
        effective = (
            self.policy.redact(record.effective_raw, self.dictionary)
            if record.effective_raw is not None
            else None
        )
        timestamp = record.timestamp
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return (
            record.record_id,
            timestamp.astimezone(timezone.utc).isoformat(),
            record.direction,
            record.session_key,
            sqlite3.Binary(original),
            sqlite3.Binary(effective) if effective is not None else None,
            record.status,
            record.msg_type,
            record.sequence_number,
            int(record.modified),
            record.source,
            self.policy.redact_text(record.framing_error or "") or None,
            int(record.bookmarked),
            self.policy.redact_text(record.note),
            self.policy.redact_text(record.fault_action),
            self.policy.redact_text(record.fault_rule),
            self.policy.redact_text(record.fault_reason),
            record.duplicate_of_record_id,
        )

    def save_record(self, record: TrafficRecord, *, commit: bool = True) -> None:
        try:
            self._connection.execute(
                """
            INSERT INTO traffic(
                record_id, captured_at, direction, session_key, original_raw, effective_raw, status,
                msg_type, sequence_number, modified, source, framing_error, bookmarked, note,
                fault_action, fault_rule, fault_reason, duplicate_of_record_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(record_id) DO UPDATE SET
                captured_at=excluded.captured_at,
                direction=excluded.direction,
                session_key=excluded.session_key,
                original_raw=excluded.original_raw,
                effective_raw=excluded.effective_raw,
                status=excluded.status,
                msg_type=excluded.msg_type,
                sequence_number=excluded.sequence_number,
                modified=excluded.modified,
                source=excluded.source,
                framing_error=excluded.framing_error,
                bookmarked=excluded.bookmarked,
                note=excluded.note,
                fault_action=excluded.fault_action,
                fault_rule=excluded.fault_rule,
                fault_reason=excluded.fault_reason,
                duplicate_of_record_id=excluded.duplicate_of_record_id
                """,
                self._row_values(record),
            )
            if commit:
                self._connection.commit()
        except sqlite3.DatabaseError as exc:
            raise RuntimeError(f"Could not save traffic record {record.record_id}: {exc}") from exc

    def replace_records(self, records: Iterable[TrafficRecord]) -> None:
        with self.transaction():
            self._connection.execute("DELETE FROM traffic")
            for record in records:
                self.save_record(record, commit=False)

    def save_records(self, records: Iterable[TrafficRecord]) -> None:
        """Upsert a live window without deleting older durable History rows."""
        with self.transaction():
            for record in records:
                self.save_record(record, commit=False)

    def record_count(self) -> int:
        return int(self._connection.execute("SELECT COUNT(*) FROM traffic").fetchone()[0])

    @staticmethod
    def _record_from_row(row: sqlite3.Row) -> TrafficRecord:
        timestamp = datetime.fromisoformat(row["captured_at"])
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return TrafficRecord(
            record_id=row["record_id"],
            direction=row["direction"],
            original_raw=bytes(row["original_raw"]),
            timestamp=timestamp,
            status=row["status"],
            msg_type=row["msg_type"],
            sequence_number=row["sequence_number"],
            effective_raw=bytes(row["effective_raw"]) if row["effective_raw"] is not None else None,
            modified=bool(row["modified"]),
            source=row["source"],
            framing_error=row["framing_error"],
            bookmarked=bool(row["bookmarked"]),
            note=row["note"],
            session_key=row["session_key"],
            fault_action=row["fault_action"],
            fault_rule=row["fault_rule"],
            fault_reason=row["fault_reason"],
            duplicate_of_record_id=row["duplicate_of_record_id"],
        )

    def load_records(self, *, limit: int | None = None) -> list[TrafficRecord]:
        if limit is None:
            rows = self._connection.execute("SELECT * FROM traffic ORDER BY record_id").fetchall()
        else:
            safe_limit = max(1, int(limit))
            rows = self._connection.execute(
                "SELECT * FROM traffic ORDER BY record_id DESC LIMIT ?", (safe_limit,)
            ).fetchall()
            rows.reverse()
        return [self._record_from_row(row) for row in rows]

    def reapply_redaction_policy(self) -> None:
        """Apply a newly expanded secret policy to every durable traffic row."""
        cursor = self._connection.execute("SELECT * FROM traffic ORDER BY record_id")
        with self.transaction():
            while rows := cursor.fetchmany(500):
                for row in rows:
                    self.save_record(self._record_from_row(row), commit=False)

    def backup_to(self, path: str | Path) -> None:
        """Create a transactionally consistent Save-As copy."""
        target = Path(path)
        if target.resolve() == self.path.resolve():
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        destination = sqlite3.connect(target)
        try:
            self._connection.backup(destination)
            destination.commit()
        except sqlite3.DatabaseError as exc:
            raise RuntimeError(f"Could not create project copy: {exc}") from exc
        finally:
            destination.close()

    def save_state(self, key: str, value: Mapping[str, Any] | list[Any] | str | int | bool | None) -> None:
        payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        self._connection.execute(
            "INSERT OR REPLACE INTO project_state(key, json_value) VALUES(?, ?)",
            (key, payload),
        )
        self._connection.commit()

    def save_states(self, states: Mapping[str, Any]) -> None:
        with self.transaction():
            for key, value in states.items():
                payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                self._connection.execute(
                    "INSERT OR REPLACE INTO project_state(key, json_value) VALUES(?, ?)",
                    (key, payload),
                )

    def load_state(self, key: str, default: Any = None) -> Any:
        row = self._connection.execute(
            "SELECT json_value FROM project_state WHERE key=?", (key,)
        ).fetchone()
        if row is None:
            return default
        try:
            return json.loads(row["json_value"])
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Project state {key!r} is corrupt") from exc

    def load_states(self) -> dict[str, Any]:
        rows = self._connection.execute("SELECT key, json_value FROM project_state").fetchall()
        try:
            return {row["key"]: json.loads(row["json_value"]) for row in rows}
        except json.JSONDecodeError as exc:
            raise RuntimeError("Project settings are corrupt") from exc


__all__ = ["ProjectDatabase", "SCHEMA_VERSION"]
