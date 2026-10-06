from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import sqlite3

from fixinspector.project import ProjectDatabase, SecretRedactionPolicy
from fixinspector.records import TrafficRecord

from tests.support import fix_message


class ProjectPersistenceTests(unittest.TestCase):
    def test_schema_one_project_migrates_session_identity_column(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            path = Path(directory) / "legacy.fixproj"
            connection = sqlite3.connect(path)
            connection.executescript(
                """
                CREATE TABLE traffic (
                    record_id INTEGER PRIMARY KEY,
                    captured_at TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    original_raw BLOB NOT NULL,
                    effective_raw BLOB,
                    status TEXT NOT NULL,
                    msg_type TEXT NOT NULL,
                    sequence_number INTEGER,
                    modified INTEGER NOT NULL DEFAULT 0,
                    source TEXT NOT NULL,
                    framing_error TEXT,
                    bookmarked INTEGER NOT NULL DEFAULT 0,
                    note TEXT NOT NULL DEFAULT ''
                );
                PRAGMA user_version=1;
                """
            )
            connection.close()

            record = TrafficRecord(
                1,
                "C→S",
                fix_message("D", 1),
                msg_type="D",
                sequence_number=1,
                session_key="connection-migrated",
            )
            with ProjectDatabase(path) as project:
                project.save_record(record)
                loaded = project.load_records()[0]
                version = project._connection.execute("PRAGMA user_version").fetchone()[0]

            self.assertEqual(3, version)
            self.assertEqual("connection-migrated", loaded.session_key)

    def test_round_trip_history_annotations_state_and_redaction(self) -> None:
        record = TrafficRecord(
            41,
            "C→S",
            fix_message("A", 1, [("553", b"never-write-me"), ("9001", b"extra-secret")]),
            status="FORWARDED",
            msg_type="A",
            sequence_number=1,
            bookmarked=True,
            note="checked 553=note secret with spaces",
        )
        record.raw = fix_message("A", 1, [("553", b"changed-secret"), ("9001", b"changed-extra")])
        policy = SecretRedactionPolicy(frozenset({"9001"}))
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            path = Path(directory) / "project.fixproj"
            with ProjectDatabase(path, policy=policy) as project:
                project.replace_records([record])
                project.save_states(
                    {
                        "history_filter": {"expression": "msgtype=A", "advanced": True},
                        "ui_layout": {"tab": 1, "splitter": "encoded"},
                    }
                )
                loaded = project.load_records()
                state = project.load_states()

            persisted = path.read_bytes()
            self.assertNotIn(b"never-write-me", persisted)
            self.assertNotIn(b"changed-secret", persisted)
            self.assertNotIn(b"extra-secret", persisted)
            self.assertNotIn(b"note-secret", persisted)
            self.assertEqual(1, len(loaded))
            self.assertTrue(loaded[0].bookmarked)
            self.assertEqual("checked 553=<REDACTED>", loaded[0].note)
            self.assertIn(b"553=<REDACTED>", loaded[0].original_raw)
            self.assertIn(b"9001=<REDACTED>", loaded[0].raw)
            self.assertTrue(loaded[0].modified)
            self.assertEqual("msgtype=A", state["history_filter"]["expression"])

    def test_malformed_state_is_reported_without_modifying_traffic(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            path = Path(directory) / "project.fixproj"
            with ProjectDatabase(path) as project:
                project.save_state("ok", {"value": 1})
                project._connection.execute(
                    "INSERT OR REPLACE INTO project_state(key, json_value) VALUES('broken', '{')"
                )
                project._connection.commit()
                with self.assertRaises(RuntimeError):
                    project.load_state("broken")

    def test_fault_evidence_round_trips_and_redacts_rule_metadata(self) -> None:
        record = TrafficRecord(
            77,
            "S→C",
            fix_message("8", 9),
            status="DROPPED",
            msg_type="8",
            fault_action="DROP",
            fault_rule="secret selector 553=do-not-store",
            fault_reason="First matching rule 553=do-not-store",
            duplicate_of_record_id=76,
        )
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            path = Path(directory) / "fault.fixproj"
            with ProjectDatabase(path) as project:
                project.save_record(record)
                loaded = project.load_records()[0]
            persisted = path.read_bytes()
        self.assertNotIn(b"do-not-store", persisted)
        self.assertEqual("DROP", loaded.fault_action)
        self.assertIn("<REDACTED>", loaded.fault_rule)
        self.assertEqual(76, loaded.duplicate_of_record_id)


if __name__ == "__main__":
    unittest.main()
