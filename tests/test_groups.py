from __future__ import annotations

import unittest
from pathlib import Path

from fixinspector.fix.dictionary import FixDictionary
from fixinspector.fix.groups import project_groups
from fixinspector.fix.parser import parse_message

from tests.support import fix_message


FIXTURES = Path(__file__).resolve().parent / "fixtures"


class GroupProjectionTests(unittest.TestCase):
    def test_group_instances_annotate_without_changing_flat_order(self) -> None:
        dictionary = FixDictionary.from_files(FIXTURES / "FIXT11_MINIMAL.xml", FIXTURES / "FIX50_MINIMAL.xml")
        raw = fix_message(
            "D",
            extra_fields=[
                ("11", b"C-1"),
                ("55", b"TEST"),
                ("453", b"2"),
                ("448", b"PARTY-A"),
                ("448", b"PARTY-B"),
            ],
        )
        message = parse_message(raw, dictionary)
        projection = project_groups(message, dictionary)
        self.assertEqual([item.tag for item in message.fields], [item.field.tag for item in projection.fields])
        party_rows = [row.group_path for row in projection.fields if row.field.tag == "448"]
        self.assertEqual(["Instrument / NoPartyIDs[1]", "Instrument / NoPartyIDs[2]"], party_rows)
        parties = next(group for group in projection.groups if group.definition.count_tag == "453")
        self.assertEqual(2, parties.declared_count)
        self.assertEqual(2, len(parties.instances))
        self.assertEqual("", parties.issue)

    def test_nested_group_projection_keeps_parent_instances_and_child_paths(self) -> None:
        dictionary = FixDictionary.from_files(FIXTURES / "FIX_GROUPS_NESTED.xml")
        raw = fix_message(
            "Z",
            extra_fields=[
                ("1000", b"2"),
                ("1001", b"A"),
                ("1002", b"2"),
                ("1003", b"A1"),
                ("1003", b"A2"),
                ("1004", b"first"),
                ("1001", b"B"),
                ("1002", b"1"),
                ("1003", b"B1"),
                ("1004", b"second"),
            ],
        )
        message = parse_message(raw, dictionary)
        projection = project_groups(message, dictionary)
        self.assertEqual([item.tag for item in message.fields], [item.field.tag for item in projection.fields])
        parent = next(group for group in projection.groups if group.definition.count_tag == "1000")
        children = [group for group in projection.groups if group.definition.count_tag == "1002"]
        self.assertEqual(2, len(parent.instances))
        self.assertEqual([2, 1], [len(group.instances) for group in children])
        sub_paths = [row.group_path for row in projection.fields if row.field.tag == "1003"]
        self.assertEqual(
            [
                "Entries / NoEntries / NoSubEntries[1]",
                "Entries / NoEntries / NoSubEntries[2]",
                "Entries / NoEntries / NoSubEntries[1]",
            ],
            sub_paths,
        )


if __name__ == "__main__":
    unittest.main()
