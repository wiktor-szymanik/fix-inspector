from __future__ import annotations

import unittest
from pathlib import Path

from fixinspector.fix.dictionary import FixDictionary


FIXTURES = Path(__file__).resolve().parent / "fixtures"
TRANSPORT = FIXTURES / "FIXT11_MINIMAL.xml"
APPLICATION = FIXTURES / "FIX50_MINIMAL.xml"


class DictionaryCharacterizationTests(unittest.TestCase):
    def test_loads_transport_and_application_dictionaries_cumulatively(self) -> None:
        dictionary = FixDictionary.from_files(TRANSPORT, APPLICATION)

        self.assertEqual("STRING", dictionary.field("11").field_type)
        self.assertEqual("NEW_ORDER_SINGLE", dictionary.field("35").enums["D"])
        self.assertEqual("NewOrderSingle", dictionary.message_name("D"))
        self.assertEqual("app", dictionary.message_category("D"))
        self.assertFalse(dictionary.is_admin("D"))
        self.assertTrue(dictionary.is_admin("A"))

    def test_tracks_required_fields_and_component_group_paths(self) -> None:
        dictionary = FixDictionary.from_files(TRANSPORT, APPLICATION)

        message = dictionary.message("D")
        self.assertEqual({"11", "55"}, message.required_tags)
        self.assertEqual("Instrument", dictionary.group_path("D", "453"))
        self.assertEqual("Instrument / NoPartyIDs", dictionary.group_path("D", "448"))

    def test_component_cycle_is_bounded(self) -> None:
        dictionary = FixDictionary.from_files(TRANSPORT, APPLICATION)

        self.assertIsNotNone(dictionary.message("D"))


if __name__ == "__main__":
    unittest.main()
