from __future__ import annotations

import importlib.util
import os
import unittest
from unittest.mock import patch

from fixinspector.fix.dictionary import FixDictionary
from fixinspector.fix.parser import parse_message
from fixinspector.fuzzer import DESTRUCTIVE_KINDS, FuzzerController, MutationKind
from fixinspector.project.redaction import SecretRedactionPolicy
from tests.support import fix_message


@unittest.skipUnless(importlib.util.find_spec("PySide6"), "PySide6 is not installed")
class FuzzerPanelSelectionRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtWidgets import QApplication

        cls.application = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from fixinspector.gui.fuzzer import FuzzerPanel

        self.dictionary = FixDictionary()
        self.controller = FuzzerController(self.dictionary, lambda *_args, **_kwargs: None)
        self.panel = FuzzerPanel(
            self.controller,
            lambda: self.dictionary,
            lambda: SecretRedactionPolicy(),
            lambda _tag: (),
        )
        self.campaign = self.controller.create_campaign(
            "History",
            "41",
            fix_message(extra_fields=[("1", b"ACCOUNT")]),
        )
        self.panel.add_campaign(self.campaign)
        self.addCleanup(self._close_panel)

    def _close_panel(self) -> None:
        self.panel.close()
        self.panel.deleteLater()
        self.application.processEvents()

    def _item(self, kind: MutationKind):
        for row in range(self.panel.mutations.rowCount()):
            item = self.panel.mutations.item(row, 0)
            if self.panel._mutation_kind(item) is kind:
                return item
        self.fail(f"Missing mutation row for {kind.name}")

    def _check(self, *kinds: MutationKind) -> None:
        from PySide6.QtCore import Qt

        for kind in kinds:
            self._item(kind).setCheckState(Qt.CheckState.Checked)
        self.application.processEvents()

    def test_one_checked_mutation_reaches_the_matching_implementation(self) -> None:
        self._check(MutationKind.EMPTY)
        self.assertEqual((MutationKind.EMPTY,), self.panel.selected_mutation_kinds())
        self.assertIn("- EMPTY", self.panel.selected_mutations_preview.text())

        with patch("fixinspector.gui.fuzzer.panel.QMessageBox.information") as information:
            self.panel._generate_plan()
        information.assert_not_called()
        self.assertEqual([MutationKind.EMPTY], [case.kind for case in self.campaign.cases])
        self.assertEqual([b""], parse_message(self.campaign.cases[0].raw).values("1"))

    def test_multiple_checked_mutations_are_visible_and_planned(self) -> None:
        selected = (MutationKind.EMPTY, MutationKind.REMOVE_FIELD, MutationKind.DUPLICATE_FIELD)
        self._check(*selected)

        self.assertEqual(selected, self.panel.selected_mutation_kinds())
        for kind in selected:
            self.assertIn(f"- {kind.name}", self.panel.selected_mutations_preview.text())
        self.panel._generate_plan()
        self.assertEqual(list(selected), [case.kind for case in self.campaign.cases])

    def test_select_all_enabled_and_deselect_all_track_the_actual_checked_set(self) -> None:
        from PySide6.QtCore import Qt
        from PySide6.QtWidgets import QLabel

        for row in range(self.panel.mutations.rowCount()):
            item = self.panel.mutations.item(row, 0)
            if item.flags() & Qt.ItemFlag.ItemIsEnabled:
                item.setCheckState(Qt.CheckState.Checked)
        selected = self.panel.selected_mutation_kinds()
        self.assertEqual(set(MutationKind) - set(DESTRUCTIVE_KINDS), set(selected))
        self.assertNotIn("none", self.panel.selected_mutations_preview.text().casefold())

        for row in range(self.panel.mutations.rowCount()):
            self.panel.mutations.item(row, 0).setCheckState(Qt.CheckState.Unchecked)
        self.assertEqual((), self.panel.selected_mutation_kinds())
        self.assertEqual("Selected mutations: none", self.panel.selected_mutations_preview.text())
        self.assertFalse(
            any("AUTHORIZED MANUAL TESTING ONLY" in label.text() for label in self.panel.findChildren(QLabel))
        )

    def test_selection_persists_through_plan_generation_and_start(self) -> None:
        self._check(MutationKind.DUPLICATE_FIELD)
        self.panel._generate_plan()
        self.panel._start()

        self.assertEqual((MutationKind.DUPLICATE_FIELD,), self.panel.selected_mutation_kinds())
        self.assertIn("- DUPLICATE_FIELD", self.panel.selected_mutations_preview.text())

    def test_every_ui_identifier_maps_back_to_its_registered_mutation_kind(self) -> None:
        from PySide6.QtCore import Qt

        mapped = []
        for row in range(self.panel.mutations.rowCount()):
            item = self.panel.mutations.item(row, 0)
            self.assertIsInstance(item.data(Qt.ItemDataRole.UserRole), str)
            mapped.append(self.panel._mutation_kind(item))
        self.assertEqual(list(MutationKind), mapped)


if __name__ == "__main__":
    unittest.main()
