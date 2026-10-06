from __future__ import annotations

import difflib

from PySide6.QtWidgets import QPlainTextEdit

from ...fix.parser import parse_message, raw_to_editor_text
from ...fix.validation import validate_message


class MessageDiffWidget(QPlainTextEdit):
    """Reusable original/effective FIX diff view."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setReadOnly(True)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)

    def set_messages(self, original: bytes, effective: bytes) -> None:
        left = raw_to_editor_text(original).split("|")
        right = raw_to_editor_text(effective).split("|")
        self.setPlainText(
            "\n".join(
                difflib.unified_diff(left, right, fromfile="original", tofile="effective", lineterm="")
            )
            or "No differences."
        )


class MessageValidationWidget(QPlainTextEdit):
    """Reusable non-blocking protocol and dictionary validation report."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setReadOnly(True)

    def set_message(self, raw: bytes, dictionary, model_issues: list[str] | None = None) -> None:
        issues = list(model_issues or [])
        try:
            issues.extend(
                f"{issue.level}: {issue.text}"
                for issue in validate_message(parse_message(raw, dictionary), dictionary)
            )
        except (TypeError, ValueError) as exc:
            issues.append(str(exc))
        self.setPlainText("\n".join(f"• {issue}" for issue in issues) if issues else "No issues detected.")


__all__ = ["MessageDiffWidget", "MessageValidationWidget"]
