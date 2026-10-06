"""Shared message inspector/editor and reusable Qt widgets."""

from .table_copy import TableCopySupport
from .message_editor import MessageEditorWidget
from .message_analysis import MessageDiffWidget, MessageValidationWidget

__all__ = ["MessageDiffWidget", "MessageEditorWidget", "MessageValidationWidget", "TableCopySupport"]
