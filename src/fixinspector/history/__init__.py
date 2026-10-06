"""Search and presentation services for captured traffic."""

from .filtering import FilterSyntaxError, HistoryDocument, compile_filter, matches_text
from .retention import HistoryRetentionPolicy, UNRESOLVED_STATUSES

__all__ = [
    "FilterSyntaxError",
    "HistoryDocument",
    "HistoryRetentionPolicy",
    "UNRESOLVED_STATUSES",
    "compile_filter",
    "matches_text",
]
