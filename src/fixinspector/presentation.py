"""Presentation-only labels for stable internal traffic directions."""

from __future__ import annotations


CLIENT_TO_SERVER = "C→S"
SERVER_TO_CLIENT = "S→C"


def display_status(value: object) -> str:
    """Format generated status prose without changing persisted enum identifiers."""
    return str(value).replace("\u2014", "-")

DIRECTION_LABELS = {
    CLIENT_TO_SERVER: "Client → Server",
    SERVER_TO_CLIENT: "Server → Client",
}

_DIRECTION_ALIASES = {
    "C→S": CLIENT_TO_SERVER,
    "C -> S": CLIENT_TO_SERVER,
    "C-S": CLIENT_TO_SERVER,
    "CLIENT → SERVER": CLIENT_TO_SERVER,
    "CLIENT -> SERVER": CLIENT_TO_SERVER,
    "S→C": SERVER_TO_CLIENT,
    "S -> C": SERVER_TO_CLIENT,
    "S-C": SERVER_TO_CLIENT,
    "SERVER → CLIENT": SERVER_TO_CLIENT,
    "SERVER -> CLIENT": SERVER_TO_CLIENT,
}


def internal_direction(value: object) -> str:
    """Return the stable internal direction identifier for a UI label/alias."""
    text = str(value).strip()
    return _DIRECTION_ALIASES.get(text.upper(), text)


def display_direction(value: object) -> str:
    """Return the long user-facing label without changing stored identifiers."""
    internal = internal_direction(value)
    return DIRECTION_LABELS.get(internal, str(value))


def display_direction_text(value: object) -> str:
    """Expand direction tokens embedded in status/journal text."""
    text = str(value)
    replacements = (
        ("CLIENT -> SERVER", "Client → Server"),
        ("SERVER -> CLIENT", "Server → Client"),
        ("CLIENT → SERVER", "Client → Server"),
        ("SERVER → CLIENT", "Server → Client"),
        ("C -> S", "Client → Server"),
        ("S -> C", "Server → Client"),
        ("C→S", "Client → Server"),
        ("S→C", "Server → Client"),
        ("C-S", "Client → Server"),
        ("S-C", "Server → Client"),
    )
    for source, target in replacements:
        text = text.replace(source, target)
    return text


__all__ = [
    "CLIENT_TO_SERVER",
    "DIRECTION_LABELS",
    "SERVER_TO_CLIENT",
    "display_direction",
    "display_direction_text",
    "display_status",
    "internal_direction",
]
