"""Local rotating application logs with mandatory FIX secret redaction."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import threading

from .project.redaction import SecretRedactionPolicy

_LOCK = threading.RLock()
_FORMATTER: "SecretRedactingFormatter | None" = None
_LOG_PATH: Path | None = None


class SecretRedactingFormatter(logging.Formatter):
    """Redact configured ``tag=value`` material after normal formatting.

    Redacting the final rendered line also covers lazy logging arguments and
    byte ``repr`` values containing the literal ``\\x01`` delimiter.
    """

    def __init__(self, policy: SecretRedactionPolicy | None = None) -> None:
        super().__init__(
            "%(asctime)s %(levelname)s %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
        self.policy = policy or SecretRedactionPolicy()

    def format(self, record: logging.LogRecord) -> str:
        rendered = super().format(record)
        # A bytes repr uses the printable four-character delimiter ``\\x01``.
        # Convert only for redaction, then retain a readable visible separator.
        normalized = rendered.replace("\\x01", "␁")
        return self.policy.redact_text(normalized)


def default_log_path() -> Path:
    root = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
    base = Path(root) if root else Path.cwd()
    return base / "FIX Inspector" / "logs" / "fix-inspector.log"


def configure_logging(
    policy: SecretRedactionPolicy | None = None,
    *,
    path: str | Path | None = None,
    max_bytes: int = 2 * 1024 * 1024,
    backup_count: int = 4,
) -> Path | None:
    """Configure a bounded local log, returning ``None`` if storage fails.

    Logging must never prevent the proxy from starting. No traffic bytes are
    logged by default; the formatter is a second boundary for diagnostic text.
    """

    global _FORMATTER, _LOG_PATH
    with _LOCK:
        target = Path(path) if path is not None else default_log_path()
        logger = logging.getLogger("fixinspector")
        logger.setLevel(logging.INFO)
        logger.propagate = False
        for handler in tuple(logger.handlers):
            logger.removeHandler(handler)
            try:
                handler.close()
            except OSError:
                pass
        _FORMATTER = SecretRedactingFormatter(policy)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(
                target,
                maxBytes=max(64 * 1024, int(max_bytes)),
                backupCount=max(1, int(backup_count)),
                encoding="utf-8",
            )
            handler.setFormatter(_FORMATTER)
            logger.addHandler(handler)
            _LOG_PATH = target
        except OSError:
            logger.addHandler(logging.NullHandler())
            _LOG_PATH = None
        return _LOG_PATH


def update_logging_policy(policy: SecretRedactionPolicy) -> None:
    with _LOCK:
        if _FORMATTER is not None:
            _FORMATTER.policy = policy


def current_log_path() -> Path | None:
    return _LOG_PATH


def shutdown_logging() -> None:
    """Flush and close FIX Inspector handlers (primarily app shutdown/tests)."""
    global _FORMATTER, _LOG_PATH
    with _LOCK:
        logger = logging.getLogger("fixinspector")
        for handler in tuple(logger.handlers):
            logger.removeHandler(handler)
            handler.close()
        _FORMATTER = None
        _LOG_PATH = None


__all__ = [
    "SecretRedactingFormatter",
    "configure_logging",
    "current_log_path",
    "default_log_path",
    "shutdown_logging",
    "update_logging_policy",
]
