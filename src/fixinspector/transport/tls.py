"""Upstream TLS configuration, context creation, and negotiated metadata."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import ssl


@dataclass(frozen=True, slots=True)
class TLSSettings:
    verify: bool = True
    ca_file: str = ""
    tls13_only: bool = True

    def __post_init__(self) -> None:
        if self.ca_file:
            path = Path(self.ca_file).expanduser()
            if not path.is_file():
                raise ValueError(f"Custom CA file does not exist or is not a file: {path}")

    @property
    def verification_label(self) -> str:
        if not self.verify:
            return "DISABLED - testing only"
        if self.ca_file:
            return f"Verified (custom CA: {Path(self.ca_file).name})"
        return "Verified (system trust)"


@dataclass(frozen=True, slots=True)
class TLSNegotiated:
    verification: str
    version: str = ""
    cipher: str = ""


def build_client_context(settings: TLSSettings) -> ssl.SSLContext:
    if settings.verify:
        context = ssl.create_default_context(cafile=settings.ca_file or None)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    if settings.tls13_only:
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
    return context
