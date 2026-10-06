"""Ordered, duplicate-preserving FIX fields."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class FixField:
    tag: str
    value: bytes

__all__ = ["FixField"]
