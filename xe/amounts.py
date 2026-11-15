"""Amounts are integers in micro-units on the wire: 1 XE = 1,000,000 µXE (same for XUSD)."""

from __future__ import annotations

from decimal import Decimal

MICRO = 1_000_000


def from_micro(micro: int) -> str:
    d = Decimal(int(micro)) / MICRO
    s = f"{d:.6f}".rstrip("0").rstrip(".")
    return s if s else "0"
