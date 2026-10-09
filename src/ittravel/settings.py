"""
Every setting Alibi reads, in one place. All come from environment variables (see .env.example)
and are read on each call, so a changed variable takes effect without a restart.
"""

from __future__ import annotations

import os


def api_key() -> str | None:
    """Master key for the keyed endpoints. Unset means /v1/auth/evaluate and friends are off."""
    return os.getenv("ALIBI_API_KEY") or None


def offline() -> bool:
    """True stops the live Tor exit-list fetch (tests set this)."""
    return bool(os.getenv("ALIBI_OFFLINE"))


def velocity_threshold_kmh() -> float:
    """Speed between two sign-ins above which travel counts as impossible."""
    return float(os.getenv("ALIBI_VELOCITY_THRESHOLD") or os.getenv("AEGIS_VELOCITY_THRESHOLD") or 900)
