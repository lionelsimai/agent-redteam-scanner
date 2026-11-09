"""Environment-based configuration — no hardcoded secrets."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    """Runtime configuration loaded from the environment."""

    demo_secret: str = "sk_live_DEMO_NOT_A_REAL_KEY"
    max_payloads: int = 100
    canary_secret: str | None = None

    @classmethod
    def from_env(cls) -> Config:
        """Build config from ``REDTEAM_*`` environment variables."""
        return cls(
            demo_secret=os.environ.get("REDTEAM_DEMO_SECRET", cls.demo_secret),
            max_payloads=int(os.environ.get("REDTEAM_MAX_PAYLOADS", "100")),
            canary_secret=os.environ.get("REDTEAM_CANARY_SECRET") or None,
        )
