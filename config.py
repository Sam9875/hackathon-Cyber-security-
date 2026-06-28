"""Configuration for PromptGuard 2.0 — Regolo API backend."""

import os
from dotenv import load_dotenv

load_dotenv()

REGOLO_BASE_URL = os.getenv("REGOLO_BASE_URL", "https://api.regolo.ai/v1")
REGOLO_API_KEY = os.getenv("REGOLO_API_KEY", "")
REGOLO_MODEL = os.getenv("REGOLO_MODEL", "")

VERDICT_THRESHOLDS = {
    "SAFE": (0, 24),
    "SUSPICIOUS": (25, 54),
    "DANGEROUS": (55, 79),
    "BLOCK": (80, 100),
}

THREAT_COLORS = {
    "SAFE": "#22c55e",
    "SUSPICIOUS": "#eab308",
    "DANGEROUS": "#f97316",
    "BLOCK": "#ef4444",
}

GAUGE_COLORS = [
    (0, "#22c55e"),
    (25, "#84cc16"),
    (50, "#eab308"),
    (75, "#f97316"),
    (100, "#ef4444"),
]