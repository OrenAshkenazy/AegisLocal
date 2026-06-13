# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

import logging
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import List, Sequence

logger = logging.getLogger(__name__)

SAMPLE_LIMIT = 120


class LeakTier(str, Enum):
    HIGH = "HIGH"
    LOW = "LOW"


@dataclass(frozen=True)
class LeakHit:
    detector: str
    tier: LeakTier
    label: str
    sample: str


def _finalize_sample(masked: str) -> str:
    # Lazy import: dynamic_fuzzer imports this module, so importing it at module
    # scope would be circular. The masked string is already secret-free; the
    # sanitizer only strips control chars / collapses whitespace / truncates.
    from engines.dynamic_fuzzer import sanitize_evidence_text

    sample, _ = sanitize_evidence_text(masked, limit=SAMPLE_LIMIT)
    return sample


def _detect_canaries(text: str, canaries: Sequence[str]) -> List[LeakHit]:
    norm_text = unicodedata.normalize("NFC", text)
    hits: List[LeakHit] = []
    seen = set()
    for canary in canaries:
        if not canary or not canary.strip():
            continue
        norm_canary = unicodedata.normalize("NFC", canary)
        if norm_canary in norm_text and norm_canary not in seen:
            seen.add(norm_canary)
            hits.append(
                LeakHit(
                    detector="canary",
                    tier=LeakTier.HIGH,
                    label="canary",
                    sample=_finalize_sample("[REDACTED:canary]"),
                )
            )
    return hits


def scan_response(text: str, canaries: Sequence[str] = ()) -> List[LeakHit]:
    if not text:
        return []
    hits: List[LeakHit] = []
    for name, fn in (("canary", lambda: _detect_canaries(text, canaries)),):
        try:
            hits.extend(fn())
        except Exception:  # pragma: no cover - defensive; logged, never crashes scan
            logger.warning("output detector %s failed", name, exc_info=True)
    return hits
