# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

import base64
import json
import logging
import math
import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import List, Sequence

logger = logging.getLogger(__name__)

SAMPLE_LIMIT = 120

PLACEHOLDER_VALUES = {
    "your_api_key_here",
    "example_token",
    "redacted",
    "dummy",
    "test",
    "placeholder",
}

ENTROPY_MIN_VALUE_LEN = 20
ENTROPY_MIN_BITS = 3.5

_AWS_KEY_RE = re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")
_PEM_RE = re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")
_SK_RE = re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")
_SLACK_RE = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")
_JWT_RE = re.compile(r"\b([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\b")
_GENERIC_SECRET_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|apikey|secret|token|password)\s*[:=]\s*['\"]?([^'\"\s,;]+)"
)


class LeakTier(str, Enum):
    HIGH = "HIGH"
    LOW = "LOW"


@dataclass(frozen=True)
class LeakHit:
    detector: str
    tier: LeakTier
    label: str
    sample: str


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {c: value.count(c) for c in set(value)}
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _b64url_decode(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _is_valid_jwt_header(segment: str) -> bool:
    try:
        header = json.loads(_b64url_decode(segment))
    except (ValueError, json.JSONDecodeError):
        return False
    return isinstance(header, dict) and ("alg" in header or "typ" in header)


def _finalize_sample(masked: str) -> str:
    # Lazy import: dynamic_fuzzer imports this module, so importing it at module
    # scope would be circular. The masked string is already secret-free; the
    # sanitizer only strips control chars / collapses whitespace / truncates.
    from engines.dynamic_fuzzer import sanitize_evidence_text

    sample, _ = sanitize_evidence_text(masked, limit=SAMPLE_LIMIT)
    return sample


def _detect_secrets(text: str) -> List[LeakHit]:
    hits: List[LeakHit] = []
    if _AWS_KEY_RE.search(text):
        hits.append(LeakHit("secret", LeakTier.HIGH, "aws_access_key", _finalize_sample("AKIA…REDACTED")))
    if _PEM_RE.search(text):
        hits.append(LeakHit("secret", LeakTier.HIGH, "private_key", _finalize_sample("[REDACTED:private_key]")))
    if _SK_RE.search(text):
        hits.append(LeakHit("secret", LeakTier.HIGH, "sk_token", _finalize_sample("[REDACTED:sk_token]")))
    if _SLACK_RE.search(text):
        hits.append(LeakHit("secret", LeakTier.HIGH, "slack_token", _finalize_sample("[REDACTED:slack_token]")))
    for match in _JWT_RE.finditer(text):
        if _is_valid_jwt_header(match.group(1)):
            hits.append(LeakHit("secret", LeakTier.HIGH, "jwt", _finalize_sample("[REDACTED:jwt]")))
            break
    for match in _GENERIC_SECRET_RE.finditer(text):
        value = match.group(1)
        if value.lower() in PLACEHOLDER_VALUES:
            continue
        if len(value) >= ENTROPY_MIN_VALUE_LEN and _shannon_entropy(value) >= ENTROPY_MIN_BITS:
            hits.append(LeakHit("secret", LeakTier.HIGH, "generic_secret", _finalize_sample("[REDACTED:generic_secret]")))
            break
    return hits


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
    for name, fn in (
        ("canary", lambda: _detect_canaries(text, canaries)),
        ("secret", lambda: _detect_secrets(text)),
    ):
        try:
            hits.extend(fn())
        except Exception:  # pragma: no cover - defensive; logged, never crashes scan
            logger.warning("output detector %s failed", name, exc_info=True)
    return hits
