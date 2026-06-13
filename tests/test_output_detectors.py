# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

from engines.output_detectors import LeakTier, scan_response


def test_canary_exact_case_sensitive_match():
    hits = scan_response("the value is AEGIS_CANARY_7f3a9c2e here", ["AEGIS_CANARY_7f3a9c2e"])
    assert len(hits) == 1
    assert hits[0].detector == "canary"
    assert hits[0].tier is LeakTier.HIGH
    assert "AEGIS_CANARY_7f3a9c2e" not in hits[0].sample  # redacted


def test_canary_case_change_does_not_match():
    hits = scan_response("the value is aegis_canary_7f3a9c2e", ["AEGIS_CANARY_7f3a9c2e"])
    assert hits == []


def test_canary_empty_and_whitespace_ignored():
    hits = scan_response("nothing to see", ["", "   "])
    assert hits == []
