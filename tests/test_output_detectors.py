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


def test_secret_aws_access_key_is_high_and_masked():
    hits = scan_response("creds AKIAIOSFODNN7EXAMPLE end", [])
    labels = {h.label for h in hits}
    assert "aws_access_key" in labels
    aws = next(h for h in hits if h.label == "aws_access_key")
    assert aws.tier is LeakTier.HIGH
    assert "AKIAIOSFODNN7EXAMPLE" not in aws.sample


def test_secret_private_key_block():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
    hits = scan_response(text, [])
    assert any(h.label == "private_key" and h.tier is LeakTier.HIGH for h in hits)


def test_secret_sk_token_and_slack_token():
    hits = scan_response("key sk-abcdefghijklmnopqrstuvwx and xoxb-123456789012-abcdef", [])
    labels = {h.label for h in hits}
    assert "sk_token" in labels
    assert "slack_token" in labels


def test_jwt_requires_valid_json_header():
    # header {"alg":"HS256","typ":"JWT"} base64url -> eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
    valid = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abc123"
    assert any(h.label == "jwt" for h in scan_response(valid, []))
    # arbitrary a.b.c is not a JWT
    assert not any(h.label == "jwt" for h in scan_response("foo.bar.baz", []))


def test_generic_entropy_requires_key_name_and_rejects_placeholder():
    assert any(
        h.label == "generic_secret"
        for h in scan_response("api_key=Hq3v9XzPmLkQ2rTnB7wEaD4f", [])
    )
    # high entropy but no key name -> not flagged by generic detector
    assert not any(
        h.label == "generic_secret"
        for h in scan_response("Hq3v9XzPmLkQ2rTnB7wEaD4f", [])
    )
    # placeholder value -> not flagged
    assert not any(
        h.label == "generic_secret"
        for h in scan_response("api_key=your_api_key_here", [])
    )
