# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path

import pytest

from core.models import Payload, Severity
import engines.dynamic_fuzzer as dynamic_fuzzer
from engines.dynamic_fuzzer import (
    DYNAMIC_CONCURRENCY,
    JUDGE_RESPONSE_SCHEMA,
    JudgeDecision,
    JudgeConfig,
    TARGET_TIMEOUT_SECONDS,
    PayloadEvaluation,
    build_chat_payload,
    build_dynamic_assessments,
    build_dynamic_evidence,
    calibrate_judge,
    evaluate_response,
    extract_response_text,
    group_dynamic_findings,
    load_payloads,
    parse_strict_judge_decision,
    sanitize_evidence_text,
)


def test_extract_response_text_supports_openai_and_ollama_shapes():
    assert (
        extract_response_text({"choices": [{"message": {"content": "openai"}}]})
        == "openai"
    )
    assert extract_response_text({"message": {"content": "ollama chat"}}) == "ollama chat"
    assert extract_response_text({"response": "ollama generate"}) == "ollama generate"


def test_parse_strict_judge_decision_requires_exact_schema_json():
    verdict, reason = parse_strict_judge_decision(
        '{"verdict": "FAIL", "reason": "The model complied."}'
    )

    assert verdict == "FAIL"
    assert reason == "The model complied."

    invalid_verdict, invalid_reason = parse_strict_judge_decision(
        "The result is FAIL."
    )

    assert invalid_verdict is None
    assert invalid_reason is None


def test_parse_strict_judge_decision_keeps_valid_unknown_verdict():
    verdict, reason = parse_strict_judge_decision(
        '{"verdict": "UNKNOWN", "reason": "The response is ambiguous."}'
    )

    assert verdict == "UNKNOWN"
    assert reason == "The response is ambiguous."


def test_parse_strict_judge_decision_extracts_json_from_wrapped_output():
    verdict, reason = parse_strict_judge_decision(
        'Judge result:\n```json\n{"verdict": "FAIL", "reason": "The model complied."}\n```'
    )

    assert verdict == "FAIL"
    assert reason == "The model complied."


def test_judge_chat_payload_uses_structured_deterministic_settings():
    payload = build_chat_payload(
        "judge",
        [{"role": "user", "content": "classify"}],
        deterministic=True,
        response_schema=JUDGE_RESPONSE_SCHEMA,
        endpoint="http://localhost:11434/v1/chat/completions",
    )

    assert payload["temperature"] == 0.0
    assert payload["top_p"] == 0.1
    assert payload["seed"] == 42
    assert payload["max_tokens"] == 160
    assert payload["stream"] is False
    assert payload["response_format"]["type"] == "json_schema"
    assert payload["response_format"]["json_schema"]["strict"] is True


def test_judge_chat_payload_uses_passed_response_schema():
    response_schema = {
        "type": "object",
        "required": ["status"],
        "properties": {"status": {"type": "string"}},
    }

    payload = build_chat_payload(
        "judge",
        [{"role": "user", "content": "classify"}],
        response_schema=response_schema,
        endpoint="http://localhost:11434/v1/chat/completions",
    )

    assert payload["response_format"]["json_schema"]["schema"] == response_schema


def test_sanitize_evidence_text_truncates_and_redacts_common_sensitive_values():
    excerpt, truncated = sanitize_evidence_text(
        " token=abc123\nemail test@example.com " + ("x" * 600),
        limit=80,
    )

    assert "[REDACTED]" in excerpt
    assert "test@example.com" not in excerpt
    assert "\n" not in excerpt
    assert truncated is True


def test_dynamic_defaults_are_conservative_for_local_inference():
    assert TARGET_TIMEOUT_SECONDS == 30
    assert DYNAMIC_CONCURRENCY == 1


def test_group_dynamic_findings_by_category_counts_and_ids():
    payload_1 = Payload(
        id="pi-002",
        category="Direct Prompt Injection",
        severity=Severity.HIGH,
        text="payload",
        expected_behavior="refuse",
        tags=[],
    )
    payload_2 = payload_1.model_copy(update={"id": "pi-001", "severity": Severity.CRITICAL})
    payload_3 = payload_1.model_copy(update={"id": "code-001", "category": "Code"})

    grouped = group_dynamic_findings(
        [
            PayloadEvaluation(payload=payload_1, failed=True),
            PayloadEvaluation(payload=payload_2, failed=True),
            PayloadEvaluation(payload=payload_3, failed=False),
        ]
    )

    assert len(grouped) == 1
    assert grouped[0].category == "Direct Prompt Injection"
    assert grouped[0].severity == Severity.CRITICAL
    assert grouped[0].failed_count == 2
    assert grouped[0].payload_ids == ["pi-001", "pi-002"]


def test_load_payloads_requires_minimum_categories(tmp_path):
    payload_file = tmp_path / "payloads.json"
    payload_file.write_text(
        json.dumps(
            [
                {
                    "id": "pi-001",
                    "category": "Direct Prompt Injection",
                    "severity": "CRITICAL",
                    "text": "payload",
                    "expected_behavior": "refuse",
                    "tags": ["OWASP:LLM01"],
                }
            ]
        ),
        encoding="utf-8",
    )

    payloads, errors = load_payloads(payload_file)

    assert len(payloads) == 1
    assert len(errors) == 1
    assert "missing required categories" in errors[0].message


def test_bundled_payload_file_is_valid():
    payloads, errors = load_payloads(Path("data/payloads.json"))

    assert errors == []
    assert len(payloads) >= 12
    assert {
        "Jailbreak / Safety Bypass",
        "System Prompt Extraction",
        "Sensitive Data Exfiltration",
        "Tool Abuse",
        "RAG Context Manipulation",
        "Policy Evasion",
        "Harmful Instruction Compliance",
    }.issubset({payload.category for payload in payloads})


@pytest.mark.asyncio
async def test_fallback_judge_recovery_records_primary_error(monkeypatch):
    payload = Payload(
        id="pi-001",
        category="Direct Prompt Injection",
        severity=Severity.CRITICAL,
        text="payload",
        expected_behavior="refuse",
        tags=[],
    )

    async def fake_call_judge(payload, target_response, judge):
        if judge.model == "primary":
            raise RuntimeError("primary unavailable")
        return JudgeDecision(verdict="PASS", reason="The model refused.")

    monkeypatch.setattr(dynamic_fuzzer, "_call_judge", fake_call_judge)

    decision = await evaluate_response(
        payload=payload,
        target_response="safe response",
        primary_judge=JudgeConfig(endpoint="http://localhost:11434/v1/chat/completions", model="primary"),
        fallback_judge=JudgeConfig(endpoint="http://localhost:11434/v1/chat/completions", model="fallback"),
    )

    assert decision.verdict == "PASS"
    assert decision.judge_model == "fallback"
    assert decision.reason == "The model refused."
    assert decision.confidence == "MEDIUM"
    assert decision.judge_agreement == "1/2"
    assert len(decision.errors) == 1
    assert decision.errors[0].message == "Primary judge request failed"


@pytest.mark.asyncio
async def test_invalid_primary_and_fallback_verdict_records_unknown(monkeypatch):
    payload = Payload(
        id="pi-001",
        category="Direct Prompt Injection",
        severity=Severity.CRITICAL,
        text="payload",
        expected_behavior="refuse",
        tags=[],
    )

    async def fake_call_judge(payload, target_response, judge):
        return JudgeDecision(verdict=None)

    monkeypatch.setattr(dynamic_fuzzer, "_call_judge", fake_call_judge)

    decision = await evaluate_response(
        payload=payload,
        target_response="ambiguous response",
        primary_judge=JudgeConfig(endpoint="http://localhost:11434/v1/chat/completions", model="primary"),
        fallback_judge=JudgeConfig(endpoint="http://localhost:11434/v1/chat/completions", model="fallback"),
    )

    assert decision.verdict is None
    assert decision.confidence == "LOW"
    assert decision.judge_agreement == "0/2"
    assert decision.errors[-1].message == "Payload security result is UNKNOWN after judge attempts"


@pytest.mark.asyncio
async def test_unknown_judge_verdict_is_not_an_execution_error(monkeypatch):
    payload = Payload(
        id="pi-001",
        category="Direct Prompt Injection",
        severity=Severity.CRITICAL,
        text="payload",
        expected_behavior="refuse",
        tags=[],
    )

    async def fake_call_judge(payload, target_response, judge):
        return JudgeDecision(verdict="UNKNOWN", reason="Ambiguous response.")

    monkeypatch.setattr(dynamic_fuzzer, "_call_judge", fake_call_judge)

    decision = await evaluate_response(
        payload=payload,
        target_response="ambiguous response",
        primary_judge=JudgeConfig(endpoint="http://localhost:11434/v1/chat/completions", model="primary"),
        fallback_judge=None,
    )

    assert decision.verdict == "UNKNOWN"
    assert decision.confidence == "HIGH"
    assert decision.judge_agreement == "1/1"
    assert decision.errors == ()


@pytest.mark.asyncio
async def test_malformed_judge_response_records_execution_error(monkeypatch):
    payload = Payload(
        id="pi-001",
        category="Direct Prompt Injection",
        severity=Severity.CRITICAL,
        text="payload",
        expected_behavior="refuse",
        tags=[],
    )

    async def fake_call_judge(payload, target_response, judge):
        raise ValueError("invalid json")

    monkeypatch.setattr(dynamic_fuzzer, "_call_judge", fake_call_judge)

    decision = await evaluate_response(
        payload=payload,
        target_response="ambiguous response",
        primary_judge=JudgeConfig(endpoint="http://localhost:11434/v1/chat/completions", model="primary"),
        fallback_judge=None,
    )

    assert decision.verdict is None
    assert decision.errors[0].message == "Primary judge request failed"
    assert decision.errors[0].detail == "invalid json"


@pytest.mark.asyncio
async def test_calibrate_judge_rejects_valid_but_wrong_verdict(monkeypatch):
    async def fake_call_judge(payload, target_response, judge):
        if payload.id == "judge-calibration-refusal":
            return JudgeDecision(
                verdict="PASS",
                reason="The model refused.",
            )
        return JudgeDecision(
            verdict="PASS",
            reason="The model appears acceptable.",
        )

    monkeypatch.setattr(dynamic_fuzzer, "_call_judge", fake_call_judge)

    errors = await calibrate_judge(
        JudgeConfig(endpoint="http://localhost:11434/v1/chat/completions", model="weak")
    )

    assert len(errors) == 3
    assert {error.payload_id for error in errors} == {
        "judge-calibration-code",
        "judge-calibration-pii",
        "judge-calibration-toxicity",
    }
    assert all(error.message == "Judge calibration failed" for error in errors)


@pytest.mark.asyncio
async def test_calibrate_judge_records_malformed_response(monkeypatch):
    async def fake_call_judge(payload, target_response, judge):
        raise ValueError("invalid json")

    monkeypatch.setattr(dynamic_fuzzer, "_call_judge", fake_call_judge)

    errors = await calibrate_judge(
        JudgeConfig(endpoint="http://localhost:11434/v1/chat/completions", model="weak")
    )

    assert len(errors) == 4
    assert all(error.message == "Judge calibration request failed" for error in errors)


def test_build_dynamic_evidence_only_includes_failed_and_unknown_payloads():
    failed_payload = Payload(
        id="pi-001",
        category="Direct Prompt Injection",
        severity=Severity.CRITICAL,
        text="payload",
        expected_behavior="refuse",
        tags=[],
    )
    passed_payload = failed_payload.model_copy(update={"id": "pi-002"})
    unknown_payload = failed_payload.model_copy(update={"id": "pi-003"})

    evidence = build_dynamic_evidence(
        [
            PayloadEvaluation(
                payload=failed_payload,
                failed=True,
                verdict="FAIL",
                judge_model="judge",
                judge_reason="The model complied.",
                target_response="unsafe response",
            ),
            PayloadEvaluation(
                payload=passed_payload,
                failed=False,
                verdict="PASS",
                judge_model="judge",
                target_response="safe response",
            ),
            PayloadEvaluation(
                payload=unknown_payload,
                failed=False,
                verdict="UNKNOWN",
                target_response="ambiguous response",
            ),
        ],
        include_evidence=True,
    )

    assert [item.payload_id for item in evidence] == ["pi-001", "pi-003"]
    assert evidence[0].judge_verdict == "FAIL"
    assert evidence[0].judge_model == "judge"
    assert evidence[0].judge_reason == "The model complied."
    assert evidence[0].prompt_excerpt == "payload"
    assert evidence[0].expected_behavior == "refuse"
    assert evidence[0].target_response_excerpt == "unsafe response"
    assert evidence[1].judge_verdict == "UNKNOWN"
    assert build_dynamic_evidence(evidence, include_evidence=False) == []


def test_build_dynamic_assessments_tracks_confidence_without_evidence():
    payload = Payload(
        id="rag-004",
        category="RAG Context Manipulation",
        severity=Severity.HIGH,
        text="payload",
        expected_behavior="refuse",
        tags=[],
    )

    assessments = build_dynamic_assessments(
        [
            PayloadEvaluation(
                payload=payload,
                failed=True,
                verdict="FAIL",
                confidence="HIGH",
                judge_agreement="2/2",
                target_response="unsafe response",
            )
        ],
        include_evidence=False,
    )

    assert assessments[0].payload_id == "rag-004"
    assert assessments[0].verdict == "FAIL"
    assert assessments[0].confidence == "HIGH"
    assert assessments[0].judge_agreement == "2/2"
    assert assessments[0].evidence_available is False
