import json
from pathlib import Path

import pytest

from core.models import Payload, Severity
import engines.dynamic_fuzzer as dynamic_fuzzer
from engines.dynamic_fuzzer import (
    DYNAMIC_CONCURRENCY,
    JudgeConfig,
    TARGET_TIMEOUT_SECONDS,
    PayloadEvaluation,
    build_dynamic_evidence,
    evaluate_response,
    extract_response_text,
    group_dynamic_findings,
    load_payloads,
    sanitize_evidence_text,
    sanitize_judge_verdict,
)


def test_extract_response_text_supports_openai_and_ollama_shapes():
    assert (
        extract_response_text({"choices": [{"message": {"content": "openai"}}]})
        == "openai"
    )
    assert extract_response_text({"message": {"content": "ollama chat"}}) == "ollama chat"
    assert extract_response_text({"response": "ollama generate"}) == "ollama generate"


def test_sanitize_judge_verdict_uses_word_boundaries():
    assert sanitize_judge_verdict(" PASS\n") == "PASS"
    assert sanitize_judge_verdict("The result is: fail.") == "FAIL"
    assert sanitize_judge_verdict("pass and fail") is None
    assert sanitize_judge_verdict("compassionate") is None


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
async def test_fallback_judge_recovery_does_not_mark_execution_error(monkeypatch):
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
        return "PASS"

    monkeypatch.setattr(dynamic_fuzzer, "_call_judge", fake_call_judge)

    decision = await evaluate_response(
        payload=payload,
        target_response="safe response",
        primary_judge=JudgeConfig(endpoint="http://localhost:11434/v1/chat/completions", model="primary"),
        fallback_judge=JudgeConfig(endpoint="http://localhost:11434/v1/chat/completions", model="fallback"),
    )

    assert decision.verdict == "PASS"
    assert decision.judge_model == "fallback"
    assert decision.errors == ()


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
        return None

    monkeypatch.setattr(dynamic_fuzzer, "_call_judge", fake_call_judge)

    decision = await evaluate_response(
        payload=payload,
        target_response="ambiguous response",
        primary_judge=JudgeConfig(endpoint="http://localhost:11434/v1/chat/completions", model="primary"),
        fallback_judge=JudgeConfig(endpoint="http://localhost:11434/v1/chat/completions", model="fallback"),
    )

    assert decision.verdict is None
    assert decision.errors[-1].message == "Payload security result is UNKNOWN after judge attempts"


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
    assert evidence[0].target_response_excerpt == "unsafe response"
    assert evidence[1].judge_verdict == "UNKNOWN"
    assert build_dynamic_evidence(evidence, include_evidence=False) == []
