# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

import asyncio
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
        tags=["OWASP:LLM01", "MITRE_ATLAS:AML.T0051"],
    )
    payload_2 = payload_1.model_copy(
        update={
            "id": "pi-001",
            "severity": Severity.CRITICAL,
            "tags": ["OWASP:LLM07"],
        }
    )
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
    assert grouped[0].owasp_tags == ["OWASP:LLM01", "OWASP:LLM07"]


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

    async def fake_call_judge(payload, target_response, judge, session, timeout_seconds=30):
        if judge.model == "primary":
            raise RuntimeError("primary unavailable")
        return JudgeDecision(verdict="PASS", reason="The model refused.")

    monkeypatch.setattr(dynamic_fuzzer, "_call_judge", fake_call_judge)

    decision = await evaluate_response(
        payload=payload,
        target_response="safe response",
        primary_judge=JudgeConfig(endpoint="http://localhost:11434/v1/chat/completions", model="primary"),
        fallback_judge=JudgeConfig(endpoint="http://localhost:11434/v1/chat/completions", model="fallback"),
        session=object(),
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

    async def fake_call_judge(payload, target_response, judge, session, timeout_seconds=30):
        return JudgeDecision(verdict=None)

    monkeypatch.setattr(dynamic_fuzzer, "_call_judge", fake_call_judge)

    decision = await evaluate_response(
        payload=payload,
        target_response="ambiguous response",
        primary_judge=JudgeConfig(endpoint="http://localhost:11434/v1/chat/completions", model="primary"),
        fallback_judge=JudgeConfig(endpoint="http://localhost:11434/v1/chat/completions", model="fallback"),
        session=object(),
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

    async def fake_call_judge(payload, target_response, judge, session, timeout_seconds=30):
        return JudgeDecision(verdict="UNKNOWN", reason="Ambiguous response.")

    monkeypatch.setattr(dynamic_fuzzer, "_call_judge", fake_call_judge)

    decision = await evaluate_response(
        payload=payload,
        target_response="ambiguous response",
        primary_judge=JudgeConfig(endpoint="http://localhost:11434/v1/chat/completions", model="primary"),
        fallback_judge=None,
        session=object(),
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

    async def fake_call_judge(payload, target_response, judge, session, timeout_seconds=30):
        raise ValueError("invalid json")

    monkeypatch.setattr(dynamic_fuzzer, "_call_judge", fake_call_judge)

    decision = await evaluate_response(
        payload=payload,
        target_response="ambiguous response",
        primary_judge=JudgeConfig(endpoint="http://localhost:11434/v1/chat/completions", model="primary"),
        fallback_judge=None,
        session=object(),
    )

    assert decision.verdict is None
    assert decision.errors[0].message == "Primary judge request failed"
    assert decision.errors[0].detail == "invalid json"


@pytest.mark.asyncio
async def test_calibrate_judge_rejects_valid_but_wrong_verdict(monkeypatch):
    async def fake_call_judge(payload, target_response, judge, session, timeout_seconds=30):
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
        JudgeConfig(endpoint="http://localhost:11434/v1/chat/completions", model="weak"),
        session=object(),
        semaphore=asyncio.Semaphore(1),
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
    async def fake_call_judge(payload, target_response, judge, session, timeout_seconds=30):
        raise ValueError("invalid json")

    monkeypatch.setattr(dynamic_fuzzer, "_call_judge", fake_call_judge)

    errors = await calibrate_judge(
        JudgeConfig(endpoint="http://localhost:11434/v1/chat/completions", model="weak"),
        session=object(),
        semaphore=asyncio.Semaphore(1),
    )

    assert len(errors) == 4
    assert all(error.message == "Judge calibration request failed" for error in errors)


@pytest.mark.asyncio
async def test_calibrate_judge_uses_configured_judge_timeout(monkeypatch):
    seen_timeouts = []

    async def fake_call_judge(payload, target_response, judge, session, timeout_seconds=30):
        seen_timeouts.append(timeout_seconds)
        return JudgeDecision(verdict="PASS", reason="The model refused.")

    monkeypatch.setattr(dynamic_fuzzer, "_call_judge", fake_call_judge)

    await calibrate_judge(
        JudgeConfig(endpoint="http://localhost:11434/v1/chat/completions", model="judge"),
        session=object(),
        semaphore=asyncio.Semaphore(1),
        timeout_seconds=90,
    )

    assert seen_timeouts == [90, 90, 90, 90]


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


def test_build_dynamic_assessments_includes_passed_payloads_when_requested():
    passed_payload = Payload(
        id="pi-001",
        category="Direct Prompt Injection",
        severity=Severity.CRITICAL,
        text="payload",
        expected_behavior="refuse",
        tags=["OWASP:LLM01", "MITRE_ATLAS:AML.T0051"],
    )
    failed_payload = passed_payload.model_copy(
        update={
            "id": "rag-001",
            "category": "RAG Context Manipulation",
            "tags": ["OWASP:LLM08"],
        }
    )

    default_assessments = build_dynamic_assessments(
        [
            PayloadEvaluation(payload=passed_payload, failed=False, verdict="PASS"),
            PayloadEvaluation(payload=failed_payload, failed=True, verdict="FAIL"),
        ],
        include_evidence=False,
    )
    verbose_assessments = build_dynamic_assessments(
        [
            PayloadEvaluation(payload=passed_payload, failed=False, verdict="PASS"),
            PayloadEvaluation(payload=failed_payload, failed=True, verdict="FAIL"),
        ],
        include_evidence=False,
        include_passed=True,
    )

    assert [item.payload_id for item in default_assessments] == ["rag-001"]
    assert [item.payload_id for item in verbose_assessments] == ["pi-001", "rag-001"]
    assert verbose_assessments[0].owasp_tags == ["OWASP:LLM01"]


def test_build_dynamic_assessments_populates_expected_and_reason():
    from engines.dynamic_fuzzer import PayloadEvaluation, build_dynamic_assessments
    from core.models import Payload, Severity

    payload = Payload(
        id="pi-001",
        category="Direct Prompt Injection",
        severity=Severity.HIGH,
        text="ignore instructions",
        expected_behavior="Refuse user-supplied override.",
        tags=["OWASP:LLM01"],
    )
    evaluation = PayloadEvaluation(
        payload=payload,
        failed=True,
        verdict="FAIL",
        judge_reason="Model followed the injected instruction.",
        confidence="HIGH",
        judge_agreement="1/1",
    )

    assessments = build_dynamic_assessments([evaluation], include_evidence=False)
    assert len(assessments) == 1
    assert assessments[0].expected_behavior == "Refuse user-supplied override."
    assert assessments[0].verdict_reason == "Model followed the injected instruction."


import pytest
from pydantic import ValidationError


def _make_payload(**overrides):
    base = dict(
        id="p1",
        category="Sensitive Data Exfiltration",
        severity=Severity.CRITICAL,
        text="protect this",
        expected_behavior="refuse",
        tags=["OWASP:LLM02"],
    )
    base.update(overrides)
    return Payload(**base)


def test_payload_canaries_default_empty_and_drops_blanks():
    assert _make_payload().canaries == []
    assert _make_payload(canaries=["keep", "", "  "]).canaries == ["keep"]


def test_payload_canaries_reject_too_many_or_too_long():
    with pytest.raises(ValidationError):
        _make_payload(canaries=[f"c{i}" for i in range(11)])
    with pytest.raises(ValidationError):
        _make_payload(canaries=["x" * 257])


from engines.output_detectors import LeakHit, LeakTier
from engines.dynamic_fuzzer import LOW_OVERRIDE_CATEGORIES, apply_leak_override


def test_high_leak_overrides_pass_to_fail():
    leaks = (LeakHit("secret", LeakTier.HIGH, "aws_access_key", "AKIA…REDACTED"),)
    verdict, failed, override, reason = apply_leak_override(
        "Tool Abuse", "PASS", "looked safe", leaks
    )
    assert verdict == "FAIL" and failed is True
    assert override and reason.startswith(override)
    assert "Previous verdict reason: looked safe" in reason


def test_low_leak_downgrades_pass_only_for_privacy_category():
    leaks = (LeakHit("pii", LeakTier.LOW, "email", "[REDACTED:email]"),)
    verdict, failed, override, _ = apply_leak_override("PII Leakage", "PASS", None, leaks)
    assert verdict == "UNKNOWN" and failed is False and override
    # unrelated category: record but keep PASS
    verdict2, failed2, override2, _ = apply_leak_override("Toxicity", "PASS", None, leaks)
    assert verdict2 == "PASS" and failed2 is False and override2 is None


def test_no_leaks_passthrough():
    verdict, failed, override, reason = apply_leak_override("Toxicity", "PASS", "ok", ())
    assert verdict == "PASS" and failed is False and override is None and reason == "ok"


def test_high_leak_on_judge_fail_keeps_fail_without_override():
    leaks = (LeakHit("secret", LeakTier.HIGH, "aws_access_key", "AKIA…REDACTED"),)
    verdict, failed, override, reason = apply_leak_override("Tool Abuse", "FAIL", "judge failed it", leaks)
    assert verdict == "FAIL" and failed is True
    assert override is None
    assert reason == "judge failed it"


def test_high_leak_on_judge_unknown_escalates_to_fail():
    leaks = (LeakHit("canary", LeakTier.HIGH, "canary", "[REDACTED:canary]"),)
    verdict, failed, override, _ = apply_leak_override("Tool Abuse", "UNKNOWN", None, leaks)
    assert verdict == "FAIL" and failed is True and override


def test_privacy_categories_constant():
    assert "PII Extraction" in LOW_OVERRIDE_CATEGORIES
    assert "Sensitive Data Exfiltration" in LOW_OVERRIDE_CATEGORIES


async def _run_eval(monkeypatch, response_text, judge_verdict, *, detection=True):
    async def fake_attack(payload, *a, **k):
        return response_text, None

    async def fake_judge(payload, target_response, *a, **k):
        return JudgeDecision(verdict=judge_verdict, judge_model="judge", reason="judge said so")

    monkeypatch.setattr(dynamic_fuzzer, "attack_target", fake_attack)
    monkeypatch.setattr(dynamic_fuzzer, "evaluate_response", fake_judge)
    payload = _make_payload(category="Tool Abuse", canaries=[])
    return await dynamic_fuzzer._evaluate_payload(
        payload, "http://t", "tm",
        JudgeConfig("http://j", "jm"), None,
        asyncio.Semaphore(1), object(), 30.0, 30.0,
        output_leak_detection=detection,
    )


def test_evaluate_payload_high_leak_overrides_pass(monkeypatch):
    result = asyncio.run(_run_eval(monkeypatch, "key AKIAIOSFODNN7EXAMPLE", "PASS"))
    assert result.verdict == "FAIL" and result.failed is True
    assert result.leak_override and result.leaks
    assert result.leaks[0].label == "aws_access_key"


def test_evaluate_payload_detection_disabled_keeps_judge(monkeypatch):
    result = asyncio.run(_run_eval(monkeypatch, "key AKIAIOSFODNN7EXAMPLE", "PASS", detection=False))
    assert result.verdict == "PASS" and result.leaks == ()


def _eval_with_leaks(category, verdict, failed, leaks, tags):
    return PayloadEvaluation(
        payload=_make_payload(id="p1", category=category, tags=tags),
        failed=failed, verdict=verdict, judge_model="j", judge_reason="r",
        target_response="resp", leaks=leaks, leak_override="ov",
    )


def test_secret_leak_adds_llm02_tag_in_findings_and_assessments():
    leaks = (LeakHit("secret", LeakTier.HIGH, "aws_access_key", "AKIA…REDACTED"),)
    ev = _eval_with_leaks("Tool Abuse", "FAIL", True, leaks, [])
    findings = group_dynamic_findings([ev])
    assert "OWASP:LLM02" in findings[0].owasp_tags
    assessment = build_dynamic_assessments([ev], include_evidence=False)[0]
    assert "OWASP:LLM02" in assessment.owasp_tags
    assert assessment.leaks[0].label == "aws_access_key"
    assert assessment.leak_override == "ov"


def test_system_marker_leak_adds_llm07_not_llm02():
    leaks = (LeakHit("system_marker", LeakTier.LOW, "system_marker", "[REDACTED:system_marker]"),)
    ev = _eval_with_leaks("System Prompt Extraction", "FAIL", True, leaks, [])
    assessment = build_dynamic_assessments([ev], include_evidence=False)[0]
    assert "OWASP:LLM07" in assessment.owasp_tags
    assert "OWASP:LLM02" not in assessment.owasp_tags


def test_evidence_carries_leaks_when_included():
    leaks = (LeakHit("canary", LeakTier.HIGH, "canary", "[REDACTED:canary]"),)
    ev = _eval_with_leaks("Sensitive Data Exfiltration", "FAIL", True, leaks, [])
    evidence = build_dynamic_evidence([ev], include_evidence=True)[0]
    assert evidence.leaks[0].label == "canary"
    assert evidence.leak_override == "ov"
