# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

from core.models import DynamicFindingAssessment, Severity


def test_assessment_accepts_expected_behavior_and_verdict_reason():
    assessment = DynamicFindingAssessment(
        payload_id="pi-001",
        category="Direct Prompt Injection",
        severity=Severity.HIGH,
        verdict="FAIL",
        confidence="HIGH",
        judge_agreement="1/1",
        expected_behavior="Refuse user-supplied override.",
        verdict_reason="Model followed the injected instruction.",
    )
    assert assessment.expected_behavior == "Refuse user-supplied override."
    assert assessment.verdict_reason == "Model followed the injected instruction."


def test_assessment_defaults_new_fields_to_none():
    assessment = DynamicFindingAssessment(
        payload_id="pi-001",
        category="Direct Prompt Injection",
        severity=Severity.HIGH,
        verdict="FAIL",
        confidence="HIGH",
        judge_agreement="1/1",
    )
    assert assessment.expected_behavior is None
    assert assessment.verdict_reason is None


from core.report_renderer import (
    CAPABILITY_LINES,
    CATEGORY_CONTEXT,
    CATEGORY_MITIGATION,
    EXFIL_DATA_CLASS,
    _scan_context_lines,
)


def _dynamic_report(assessments=None, errors=None, total=0):
    from main import DEFAULT_ENDPOINT, DEFAULT_MODEL, build_report
    from engines.dynamic_fuzzer import DYNAMIC_CONCURRENCY, TARGET_TIMEOUT_SECONDS

    return build_report(
        target_endpoint=DEFAULT_ENDPOINT,
        target_model=DEFAULT_MODEL,
        target_timeout_seconds=TARGET_TIMEOUT_SECONDS,
        dynamic_concurrency=DYNAMIC_CONCURRENCY,
        judge_endpoint=DEFAULT_ENDPOINT,
        judge_model=DEFAULT_MODEL,
        fallback_judge_endpoint=None,
        fallback_judge_model=None,
        include_evidence=False,
        static_findings=[],
        dynamic_findings=[],
        dynamic_assessments=assessments or [],
        dynamic_evidence=[],
        execution_errors=errors or [],
        scan_type="dynamic",
        include_static_section=False,
        dynamic_total_payloads=total,
    )


def test_scan_context_shows_target_type_and_counts():
    report = _dynamic_report(total=41, errors=[])
    joined = "\n".join(_scan_context_lines(report))
    assert "Target:   llama3.1:8b" in joined
    assert "Type:     dynamic" in joined
    assert "Payloads: 41 total, 41 evaluated, 0 error" in joined
    assert "Attempts: 1 per payload" in joined


def test_scan_context_capability_line_only_when_category_failed():
    from core.models import DynamicFindingAssessment, Severity
    tool_fail = DynamicFindingAssessment(
        payload_id="tool-004", category="Tool Abuse", severity=Severity.HIGH,
        verdict="FAIL", confidence="HIGH", judge_agreement="1/1",
    )
    report = _dynamic_report(assessments=[tool_fail], total=1)
    joined = "\n".join(_scan_context_lines(report))
    assert "Tools:    simulated only" in joined
    assert "RAG:" not in joined
    assert "Memory:" not in joined


def test_scan_context_count_guard_when_total_zero():
    from core.models import DynamicFindingAssessment, Severity
    fail = DynamicFindingAssessment(
        payload_id="pi-001", category="Direct Prompt Injection", severity=Severity.HIGH,
        verdict="FAIL", confidence="HIGH", judge_agreement="1/1",
    )
    report = _dynamic_report(assessments=[fail], total=0)
    joined = "\n".join(_scan_context_lines(report))
    assert "Payloads: 1 total, 1 evaluated, 0 error" in joined


def test_scan_context_empty_for_static_scan():
    from main import DEFAULT_ENDPOINT, DEFAULT_MODEL, build_report
    from engines.dynamic_fuzzer import DYNAMIC_CONCURRENCY, TARGET_TIMEOUT_SECONDS
    report = build_report(
        target_endpoint=DEFAULT_ENDPOINT, target_model=DEFAULT_MODEL,
        target_timeout_seconds=TARGET_TIMEOUT_SECONDS, dynamic_concurrency=DYNAMIC_CONCURRENCY,
        judge_endpoint=DEFAULT_ENDPOINT, judge_model=DEFAULT_MODEL,
        fallback_judge_endpoint=None, fallback_judge_model=None, include_evidence=False,
        static_findings=[], dynamic_findings=[], dynamic_evidence=[], execution_errors=[],
        scan_type="static", include_dynamic_section=False,
    )
    assert _scan_context_lines(report) == []
