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


from core.report_renderer import _required_fixes_lines


def _fail(category, payload_id="x-1", severity=None, tags=None):
    from core.models import DynamicFindingAssessment, Severity
    return DynamicFindingAssessment(
        payload_id=payload_id, category=category, severity=severity or Severity.HIGH,
        verdict="FAIL", confidence="HIGH", judge_agreement="1/1", owasp_tags=tags or [],
    )


def test_required_fixes_derives_from_assessments_not_grouped():
    report = _dynamic_report(
        assessments=[_fail("System Prompt Extraction", "sys-001", tags=["OWASP:LLM07"])], total=1)
    joined = "\n".join(_required_fixes_lines(report))
    assert "System Prompt Extraction" in joined
    assert "Treat system prompts as control instructions, not a secret store." in joined
    assert "OWASP: LLM07" in joined


def test_required_fixes_covers_every_high_critical_category():
    report = _dynamic_report(assessments=[
        _fail("System Prompt Extraction", "sys-001", tags=["OWASP:LLM07"]),
        _fail("Tool Abuse", "tool-004", tags=["OWASP:LLM02"]),
    ], total=2)
    joined = "\n".join(_required_fixes_lines(report))
    assert "System Prompt Extraction" in joined
    assert "Tool Abuse" in joined
    assert "Deny user-supplied tool directives." in joined


def test_required_fixes_excludes_low_medium_severity():
    from core.models import Severity
    report = _dynamic_report(assessments=[_fail("Toxicity", "tox-1", severity=Severity.MEDIUM)], total=1)
    assert _required_fixes_lines(report) == []


def test_required_fixes_unknown_category_shows_generic_fallback():
    report = _dynamic_report(assessments=[_fail("Unmapped Category", "u-1")], total=1)
    joined = "\n".join(_required_fixes_lines(report))
    assert "Unmapped Category" in joined
    assert "Payloads: u-1" in joined
    assert "add category-specific mitigation before release" in joined


def test_required_fixes_preserves_supply_chain_source_and_owner():
    from core.models import Finding, Severity
    from main import DEFAULT_ENDPOINT, DEFAULT_MODEL, build_report
    from engines.dynamic_fuzzer import DYNAMIC_CONCURRENCY, TARGET_TIMEOUT_SECONDS
    report = build_report(
        target_endpoint=DEFAULT_ENDPOINT, target_model=DEFAULT_MODEL,
        target_timeout_seconds=TARGET_TIMEOUT_SECONDS, dynamic_concurrency=DYNAMIC_CONCURRENCY,
        judge_endpoint=DEFAULT_ENDPOINT, judge_model=DEFAULT_MODEL,
        fallback_judge_endpoint=None, fallback_judge_model=None, include_evidence=False,
        static_findings=[Finding(
            severity=Severity.MEDIUM, category="Dependency Vulnerability",
            description="idna==3.13 is affected by CVE-2026-45409.", package_name="idna",
            package_version="3.13", fixed_version="3.15", vulnerability_id="CVE-2026-45409",
            source_file="pyproject.toml")],
        dynamic_findings=[], dynamic_evidence=[], execution_errors=[],
        scan_type="static", include_dynamic_section=False)
    joined = "\n".join(_required_fixes_lines(report))
    assert "idna 3.13 -> upgrade to 3.15 or later" in joined
    assert "Source: pyproject.toml" in joined
    assert "Owner (from CODEOWNERS): Unassigned (no CODEOWNERS match)" in joined
    assert "CVE: CVE-2026-45409" in joined


from core.report_renderer import _failed_payloads_lines


def test_failed_payload_header_uses_severity_and_failure_ratio():
    report = _dynamic_report(
        assessments=[_fail("Direct Prompt Injection", "pi-001", tags=["OWASP:LLM01"])], total=1)
    joined = "\n".join(_failed_payloads_lines(report))
    assert "pi-001 · Direct Prompt Injection · FAIL · HIGH · 1/1 · OWASP: LLM01" in joined


def test_failed_payload_expected_and_observed_lines():
    from core.models import DynamicFindingAssessment, Severity
    a = DynamicFindingAssessment(
        payload_id="pi-001", category="Direct Prompt Injection", severity=Severity.HIGH,
        verdict="FAIL", confidence="HIGH", judge_agreement="1/1",
        expected_behavior="Refuse override.", verdict_reason="Model followed the injection.")
    report = _dynamic_report(assessments=[a], total=1)
    joined = "\n".join(_failed_payloads_lines(report))
    assert "Expected: Refuse override." in joined
    assert "Observed: Model followed the injection." in joined


def test_failed_payload_evidence_unavailable_without_flag():
    report = _dynamic_report(assessments=[_fail("Direct Prompt Injection", "pi-001")], total=1)
    assert "Evidence: unavailable" in "\n".join(_failed_payloads_lines(report))


def test_failed_payload_evidence_mismatch_renders_unavailable():
    from core.models import DynamicFindingAssessment, Severity
    a = DynamicFindingAssessment(
        payload_id="pi-001", category="Direct Prompt Injection", severity=Severity.HIGH,
        verdict="FAIL", confidence="HIGH", judge_agreement="1/1", evidence_available=True)
    report = _dynamic_report(assessments=[a], total=1)  # no DynamicEvidence supplied
    assert "Evidence: unavailable" in "\n".join(_failed_payloads_lines(report))


def test_failed_payload_evidence_shown_when_available():
    from core.models import DynamicFindingAssessment, DynamicEvidence, Severity
    a = DynamicFindingAssessment(
        payload_id="pi-001", category="Direct Prompt Injection", severity=Severity.HIGH,
        verdict="FAIL", confidence="HIGH", judge_agreement="1/1", evidence_available=True)
    ev = DynamicEvidence(
        payload_id="pi-001", category="Direct Prompt Injection", severity=Severity.HIGH,
        judge_verdict="FAIL", target_response_excerpt="leaked secret xyz", response_truncated=True)
    from main import DEFAULT_ENDPOINT, DEFAULT_MODEL, build_report
    from engines.dynamic_fuzzer import DYNAMIC_CONCURRENCY, TARGET_TIMEOUT_SECONDS
    report = build_report(
        target_endpoint=DEFAULT_ENDPOINT, target_model=DEFAULT_MODEL,
        target_timeout_seconds=TARGET_TIMEOUT_SECONDS, dynamic_concurrency=DYNAMIC_CONCURRENCY,
        judge_endpoint=DEFAULT_ENDPOINT, judge_model=DEFAULT_MODEL,
        fallback_judge_endpoint=None, fallback_judge_model=None, include_evidence=True,
        static_findings=[], dynamic_findings=[], dynamic_assessments=[a],
        dynamic_evidence=[ev], execution_errors=[], scan_type="dynamic",
        include_static_section=False, dynamic_total_payloads=1)
    joined = "\n".join(_failed_payloads_lines(report))
    assert 'Evidence: "leaked secret xyz" [truncated]' in joined


def test_failed_payload_context_only_for_known_category():
    report = _dynamic_report(assessments=[
        _fail("Direct Prompt Injection", "pi-001"),
        _fail("Tool Abuse", "tool-004")], total=2)
    joined = "\n".join(_failed_payloads_lines(report))
    assert "Context:  simulated tool access, no real tool execution observed" in joined
    pi_block = joined.split("tool-004")[0]
    assert "Context:" not in pi_block


def test_failed_payload_exfil_shows_data_class():
    report = _dynamic_report(
        assessments=[_fail("Sensitive Data Exfiltration", "exfil-003", tags=["OWASP:LLM06"])], total=1)
    assert "Data class: canary secret" in "\n".join(_failed_payloads_lines(report))


def test_failed_payloads_sorted_by_severity_then_category():
    from core.models import Severity
    report = _dynamic_report(assessments=[
        _fail("Tool Abuse", "tool-1", severity=Severity.HIGH),
        _fail("Direct Prompt Injection", "pi-1", severity=Severity.CRITICAL)], total=2)
    text = "\n".join(_failed_payloads_lines(report))
    assert text.index("pi-1") < text.index("tool-1")


from core.report_renderer import _finding_count_lines


def test_finding_counts_split_grouped_and_failed_payloads():
    from core.models import GroupedFinding, Severity
    from main import DEFAULT_ENDPOINT, DEFAULT_MODEL, build_report
    from engines.dynamic_fuzzer import DYNAMIC_CONCURRENCY, TARGET_TIMEOUT_SECONDS
    report = build_report(
        target_endpoint=DEFAULT_ENDPOINT, target_model=DEFAULT_MODEL,
        target_timeout_seconds=TARGET_TIMEOUT_SECONDS, dynamic_concurrency=DYNAMIC_CONCURRENCY,
        judge_endpoint=DEFAULT_ENDPOINT, judge_model=DEFAULT_MODEL,
        fallback_judge_endpoint=None, fallback_judge_model=None, include_evidence=False,
        static_findings=[],
        dynamic_findings=[GroupedFinding(
            category="Direct Prompt Injection", severity=Severity.HIGH,
            failed_count=1, payload_ids=["pi-1"], owasp_tags=["OWASP:LLM01"])],
        dynamic_assessments=[_fail("Direct Prompt Injection", "pi-1")],
        dynamic_evidence=[], execution_errors=[], scan_type="dynamic",
        include_static_section=False, dynamic_total_payloads=1)
    joined = "\n".join(_finding_count_lines(report))
    assert "Grouped findings:" in joined
    assert "Failed payloads:" in joined


def test_finding_counts_preserve_supply_chain_row():
    from core.models import Finding, Severity
    from main import DEFAULT_ENDPOINT, DEFAULT_MODEL, build_report
    from engines.dynamic_fuzzer import DYNAMIC_CONCURRENCY, TARGET_TIMEOUT_SECONDS
    report = build_report(
        target_endpoint=DEFAULT_ENDPOINT, target_model=DEFAULT_MODEL,
        target_timeout_seconds=TARGET_TIMEOUT_SECONDS, dynamic_concurrency=DYNAMIC_CONCURRENCY,
        judge_endpoint=DEFAULT_ENDPOINT, judge_model=DEFAULT_MODEL,
        fallback_judge_endpoint=None, fallback_judge_model=None, include_evidence=False,
        static_findings=[Finding(severity=Severity.MEDIUM, category="Dependency Vulnerability", description="x")],
        dynamic_findings=[], dynamic_evidence=[], execution_errors=[],
        scan_type="static", include_dynamic_section=False)
    joined = "\n".join(_finding_count_lines(report))
    assert "Application supply chain: medium" in joined


def test_finding_counts_hides_zero_rows_and_shows_execution_errors():
    from core.models import ErrorSource, ExecutionError
    report = _dynamic_report(
        assessments=[_fail("Direct Prompt Injection", "pi-1")],
        errors=[ExecutionError(source=ErrorSource.DYNAMIC, message="x", payload_id="sys-1")],
        total=2)
    joined = "\n".join(_finding_count_lines(report))
    assert "Failed payloads:" in joined
    assert "Execution errors: 1" in joined
    assert "Application supply chain:" not in joined  # zero → hidden


from core.report_renderer import _scan_reliability_lines


def test_scan_reliability_absent_without_errors():
    report = _dynamic_report(assessments=[_fail("Direct Prompt Injection", "pi-1")], total=1)
    assert _scan_reliability_lines(report) == []


def test_scan_reliability_uses_specific_remediation_when_known():
    from core.models import ErrorSource, ExecutionError
    report = _dynamic_report(
        errors=[ExecutionError(source=ErrorSource.DYNAMIC, message="Judge calibration failed",
                               payload_id="judge-calibration-refusal")],
        total=1)
    joined = "\n".join(_scan_reliability_lines(report))
    assert "judge-calibration-refusal · Judge calibration failed" in joined
    assert "Impact:   payload was not evaluated" in joined
    assert "Configure a fallback judge and re-run the dynamic scan." in joined


def test_scan_reliability_coverage_from_matching_assessment():
    from core.models import ErrorSource, ExecutionError
    report = _dynamic_report(
        assessments=[_fail("System Prompt Extraction", "sys-005")],
        errors=[ExecutionError(source=ErrorSource.DYNAMIC, message="Target request failed",
                               payload_id="sys-005")],
        total=2)
    joined = "\n".join(_scan_reliability_lines(report))
    assert "Coverage: System Prompt Extraction" in joined


def test_scan_reliability_uses_specific_remediation_for_static_error():
    from core.models import ErrorSource, ExecutionError
    report = _dynamic_report(
        assessments=[_fail("Tool Abuse", "tool-1")],
        errors=[ExecutionError(source=ErrorSource.STATIC, message="OSV timeout", payload_id="tool-1")],
        total=1)
    joined = "\n".join(_scan_reliability_lines(report))
    # STATIC source with non-judge message → upstream _execution_error_remediation returns
    # "Re-run the scan and review the failing scanner dependency or service."
    # That remediation is stored in scan_reliability ReportRisk, so "specific-when-known" applies.
    assert "Re-run the scan and review the failing scanner dependency or service." in joined


from core.report_renderer import render_console_text


def test_render_console_text_section_order():
    from core.models import ErrorSource, ExecutionError
    report = _dynamic_report(
        assessments=[_fail("Direct Prompt Injection", "pi-001", tags=["OWASP:LLM01"])],
        errors=[ExecutionError(source=ErrorSource.DYNAMIC, message="Target request failed", payload_id="sys-005")],
        total=2)
    text = render_console_text(report, verbose=False).plain
    order = ["Why", "Scan context", "Required fixes", "Failed payloads",
             "Finding counts", "Scan reliability", "Next step"]
    positions = [text.index(h) for h in order]
    assert positions == sorted(positions), f"sections out of order:\n{text}"


def test_render_console_text_failed_header_has_no_judge_metadata():
    report = _dynamic_report(
        assessments=[_fail("Direct Prompt Injection", "pi-001", tags=["OWASP:LLM01"])], total=1)
    text = render_console_text(report, verbose=False).plain
    assert "Failed payloads" in text
    assert "pi-001 · Direct Prompt Injection · FAIL · HIGH · 1/1 · OWASP: LLM01" in text
