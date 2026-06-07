# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

from core.models import (
    DynamicFindingAssessment,
    ErrorSource,
    ExecutionError,
    Finding,
    FindingAction,
    GroupedFinding,
    Severity,
)
from engines.dynamic_fuzzer import DYNAMIC_CONCURRENCY, TARGET_TIMEOUT_SECONDS
from main import (
    DEFAULT_ENDPOINT,
    DEFAULT_MODEL,
    build_report,
    load_codeowners,
    render_json_report,
    render_markdown_report,
)


def test_report_passes_only_when_complete_and_no_findings():
    report = build_report(
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
        dynamic_evidence=[],
        execution_errors=[],
    )

    assert report.security_result == "PASS"
    assert report.production_decision == "PASS"
    assert report.executive_summary.decision == "PASS"
    assert report.execution_status == "COMPLETE"
    assert report.passed_audit is True


def test_report_marks_incomplete_without_conflating_security_failure():
    report = build_report(
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
        dynamic_evidence=[],
        execution_errors=[
            ExecutionError(source=ErrorSource.STATIC, message="OSV timeout")
        ],
    )

    assert report.security_result == "UNKNOWN"
    assert report.production_decision == "SCAN_INVALID"
    assert report.execution_status == "SCAN_INCOMPLETE"
    assert report.status_message == "**SCAN INCOMPLETE**"
    assert report.incomplete_reason is not None
    assert report.passed_audit is False


def test_report_fails_security_when_findings_exist():
    report = build_report(
        target_endpoint=DEFAULT_ENDPOINT,
        target_model=DEFAULT_MODEL,
        target_timeout_seconds=TARGET_TIMEOUT_SECONDS,
        dynamic_concurrency=DYNAMIC_CONCURRENCY,
        judge_endpoint=DEFAULT_ENDPOINT,
        judge_model=DEFAULT_MODEL,
        fallback_judge_endpoint=None,
        fallback_judge_model=None,
        include_evidence=False,
        static_findings=[
            Finding(
                severity=Severity.HIGH,
                category="Dependency Vulnerability",
                description="requests is vulnerable",
            )
        ],
        dynamic_findings=[],
        dynamic_evidence=[],
        execution_errors=[],
    )

    assert report.security_result == "FAIL"
    assert report.production_decision == "BLOCK_PRODUCTION"
    assert report.execution_status == "COMPLETE"
    assert report.findings.application_supply_chain[0].owner == "Unassigned"
    assert report.passed_audit is False


def test_report_uses_codeowners_for_source_file_owner(tmp_path):
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "CODEOWNERS").write_text(
        "* @platform-team\n",
        encoding="utf-8",
    )
    source_file = tmp_path / "uv.lock"
    source_file.write_text("", encoding="utf-8")

    report = build_report(
        target_endpoint=DEFAULT_ENDPOINT,
        target_model=DEFAULT_MODEL,
        target_timeout_seconds=TARGET_TIMEOUT_SECONDS,
        dynamic_concurrency=DYNAMIC_CONCURRENCY,
        judge_endpoint=DEFAULT_ENDPOINT,
        judge_model=DEFAULT_MODEL,
        fallback_judge_endpoint=None,
        fallback_judge_model=None,
        include_evidence=False,
        static_findings=[
            Finding(
                severity=Severity.MEDIUM,
                category="Dependency Vulnerability",
                description="idna is vulnerable",
                source_file=str(source_file),
            )
        ],
        dynamic_findings=[],
        dynamic_evidence=[],
        execution_errors=[],
        codeowners=load_codeowners(tmp_path),
        project_root=tmp_path,
    )

    assert report.findings.application_supply_chain[0].owner == "@platform-team"


def test_static_report_keeps_common_output_sections():
    report = build_report(
        target_endpoint=DEFAULT_ENDPOINT,
        target_model=DEFAULT_MODEL,
        target_timeout_seconds=TARGET_TIMEOUT_SECONDS,
        dynamic_concurrency=DYNAMIC_CONCURRENCY,
        judge_endpoint=DEFAULT_ENDPOINT,
        judge_model=DEFAULT_MODEL,
        fallback_judge_endpoint=None,
        fallback_judge_model=None,
        include_evidence=False,
        static_findings=[
            Finding(
                severity=Severity.MEDIUM,
                category="Dependency Vulnerability",
                description="idna is vulnerable",
            )
        ],
        dynamic_findings=[],
        dynamic_evidence=[],
        execution_errors=[],
        scan_type="static",
        include_dynamic_section=False,
        include_license_section=False,
    )

    dumped = report.model_dump(mode="json")

    assert "static_findings" not in dumped
    assert "dynamic_findings" not in dumped
    assert "license_findings" not in dumped
    assert dumped["findings"]["application_supply_chain"]
    assert dumped["findings"]["model_behavior"] == []
    assert dumped["findings"]["model_license"] == []
    assert dumped["findings"]["scan_reliability"] == []
    assert dumped["dynamic_assessments"] == []
    assert dumped["dynamic_evidence"] == []
    assert set(dumped["findings"]) == {
        "application_supply_chain",
        "model_behavior",
        "model_license",
        "scan_reliability",
    }


def test_compact_json_report_contains_actions_not_internal_junk():
    report = build_report(
        target_endpoint=DEFAULT_ENDPOINT,
        target_model=DEFAULT_MODEL,
        target_timeout_seconds=TARGET_TIMEOUT_SECONDS,
        dynamic_concurrency=DYNAMIC_CONCURRENCY,
        judge_endpoint=DEFAULT_ENDPOINT,
        judge_model=DEFAULT_MODEL,
        fallback_judge_endpoint=None,
        fallback_judge_model=None,
        include_evidence=False,
        static_findings=[
            Finding(
                severity=Severity.MEDIUM,
                category="Dependency Vulnerability",
                description="idna==3.13 is affected by CVE-2026-45409.",
                package_name="idna",
                package_version="3.13",
                fixed_version="3.15",
                vulnerability_id="CVE-2026-45409",
            )
        ],
        dynamic_findings=[],
        dynamic_evidence=[],
        execution_errors=[],
        scan_type="static",
        include_dynamic_section=False,
    )

    rendered = render_json_report(report)

    assert '"target_endpoint"' not in rendered
    assert '"dynamic_assessments"' not in rendered
    assert '"license_coverage"' not in rendered
    assert '"package": "idna"' in rendered
    assert '"current_version": "3.13"' in rendered
    assert '"fixed_version": "3.15"' in rendered
    assert '"action": "Upgrade idna to 3.15 or later"' in rendered


def test_report_does_not_fail_for_warning_only_findings():
    report = build_report(
        target_endpoint=DEFAULT_ENDPOINT,
        target_model=DEFAULT_MODEL,
        target_timeout_seconds=TARGET_TIMEOUT_SECONDS,
        dynamic_concurrency=DYNAMIC_CONCURRENCY,
        judge_endpoint=DEFAULT_ENDPOINT,
        judge_model=DEFAULT_MODEL,
        fallback_judge_endpoint=None,
        fallback_judge_model=None,
        include_evidence=False,
        static_findings=[
            Finding(
                severity=Severity.MEDIUM,
                action=FindingAction.WARN,
                category="License Policy Review",
                description="Dependency has a GPL-family license.",
            )
        ],
        dynamic_findings=[],
        dynamic_evidence=[],
        execution_errors=[],
    )

    assert report.security_result == "PASS"
    assert report.production_decision == "WARN"
    assert report.execution_status == "COMPLETE"
    assert report.passed_audit is True


def test_report_separates_risk_areas_and_owner_remediation():
    report = build_report(
        target_endpoint=DEFAULT_ENDPOINT,
        target_model=DEFAULT_MODEL,
        target_timeout_seconds=TARGET_TIMEOUT_SECONDS,
        dynamic_concurrency=DYNAMIC_CONCURRENCY,
        judge_endpoint=DEFAULT_ENDPOINT,
        judge_model=DEFAULT_MODEL,
        fallback_judge_endpoint=None,
        fallback_judge_model=None,
        include_evidence=False,
        static_findings=[
            Finding(
                severity=Severity.CRITICAL,
                category="Dependency Vulnerability",
                description="litellm is affected by a critical vulnerability.",
                package_name="litellm",
                fixed_version="1.2.3",
            )
        ],
        dynamic_findings=[
            GroupedFinding(
                category="Sensitive Data Exfiltration",
                severity=Severity.HIGH,
                failed_count=1,
                payload_ids=["pii-003"],
            )
        ],
        dynamic_assessments=[
            DynamicFindingAssessment(
                payload_id="pii-003",
                category="Sensitive Data Exfiltration",
                severity=Severity.HIGH,
                verdict="FAIL",
                confidence="HIGH",
                judge_agreement="2/2",
                evidence_available=False,
            )
        ],
        dynamic_evidence=[],
        license_findings=[
            Finding(
                severity=Severity.INFO,
                action=FindingAction.WARN,
                category="Model License Policy Review",
                description="Model uses a GPL-family license.",
                subject_type="model",
                subject_name="gpt4all-lora",
            )
        ],
        execution_errors=[
            ExecutionError(
                source=ErrorSource.DYNAMIC,
                message="Primary judge returned an invalid verdict",
                payload_id="pi-003",
            ),
            ExecutionError(
                source=ErrorSource.DYNAMIC,
                message="No fallback judge configured after primary judge failure",
                payload_id="pi-003",
            ),
        ],
        include_license_section=True,
    )

    assert report.production_decision == "BLOCK_PRODUCTION"
    assert report.executive_summary.reason == (
        "Confirmed high-risk dynamic failures and critical dependency vulnerabilities"
    )
    assert report.incomplete_reason == (
        "The scan found confirmed failures, but payload pi-003 could not be "
        "evaluated reliably because the primary judge returned an invalid "
        "verdict and no fallback judge was configured."
    )
    assert report.executive_summary.next_actions[0] == "Re-run with fallback judge."
    assert len(report.findings.application_supply_chain) == 1
    assert len(report.findings.model_behavior) == 1
    assert len(report.findings.model_license) == 1
    assert len(report.findings.scan_reliability) == 2
    assert report.dynamic_assessments[0].judge_agreement == "2/2"
    assert {item.owner for item in report.owner_remediation} == {
        "AI platform team",
        "ML team",
        "Platform team",
        "Security team",
    }


def test_markdown_report_is_compact_and_human_readable():
    report = build_report(
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
        dynamic_findings=[
            GroupedFinding(
                category="Tool Abuse",
                severity=Severity.HIGH,
                failed_count=1,
                payload_ids=["tool-001"],
            )
        ],
        dynamic_assessments=[
            DynamicFindingAssessment(
                payload_id="tool-001",
                category="Tool Abuse",
                severity=Severity.HIGH,
                verdict="FAIL",
                confidence="HIGH",
                judge_agreement="1/1",
                evidence_available=False,
            )
        ],
        dynamic_evidence=[],
        execution_errors=[],
    )

    markdown = render_markdown_report(report)

    assert "# AegisLocal Report" in markdown
    assert "Decision: BLOCK_PRODUCTION" in markdown
    assert "Model: llama3.1:8b" in markdown
    assert "Scan status: Complete" in markdown
    assert "| tool-001 | FAIL | HIGH | 1/1 | no |" in markdown
    assert "## Remediation By Owner" in markdown


def test_report_does_not_generate_none_package_remediation():
    report = build_report(
        target_endpoint=DEFAULT_ENDPOINT,
        target_model=DEFAULT_MODEL,
        target_timeout_seconds=TARGET_TIMEOUT_SECONDS,
        dynamic_concurrency=DYNAMIC_CONCURRENCY,
        judge_endpoint=DEFAULT_ENDPOINT,
        judge_model=DEFAULT_MODEL,
        fallback_judge_endpoint=None,
        fallback_judge_model=None,
        include_evidence=False,
        static_findings=[
            Finding(
                severity=Severity.HIGH,
                category="Dependency Vulnerability",
                description="A dependency has a fixed version.",
                fixed_version="1.2.3",
            )
        ],
        dynamic_findings=[],
        dynamic_evidence=[],
        execution_errors=[],
    )

    assert report.findings.application_supply_chain[0].remediation is None


def test_incomplete_reason_does_not_mix_unrelated_payload_errors():
    report = build_report(
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
        dynamic_evidence=[],
        execution_errors=[
            ExecutionError(
                source=ErrorSource.DYNAMIC,
                message="Primary judge returned an invalid verdict",
                payload_id="pi-003",
            ),
            ExecutionError(
                source=ErrorSource.DYNAMIC,
                message="No fallback judge configured after primary judge failure",
                payload_id="pi-004",
            ),
        ],
    )

    assert report.incomplete_reason == (
        "The scan result is incomplete because 2 execution error(s) occurred. "
        "Review execution_errors before treating missing findings as clean."
    )


def test_incomplete_reason_covers_primary_judge_request_failure_without_fallback():
    report = build_report(
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
        dynamic_evidence=[],
        execution_errors=[
            ExecutionError(
                source=ErrorSource.DYNAMIC,
                message="Primary judge request failed",
                payload_id="pi-003",
            ),
            ExecutionError(
                source=ErrorSource.DYNAMIC,
                message="No fallback judge configured after primary judge failure",
                payload_id="pi-003",
            ),
        ],
    )

    assert report.incomplete_reason == (
        "The scan could not complete because payload pi-003 could not be "
        "evaluated reliably because the primary judge request failed and no "
        "fallback judge was configured."
    )
