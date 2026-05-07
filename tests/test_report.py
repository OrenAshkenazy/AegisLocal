# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

from core.models import ErrorSource, ExecutionError, Finding, Severity
from engines.dynamic_fuzzer import DYNAMIC_CONCURRENCY, TARGET_TIMEOUT_SECONDS
from main import DEFAULT_ENDPOINT, DEFAULT_MODEL, build_report


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
    assert report.execution_status == "SCAN_INCOMPLETE"
    assert report.status_message == "**SCAN INCOMPLETE**"
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
    assert report.execution_status == "COMPLETE"
    assert report.passed_audit is False
