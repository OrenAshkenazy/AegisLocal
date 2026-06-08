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
