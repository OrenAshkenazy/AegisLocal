# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

from collections import Counter
from typing import Optional

from rich.text import Text

from core.models import ReportRisk, ScanReport, Severity

SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

CATEGORY_CONTEXT = {
    "Tool Abuse": "simulated tool access, no real tool execution observed",
    "RAG Context Manipulation": "synthetic retrieved context, real RAG not configured",
    "Multi-Turn Setup Injection": "multi-turn prompt state tested, persistent memory not configured",
    "Sensitive Data Exfiltration": "canary secret exposure test, no real secret confirmed",
    "PII Leakage": "synthetic PII context, no real user data present",
}

EXFIL_DATA_CLASS = {
    "exfil-001": "credential-like string",
    "exfil-002": "canary secret",
    "exfil-003": "canary secret",
    "exfil-004": "retrieved context secret",
    "exfil-005": "tool output secret",
}

CAPABILITY_LINES = {
    "RAG Context Manipulation": ("RAG", "synthetic only"),
    "Tool Abuse": ("Tools", "simulated only"),
    "Multi-Turn Setup Injection": ("Memory", "prompt only"),
}

CATEGORY_MITIGATION = {
    "Direct Prompt Injection": [
        "Reject user-supplied system/developer directives.",
        "Strip role markers from untrusted input.",
        "Enforce instruction precedence at the system layer.",
        "Add regression tests for pi-* payloads.",
    ],
    "Jailbreak / Safety Bypass": [
        "Add refusal policy tests covering roleplay, encoding, and split-response bypasses.",
        "Add safety pre- and post-checks where applicable.",
        "Test policy translation bypasses across languages.",
    ],
    "System Prompt Extraction": [
        "Do not place secrets, credentials, or sensitive implementation notes in system prompts.",
        "Treat system prompts as control instructions, not a secret store.",
        "Add regression tests for prompt reveal, paraphrase, roleplay, debug mode, and extraction attempts.",
    ],
    "Insecure Code Generation": [
        "Require secure coding defaults.",
        "Reject unsafe implementation patterns (plaintext passwords, SQL concatenation, etc.).",
        "Add policy checks for generated code before output.",
    ],
    "Toxicity": [
        "Tune safety policy and moderation guardrails for protected-class abuse and hateful content.",
        "Add regression tests covering slur variants and indirect toxicity.",
    ],
    "Harmful Instruction Compliance": [
        "Strengthen refusal behavior for harmful operational instructions.",
        "Add safety checks before detailed procedural output.",
    ],
    "PII Extraction": [
        "Block requests for private personal data.",
        "Require privacy-preserving responses when identity data is requested.",
    ],
    "PII Leakage": [
        "Prevent replay of prior-user data, secrets, and private conversation context.",
        "Add memory and context isolation checks.",
    ],
    "Sensitive Data Exfiltration": [
        "Add canary secret detection in prompts, retrieved context, and tool outputs.",
        "Redact secrets before passing to the model.",
        "Enforce least-context exposure.",
        "Add regression tests for extraction and transformation attempts.",
    ],
    "Tool Abuse": [
        "Require tool allowlists and strict argument validation.",
        "Require user confirmation for sensitive actions.",
        "Enforce least-privilege tool scopes.",
        "Deny user-supplied tool directives.",
    ],
    "RAG Context Manipulation": [
        "Wrap retrieved text as untrusted quoted content.",
        "Strip embedded instructions from retrieved documents.",
        "Separate retrieval content from control instructions.",
        "Add canary tests in retrieved context.",
    ],
    "Policy Evasion": [
        "Test multilingual, encoded, roleplay, and formatting bypasses.",
        "Keep policy enforcement invariant across presentation changes.",
    ],
    "Multi-Turn Setup Injection": [
        "Do not persist user-supplied policy overrides across turns.",
        "Validate memory writes.",
        "Separate user preferences from security policy.",
        "Expire or scope conversation state.",
    ],
}

GENERIC_MITIGATION = (
    "Review failed payload behavior, add a regression test for the payload IDs "
    "listed, and add category-specific mitigation before release."
)


def _is_dynamic(report: ScanReport) -> bool:
    return report.scan_type in {"dynamic", "all", "custom"} and (
        bool(report.dynamic_assessments)
        or report.dynamic_total_payloads > 0
        or any(e.payload_id for e in report.execution_errors)
    )


def _failed_assessments(report: ScanReport) -> list:
    return [a for a in report.dynamic_assessments if a.verdict != "PASS"]


def _payload_error_count(report: ScanReport) -> int:
    return sum(1 for e in report.execution_errors if e.payload_id)


def _scan_context_lines(report: ScanReport) -> list[str]:
    if not _is_dynamic(report):
        return []

    error_count = _payload_error_count(report)
    total = report.dynamic_total_payloads
    if total <= 0:
        total = len(report.dynamic_assessments) + error_count
    evaluated = max(total - error_count, 0)

    lines = [
        f"Target:   {report.target_model or 'unknown'}",
        f"Type:     {report.scan_type}",
        f"Payloads: {total} total, {evaluated} evaluated, {error_count} error",
        "Attempts: 1 per payload",
        "Note:     single-attempt scan; rerun with more attempts for stochastic confidence",
    ]

    failed_categories = {a.category for a in _failed_assessments(report)}
    for category, (label, value) in CAPABILITY_LINES.items():
        if category in failed_categories:
            lines.append(f"{label + ':':<9} {value}")
    return lines
