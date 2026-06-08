# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

from collections import Counter
from typing import Optional

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


def _risk_title(risk: ReportRisk) -> str:
    if risk.package_name and risk.package_version and risk.fixed_version:
        return (
            f"{risk.package_name} {risk.package_version} -> "
            f"upgrade to {risk.fixed_version} or later"
        )
    if risk.payload_ids and risk.category != "Scan Reliability":
        return f"{risk.category} failed"
    if risk.remediation:
        return risk.remediation.rstrip(".")
    return risk.description


def _risk_details(risk: ReportRisk) -> list[str]:
    details: list[str] = []
    if risk.payload_ids and risk.category != "Scan Reliability":
        details.append(f"Payload type: {risk.category}")
        details.append(f"Payloads: {', '.join(risk.payload_ids)}")
    if risk.owasp_tags:
        details.append(f"OWASP: {', '.join(_display_owasp_tags(risk.owasp_tags))}")
    if risk.vulnerability_ids:
        label = "CVE" if len(risk.vulnerability_ids) == 1 else "CVEs"
        details.append(f"{label}: {', '.join(risk.vulnerability_ids)}")
    if risk.source_file:
        details.append(f"Source: {risk.source_file}")
        owner_detail = f"Owner (from CODEOWNERS): {risk.owner}"
        if risk.owner == "Unassigned":
            owner_detail += " (no CODEOWNERS match)"
        details.append(owner_detail)
    if risk.payload_ids and risk.category != "Scan Reliability" and risk.remediation:
        details.append(f"Mitigation: {risk.remediation.rstrip('.')}")
    return details


def _display_owasp_tags(tags: list[str]) -> list[str]:
    return [tag.removeprefix("OWASP:") for tag in tags]


def _required_fixes_lines(report: ScanReport) -> list[str]:
    lines: list[str] = []
    index = 1

    # Block 1: model behavior, sourced from failed HIGH/CRITICAL assessments
    failed = [
        a for a in _failed_assessments(report)
        if SEVERITY_RANK[a.severity] >= SEVERITY_RANK[Severity.HIGH]
    ]
    by_category: dict[str, dict] = {}
    for a in failed:
        bucket = by_category.setdefault(
            a.category, {"severity": a.severity, "ids": [], "tags": set()})
        bucket["ids"].append(a.payload_id)
        bucket["tags"].update(a.owasp_tags)
        if SEVERITY_RANK[a.severity] > SEVERITY_RANK[bucket["severity"]]:
            bucket["severity"] = a.severity

    for category, bucket in sorted(
        by_category.items(), key=lambda kv: (-SEVERITY_RANK[kv[1]["severity"]], kv[0])
    ):
        lines.append(f"{index}. {category}")
        bullets = CATEGORY_MITIGATION.get(category)
        if bullets:
            for bullet in bullets:
                lines.append(f"   - {bullet}")
        else:
            lines.append(f"   Payloads: {', '.join(sorted(bucket['ids']))}")
            lines.append(f"   - {GENERIC_MITIGATION}")
        if bucket["tags"]:
            lines.append(f"   OWASP: {', '.join(_display_owasp_tags(sorted(bucket['tags'])))}")
        lines.append("")
        index += 1

    # Block 2: preserved supply-chain + model-license rendering (original detail)
    for risk in [
        *report.findings.application_supply_chain,
        *report.findings.model_license,
    ]:
        lines.append(f"{index}. {_risk_title(risk)}")
        for detail in _risk_details(risk):
            lines.append(f"   {detail}")
        lines.append("")
        index += 1

    if lines and lines[-1] == "":
        lines.pop()
    return lines


def _evidence_excerpt(report: ScanReport, payload_id: str) -> Optional[str]:
    for evidence in report.dynamic_evidence:
        if evidence.payload_id == payload_id and evidence.target_response_excerpt:
            suffix = " [truncated]" if evidence.response_truncated else ""
            return f'"{evidence.target_response_excerpt}"{suffix}'
    return None


def _failed_payloads_lines(report: ScanReport) -> list[str]:
    failed = sorted(
        _failed_assessments(report),
        key=lambda a: (-SEVERITY_RANK[a.severity], a.category, a.payload_id),
    )
    lines: list[str] = []
    for assessment in failed:
        tags = (
            f" · OWASP: {', '.join(_display_owasp_tags(assessment.owasp_tags))}"
            if assessment.owasp_tags
            else ""
        )
        lines.append(
            f"{assessment.payload_id} · {assessment.category} · "
            f"{assessment.verdict} · {assessment.severity.value} · 1/1{tags}"
        )
        if assessment.category == "Sensitive Data Exfiltration":
            data_class = EXFIL_DATA_CLASS.get(assessment.payload_id)
            if data_class:
                lines.append(f"  Data class: {data_class}")
        lines.append(f"  Expected: {assessment.expected_behavior or 'not recorded'}")
        lines.append(f"  Observed: {assessment.verdict_reason or 'no reason recorded'}")
        excerpt = (
            _evidence_excerpt(report, assessment.payload_id)
            if assessment.evidence_available
            else None
        )
        lines.append(f"  Evidence: {excerpt}" if excerpt else "  Evidence: unavailable")
        context = CATEGORY_CONTEXT.get(assessment.category)
        if context:
            lines.append(f"  Context:  {context}")
        lines.append("")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def _severity_count_text(severities: Counter) -> str:
    ordered = ["critical", "high", "medium", "low", "info"]
    parts = [
        f"{count} {severity}" if count > 1 else severity
        for severity in ordered
        if (count := severities.get(severity, 0))
    ]
    return ", ".join(parts) if parts else "confirmed"


def _risk_count(risks: list[ReportRisk]) -> str:
    return _severity_count_text(Counter(r.severity.value.lower() for r in risks))


def _finding_count_lines(report: ScanReport) -> list[str]:
    failed = _failed_assessments(report)
    rows: list[tuple[str, str, bool]] = [
        ("Application supply chain", _risk_count(report.findings.application_supply_chain),
         bool(report.findings.application_supply_chain)),
        ("Grouped findings", _risk_count(report.findings.model_behavior),
         bool(report.findings.model_behavior)),
        ("Failed payloads",
         _severity_count_text(Counter(a.severity.value.lower() for a in failed)),
         bool(failed)),
        ("Model license", _risk_count(report.findings.model_license),
         bool(report.findings.model_license)),
        ("Scan reliability", _risk_count(report.findings.scan_reliability),
         bool(report.findings.scan_reliability)),
    ]
    lines = [f"{label}: {value}" for label, value, present in rows if present]
    if report.execution_errors:
        lines.append(f"Execution errors: {len(report.execution_errors)}")
    return lines or ["None"]
