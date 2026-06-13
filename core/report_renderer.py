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

# Shown when a package has at least one advisory with no upstream fix.
SUPPLY_CHAIN_NO_FIX = (
    "No upstream fix available — evaluate removing or replacing this dependency; "
    "if it must stay, isolate it and document a risk exception."
)

# Opinionated, package-specific guidance for libraries that are unsafe or
# unmaintained for their purpose regardless of the available patch level.
# Keyed by lowercase package name.
OPINIONATED_ADVICE = {
    "ecdsa": (
        "python-ecdsa is not constant-time (Minerva timing attack, CVE-2024-23342) and is "
        "not actively hardened against side channels; migrate sensitive ECDSA/ECDH "
        "operations to the maintained `cryptography` library."
    ),
}

GENERIC_RELIABILITY_ACTION = "rerun scan before accepting coverage for this category"


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
    error_payloads_count = len(
        {e.payload_id for e in report.execution_errors if e.payload_id}
    )
    total = report.dynamic_total_payloads
    if total <= 0:
        total = len(report.dynamic_assessments) + error_payloads_count
    evaluated = max(total - error_payloads_count, 0)

    lines = [
        f"Target:   {report.target_model or 'unknown'}",
        f"Type:     {report.scan_type}",
        f"Payloads: {total} total, {evaluated} evaluated, "
        f"{error_count} error{'' if error_count == 1 else 's'}",
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


def _parse_version(value: str):
    try:
        from packaging.version import Version
    except ImportError:
        Version = None

    # When packaging is available, always return a Version so comparisons in
    # _max_version never mix Version and tuple (which raises TypeError). An
    # unparseable string sorts lowest via Version("0.0.0").
    if Version is not None:
        try:
            return Version(value)
        except Exception:
            return Version("0.0.0")

    # Fallback (no packaging): compare numeric-dotted segments consistently.
    # Only the leading digits of each segment count, so a pre-release like
    # "3.13a1" parses as (3, 13) rather than (3, 131) and stays below "3.14".
    segments = []
    for segment in value.split("."):
        digits = []
        for ch in segment:
            if ch.isdigit():
                digits.append(ch)
            else:
                break
        segments.append(int("".join(digits)) if digits else 0)
    return tuple(segments)


def _max_version(versions: list[str]) -> Optional[str]:
    best = None
    best_key = None
    for version in versions:
        key = _parse_version(version)
        if best_key is None or key > best_key:
            best, best_key = version, key
    return best


def _aggregate_supply_chain(risks: list[ReportRisk]) -> list[dict]:
    """Collapse multiple advisories for the same package into one entry.

    Console-only: the JSON report keeps per-advisory findings. Each group records the
    highest available fixed version, the union of CVEs, the worst severity, and whether
    any advisory has no upstream fix.
    """
    groups: dict[str, dict] = {}
    order: list[str] = []
    for risk in risks:
        key = risk.package_name or f"__nopkg__{id(risk)}"
        group = groups.get(key)
        if group is None:
            group = {
                "package_name": risk.package_name,
                "package_version": risk.package_version,
                "severity": risk.severity,
                "fixed_versions": [],
                "fixed_cves": [],
                "unfixed_cves": [],
                "source_file": risk.source_file,
                "owner": risk.owner,
                "remediation": risk.remediation,
                "description": risk.description,
                "has_unfixed": False,
            }
            groups[key] = group
            order.append(key)
        if SEVERITY_RANK[risk.severity] > SEVERITY_RANK[group["severity"]]:
            group["severity"] = risk.severity
        # A CVE is "fixed" if any advisory for this package ships a fixed version.
        # Classification must not depend on advisory order, so a later fixed
        # advisory promotes a CVE out of unfixed_cves seen earlier.
        if risk.fixed_version:
            group["fixed_versions"].append(risk.fixed_version)
        else:
            group["has_unfixed"] = True
        for cve in risk.vulnerability_ids or []:
            if risk.fixed_version:
                if cve in group["unfixed_cves"]:
                    group["unfixed_cves"].remove(cve)
                if cve not in group["fixed_cves"]:
                    group["fixed_cves"].append(cve)
            elif cve not in group["fixed_cves"] and cve not in group["unfixed_cves"]:
                group["unfixed_cves"].append(cve)

    result = [groups[key] for key in order]
    result.sort(key=lambda g: (-SEVERITY_RANK[g["severity"]], (g["package_name"] or "")))
    return result


def _supply_chain_advice(
    package_name: Optional[str], has_unfixed: bool
) -> Optional[str]:
    curated = OPINIONATED_ADVICE.get((package_name or "").lower())
    if curated:
        return curated
    if has_unfixed:
        return SUPPLY_CHAIN_NO_FIX
    return None


def _cve_label(cves: list[str]) -> str:
    return "CVE" if len(cves) == 1 else "CVEs"


def _supply_chain_entry_lines(index: int, group: dict) -> list[str]:
    severity = group["severity"].value
    package = group["package_name"]
    version = group["package_version"]
    fixed = _max_version(group["fixed_versions"]) if group["fixed_versions"] else None
    fixed_cves = group["fixed_cves"]
    unfixed_cves = group["unfixed_cves"]

    if package and version and fixed:
        title = f"{package} {version} -> upgrade to {fixed} or later"
    elif package and version:
        title = f"{package} {version} — no upstream fix available"
    elif group["remediation"]:
        title = group["remediation"].rstrip(".")
    elif package:
        title = package
    else:
        title = group["description"]

    lines = [f"{index}. [{severity}] {title}"]

    # When an upgrade exists but some CVEs have no fix, split them so the upgrade
    # title is not read as resolving everything.
    if fixed and unfixed_cves:
        if fixed_cves:
            lines.append(f"   Fixed by upgrade: {', '.join(fixed_cves)}")
        lines.append(f"   No fix available: {', '.join(unfixed_cves)}")
    else:
        all_cves = fixed_cves + unfixed_cves
        if all_cves:
            lines.append(f"   {_cve_label(all_cves)}: {', '.join(all_cves)}")

    advice = _supply_chain_advice(package, group["has_unfixed"])
    if advice:
        lines.append(f"   Action: {advice}")
    if group["source_file"]:
        lines.append(f"   Source: {group['source_file']}")
        owner = f"Owner (from CODEOWNERS): {group['owner']}"
        if group["owner"] == "Unassigned":
            owner += " (no CODEOWNERS match)"
        lines.append(f"   {owner}")
    return lines


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
        lines.append(f"{index}. [{bucket['severity'].value}] {category}")
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

    # Block 2: supply chain, aggregated per package (one upgrade target + union of CVEs).
    for group in _aggregate_supply_chain(report.findings.application_supply_chain):
        lines.extend(_supply_chain_entry_lines(index, group))
        lines.append("")
        index += 1

    # Block 3: model-license findings, original detail with severity prefix.
    for risk in report.findings.model_license:
        lines.append(f"{index}. [{risk.severity.value}] {_risk_title(risk)}")
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
        for leak in assessment.leaks:
            lines.append(f"  Leak:     {leak.label} ({leak.tier})")
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
        f"{count} {severity}"
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


def _scan_reliability_lines(report: ScanReport) -> list[str]:
    if not report.execution_errors:
        return []

    category_by_payload = {a.payload_id: a.category for a in report.dynamic_assessments}

    category_by_payload = {a.payload_id: a.category for a in report.dynamic_assessments}
    lines: list[str] = []
    for index, (error, risk) in enumerate(zip(report.execution_errors, report.findings.scan_reliability), start=1):
        subject = error.payload_id or "(no payload)"
        lines.append(f"{index}. {subject} · {error.message}")
        impact = "payload was not evaluated" if error.payload_id else "scan coverage was reduced"
        lines.append(f"   Impact:   {impact}")
        coverage = category_by_payload.get(error.payload_id) if error.payload_id else None
        if coverage:
            lines.append(f"   Coverage: {coverage}")
        action = risk.remediation or GENERIC_RELIABILITY_ACTION
        lines.append(f"   Action:   {action}")
        lines.append("")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


# ---------------------------------------------------------------------------
# Ported helpers from console.py (verbatim)
# ---------------------------------------------------------------------------


def _all_risks(report: ScanReport) -> list[ReportRisk]:
    return [
        *report.findings.application_supply_chain,
        *report.findings.model_behavior,
        *report.findings.model_license,
        *report.findings.scan_reliability,
    ]


def _severity_label_text(severities: Counter) -> str:
    populated = [severity for severity, count in severities.items() if count]
    if len(populated) == 1:
        return populated[0]
    return _severity_count_text(severities)


def _human_reason(report: ScanReport) -> str:
    blocking = [
        risk
        for risk in _all_risks(report)
        if risk.severity.value in {"MEDIUM", "HIGH", "CRITICAL"}
    ]
    if report.scan_type == "static" and blocking:
        severities = Counter(risk.severity.value.lower() for risk in blocking)
        severity_text = _severity_label_text(severities)
        noun = "vulnerability" if len(blocking) == 1 else "vulnerabilities"
        return (
            f"{len(blocking)} confirmed {severity_text} dependency {noun} "
            "must be fixed before staging."
        )
    return report.executive_summary.reason


def _passed_payload_lines(report: ScanReport) -> list[str]:
    lines: list[str] = []
    for assessment in report.dynamic_assessments:
        if assessment.verdict != "PASS":
            continue
        tag_text = (
            f" · OWASP: {', '.join(_display_owasp_tags(assessment.owasp_tags))}"
            if assessment.owasp_tags
            else ""
        )
        lines.append(f"{assessment.payload_id} · {assessment.category}{tag_text}")
    return lines


def _next_step(report: ScanReport) -> str:
    if report.findings.application_supply_chain:
        return "Fix the dependency versions above, then rerun AegisLocal."
    if report.findings.model_behavior:
        return "Review the failed payloads above, update guardrails, then rerun AegisLocal."
    if report.execution_errors:
        return "Fix the scan reliability issues above, then rerun AegisLocal."
    return "No blocking action is required."


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

_RESULT_STYLES = {
    "PASS": "bold green",
    "FAIL": "bold red",
    "UNKNOWN": "bold yellow",
}


def _append_section(text: Text, header: str, body: list[str]) -> None:
    text.append(f"\n\n{header}\n", style="bold")
    text.append("\n".join(body) if body else "None")


def render_console_text(report: ScanReport, verbose: bool) -> Text:
    text = Text()
    text.append(
        f"{report.production_decision.value} · {report.security_result.value} · "
        f"{report.scan_type} scan · {report.scan_duration_seconds:.1f}s",
        style=_RESULT_STYLES.get(report.security_result.value, "bold"),
    )

    text.append("\n\nWhy\n", style="bold")
    text.append(_human_reason(report))

    scan_context = _scan_context_lines(report)
    if scan_context:
        _append_section(text, "Scan context", scan_context)

    required_fixes = _required_fixes_lines(report)
    if required_fixes:
        _append_section(text, "Required fixes", required_fixes)

    failed_payloads = _failed_payloads_lines(report)
    if failed_payloads:
        _append_section(text, "Failed payloads", failed_payloads)

    _append_section(text, "Finding counts", _finding_count_lines(report))

    scan_reliability = _scan_reliability_lines(report)
    if scan_reliability:
        _append_section(text, "Scan reliability", scan_reliability)

    if verbose:
        passed = _passed_payload_lines(report)
        if passed:
            _append_section(text, "Passed payloads", passed)

    text.append("\n\nNext step\n", style="bold")
    text.append(_next_step(report))
    return text
