# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

import asyncio
import time
from importlib.metadata import PackageNotFoundError, version as pkg_version
from pathlib import Path
from typing import Optional, Sequence

import typer

from core.console import ScanConsole
from core.models import (
    ErrorSource,
    ExecutionError,
    ExecutionStatus,
    ExecutiveSummary,
    Finding,
    FindingAction,
    GroupedFinding,
    OwnerRemediation,
    ProductionDecision,
    ReportRisk,
    RiskAreas,
    ScanReport,
    SecurityResult,
    Severity,
)
from engines.bom import write_aibom, write_sbom
from engines.dynamic_fuzzer import (
    DYNAMIC_CONCURRENCY,
    TARGET_TIMEOUT_SECONDS,
    load_payloads,
    run_dynamic_scan,
)
from engines.license_enrichment import enrich_license_metadata
from engines.license_policy import run_license_policy_review
from engines.model_inventory import discover_project_model_names
from engines.static_scanner import (
    discover_manifest_files,
    parse_manifest_files,
    run_static_scan,
)


DEFAULT_ENDPOINT = "http://localhost:11434/v1/chat/completions"
DEFAULT_MODEL = "llama3.1:8b"
DEFAULT_SBOM_FILE = "bom.sbom.cdx.json"
DEFAULT_AIBOM_FILE = "bom.aibom.cdx.json"
SCAN_MODES = {"static", "dynamic", "licenses", "all"}
SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

app = typer.Typer(help="AegisLocal local AI security scanner.")


def _get_version() -> str:
    try:
        return pkg_version("aegislocal")
    except PackageNotFoundError:
        return "0.1.0"


@app.callback()
def main() -> None:
    """Run AegisLocal commands."""


def build_report(
    target_endpoint: str,
    target_model: str,
    target_timeout_seconds: float,
    dynamic_concurrency: int,
    judge_endpoint: str,
    judge_model: str,
    fallback_judge_endpoint: Optional[str],
    fallback_judge_model: Optional[str],
    include_evidence: bool,
    static_findings,
    dynamic_findings,
    dynamic_evidence,
    execution_errors,
    dynamic_assessments=None,
    license_findings=None,
    license_coverage=None,
    scan_type: str = "all",
    include_static_section: bool = True,
    include_dynamic_section: bool = True,
    include_license_section: bool = False,
    scan_duration_seconds: float = 0.0,
) -> ScanReport:
    static_findings = list(static_findings or [])
    dynamic_findings = list(dynamic_findings or [])
    dynamic_assessments = list(dynamic_assessments or [])
    dynamic_evidence = list(dynamic_evidence or [])
    license_findings = list(license_findings or [])
    has_failing_static_findings = any(
        getattr(finding, "action", FindingAction.FAIL) == FindingAction.FAIL
        for finding in [*static_findings, *license_findings]
    )
    has_failing_findings = has_failing_static_findings or bool(dynamic_findings)
    execution_status = (
        ExecutionStatus.SCAN_INCOMPLETE if execution_errors else ExecutionStatus.COMPLETE
    )

    if has_failing_findings:
        security_result = SecurityResult.FAIL
    elif execution_status == ExecutionStatus.SCAN_INCOMPLETE:
        security_result = SecurityResult.UNKNOWN
    else:
        security_result = SecurityResult.PASS

    passed_audit = (
        security_result == SecurityResult.PASS
        and execution_status == ExecutionStatus.COMPLETE
    )
    production_decision = _production_decision(
        static_findings=static_findings,
        dynamic_findings=dynamic_findings,
        license_findings=license_findings,
        execution_errors=execution_errors,
    )
    risk_areas = _build_risk_areas(
        static_findings=static_findings,
        dynamic_findings=dynamic_findings,
        license_findings=license_findings,
        execution_errors=execution_errors,
    )
    incomplete_reason = _build_incomplete_reason(
        execution_errors=execution_errors,
        has_confirmed_findings=has_failing_findings,
    )
    owner_remediation = _build_owner_remediation(risk_areas)
    executive_summary = _build_executive_summary(
        decision=production_decision,
        risk_areas=risk_areas,
        owner_remediation=owner_remediation,
        incomplete_reason=incomplete_reason,
    )

    return ScanReport(
        scan_type=scan_type,
        target_endpoint=target_endpoint if include_dynamic_section else None,
        target_model=target_model if include_dynamic_section else None,
        target_timeout_seconds=(
            target_timeout_seconds if include_dynamic_section else None
        ),
        dynamic_concurrency=dynamic_concurrency if include_dynamic_section else None,
        judge_endpoint=judge_endpoint if include_dynamic_section else None,
        judge_model=judge_model if include_dynamic_section else None,
        fallback_judge_endpoint=(
            fallback_judge_endpoint if include_dynamic_section else None
        ),
        fallback_judge_model=fallback_judge_model if include_dynamic_section else None,
        include_evidence=include_evidence if include_dynamic_section else None,
        security_result=security_result,
        production_decision=production_decision,
        executive_summary=executive_summary,
        execution_status=execution_status,
        status_message=(
            "**SCAN INCOMPLETE**"
            if execution_status == ExecutionStatus.SCAN_INCOMPLETE
            else "COMPLETE"
        ),
        incomplete_reason=incomplete_reason,
        static_findings=static_findings if include_static_section else None,
        dynamic_findings=dynamic_findings if include_dynamic_section else None,
        dynamic_assessments=(
            dynamic_assessments if include_dynamic_section else None
        ),
        dynamic_evidence=dynamic_evidence if include_dynamic_section else None,
        license_findings=license_findings if include_license_section else None,
        license_coverage=license_coverage if include_license_section else None,
        risk_areas=risk_areas,
        owner_remediation=owner_remediation,
        execution_errors=execution_errors,
        passed_audit=passed_audit,
        scan_duration_seconds=scan_duration_seconds,
        scanner_version=_get_version(),
    )


def _production_decision(
    *,
    static_findings: Sequence[Finding],
    dynamic_findings: Sequence[GroupedFinding],
    license_findings: Sequence[Finding],
    execution_errors: Sequence[ExecutionError],
) -> ProductionDecision:
    failing_findings = [
        finding
        for finding in [*static_findings, *license_findings]
        if getattr(finding, "action", FindingAction.FAIL) == FindingAction.FAIL
    ]
    all_confirmed = [*failing_findings, *dynamic_findings]

    if any(_severity_at_least(item.severity, Severity.HIGH) for item in all_confirmed):
        return ProductionDecision.BLOCK_PRODUCTION
    if any(_severity_at_least(item.severity, Severity.MEDIUM) for item in all_confirmed):
        return ProductionDecision.BLOCK_STAGING
    if execution_errors:
        return ProductionDecision.SCAN_INVALID
    if all_confirmed or _has_warning_findings([*static_findings, *license_findings]):
        return ProductionDecision.WARN
    return ProductionDecision.PASS


def _has_warning_findings(findings: Sequence[Finding]) -> bool:
    return any(
        getattr(finding, "action", FindingAction.FAIL) != FindingAction.FAIL
        for finding in findings
    )


def _severity_at_least(severity: Severity, minimum: Severity) -> bool:
    return SEVERITY_RANK[severity] >= SEVERITY_RANK[minimum]


def _build_risk_areas(
    *,
    static_findings: Sequence[Finding],
    dynamic_findings: Sequence[GroupedFinding],
    license_findings: Sequence[Finding],
    execution_errors: Sequence[ExecutionError],
) -> RiskAreas:
    application_supply_chain: list[ReportRisk] = [
        _risk_from_finding(finding, owner="Platform team")
        for finding in static_findings
    ]
    model_license: list[ReportRisk] = []

    for finding in license_findings:
        if finding.subject_type == "model" or "Model License" in finding.category:
            model_license.append(_risk_from_finding(finding, owner="Security team"))
        else:
            application_supply_chain.append(
                _risk_from_finding(finding, owner="Platform team")
            )

    model_behavior = [
        ReportRisk(
            severity=finding.severity,
            category=finding.category,
            description=(
                f"{finding.failed_count} dynamic payload(s) failed: "
                f"{', '.join(finding.payload_ids)}"
            ),
            owner="AI platform team",
            remediation="Review failed payloads and tune prompts, policies, or guardrails.",
            payload_ids=finding.payload_ids,
        )
        for finding in dynamic_findings
    ]

    scan_reliability = [
        ReportRisk(
            severity=_execution_error_severity(error),
            category="Scan Reliability",
            description=_execution_error_description(error),
            owner="AI platform team",
            remediation=_execution_error_remediation(error),
            payload_ids=[error.payload_id] if error.payload_id else [],
        )
        for error in execution_errors
    ]

    return RiskAreas(
        application_supply_chain=sorted(
            application_supply_chain,
            key=lambda item: (-SEVERITY_RANK[item.severity], item.category),
        ),
        model_behavior=sorted(
            model_behavior,
            key=lambda item: (-SEVERITY_RANK[item.severity], item.category),
        ),
        model_license=sorted(
            model_license,
            key=lambda item: (-SEVERITY_RANK[item.severity], item.category),
        ),
        scan_reliability=scan_reliability,
    )


def _risk_from_finding(finding: Finding, *, owner: str) -> ReportRisk:
    remediation = finding.remediation
    if finding.fixed_version:
        remediation = f"Upgrade {finding.package_name} to {finding.fixed_version} or later."
    return ReportRisk(
        severity=finding.severity,
        category=finding.category,
        description=finding.description,
        owner=owner,
        remediation=remediation,
        subject_name=finding.subject_name,
        package_name=finding.package_name,
    )


def _execution_error_severity(error: ExecutionError) -> Severity:
    if error.source in {ErrorSource.CONFIG, ErrorSource.DYNAMIC}:
        return Severity.HIGH
    return Severity.MEDIUM


def _execution_error_description(error: ExecutionError) -> str:
    subject = f" for {error.payload_id}" if error.payload_id else ""
    detail = f": {error.detail}" if error.detail else ""
    return f"{error.message}{subject}{detail}"


def _execution_error_remediation(error: ExecutionError) -> str:
    if "fallback judge" in error.message.lower() or "judge" in error.message.lower():
        return "Configure a fallback judge and re-run the dynamic scan."
    if error.source == ErrorSource.CONFIG:
        return "Fix scan configuration and re-run before trusting omitted results."
    return "Re-run the scan and review the failing scanner dependency or service."


def _build_incomplete_reason(
    *,
    execution_errors: Sequence[ExecutionError],
    has_confirmed_findings: bool,
) -> Optional[str]:
    if not execution_errors:
        return None

    invalid_verdict_payload_ids = {
        error.payload_id
        for error in execution_errors
        if error.payload_id and "invalid verdict" in error.message.lower()
    }
    request_failed_payload_ids = {
        error.payload_id
        for error in execution_errors
        if error.payload_id and "judge request failed" in error.message.lower()
    }
    invalid_payload_ids = invalid_verdict_payload_ids | request_failed_payload_ids
    no_fallback_payload_ids = {
        error.payload_id
        for error in execution_errors
        if error.payload_id and "no fallback judge" in error.message.lower()
    }
    judge_failed_with_no_fallback = sorted(invalid_payload_ids & no_fallback_payload_ids)
    if judge_failed_with_no_fallback:
        prefix = (
            "The scan found confirmed failures, but "
            if has_confirmed_findings
            else "The scan could not complete because "
        )
        payload_text = ", ".join(judge_failed_with_no_fallback)
        reason = _primary_judge_failure_reason(
            payload_ids=judge_failed_with_no_fallback,
            invalid_payload_ids=invalid_verdict_payload_ids,
            request_failed_payload_ids=request_failed_payload_ids,
        )
        return (
            f"{prefix}payload {payload_text} could not be evaluated reliably because "
            f"{reason} and no fallback judge was configured."
        )

    calibration_payloads = sorted(
        {
            error.payload_id
            for error in execution_errors
            if error.payload_id and "calibration" in error.message.lower()
        }
    )
    if calibration_payloads:
        return (
            "The dynamic scan stopped before payload evaluation because judge "
            "calibration failed; configure a stronger judge or disable calibration only "
            "for diagnostic runs."
        )

    prefix = (
        "The scan found confirmed failures, but "
        if has_confirmed_findings
        else "The scan result is incomplete because "
    )
    return (
        f"{prefix}{len(execution_errors)} execution error(s) occurred. "
        "Review execution_errors before treating missing findings as clean."
    )


def _primary_judge_failure_reason(
    *,
    payload_ids: Sequence[str],
    invalid_payload_ids: set[str],
    request_failed_payload_ids: set[str],
) -> str:
    all_invalid = all(payload_id in invalid_payload_ids for payload_id in payload_ids)
    all_request_failed = all(
        payload_id in request_failed_payload_ids for payload_id in payload_ids
    )
    if all_invalid and not all_request_failed:
        return "the primary judge returned an invalid verdict"
    if all_request_failed and not all_invalid:
        return "the primary judge request failed"
    return "the primary judge could not produce a valid verdict"


def _build_owner_remediation(risk_areas: RiskAreas) -> list[OwnerRemediation]:
    owner_actions: dict[str, list[str]] = {}

    def add(owner: str, action: str) -> None:
        owner_actions.setdefault(owner, [])
        if action not in owner_actions[owner]:
            owner_actions[owner].append(action)

    if risk_areas.application_supply_chain:
        add("Platform team", "Fix dependency vulnerabilities and supply-chain warnings.")
    if risk_areas.model_behavior:
        payloads = sorted(
            {
                payload_id
                for risk in risk_areas.model_behavior
                for payload_id in risk.payload_ids
            }
        )
        add("AI platform team", f"Review failed dynamic payloads: {', '.join(payloads)}.")
        categories = sorted({risk.category for risk in risk_areas.model_behavior})
        add("ML team", f"Tune system prompt or guardrails for: {', '.join(categories)}.")
    if risk_areas.model_license:
        add("Security team", "Approve model license policy before production use.")
    if risk_areas.scan_reliability:
        add("AI platform team", "Re-run incomplete scans with fallback judge and evidence capture.")

    return [
        OwnerRemediation(owner=owner, actions=actions)
        for owner, actions in sorted(owner_actions.items())
    ]


def _build_executive_summary(
    *,
    decision: ProductionDecision,
    risk_areas: RiskAreas,
    owner_remediation: Sequence[OwnerRemediation],
    incomplete_reason: Optional[str],
) -> ExecutiveSummary:
    top_risks = _top_risk_descriptions(risk_areas)
    next_actions = [
        action
        for remediation in owner_remediation
        for action in remediation.actions
    ]
    if incomplete_reason and "fallback judge" in incomplete_reason.lower():
        next_actions.insert(0, "Re-run with fallback judge.")
    reason = _decision_reason(decision, risk_areas, incomplete_reason)
    return ExecutiveSummary(
        decision=decision,
        reason=reason,
        top_risks=top_risks[:5],
        next_actions=next_actions[:5],
    )


def _top_risk_descriptions(risk_areas: RiskAreas) -> list[str]:
    risks = [
        *risk_areas.application_supply_chain,
        *risk_areas.model_behavior,
        *risk_areas.model_license,
        *risk_areas.scan_reliability,
    ]
    return [
        risk.description
        for risk in sorted(risks, key=lambda item: -SEVERITY_RANK[item.severity])
    ]


def _decision_reason(
    decision: ProductionDecision,
    risk_areas: RiskAreas,
    incomplete_reason: Optional[str],
) -> str:
    has_critical_app = any(
        risk.severity == Severity.CRITICAL
        for risk in risk_areas.application_supply_chain
    )
    has_high_behavior = any(
        _severity_at_least(risk.severity, Severity.HIGH)
        for risk in risk_areas.model_behavior
    )
    if decision == ProductionDecision.BLOCK_PRODUCTION and has_critical_app and has_high_behavior:
        return "Confirmed high-risk dynamic failures and critical dependency vulnerabilities"
    if decision == ProductionDecision.BLOCK_PRODUCTION:
        return "Confirmed high or critical severity findings block production use"
    if decision == ProductionDecision.BLOCK_STAGING:
        return "Confirmed medium severity findings require remediation before staging"
    if decision == ProductionDecision.SCAN_INVALID:
        return incomplete_reason or "The scan did not complete reliably"
    if decision == ProductionDecision.WARN:
        return "No blocking findings, but warnings require owner review"
    return "No blocking findings and the scan completed"


def render_markdown_report(report: ScanReport) -> str:
    scan_status = (
        "Incomplete"
        if report.execution_status == ExecutionStatus.SCAN_INCOMPLETE
        else "Complete"
    )
    lines = [
        "# AegisLocal Report",
        "",
        f"Decision: {report.production_decision.value}",
    ]
    if report.target_model:
        lines.append(f"Model: {report.target_model}")
    lines.extend(
        [
            f"Scan status: {scan_status}",
            f"Main reason: {report.executive_summary.reason}",
            "",
            "## Top Issues",
        ]
    )

    if report.executive_summary.top_risks:
        for index, risk in enumerate(report.executive_summary.top_risks, start=1):
            lines.append(f"{index}. {risk}")
    else:
        lines.append("None.")

    if report.incomplete_reason:
        lines.extend(["", "## Why Incomplete", report.incomplete_reason])

    if report.dynamic_assessments:
        lines.extend(
            [
                "",
                "## Dynamic Confidence",
                "| Payload | Verdict | Confidence | Judge agreement | Evidence |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for assessment in report.dynamic_assessments:
            evidence = "yes" if assessment.evidence_available else "no"
            lines.append(
                "| "
                f"{assessment.payload_id} | {assessment.verdict} | "
                f"{assessment.confidence} | {assessment.judge_agreement} | {evidence} |"
            )

    lines.extend(["", "## Risk Areas"])
    lines.extend(_markdown_risk_area("Application supply chain risk", report.risk_areas.application_supply_chain))
    lines.extend(_markdown_risk_area("Model behavioral risk", report.risk_areas.model_behavior))
    lines.extend(_markdown_risk_area("Model license risk", report.risk_areas.model_license))
    lines.extend(_markdown_risk_area("Scan reliability risk", report.risk_areas.scan_reliability))

    lines.extend(["", "## Remediation By Owner"])
    if report.owner_remediation:
        for owner in report.owner_remediation:
            actions = "; ".join(owner.actions)
            lines.append(f"- {owner.owner}: {actions}")
    else:
        lines.append("- None.")

    return "\n".join(lines).rstrip() + "\n"


def _markdown_risk_area(title: str, risks: Sequence[ReportRisk]) -> list[str]:
    lines = [f"### {title}"]
    if not risks:
        lines.append("- None.")
        return lines
    for risk in risks:
        remediation = f" Remediation: {risk.remediation}" if risk.remediation else ""
        lines.append(
            f"- {risk.severity.value} - {risk.description} "
            f"Owner: {risk.owner}.{remediation}"
        )
    return lines


async def run_scan(
    project_root: Path,
    payload_file: Path,
    target_endpoint: str,
    target_model: str,
    target_timeout_seconds: float,
    dynamic_concurrency: int,
    judge_endpoint: str,
    judge_model: str,
    fallback_judge_endpoint: Optional[str],
    fallback_judge_model: Optional[str],
    include_evidence: bool,
    calibrate_judge_model: bool,
    run_static: bool,
    run_dynamic: bool,
    license_scan: bool,
    license_enrich: bool,
    generate_bom: bool,
    sbom_file: Optional[Path],
    aibom_file: Optional[Path],
    license_cache_file: Optional[Path],
    console: ScanConsole,
) -> ScanReport:
    start = time.monotonic()
    project_root = project_root.expanduser().resolve()

    # Parse once, pass to engines to avoid redundant I/O
    manifest_files = discover_manifest_files(project_root)
    deps, dep_errors = parse_manifest_files(manifest_files)

    static_findings = []
    static_errors = []
    if run_static:
        with console.static_progress(len(deps)) as static_cb:
            static_findings, static_errors = await run_static_scan(
                project_root,
                on_progress=static_cb,
                dependencies=deps,
                initial_errors=dep_errors,
            )

    license_findings = []
    license_errors = []
    license_coverage = None
    scanned_models = _license_model_names(
        project_root=project_root,
        target_model=target_model,
        judge_model=judge_model,
        fallback_judge_model=fallback_judge_model,
        include_runtime_models=run_dynamic,
    )
    if license_scan:
        sbom_file, aibom_file = _prepare_license_boms(
            project_root=project_root,
            dependencies=deps,
            model_names=scanned_models,
            sbom_file=sbom_file,
            aibom_file=aibom_file,
            generate_bom=generate_bom,
        )
        if license_enrich:
            license_errors.extend(
                await enrich_license_metadata(
                    project_root=project_root,
                    dependencies=deps,
                    model_names=scanned_models,
                    license_cache_path=license_cache_file,
                )
            )
        policy_findings, license_coverage, policy_errors = run_license_policy_review(
            project_root=project_root,
            dependencies=deps,
            model_names=scanned_models,
            sbom_path=sbom_file,
            aibom_path=aibom_file,
            license_cache_path=license_cache_file,
        )
        license_findings = policy_findings
        license_errors.extend(policy_errors)

    dynamic_findings = []
    dynamic_errors = []
    dynamic_evidence = []
    dynamic_assessments = []
    if run_dynamic:
        payloads, payload_errors = load_payloads(payload_file)
        with console.dynamic_progress(len(payloads)) as dynamic_cb:
            (
                dynamic_findings,
                dynamic_errors,
                dynamic_evidence,
                dynamic_assessments,
            ) = await run_dynamic_scan(
                payload_file=payload_file,
                target_endpoint=target_endpoint,
                target_model=target_model,
                judge_endpoint=judge_endpoint,
                judge_model=judge_model,
                fallback_judge_endpoint=fallback_judge_endpoint,
                fallback_judge_model=fallback_judge_model,
                target_timeout_seconds=target_timeout_seconds,
                dynamic_concurrency=dynamic_concurrency,
                include_evidence=include_evidence,
                calibrate_judge_model=calibrate_judge_model,
                on_progress=dynamic_cb,
                payloads=payloads,
                initial_errors=payload_errors,
            )

    duration = time.monotonic() - start
    scan_type = _report_scan_type(run_static, run_dynamic, license_scan)

    return build_report(
        target_endpoint=target_endpoint,
        target_model=target_model,
        target_timeout_seconds=target_timeout_seconds,
        dynamic_concurrency=dynamic_concurrency,
        judge_endpoint=judge_endpoint,
        judge_model=judge_model,
        fallback_judge_endpoint=fallback_judge_endpoint,
        fallback_judge_model=fallback_judge_model,
        include_evidence=include_evidence,
        static_findings=static_findings,
        dynamic_findings=dynamic_findings,
        dynamic_evidence=dynamic_evidence,
        dynamic_assessments=dynamic_assessments,
        license_findings=license_findings,
        license_coverage=license_coverage,
        execution_errors=[*static_errors, *license_errors, *dynamic_errors],
        scan_type=scan_type,
        include_static_section=run_static,
        include_dynamic_section=run_dynamic,
        include_license_section=license_scan,
        scan_duration_seconds=round(duration, 2),
    )


def _scan_model_names(
    target_model: str,
    judge_model: str,
    fallback_judge_model: Optional[str],
) -> list[str]:
    model_names = [target_model, judge_model]
    if fallback_judge_model:
        model_names.append(fallback_judge_model)
    return list(dict.fromkeys(model_names))


def _license_model_names(
    *,
    project_root: Path,
    target_model: str,
    judge_model: str,
    fallback_judge_model: Optional[str],
    include_runtime_models: bool,
) -> list[str]:
    model_names = discover_project_model_names(project_root)
    if include_runtime_models:
        model_names.extend(_scan_model_names(target_model, judge_model, fallback_judge_model))
    else:
        if target_model != DEFAULT_MODEL:
            model_names.append(target_model)
        if judge_model != DEFAULT_MODEL:
            model_names.append(judge_model)
        if fallback_judge_model:
            model_names.append(fallback_judge_model)
    return list(dict.fromkeys(model for model in model_names if model))


def _prepare_license_boms(
    *,
    project_root: Path,
    dependencies: Sequence,
    model_names: Sequence[str],
    sbom_file: Optional[Path],
    aibom_file: Optional[Path],
    generate_bom: bool,
) -> tuple[Optional[Path], Optional[Path]]:
    resolved_sbom = _resolve_bom_path(project_root, sbom_file, DEFAULT_SBOM_FILE)
    resolved_aibom = _resolve_bom_path(project_root, aibom_file, DEFAULT_AIBOM_FILE)

    if generate_bom and sbom_file is None:
        write_sbom(
            project_root=project_root,
            dependencies=dependencies,
            output_path=resolved_sbom,
            scanner_version=_get_version(),
        )
        typer.echo(f"Generated SBOM: {resolved_sbom}", err=True)

    if generate_bom and aibom_file is None:
        write_aibom(
            project_root=project_root,
            model_names=model_names,
            output_path=resolved_aibom,
            scanner_version=_get_version(),
        )
        typer.echo(f"Generated AIBOM: {resolved_aibom}", err=True)

    return (
        resolved_sbom if resolved_sbom.exists() else None,
        resolved_aibom if resolved_aibom.exists() else None,
    )


def _resolve_bom_path(project_root: Path, path: Optional[Path], default_name: str) -> Path:
    selected = path or Path(default_name)
    selected = selected.expanduser()
    return selected if selected.is_absolute() else project_root / selected


def _scan_mode_flags(scan_mode: Optional[str], license_scan: bool) -> tuple[bool, bool, bool, bool]:
    if scan_mode is None:
        return True, True, license_scan, True

    normalized = scan_mode.lower()
    if normalized not in SCAN_MODES:
        allowed = ", ".join(sorted(SCAN_MODES))
        typer.echo(f"Error: scan type must be one of: {allowed}", err=True)
        raise typer.Exit(code=2)

    if normalized == "static":
        return True, False, license_scan, True
    if normalized == "dynamic":
        return False, True, False, False
    if normalized == "licenses":
        return False, False, True, True
    return True, True, True, True


def _report_scan_type(run_static: bool, run_dynamic: bool, license_scan: bool) -> str:
    if license_scan and not run_static and not run_dynamic:
        return "licenses"
    if run_static and not run_dynamic and not license_scan:
        return "static"
    if run_dynamic and not run_static and not license_scan:
        return "dynamic"
    if run_static and run_dynamic and license_scan:
        return "all"
    return "custom"


@app.command()
def scan(
    scan_mode: Optional[str] = typer.Argument(
        None,
        metavar="[static|dynamic|licenses|all]",
        help="Optional scan type. Use 'licenses' for License Policy Review.",
    ),
    project_root: Path = typer.Option(
        Path("."),
        "--project-root",
        help="Project root to recursively scan for supported dependency manifests.",
    ),
    payload_file: Path = typer.Option(
        Path("data/payloads.json"),
        "--payload-file",
        help="Payload JSON file for dynamic behavioral tests.",
    ),
    target_endpoint: str = typer.Option(
        DEFAULT_ENDPOINT,
        "--target-endpoint",
        help="Target chat-completions endpoint.",
    ),
    target_model: str = typer.Option(
        DEFAULT_MODEL,
        "--target-model",
        help="Target model name sent in chat-completions requests.",
    ),
    target_timeout: float = typer.Option(
        float(TARGET_TIMEOUT_SECONDS),
        "--target-timeout",
        min=1.0,
        help="Target request timeout in seconds. Covers the full non-streaming response.",
    ),
    dynamic_concurrency: int = typer.Option(
        DYNAMIC_CONCURRENCY,
        "--dynamic-concurrency",
        min=1,
        max=10,
        help="Maximum concurrent target/judge payload evaluations.",
    ),
    judge_endpoint: str = typer.Option(
        DEFAULT_ENDPOINT,
        "--judge-endpoint",
        help="Primary judge chat-completions endpoint.",
    ),
    judge_model: str = typer.Option(
        DEFAULT_MODEL,
        "--judge-model",
        help="Primary judge model name.",
    ),
    fallback_judge_endpoint: Optional[str] = typer.Option(
        None,
        "--fallback-judge-endpoint",
        help="Fallback judge endpoint. Defaults to --judge-endpoint when only fallback model is set.",
    ),
    fallback_judge_model: Optional[str] = typer.Option(
        None,
        "--fallback-judge-model",
        help="Optional fallback judge model name.",
    ),
    include_evidence: bool = typer.Option(
        False,
        "--include-evidence",
        help="Include sanitized target response excerpts for failed or unknown dynamic payloads.",
    ),
    calibrate_judge_model: bool = typer.Option(
        True,
        "--judge-calibration/--no-judge-calibration",
        help="Run deterministic judge calibration before dynamic payload evaluation.",
    ),
    license_scan: bool = typer.Option(
        False,
        "--license-scan/--no-license-scan",
        help="Run License Policy Review using SBOM/AIBOM/cache metadata.",
    ),
    sbom_file: Optional[Path] = typer.Option(
        None,
        "--sbom",
        help="CycloneDX SBOM JSON file containing dependency license metadata.",
    ),
    aibom_file: Optional[Path] = typer.Option(
        None,
        "--aibom",
        help="CycloneDX-style AIBOM JSON file containing model license metadata.",
    ),
    license_cache_file: Optional[Path] = typer.Option(
        None,
        "--license-cache",
        help="Local License Policy Review metadata cache JSON file.",
    ),
    license_enrich: bool = typer.Option(
        True,
        "--license-enrich/--no-license-enrich",
        help="Fetch missing license metadata from public package/model APIs and cache it locally.",
    ),
    generate_bom: bool = typer.Option(
        True,
        "--generate-bom/--no-generate-bom",
        help="Generate missing default SBOM/AIBOM files for License Policy Review.",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Suppress all terminal UI. JSON report only.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show per-item status lines during scan.",
    ),
    output_file: Optional[Path] = typer.Option(
        None,
        "--output-file",
        "-o",
        help="Write JSON report to file (in addition to stdout).",
    ),
    markdown_output_file: Optional[Path] = typer.Option(
        None,
        "--markdown-output-file",
        help="Write a compact Markdown report for human review.",
    ),
) -> None:
    if quiet and verbose:
        typer.echo("Error: --quiet and --verbose are mutually exclusive.", err=True)
        raise typer.Exit(code=2)

    console = ScanConsole(quiet=quiet, verbose=verbose)
    run_static, run_dynamic, effective_license_scan, effective_generate_bom = _scan_mode_flags(
        scan_mode,
        license_scan,
    )

    report = asyncio.run(
        run_scan(
            project_root=project_root,
            payload_file=payload_file,
            target_endpoint=target_endpoint,
            target_model=target_model,
            target_timeout_seconds=target_timeout,
            dynamic_concurrency=dynamic_concurrency,
            judge_endpoint=judge_endpoint,
            judge_model=judge_model,
            fallback_judge_endpoint=fallback_judge_endpoint,
            fallback_judge_model=fallback_judge_model,
            include_evidence=include_evidence,
            calibrate_judge_model=calibrate_judge_model,
            run_static=run_static,
            run_dynamic=run_dynamic,
            license_scan=effective_license_scan,
            license_enrich=license_enrich,
            generate_bom=generate_bom and effective_generate_bom,
            sbom_file=sbom_file,
            aibom_file=aibom_file,
            license_cache_file=license_cache_file,
            console=console,
        )
    )

    console.print_summary(report)

    report_json = report.model_dump_json(indent=2, exclude_none=True)
    typer.echo(report_json)

    if output_file is not None:
        output_file.write_text(report_json, encoding="utf-8")
    if markdown_output_file is not None:
        markdown_output_file.write_text(render_markdown_report(report), encoding="utf-8")

    raise typer.Exit(code=0 if report.passed_audit else 1)


if __name__ == "__main__":
    app()
