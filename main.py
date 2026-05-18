# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

import asyncio
import time
from importlib.metadata import PackageNotFoundError, version as pkg_version
from pathlib import Path
from typing import Optional

import typer

from core.console import ScanConsole
from core.models import ExecutionStatus, FindingAction, ScanReport, SecurityResult
from engines.dynamic_fuzzer import (
    DYNAMIC_CONCURRENCY,
    TARGET_TIMEOUT_SECONDS,
    load_payloads,
    run_dynamic_scan,
)
from engines.license_policy import run_license_policy_review
from engines.static_scanner import (
    discover_manifest_files,
    parse_manifest_files,
    run_static_scan,
)


DEFAULT_ENDPOINT = "http://localhost:11434/v1/chat/completions"
DEFAULT_MODEL = "llama3.1:8b"

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
    license_coverage=None,
    scan_duration_seconds: float = 0.0,
) -> ScanReport:
    has_failing_static_findings = any(
        getattr(finding, "action", FindingAction.FAIL) == FindingAction.FAIL
        for finding in static_findings
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

    return ScanReport(
        target_endpoint=target_endpoint,
        target_model=target_model,
        target_timeout_seconds=target_timeout_seconds,
        dynamic_concurrency=dynamic_concurrency,
        judge_endpoint=judge_endpoint,
        judge_model=judge_model,
        fallback_judge_endpoint=fallback_judge_endpoint,
        fallback_judge_model=fallback_judge_model,
        include_evidence=include_evidence,
        security_result=security_result,
        execution_status=execution_status,
        status_message=(
            "**SCAN INCOMPLETE**"
            if execution_status == ExecutionStatus.SCAN_INCOMPLETE
            else "COMPLETE"
        ),
        static_findings=static_findings,
        dynamic_findings=dynamic_findings,
        dynamic_evidence=dynamic_evidence,
        license_coverage=license_coverage,
        execution_errors=execution_errors,
        passed_audit=passed_audit,
        scan_duration_seconds=scan_duration_seconds,
        scanner_version=_get_version(),
    )


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
    license_scan: bool,
    sbom_file: Optional[Path],
    aibom_file: Optional[Path],
    license_cache_file: Optional[Path],
    console: ScanConsole,
) -> ScanReport:
    start = time.monotonic()

    # Parse once, pass to engines to avoid redundant I/O
    manifest_files = discover_manifest_files(project_root)
    deps, dep_errors = parse_manifest_files(manifest_files)
    payloads, payload_errors = load_payloads(payload_file)

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
    if license_scan:
        scanned_models = [target_model, judge_model]
        if fallback_judge_model:
            scanned_models.append(fallback_judge_model)
        license_findings, license_coverage, license_errors = run_license_policy_review(
            project_root=project_root,
            dependencies=deps,
            model_names=scanned_models,
            sbom_path=sbom_file,
            aibom_path=aibom_file,
            license_cache_path=license_cache_file,
        )

    with console.dynamic_progress(len(payloads)) as dynamic_cb:
        dynamic_findings, dynamic_errors, dynamic_evidence = await run_dynamic_scan(
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
            on_progress=dynamic_cb,
            payloads=payloads,
            initial_errors=payload_errors,
        )

    duration = time.monotonic() - start

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
        static_findings=[*static_findings, *license_findings],
        dynamic_findings=dynamic_findings,
        dynamic_evidence=dynamic_evidence,
        license_coverage=license_coverage,
        execution_errors=[*static_errors, *license_errors, *dynamic_errors],
        scan_duration_seconds=round(duration, 2),
    )


@app.command()
def scan(
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
    license_scan: bool = typer.Option(
        False,
        "--license-scan/--no-license-scan",
        help="Run License Policy Review using local SBOM/AIBOM/cache metadata.",
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
) -> None:
    if quiet and verbose:
        typer.echo("Error: --quiet and --verbose are mutually exclusive.", err=True)
        raise typer.Exit(code=2)

    console = ScanConsole(quiet=quiet, verbose=verbose)

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
            license_scan=license_scan,
            sbom_file=sbom_file,
            aibom_file=aibom_file,
            license_cache_file=license_cache_file,
            console=console,
        )
    )

    console.print_summary(report)

    report_json = report.model_dump_json(indent=2)
    typer.echo(report_json)

    if output_file is not None:
        output_file.write_text(report_json, encoding="utf-8")

    raise typer.Exit(code=0 if report.passed_audit else 1)


if __name__ == "__main__":
    app()
