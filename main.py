# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

import asyncio
import time
from importlib.metadata import PackageNotFoundError, version as pkg_version
from pathlib import Path
from typing import Optional, Sequence

import typer

from core.console import ScanConsole
from core.models import ExecutionStatus, FindingAction, ScanReport, SecurityResult
from engines.bom import write_aibom, write_sbom
from engines.dynamic_fuzzer import (
    DYNAMIC_CONCURRENCY,
    TARGET_TIMEOUT_SECONDS,
    load_payloads,
    run_dynamic_scan,
)
from engines.license_enrichment import enrich_license_metadata
from engines.license_policy import run_license_policy_review
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
        execution_status=execution_status,
        status_message=(
            "**SCAN INCOMPLETE**"
            if execution_status == ExecutionStatus.SCAN_INCOMPLETE
            else "COMPLETE"
        ),
        static_findings=static_findings if include_static_section else None,
        dynamic_findings=dynamic_findings if include_dynamic_section else None,
        dynamic_evidence=dynamic_evidence if include_dynamic_section else None,
        license_findings=license_findings if include_license_section else None,
        license_coverage=license_coverage if include_license_section else None,
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
    scanned_models = _scan_model_names(target_model, judge_model, fallback_judge_model)
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
    if run_dynamic:
        payloads, payload_errors = load_payloads(payload_file)
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

    if generate_bom and not resolved_sbom.exists():
        write_sbom(
            project_root=project_root,
            dependencies=dependencies,
            output_path=resolved_sbom,
            scanner_version=_get_version(),
        )
        typer.echo(f"Generated missing SBOM: {resolved_sbom}", err=True)

    if generate_bom and not resolved_aibom.exists():
        write_aibom(
            project_root=project_root,
            model_names=model_names,
            output_path=resolved_aibom,
            scanner_version=_get_version(),
        )
        typer.echo(f"Generated missing AIBOM: {resolved_aibom}", err=True)

    return (
        resolved_sbom if resolved_sbom.exists() else None,
        resolved_aibom if resolved_aibom.exists() else None,
    )


def _resolve_bom_path(project_root: Path, path: Optional[Path], default_name: str) -> Path:
    selected = path or Path(default_name)
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

    raise typer.Exit(code=0 if report.passed_audit else 1)


if __name__ == "__main__":
    app()
