# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

import asyncio
from pathlib import Path
from typing import Optional

import typer

from core.models import ExecutionStatus, ScanReport, SecurityResult
from engines.dynamic_fuzzer import (
    DYNAMIC_CONCURRENCY,
    TARGET_TIMEOUT_SECONDS,
    run_dynamic_scan,
)
from engines.static_scanner import run_static_scan


DEFAULT_ENDPOINT = "http://localhost:11434/v1/chat/completions"
DEFAULT_MODEL = "llama3.1:8b"

app = typer.Typer(help="AegisLocal local AI security scanner.")


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
) -> ScanReport:
    has_findings = bool(static_findings or dynamic_findings)
    execution_status = (
        ExecutionStatus.SCAN_INCOMPLETE if execution_errors else ExecutionStatus.COMPLETE
    )

    if has_findings:
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
        execution_errors=execution_errors,
        passed_audit=passed_audit,
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
) -> ScanReport:
    static_findings, static_errors = await run_static_scan(project_root)
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
    )
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
        execution_errors=[*static_errors, *dynamic_errors],
    )


@app.command()
def scan(
    project_root: Path = typer.Option(
        Path("."),
        "--project-root",
        help="Project root to recursively scan for requirements.txt files.",
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
) -> None:
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
        )
    )
    typer.echo(report.model_dump_json(indent=2))
    raise typer.Exit(code=0 if report.passed_audit else 1)


if __name__ == "__main__":
    app()
