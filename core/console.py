from collections import Counter
from contextlib import contextmanager
from typing import Callable, Generator

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.text import Text

from core.models import ReportRisk, ScanReport, SecurityResult


ProgressCallback = Callable[[str], None]

_RESULT_STYLES = {
    SecurityResult.PASS: "bold green",
    SecurityResult.FAIL: "bold red",
    SecurityResult.UNKNOWN: "bold yellow",
}

_RESULT_BORDER = {
    SecurityResult.PASS: "green",
    SecurityResult.FAIL: "red",
    SecurityResult.UNKNOWN: "yellow",
}


class ScanConsole:
    def __init__(self, quiet: bool = False, verbose: bool = False) -> None:
        self._quiet = quiet
        self._verbose = verbose
        self._console = Console(stderr=True)

    @contextmanager
    def static_progress(self, total: int) -> Generator[ProgressCallback, None, None]:
        if self._quiet:
            yield lambda _desc: None
            return

        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]Static Scan"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=self._console,
        )
        task_id = progress.add_task("static", total=total)

        def advance(description: str) -> None:
            progress.advance(task_id)
            if self._verbose:
                self._console.print(f"  [dim]{description}[/dim]")

        with progress:
            yield advance

    @contextmanager
    def dynamic_progress(self, total: int) -> Generator[ProgressCallback, None, None]:
        if self._quiet:
            yield lambda _desc: None
            return

        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold magenta]Dynamic Scan"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=self._console,
        )
        task_id = progress.add_task("dynamic", total=total)

        def advance(description: str) -> None:
            progress.advance(task_id)
            if self._verbose:
                self._console.print(f"  [dim]{description}[/dim]")

        with progress:
            yield advance

    def print_summary(self, report: ScanReport) -> None:
        if self._quiet:
            return

        result = report.security_result
        border = _RESULT_BORDER.get(result, "white")

        lines = Text()
        lines.append(
            (
                f"{report.production_decision.value} · {result.value} · "
                f"{report.scan_type} scan · {report.scan_duration_seconds:.1f}s"
            ),
            style=_RESULT_STYLES.get(result, "bold"),
        )
        lines.append("\n\nWhy\n", style="bold")
        lines.append(_human_reason(report))

        required_fixes = _required_fixes(report)
        if required_fixes:
            lines.append("\n\nRequired fixes\n", style="bold")
            for index, risk in enumerate(required_fixes, start=1):
                lines.append(f"{index}. {_risk_title(risk)}\n")
                details = _risk_details(risk)
                for detail in details:
                    lines.append(f"   {detail}\n")
                if index != len(required_fixes):
                    lines.append("\n")

        lines.append("\nFinding counts\n", style="bold")
        count_lines = _finding_count_lines(report)
        for index, count_line in enumerate(count_lines):
            lines.append(count_line)
            if index != len(count_lines) - 1:
                lines.append("\n")
        if report.execution_errors:
            lines.append(f"\nExecution errors: {len(report.execution_errors)}")
        lines.append("\n\nNext step\n", style="bold")
        lines.append(_next_step(report))

        title = (
            "AegisLocal License Policy Review"
            if report.scan_type == "licenses"
            else "AegisLocal Report"
        )
        panel = Panel(lines, title=title, border_style=border)
        self._console.print(panel)


def _all_risks(report: ScanReport) -> list[ReportRisk]:
    return [
        *report.findings.application_supply_chain,
        *report.findings.model_behavior,
        *report.findings.model_license,
        *report.findings.scan_reliability,
    ]


def _required_fixes(report: ScanReport) -> list[ReportRisk]:
    return [
        risk
        for risk in _all_risks(report)
        if risk.remediation or risk.package_name or risk.payload_ids
    ][:5]


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


def _severity_count_text(severities: Counter[str]) -> str:
    ordered = ["critical", "high", "medium", "low", "info"]
    parts = [
        f"{count} {severity}" if count > 1 else severity
        for severity in ordered
        if (count := severities.get(severity, 0))
    ]
    return ", ".join(parts) if parts else "confirmed"


def _severity_label_text(severities: Counter[str]) -> str:
    populated = [severity for severity, count in severities.items() if count]
    if len(populated) == 1:
        return populated[0]
    return _severity_count_text(severities)


def _risk_title(risk: ReportRisk) -> str:
    if risk.package_name and risk.package_version and risk.fixed_version:
        return (
            f"{risk.package_name} {risk.package_version} -> "
            f"upgrade to {risk.fixed_version} or later"
        )
    if risk.remediation:
        return risk.remediation.rstrip(".")
    return risk.description


def _risk_details(risk: ReportRisk) -> list[str]:
    details: list[str] = []
    if risk.vulnerability_ids:
        label = "CVE" if len(risk.vulnerability_ids) == 1 else "CVEs"
        details.append(f"{label}: {', '.join(risk.vulnerability_ids)}")
    if risk.source_file:
        details.append(f"Source: {risk.source_file}")
    details.append(f"Owner: {risk.owner}")
    return details


def _count_summary(risks: list[ReportRisk]) -> str:
    if not risks:
        return "0"
    severities = Counter(risk.severity.value.lower() for risk in risks)
    return _severity_count_text(severities)


def _finding_count_lines(report: ScanReport) -> list[str]:
    sections = [
        ("Application supply chain", report.findings.application_supply_chain),
        ("Model behavior", report.findings.model_behavior),
        ("Model license", report.findings.model_license),
        ("Scan reliability", report.findings.scan_reliability),
    ]
    lines = [
        f"{label}: {_count_summary(risks)}"
        for label, risks in sections
        if risks
    ]
    return lines or ["None"]


def _next_step(report: ScanReport) -> str:
    if report.findings.application_supply_chain:
        return "Fix the dependency versions above, then rerun AegisLocal."
    if report.findings.model_behavior:
        return "Review the failed payloads above, update guardrails, then rerun AegisLocal."
    if report.execution_errors:
        return "Fix the scan reliability issues above, then rerun AegisLocal."
    return "No blocking action is required."
