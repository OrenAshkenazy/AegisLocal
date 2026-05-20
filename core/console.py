from contextlib import contextmanager
from typing import Callable, Generator

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.text import Text

from core.models import ScanReport, SecurityResult


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
        style = _RESULT_STYLES.get(result, "bold")
        border = _RESULT_BORDER.get(result, "white")

        lines = Text()
        lines.append("Result: ")
        lines.append(result.value, style=style)
        lines.append(f"\nDuration: {report.scan_duration_seconds:.1f}s")
        if report.static_findings is not None:
            lines.append(f"\nStatic findings: {len(report.static_findings)}")
        if report.dynamic_findings is not None:
            lines.append(f"\nDynamic findings: {len(report.dynamic_findings)}")
        if report.license_findings is not None:
            lines.append(f"\nLicense findings: {len(report.license_findings)}")
        if report.license_coverage is not None:
            coverage = report.license_coverage
            lines.append(
                "\nLicense metadata: "
                f"{coverage.dependencies_with_license_metadata}/"
                f"{coverage.dependencies_total} dependencies, "
                f"{coverage.models_with_license_metadata}/"
                f"{coverage.models_total} models"
            )
        lines.append(f"\nExecution errors: {len(report.execution_errors)}")
        lines.append(f"\nVersion: {report.scanner_version}")

        title = (
            "AegisLocal License Policy Review"
            if report.scan_type == "licenses"
            else "AegisLocal Scan Report"
        )
        panel = Panel(lines, title=title, border_style=border)
        self._console.print(panel)
