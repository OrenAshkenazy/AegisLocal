from contextlib import contextmanager
from typing import Callable, Generator

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from core.models import ScanReport, SecurityResult
from core.report_renderer import render_console_text


ProgressCallback = Callable[[str], None]

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
        text = render_console_text(report, verbose=self._verbose)
        title = (
            "AegisLocal License Policy Review"
            if report.scan_type == "licenses"
            else "AegisLocal Report"
        )
        panel = Panel(
            text,
            title=title,
            border_style=_RESULT_BORDER.get(report.security_result, "white"),
        )
        self._console.print(panel)
