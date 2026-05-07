# Rich Terminal Output & CLI Enhancements

## Overview

Add rich terminal UI (progress bars, colored panels, spinners), `--output-file`, `--quiet`/`--verbose` flags, scan duration timestamp, and version field to AegisLocal's scan command.

## New Dependency

Add `rich>=13` to `pyproject.toml` dependencies.

## CLI Flags

### `--quiet` / `--verbose`

Mutually exclusive flags on the `scan` command.

| Mode | Rich UI | Per-item lines | JSON to stdout |
|---------|---------|----------------|----------------|
| quiet | no | no | yes |
| default | yes | no | yes |
| verbose | yes | yes | yes |

- **quiet**: no progress bars, no panels, no spinners. JSON report to stdout only. Intended for CI/piping.
- **default**: rich progress bars per scan phase, summary panel after completion, JSON to stdout.
- **verbose**: everything in default plus real-time per-item status lines as dependencies/payloads complete (e.g., `requests==2.31.0 -- 0 vulns`, `payload dpi-001 -- FAIL`).

### `--output-file` / `-o`

Optional path. When set, writes the JSON report to the specified file. JSON is always printed to stdout regardless of this flag.

## Two-Stage Progress Bars

### Static Scan Phase

Progress bar titled "Static Scan" tracking each dependency's OSV query. Total = number of parsed dependencies. Advances by 1 per completed query.

### Dynamic Scan Phase

Progress bar titled "Dynamic Scan" tracking each payload evaluation. Total = number of loaded payloads. Advances by 1 per completed evaluation.

### Engine Integration

Both `run_static_scan` and `run_dynamic_scan` accept an optional `on_progress` callback with signature `Callable[[str], None]`. The callback receives a short description string per completed item. The engines call this after each item finishes. No rich imports in engine modules.

In quiet mode, no callback is passed (or a no-op). In default mode, the callback advances the progress bar. In verbose mode, the callback advances the bar and prints a detail line.

## Scan Duration

Capture `time.monotonic()` before and after `run_scan()` in the `scan` command. Add `scan_duration_seconds: float` to `ScanReport`. Displayed in the summary panel as human-readable (e.g., "12.3s").

## Version Field

Add `scanner_version: str` to `ScanReport`. Populated from `importlib.metadata.version("aegislocal")` with a fallback to `"0.1.0"` if the package is not installed.

## Rich Summary Panel

Displayed after scan completion in default and verbose modes. Uses `rich.panel.Panel`. Contents:

```
AegisLocal Scan Report
Result: PASS (green) / FAIL (red) / UNKNOWN (yellow)
Duration: 12.3s
Static findings: 3
Dynamic findings: 2
Execution errors: 1
```

Result text is colored based on value. Panel has a border colored to match (green/red/yellow).

## New Module: `core/console.py`

Encapsulates all rich output logic. Key class:

### `ScanConsole`

```python
class ScanConsole:
    def __init__(self, quiet: bool = False, verbose: bool = False):
        ...

    def static_progress(self, total: int) -> context manager yielding on_progress callback
    def dynamic_progress(self, total: int) -> context manager yielding on_progress callback
    def print_summary(self, report: ScanReport) -> None
```

- When `quiet=True`, all methods are no-ops.
- Progress context managers yield a callback that advances the bar (and optionally prints verbose lines).
- `print_summary` renders the panel to stderr so it doesn't interfere with JSON on stdout.

All rich output goes to stderr. JSON goes to stdout.

## File Changes

| File | Change |
|------|--------|
| `pyproject.toml` | Add `rich>=13` dependency |
| `core/models.py` | Add `scan_duration_seconds: float` and `scanner_version: str` to `ScanReport` |
| `core/console.py` | New file: `ScanConsole` class with all rich UI logic |
| `engines/static_scanner.py` | Add optional `on_progress` callback parameter to `run_static_scan`, call it per dependency |
| `engines/dynamic_fuzzer.py` | Add optional `on_progress` callback parameter to `run_dynamic_scan`, call it per payload |
| `main.py` | Add `--quiet`, `--verbose`, `--output-file` flags; timing; version; `ScanConsole` orchestration; write to file |

## Backwards Compatibility

- JSON output to stdout is preserved in all modes.
- `on_progress` callbacks default to `None` so existing callers (tests) are unaffected.
- New `ScanReport` fields have defaults (`scan_duration_seconds=0.0`, `scanner_version="unknown"`) so existing serialized reports remain valid.
