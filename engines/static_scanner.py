# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

import asyncio
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Sequence, Tuple

import aiohttp

from core.models import ErrorSource, ExecutionError, Finding, Severity


OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_TIMEOUT_SECONDS = 5
STATIC_CONCURRENCY = 10

EXCLUDED_DIR_NAMES = {
    ".git",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
}

PINNED_REQUIREMENT_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[A-Za-z0-9_,_.-]+\])?\s*==\s*([^\s;#]+)"
)


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str
    source_file: Path
    line_number: int


def _warn(error: ExecutionError) -> None:
    location = f" ({error.path})" if error.path else ""
    detail = f": {error.detail}" if error.detail else ""
    print(f"[{error.source.value}] {error.message}{location}{detail}", file=sys.stderr)


def _is_excluded_path(path: Path, root: Path) -> bool:
    try:
        relative_parts = path.relative_to(root).parts
    except ValueError:
        return False
    if any(part in EXCLUDED_DIR_NAMES for part in relative_parts):
        return True
    return len(relative_parts) >= 2 and relative_parts[:2] == ("tests", "fixtures")


def discover_requirement_files(project_root: Path) -> List[Path]:
    root = project_root.resolve()
    if not root.exists():
        return []

    requirement_files: List[Path] = []
    for current_root_text, dirnames, filenames in os.walk(root):
        current_root = Path(current_root_text)
        dirnames[:] = [
            dirname
            for dirname in dirnames
            if not _is_excluded_path(current_root / dirname, root)
        ]
        if _is_excluded_path(current_root, root):
            continue
        if "requirements.txt" in filenames:
            requirement_files.append(current_root / "requirements.txt")
    return sorted(requirement_files)


def parse_requirement_file(path: Path) -> Tuple[List[Dependency], List[ExecutionError]]:
    dependencies: List[Dependency] = []
    errors: List[ExecutionError] = []

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        error = ExecutionError(
            source=ErrorSource.STATIC,
            message="Unable to read requirements file",
            path=str(path),
            detail=str(exc),
        )
        _warn(error)
        return dependencies, [error]

    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        normalized = line.split("#", 1)[0].strip()
        match = PINNED_REQUIREMENT_RE.match(normalized)
        if match:
            dependencies.append(
                Dependency(
                    name=match.group(1),
                    version=match.group(2),
                    source_file=path,
                    line_number=line_number,
                )
            )
            continue

        error = ExecutionError(
            source=ErrorSource.STATIC,
            message="Unsupported requirement line; only pinned name==version entries are audited",
            path=f"{path}:{line_number}",
            detail=raw_line,
        )
        _warn(error)
        errors.append(error)

    return dependencies, errors


def parse_requirement_files(paths: Iterable[Path]) -> Tuple[List[Dependency], List[ExecutionError]]:
    dependencies: List[Dependency] = []
    errors: List[ExecutionError] = []
    for path in paths:
        parsed_dependencies, parsed_errors = parse_requirement_file(path)
        dependencies.extend(parsed_dependencies)
        errors.extend(parsed_errors)
    return dependencies, errors


async def _query_osv(
    session: aiohttp.ClientSession,
    dependency: Dependency,
    semaphore: asyncio.Semaphore,
) -> Tuple[List[Finding], List[ExecutionError]]:
    payload = {
        "package": {"name": dependency.name, "ecosystem": "PyPI"},
        "version": dependency.version,
    }

    async with semaphore:
        try:
            async with session.post(OSV_QUERY_URL, json=payload) as response:
                if response.status >= 400:
                    body = await response.text()
                    error = ExecutionError(
                        source=ErrorSource.STATIC,
                        message="OSV query failed",
                        path=str(dependency.source_file),
                        detail=f"{dependency.name}=={dependency.version}: HTTP {response.status} {body[:200]}",
                    )
                    _warn(error)
                    return [], [error]
                data = await response.json()
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            error = ExecutionError(
                source=ErrorSource.STATIC,
                message="OSV query failed",
                path=str(dependency.source_file),
                detail=f"{dependency.name}=={dependency.version}: {exc}",
            )
            _warn(error)
            return [], [error]

    findings: List[Finding] = []
    for vuln in data.get("vulns") or []:
        vulnerability_id = _select_vulnerability_id(vuln)
        findings.append(
            Finding(
                severity=Severity.HIGH,
                category="Dependency Vulnerability",
                description=(
                    f"{dependency.name}=={dependency.version} is affected by "
                    f"{vulnerability_id}."
                ),
                remediation="Upgrade the package to a non-vulnerable version.",
                package_name=dependency.name,
                package_version=dependency.version,
                vulnerability_id=vulnerability_id,
                source_file=str(dependency.source_file),
            )
        )
    return findings, []


def _select_vulnerability_id(vuln: dict) -> str:
    aliases = vuln.get("aliases") or []
    for alias in aliases:
        if alias.startswith(("CVE-", "GHSA-")):
            return alias
    return str(vuln.get("id") or "UNKNOWN")


async def run_static_scan(
    project_root: Path,
    on_progress: Optional[Callable[[str], None]] = None,
    *,
    dependencies: Optional[List[Dependency]] = None,
    initial_errors: Optional[List[ExecutionError]] = None,
) -> Tuple[List[Finding], List[ExecutionError]]:
    if dependencies is not None:
        errors = list(initial_errors or [])
    else:
        requirement_files = discover_requirement_files(project_root)
        dependencies, errors = parse_requirement_files(requirement_files)

    if not dependencies:
        return [], errors

    async def _query_and_report(
        session: aiohttp.ClientSession,
        dependency: Dependency,
        semaphore: asyncio.Semaphore,
    ) -> Tuple[List[Finding], List[ExecutionError]]:
        result = await _query_osv(session, dependency, semaphore)
        vuln_count = len(result[0])
        if on_progress:
            on_progress(f"{dependency.name}=={dependency.version} -- {vuln_count} vuln{'s' if vuln_count != 1 else ''}")
        return result

    timeout = aiohttp.ClientTimeout(total=OSV_TIMEOUT_SECONDS)
    semaphore = asyncio.Semaphore(STATIC_CONCURRENCY)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        results = await asyncio.gather(
            *(_query_and_report(session, dependency, semaphore) for dependency in dependencies)
        )

    findings: List[Finding] = []
    for dependency_findings, dependency_errors in results:
        findings.extend(dependency_findings)
        errors.extend(dependency_errors)
    return findings, errors


__all__ = [
    "Dependency",
    "discover_requirement_files",
    "parse_requirement_file",
    "parse_requirement_files",
    "run_static_scan",
]
