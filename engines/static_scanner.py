# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

import asyncio
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Sequence, Tuple

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

import aiohttp

from core.models import ErrorSource, ExecutionError, Finding, Severity


OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_TIMEOUT_SECONDS = 5
STATIC_CONCURRENCY = 10

EXCLUDED_DIR_NAMES = {
    ".git",
    ".venv",
    ".worktrees",
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
SUPPORTED_EXACT_SPEC_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[A-Za-z0-9_,_.-]+\])?\s*==\s*([^\s;#]+)"
)
SUPPORTED_MANIFEST_NAMES = {"pyproject.toml", "uv.lock", "poetry.lock"}


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


def discover_manifest_files(project_root: Path) -> List[Path]:
    root = project_root.resolve()
    if not root.exists():
        return []

    manifest_files: List[Path] = []
    for current_root_text, dirnames, filenames in os.walk(root):
        current_root = Path(current_root_text)
        dirnames[:] = [
            dirname
            for dirname in dirnames
            if not _is_excluded_path(current_root / dirname, root)
        ]
        if _is_excluded_path(current_root, root):
            continue
        for filename in filenames:
            if _is_supported_manifest_name(filename):
                manifest_files.append(current_root / filename)
    return sorted(manifest_files)


def discover_requirement_files(project_root: Path) -> List[Path]:
    return [
        path
        for path in discover_manifest_files(project_root)
        if _is_requirement_file(path.name)
    ]


def _is_supported_manifest_name(filename: str) -> bool:
    return _is_requirement_file(filename) or filename in SUPPORTED_MANIFEST_NAMES


def _is_requirement_file(filename: str) -> bool:
    return (
        filename == "requirements.txt"
        or (filename.startswith("requirements-") and filename.endswith(".txt"))
        or (filename.startswith("requirements.") and filename.endswith(".txt"))
    )


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


def parse_manifest_file(path: Path) -> Tuple[List[Dependency], List[ExecutionError]]:
    if _is_requirement_file(path.name):
        return parse_requirement_file(path)
    if path.name == "pyproject.toml":
        return parse_pyproject_file(path)
    if path.name == "uv.lock":
        return parse_uv_lock_file(path)
    if path.name == "poetry.lock":
        return parse_poetry_lock_file(path)
    return [], []


def parse_manifest_files(paths: Iterable[Path]) -> Tuple[List[Dependency], List[ExecutionError]]:
    dependencies: List[Dependency] = []
    errors: List[ExecutionError] = []
    manifest_paths = list(paths)
    lock_dirs = {
        path.parent.resolve()
        for path in manifest_paths
        if path.name in {"uv.lock", "poetry.lock"}
    }
    for path in manifest_paths:
        if path.name == "pyproject.toml" and path.parent.resolve() in lock_dirs:
            continue
        parsed_dependencies, parsed_errors = parse_manifest_file(path)
        dependencies.extend(parsed_dependencies)
        errors.extend(parsed_errors)
    return _dedupe_dependencies(dependencies), errors


def parse_pyproject_file(path: Path) -> Tuple[List[Dependency], List[ExecutionError]]:
    data, errors = _read_toml(path, "Unable to read pyproject.toml")
    if data is None:
        return [], errors

    dependencies: List[Dependency] = []
    project = data.get("project") if isinstance(data.get("project"), dict) else {}
    for spec in project.get("dependencies") or []:
        dependency, error = _dependency_from_spec_string(spec, path)
        _append_dependency_or_error(dependencies, errors, dependency, error)

    optional_dependencies = project.get("optional-dependencies") or {}
    if isinstance(optional_dependencies, dict):
        for specs in optional_dependencies.values():
            for spec in specs or []:
                dependency, error = _dependency_from_spec_string(spec, path)
                _append_dependency_or_error(dependencies, errors, dependency, error)

    poetry = ((data.get("tool") or {}).get("poetry") or {})
    if isinstance(poetry, dict):
        for section_name in ("dependencies", "dev-dependencies"):
            section = poetry.get(section_name) or {}
            if isinstance(section, dict):
                _parse_poetry_dependency_table(path, section, dependencies, errors)
        groups = poetry.get("group") or {}
        if isinstance(groups, dict):
            for group in groups.values():
                section = (group or {}).get("dependencies") if isinstance(group, dict) else {}
                if isinstance(section, dict):
                    _parse_poetry_dependency_table(path, section, dependencies, errors)

    return _dedupe_dependencies(dependencies), errors


def parse_uv_lock_file(path: Path) -> Tuple[List[Dependency], List[ExecutionError]]:
    return _parse_lock_packages(path, "Unable to read uv.lock")


def parse_poetry_lock_file(path: Path) -> Tuple[List[Dependency], List[ExecutionError]]:
    return _parse_lock_packages(path, "Unable to read poetry.lock")


def _parse_lock_packages(
    path: Path,
    read_error_message: str,
) -> Tuple[List[Dependency], List[ExecutionError]]:
    data, errors = _read_toml(path, read_error_message)
    if data is None:
        return [], errors

    dependencies: List[Dependency] = []
    for package in data.get("package") or []:
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        version = package.get("version")
        if isinstance(name, str) and isinstance(version, str):
            dependencies.append(
                Dependency(name=name, version=version, source_file=path, line_number=1)
            )
    return _dedupe_dependencies(dependencies), errors


def _read_toml(path: Path, message: str) -> Tuple[Optional[dict], List[ExecutionError]]:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle), []
    except (OSError, tomllib.TOMLDecodeError) as exc:
        error = ExecutionError(
            source=ErrorSource.STATIC,
            message=message,
            path=str(path),
            detail=str(exc),
        )
        _warn(error)
        return None, [error]


def _dependency_from_spec_string(
    spec: object,
    path: Path,
) -> Tuple[Optional[Dependency], Optional[ExecutionError]]:
    if not isinstance(spec, str):
        return None, None
    normalized = spec.split("#", 1)[0].strip()
    if not normalized:
        return None, None
    match = SUPPORTED_EXACT_SPEC_RE.match(normalized)
    if match:
        return (
            Dependency(
                name=match.group(1),
                version=match.group(2),
                source_file=path,
                line_number=1,
            ),
            None,
        )
    return None, ExecutionError(
        source=ErrorSource.STATIC,
        message="Unsupported dependency spec; only exact name==version entries are audited",
        path=str(path),
        detail=spec,
    )


def _parse_poetry_dependency_table(
    path: Path,
    section: dict,
    dependencies: List[Dependency],
    errors: List[ExecutionError],
) -> None:
    for name, raw_spec in section.items():
        if name.lower() == "python":
            continue
        if isinstance(raw_spec, str):
            dependency, error = _dependency_from_poetry_spec(name, raw_spec, path)
        elif isinstance(raw_spec, dict):
            dependency, error = _dependency_from_poetry_spec(
                name,
                raw_spec.get("version"),
                path,
            )
        else:
            dependency, error = None, None
        _append_dependency_or_error(dependencies, errors, dependency, error)


def _dependency_from_poetry_spec(
    name: str,
    raw_spec: object,
    path: Path,
) -> Tuple[Optional[Dependency], Optional[ExecutionError]]:
    if not isinstance(raw_spec, str):
        return None, None
    spec = raw_spec.strip()
    if spec.startswith("=="):
        version = spec[2:].strip()
    else:
        return None, ExecutionError(
            source=ErrorSource.STATIC,
            message="Unsupported Poetry dependency spec; only exact ==version entries are audited",
            path=str(path),
            detail=f"{name} = {raw_spec}",
        )
    if not version:
        return None, None
    return (
        Dependency(name=name, version=version, source_file=path, line_number=1),
        None,
    )


def _append_dependency_or_error(
    dependencies: List[Dependency],
    errors: List[ExecutionError],
    dependency: Optional[Dependency],
    error: Optional[ExecutionError],
) -> None:
    if dependency is not None:
        dependencies.append(dependency)
    if error is not None:
        _warn(error)
        errors.append(error)


def _dedupe_dependencies(dependencies: Iterable[Dependency]) -> List[Dependency]:
    seen = set()
    deduped: List[Dependency] = []
    for dependency in dependencies:
        key = (dependency.name.lower(), dependency.version, str(dependency.source_file))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(dependency)
    return deduped


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
        fixed_version = _select_fixed_version(vuln, dependency.name, dependency.version)
        fix_available = fixed_version is not None
        remediation = (
            f"Upgrade {dependency.name} from {dependency.version} to {fixed_version}+."
            if fixed_version
            else "No fixed version is listed by OSV; review advisory references for mitigation or workaround guidance."
        )
        findings.append(
            Finding(
                severity=Severity.HIGH,
                category="Dependency Vulnerability",
                description=(
                    f"{dependency.name}=={dependency.version} is affected by "
                    f"{vulnerability_id}."
                ),
                remediation=remediation,
                fix_available=fix_available,
                fixed_version=fixed_version,
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


def _select_fixed_version(
    vuln: dict,
    package_name: str,
    current_version: str,
) -> Optional[str]:
    current_key = _version_sort_key(current_version)
    fixed_versions: List[str] = []
    for affected in vuln.get("affected") or []:
        package = affected.get("package") or {}
        if package.get("name", "").lower() != package_name.lower():
            continue
        if package.get("ecosystem") != "PyPI":
            continue
        for affected_range in affected.get("ranges") or []:
            for event in affected_range.get("events") or []:
                fixed = event.get("fixed")
                if (
                    isinstance(fixed, str)
                    and fixed
                    and _version_sort_key(fixed) > current_key
                ):
                    fixed_versions.append(fixed)
    if not fixed_versions:
        return None
    return sorted(set(fixed_versions), key=_version_sort_key)[0]


def _version_sort_key(version: str) -> Tuple[object, ...]:
    parts: List[object] = []
    for part in re.split(r"[.+_-]", version):
        if part.isdigit():
            parts.append((0, int(part)))
        else:
            parts.append((1, part))
    return tuple(parts)


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
        manifest_files = discover_manifest_files(project_root)
        dependencies, errors = parse_manifest_files(manifest_files)

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
    seen_findings = set()
    for dependency_findings, dependency_errors in results:
        for finding in dependency_findings:
            key = (
                finding.package_name,
                finding.package_version,
                finding.vulnerability_id,
                finding.source_file,
            )
            if key in seen_findings:
                continue
            seen_findings.add(key)
            findings.append(finding)
        errors.extend(dependency_errors)
    return findings, errors


__all__ = [
    "Dependency",
    "discover_manifest_files",
    "discover_requirement_files",
    "parse_manifest_file",
    "parse_manifest_files",
    "parse_poetry_lock_file",
    "parse_pyproject_file",
    "parse_requirement_file",
    "parse_requirement_files",
    "parse_uv_lock_file",
    "run_static_scan",
]
