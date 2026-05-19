# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

import asyncio
import math
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
    ".claude",
    ".codex",
    ".git",
    ".worktrees",
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
SUPPORTED_EXACT_SPEC_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[A-Za-z0-9_,_.-]+\])?\s*==\s*([^\s;#]+)"
)
SUPPORTED_MANIFEST_NAMES = {"pyproject.toml", "uv.lock", "poetry.lock"}
LOCKFILE_NAMES = {"uv.lock", "poetry.lock"}
SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


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
    indexes_by_key: dict[tuple[str, str], int] = {}
    deduped: List[Dependency] = []
    for dependency in dependencies:
        key = (dependency.name.lower(), dependency.version)
        existing_index = indexes_by_key.get(key)
        if existing_index is None:
            indexes_by_key[key] = len(deduped)
            deduped.append(dependency)
            continue
        existing = deduped[existing_index]
        if _source_priority(dependency.source_file) < _source_priority(existing.source_file):
            deduped[existing_index] = dependency
    return deduped


def _source_priority(path: Path | str | None) -> int:
    if path is None:
        return 2
    name = Path(path).name
    return 1 if name in LOCKFILE_NAMES else 0


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
                severity=_select_severity(vuln),
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


def _select_severity(vuln: dict) -> Severity:
    database_specific_severity = (vuln.get("database_specific") or {}).get("severity")
    severity = _severity_from_raw_value(database_specific_severity)
    if severity is not None:
        return severity

    for item in vuln.get("severity") or []:
        if not isinstance(item, dict):
            continue
        severity = _severity_from_raw_value(item.get("score"))
        if severity is not None:
            return severity

    return Severity.HIGH


def _severity_from_raw_value(raw_value: object) -> Optional[Severity]:
    if raw_value is None:
        return None
    if isinstance(raw_value, (int, float)):
        return _severity_from_cvss_score(float(raw_value))
    if not isinstance(raw_value, str):
        return None

    value = raw_value.strip()
    if not value:
        return None

    severity_names = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MODERATE": Severity.MEDIUM,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
        "INFORMATIONAL": Severity.INFO,
        "NONE": Severity.INFO,
    }
    named_severity = severity_names.get(value.upper())
    if named_severity is not None:
        return named_severity

    try:
        return _severity_from_cvss_score(float(value))
    except ValueError:
        pass

    if value.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        score = _cvss_v3_base_score(value)
        if score is not None:
            return _severity_from_cvss_score(score)

    return None


def _severity_from_cvss_score(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


def _cvss_v3_base_score(vector: str) -> Optional[float]:
    parts = vector.split("/")
    if not parts or parts[0] not in {"CVSS:3.0", "CVSS:3.1"}:
        return None

    metrics: dict[str, str] = {}
    for part in parts[1:]:
        if ":" not in part:
            continue
        name, value = part.split(":", 1)
        metrics[name] = value

    required_metrics = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if not required_metrics.issubset(metrics):
        return None

    scope = metrics["S"]
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(metrics["AV"])
    ac = {"L": 0.77, "H": 0.44}.get(metrics["AC"])
    ui = {"N": 0.85, "R": 0.62}.get(metrics["UI"])
    cia_values = {"H": 0.56, "L": 0.22, "N": 0.0}
    confidentiality = cia_values.get(metrics["C"])
    integrity = cia_values.get(metrics["I"])
    availability = cia_values.get(metrics["A"])
    if scope == "U":
        pr = {"N": 0.85, "L": 0.62, "H": 0.27}.get(metrics["PR"])
    elif scope == "C":
        pr = {"N": 0.85, "L": 0.68, "H": 0.5}.get(metrics["PR"])
    else:
        return None

    if None in {av, ac, pr, ui, confidentiality, integrity, availability}:
        return None

    impact = 1 - (
        (1 - confidentiality)
        * (1 - integrity)
        * (1 - availability)
    )
    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    if scope == "U":
        impact_sub_score = 6.42 * impact
        raw_score = impact_sub_score + exploitability
    else:
        impact_sub_score = 7.52 * (impact - 0.029) - 3.25 * ((impact - 0.02) ** 15)
        raw_score = 1.08 * (impact_sub_score + exploitability)
    return min(_round_up_1_decimal(raw_score), 10.0)


def _round_up_1_decimal(value: float) -> float:
    return math.ceil((value - 1e-10) * 10) / 10


def _merge_dependency_findings(findings: Iterable[Finding]) -> List[Finding]:
    findings_by_key: dict[
        tuple[Optional[str], Optional[str], Optional[str], Optional[str]],
        Finding,
    ] = {}
    finding_order: List[tuple[Optional[str], Optional[str], Optional[str], Optional[str]]] = []
    for finding in findings:
        key = (
            finding.package_name.lower() if finding.package_name else None,
            finding.package_version,
            finding.fixed_version,
            finding.remediation,
        )
        existing = findings_by_key.get(key)
        if existing is None:
            findings_by_key[key] = finding
            finding_order.append(key)
            continue
        findings_by_key[key] = _combine_dependency_findings(existing, finding)
    return [findings_by_key[key] for key in finding_order]


def _combine_dependency_findings(existing: Finding, new: Finding) -> Finding:
    vulnerability_ids = _merge_vulnerability_ids(existing, new)
    source_file = existing.source_file
    if _source_priority(new.source_file) < _source_priority(existing.source_file):
        source_file = new.source_file

    severity = existing.severity
    if SEVERITY_RANK[new.severity] > SEVERITY_RANK[existing.severity]:
        severity = new.severity

    return existing.model_copy(
        update={
            "severity": severity,
            "description": _dependency_vulnerability_description(
                existing.package_name,
                existing.package_version,
                vulnerability_ids,
            ),
            "vulnerability_id": vulnerability_ids[0] if vulnerability_ids else None,
            "vulnerability_ids": vulnerability_ids if len(vulnerability_ids) > 1 else None,
            "source_file": source_file,
        }
    )


def _merge_vulnerability_ids(existing: Finding, new: Finding) -> List[str]:
    vulnerability_ids: List[str] = []
    for finding in (existing, new):
        for vulnerability_id in finding.vulnerability_ids or []:
            if vulnerability_id not in vulnerability_ids:
                vulnerability_ids.append(vulnerability_id)
        if finding.vulnerability_id and finding.vulnerability_id not in vulnerability_ids:
            vulnerability_ids.append(finding.vulnerability_id)
    return vulnerability_ids


def _dependency_vulnerability_description(
    package_name: Optional[str],
    package_version: Optional[str],
    vulnerability_ids: Sequence[str],
) -> str:
    package = f"{package_name}=={package_version}"
    if len(vulnerability_ids) == 1:
        return f"{package} is affected by {vulnerability_ids[0]}."
    return (
        f"{package} is affected by {len(vulnerability_ids)} vulnerabilities: "
        f"{', '.join(vulnerability_ids)}."
    )


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
    for dependency_findings, dependency_errors in results:
        findings.extend(dependency_findings)
        errors.extend(dependency_errors)
    return _merge_dependency_findings(findings), errors


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
