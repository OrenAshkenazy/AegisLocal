# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple

from core.models import (
    ErrorSource,
    ExecutionError,
    Finding,
    FindingAction,
    LicenseCoverage,
    Severity,
)
from engines.static_scanner import Dependency


DEPENDENCY_PRIORITY = 1
MODEL_PRIORITY = 1
CACHE_PRIORITY = 2

PERMISSIVE_LICENSES = {
    "MIT",
    "APACHE-2.0",
    "BSD-2-CLAUSE",
    "BSD-3-CLAUSE",
    "ISC",
}
GPL_FAMILY_RE = re.compile(r"\b(A?GPL|LGPL)-\d+(?:\.\d+)?(?:-(?:ONLY|OR-LATER))?\b")
WITH_RE = re.compile(r"\s+WITH\s+", re.IGNORECASE)
AND_RE = re.compile(r"\s+AND\s+", re.IGNORECASE)
OR_RE = re.compile(r"\s+OR\s+", re.IGNORECASE)


@dataclass(frozen=True)
class LicenseRecord:
    subject_type: str
    key: str
    name: str
    version: Optional[str]
    raw_license: str
    license_id: str
    source_label: str
    source_file: Optional[str]
    source_url: Optional[str]
    priority: int


@dataclass(frozen=True)
class LicenseDecision:
    should_warn: bool
    license_id: str
    softer_warning: bool = False
    exception: Optional[str] = None


def run_license_policy_review(
    *,
    project_root: Path,
    dependencies: Sequence[Dependency],
    model_names: Sequence[str],
    sbom_path: Optional[Path] = None,
    aibom_path: Optional[Path] = None,
    license_cache_path: Optional[Path] = None,
) -> Tuple[List[Finding], LicenseCoverage, List[ExecutionError]]:
    errors: List[ExecutionError] = []
    records: List[LicenseRecord] = []
    dependency_subjects = {
        _dependency_key(dependency.name, dependency.version)
        for dependency in dependencies
    }
    model_subjects = {
        _model_key(model_name)
        for model_name in model_names
        if model_name
    }

    if sbom_path is not None:
        sbom_records, sbom_subjects, sbom_errors = _load_bom_records(
            sbom_path,
            subject_type="dependency",
            priority=DEPENDENCY_PRIORITY,
        )
        records.extend(sbom_records)
        dependency_subjects.update(sbom_subjects)
        errors.extend(sbom_errors)

    if aibom_path is not None:
        aibom_records, aibom_subjects, aibom_errors = _load_bom_records(
            aibom_path,
            subject_type="model",
            priority=MODEL_PRIORITY,
        )
        records.extend(aibom_records)
        model_subjects.update(aibom_subjects)
        errors.extend(aibom_errors)

    cache_path = _resolve_cache_path(project_root, license_cache_path)
    if cache_path is not None:
        cache_records, cache_errors = _load_cache_records(cache_path)
        records.extend(cache_records)
        errors.extend(cache_errors)

    scoped_keys = dependency_subjects | model_subjects
    selected_records, conflict_findings = _select_records(records, scoped_keys)
    findings = [*conflict_findings]
    findings.extend(_policy_findings(selected_records.values()))

    coverage = _build_coverage(
        dependency_subjects=dependency_subjects,
        model_subjects=model_subjects,
        selected_records=selected_records,
    )
    return findings, coverage, errors


def evaluate_license(raw_license: str) -> Optional[LicenseDecision]:
    normalized = _normalize_license_text(raw_license)
    if not normalized:
        return None

    exception = _extract_exception(normalized)
    without_exception = WITH_RE.split(normalized, maxsplit=1)[0].strip()

    if OR_RE.search(without_exception):
        parts = [part.strip(" ()") for part in OR_RE.split(without_exception)]
        if not any(_is_gpl_family(part) for part in parts):
            return None
        if any(_is_permissive(part) for part in parts):
            return None
        if all(_is_recognized_license(part) for part in parts):
            return LicenseDecision(
                should_warn=True,
                license_id=_first_gpl_family(parts) or raw_license,
                softer_warning=bool(exception),
                exception=exception,
            )
        return None

    if AND_RE.search(without_exception):
        parts = [part.strip(" ()") for part in AND_RE.split(without_exception)]
        gpl_license = _first_gpl_family(parts)
        if gpl_license is None:
            return None
        return LicenseDecision(
            should_warn=True,
            license_id=gpl_license,
            softer_warning=bool(exception),
            exception=exception,
        )

    if _is_gpl_family(without_exception):
        return LicenseDecision(
            should_warn=True,
            license_id=_first_gpl_family([without_exception]) or raw_license,
            softer_warning=bool(exception),
            exception=exception,
        )
    return None


def _load_bom_records(
    path: Path,
    *,
    subject_type: str,
    priority: int,
) -> Tuple[List[LicenseRecord], set[str], List[ExecutionError]]:
    data, errors = _read_json(path)
    if data is None:
        return [], set(), errors

    records: List[LicenseRecord] = []
    subjects: set[str] = set()
    for component in data.get("components") or []:
        if not isinstance(component, dict):
            continue
        if subject_type == "dependency" and component.get("type") != "library":
            continue
        if subject_type == "model" and not _is_model_component(component):
            continue

        name = str(component.get("name") or "").strip()
        version = _component_version(component)
        if not name:
            continue
        if subject_type == "dependency" and not version:
            continue

        key = (
            _dependency_key(name, version)
            if subject_type == "dependency"
            else _model_key(name, component)
        )
        subjects.add(key)

        raw_license = _extract_component_license(component)
        if not raw_license:
            continue
        records.append(
            LicenseRecord(
                subject_type=subject_type,
                key=key,
                name=name,
                version=version,
                raw_license=raw_license,
                license_id=_normalize_license_id(raw_license),
                source_label="sbom" if subject_type == "dependency" else "aibom",
                source_file=str(path),
                source_url=_extract_component_url(component),
                priority=priority,
            )
        )
    return records, subjects, errors


def _load_cache_records(
    path: Path,
) -> Tuple[List[LicenseRecord], List[ExecutionError]]:
    data, errors = _read_json(path)
    if data is None:
        return [], errors

    records: List[LicenseRecord] = []

    for key, entry in (data.get("dependencies") or {}).items():
        if not isinstance(entry, dict):
            continue
        normalized_key = str(key)
        raw_license = str(entry.get("raw_license") or entry.get("license_id") or "").strip()
        if not raw_license:
            continue
        name, version = _name_version_from_dependency_key(normalized_key)
        records.append(
            LicenseRecord(
                subject_type="dependency",
                key=normalized_key,
                name=name,
                version=version,
                raw_license=raw_license,
                license_id=_normalize_license_id(str(entry.get("license_id") or raw_license)),
                source_label=f"cache:{entry.get('source') or 'user'}",
                source_file=str(path),
                source_url=entry.get("source_url"),
                priority=CACHE_PRIORITY,
            )
        )

    for key, entry in (data.get("models") or {}).items():
        if not isinstance(entry, dict):
            continue
        normalized_key = str(key)
        raw_license = str(entry.get("raw_license") or entry.get("license_id") or "").strip()
        if not raw_license:
            continue
        records.append(
            LicenseRecord(
                subject_type="model",
                key=normalized_key,
                name=_name_from_model_key(normalized_key),
                version=None,
                raw_license=raw_license,
                license_id=_normalize_license_id(str(entry.get("license_id") or raw_license)),
                source_label=f"cache:{entry.get('source') or 'user'}",
                source_file=str(path),
                source_url=entry.get("source_url"),
                priority=CACHE_PRIORITY,
            )
        )

    return records, errors


def _select_records(
    records: Iterable[LicenseRecord],
    scoped_keys: set[str],
) -> Tuple[dict[str, LicenseRecord], List[Finding]]:
    by_key: dict[str, List[LicenseRecord]] = {}
    for record in records:
        if record.key not in scoped_keys:
            continue
        by_key.setdefault(record.key, []).append(record)

    selected: dict[str, LicenseRecord] = {}
    conflicts: List[Finding] = []
    for key, key_records in by_key.items():
        best_priority = min(record.priority for record in key_records)
        best_records = [
            record for record in key_records if record.priority == best_priority
        ]
        license_values = {
            _normalize_license_text(record.raw_license)
            for record in best_records
            if record.raw_license
        }
        if len(license_values) > 1:
            conflicts.append(_conflict_finding(key, best_records))
            continue
        selected[key] = best_records[0]
    return selected, conflicts


def _policy_findings(records: Iterable[LicenseRecord]) -> List[Finding]:
    findings: List[Finding] = []
    for record in records:
        decision = evaluate_license(record.raw_license)
        if decision is None or not decision.should_warn:
            continue
        findings.append(_license_finding(record, decision))
    return findings


def _license_finding(record: LicenseRecord, decision: LicenseDecision) -> Finding:
    subject_label = (
        f"Dependency {record.name}=={record.version}"
        if record.subject_type == "dependency"
        else f"Model {record.name}"
    )
    category = (
        "License Policy Review"
        if record.subject_type == "dependency"
        else "Model License Policy Review"
    )
    risk_summary = _risk_summary(decision.license_id)
    if decision.softer_warning and decision.exception:
        risk_summary = (
            f"{risk_summary} The license expression includes the "
            f"{decision.exception} exception, which may change the obligations."
        )

    return Finding(
        severity=Severity.MEDIUM,
        action=FindingAction.WARN,
        category=category,
        description=(
            f"{subject_label} declares license {record.raw_license}. "
            f"{risk_summary}"
        ),
        remediation=(
            "Review this license against your organization's policy. If the "
            "license is not acceptable for your distribution or deployment "
            "model, replace it, isolate it, or document an explicit approval."
        ),
        package_name=record.name if record.subject_type == "dependency" else None,
        package_version=record.version if record.subject_type == "dependency" else None,
        source_file=record.source_file,
        license_id=decision.license_id,
        license_source=_license_source(record),
        subject_type=record.subject_type,
        subject_name=record.name,
    )


def _conflict_finding(key: str, records: Sequence[LicenseRecord]) -> Finding:
    values = sorted({record.raw_license for record in records})
    sources = sorted(
        {
            f"{record.source_label}:{record.source_file or 'unknown'}"
            for record in records
        }
    )
    first = records[0]
    return Finding(
        severity=Severity.INFO,
        action=FindingAction.WARN,
        category="License Metadata Conflict",
        description=(
            f"Conflicting license metadata for {key}: "
            f"{', '.join(values)}. No GPL-family policy decision was made for "
            "this subject."
        ),
        remediation=(
            "Correct the conflicting SBOM, AIBOM, or cache entries so the "
            "license policy review can evaluate a single license value."
        ),
        source_file="; ".join(sources),
        license_source="conflict",
        subject_type=first.subject_type,
        subject_name=first.name,
    )


def _build_coverage(
    *,
    dependency_subjects: set[str],
    model_subjects: set[str],
    selected_records: dict[str, LicenseRecord],
) -> LicenseCoverage:
    dependency_with_metadata = {
        key
        for key in dependency_subjects
        if key in selected_records and selected_records[key].raw_license
    }
    model_with_metadata = {
        key
        for key in model_subjects
        if key in selected_records and selected_records[key].raw_license
    }
    return LicenseCoverage(
        dependencies_total=len(dependency_subjects),
        dependencies_with_license_metadata=len(dependency_with_metadata),
        dependencies_missing_license_metadata=(
            len(dependency_subjects) - len(dependency_with_metadata)
        ),
        models_total=len(model_subjects),
        models_with_license_metadata=len(model_with_metadata),
        models_missing_license_metadata=len(model_subjects) - len(model_with_metadata),
    )


def _read_json(path: Path) -> Tuple[Optional[dict], List[ExecutionError]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        return None, [
            ExecutionError(
                source=ErrorSource.STATIC,
                message="Unable to read license metadata file",
                path=str(path),
                detail=str(exc),
            )
        ]
    except json.JSONDecodeError as exc:
        return None, [
            ExecutionError(
                source=ErrorSource.STATIC,
                message="Unable to parse license metadata JSON",
                path=str(path),
                detail=str(exc),
            )
        ]
    if not isinstance(data, dict):
        return None, [
            ExecutionError(
                source=ErrorSource.STATIC,
                message="License metadata JSON must be an object",
                path=str(path),
            )
        ]
    return data, []


def _resolve_cache_path(project_root: Path, path: Optional[Path]) -> Optional[Path]:
    if path is not None:
        return path
    default = project_root / ".aegislocal" / "license-metadata-cache.json"
    return default if default.exists() else None


def _dependency_key(name: str, version: str) -> str:
    return f"pypi:{name.lower()}@{version}"


def _model_key(name: str, component: Optional[dict] = None) -> str:
    source = _model_source(component) if component is not None else None
    if source == "huggingface":
        return f"huggingface:{name}"
    if source == "ollama":
        return f"ollama:{name}"
    if source == "local":
        return f"local-model:{name}"
    if "/" in name:
        return f"huggingface:{name}"
    return f"ollama:{name}"


def _name_version_from_dependency_key(key: str) -> Tuple[str, Optional[str]]:
    if key.startswith("pypi:") and "@" in key:
        name, version = key[5:].split("@", 1)
        return name, version
    return key, None


def _name_from_model_key(key: str) -> str:
    return key.split(":", 1)[1] if ":" in key else key


def _component_version(component: dict) -> Optional[str]:
    version = str(component.get("version") or "").strip()
    return None if not version or version == "unresolved" else version


def _is_model_component(component: dict) -> bool:
    return (
        component.get("type") == "machine-learning-model"
        or str(component.get("bom-ref") or "").startswith("model:")
        or _property_value(component, "aegislocal:artifact-type") == "model"
    )


def _model_source(component: Optional[dict]) -> Optional[str]:
    if component is None:
        return None
    source = _property_value(component, "aegislocal:model-source")
    if source:
        return source.lower()
    bom_ref = str(component.get("bom-ref") or "")
    if bom_ref.startswith("model:huggingface/"):
        return "huggingface"
    if bom_ref.startswith("model:ollama/"):
        return "ollama"
    return None


def _property_value(component: dict, name: str) -> Optional[str]:
    for prop in component.get("properties") or []:
        if isinstance(prop, dict) and prop.get("name") == name:
            return str(prop.get("value") or "")
    return None


def _extract_component_license(component: dict) -> Optional[str]:
    licenses = component.get("licenses") or []
    values: List[str] = []
    for item in licenses:
        if not isinstance(item, dict):
            continue
        expression = item.get("expression")
        if isinstance(expression, str) and expression.strip():
            values.append(expression.strip())
            continue
        license_info = item.get("license") or {}
        if not isinstance(license_info, dict):
            continue
        value = license_info.get("id") or license_info.get("name")
        if isinstance(value, str) and value.strip():
            values.append(value.strip())
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    return " AND ".join(values)


def _extract_component_url(component: dict) -> Optional[str]:
    for ref in component.get("externalReferences") or []:
        if isinstance(ref, dict) and ref.get("url"):
            return str(ref["url"])
    purl = component.get("purl")
    return str(purl) if purl else None


def _normalize_license_text(raw_license: str) -> str:
    normalized = raw_license.strip()
    if not normalized:
        return ""
    normalized = normalized.replace("_", "-")
    normalized = re.sub(r"\s+", " ", normalized)
    normalized = normalized.upper()
    replacements = {
        "GNU GENERAL PUBLIC LICENSE V3 (GPLV3)": "GPL-3.0-ONLY",
        "GNU GENERAL PUBLIC LICENSE V3": "GPL-3.0-ONLY",
        "GNU AFFERO GENERAL PUBLIC LICENSE V3": "AGPL-3.0-ONLY",
        "GNU LESSER GENERAL PUBLIC LICENSE V2 OR LATER": "LGPL-2.1-OR-LATER",
    }
    return replacements.get(normalized, normalized)


def _normalize_license_id(raw_license: str) -> str:
    return _normalize_license_text(raw_license)


def _extract_exception(normalized_license: str) -> Optional[str]:
    if not WITH_RE.search(normalized_license):
        return None
    return WITH_RE.split(normalized_license, maxsplit=1)[1].strip(" ()") or None


def _is_gpl_family(value: str) -> bool:
    return GPL_FAMILY_RE.search(_normalize_license_text(value)) is not None


def _first_gpl_family(values: Iterable[str]) -> Optional[str]:
    for value in values:
        match = GPL_FAMILY_RE.search(_normalize_license_text(value))
        if match:
            return match.group(0)
    return None


def _is_permissive(value: str) -> bool:
    return _normalize_license_text(value) in PERMISSIVE_LICENSES


def _is_recognized_license(value: str) -> bool:
    return _is_permissive(value) or _is_gpl_family(value)


def _risk_summary(license_id: str) -> str:
    normalized = _normalize_license_text(license_id)
    if normalized.startswith("AGPL-"):
        return "Network-service copyleft obligations may apply depending on usage and distribution model."
    if normalized.startswith("LGPL-"):
        return "Linking, modification, and redistribution obligations may apply."
    return "Copyleft redistribution obligations may apply when distributed with the product."


def _license_source(record: LicenseRecord) -> str:
    parts = [record.source_label]
    if record.source_url:
        parts.append(record.source_url)
    return " | ".join(parts)


__all__ = [
    "evaluate_license",
    "run_license_policy_review",
]
