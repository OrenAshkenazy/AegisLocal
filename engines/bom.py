# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional, Tuple
from urllib.parse import quote

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

from core.models import ErrorSource, ExecutionError
from engines.model_scanner import (
    MODEL_MANIFEST_NAME,
    ModelArtifact,
    ModelInventory,
    ModelManifest,
    ModelManifestEntry,
    ModelReference,
    collect_model_inventory,
    _normalize_configured_path,
    _normalize_manifest_path,
)
from engines.static_scanner import Dependency


# Repository-local UUID namespace generated for deterministic AegisLocal BOM serials.
AIBOM_UUID_NAMESPACE = uuid.UUID("7896898a-2bab-4696-8022-790809696801")
CYCLONEDX_SPEC_VERSION = "1.6"
UNRESOLVED_VERSION = "unresolved"

PINNED_REQUIREMENT_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[A-Za-z0-9_,_.-]+\])?\s*==\s*([^\s;#]+)"
)
REQUIREMENT_NAME_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[A-Za-z0-9_,_.-]+\])?"
)


def build_cyclonedx_bom(
    project_root: Path,
    dependencies: Iterable[Dependency],
    *,
    target_model: Optional[str],
    target_endpoint: Optional[str],
    scanner_version: str,
    model_inventory: Optional[ModelInventory] = None,
) -> dict:
    root = project_root.resolve()
    model_inventory = model_inventory or collect_model_inventory(
        root,
        target_model=target_model,
        target_endpoint=target_endpoint,
        include_hashes=True,
    )
    return _build_cyclonedx_document(
        root,
        scanner_version=scanner_version,
        bom_kind="sbom+aibom",
        components=[
            *_dependency_components(dependencies),
            *_aibom_components(root, model_inventory),
        ],
    )


def build_cyclonedx_sbom(
    project_root: Path,
    dependencies: Iterable[Dependency],
    *,
    scanner_version: str,
) -> dict:
    return _build_cyclonedx_document(
        project_root.resolve(),
        scanner_version=scanner_version,
        bom_kind="sbom",
        components=_dependency_components(dependencies),
    )


def build_cyclonedx_aibom(
    project_root: Path,
    *,
    target_model: Optional[str],
    target_endpoint: Optional[str],
    scanner_version: str,
    model_inventory: Optional[ModelInventory] = None,
) -> dict:
    root = project_root.resolve()
    model_inventory = model_inventory or collect_model_inventory(
        root,
        target_model=target_model,
        target_endpoint=target_endpoint,
        include_hashes=True,
    )
    return _build_cyclonedx_document(
        root,
        scanner_version=scanner_version,
        bom_kind="aibom",
        components=_aibom_components(root, model_inventory),
    )


def _build_cyclonedx_document(
    root: Path,
    *,
    scanner_version: str,
    bom_kind: str,
    components: Iterable[dict],
) -> dict:
    components = _dedupe_components(components)
    root_ref = f"pkg:generic/{_safe_ref(root.name or 'project')}"
    component_refs = [component["bom-ref"] for component in components]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{_stable_bom_uuid(root, bom_kind, component_refs)}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "AegisLocal",
                    "name": "AegisLocal",
                    "version": scanner_version,
                }
            ],
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": root.name or "project",
                "version": "unresolved",
                "properties": [
                    _property("aegislocal:project-root", str(root)),
                    _property("aegislocal:bom-kind", bom_kind),
                ],
            },
        },
        "components": components,
        "dependencies": [
            {
                "ref": root_ref,
                "dependsOn": component_refs,
            }
        ],
    }


def _dependency_components(dependencies: Iterable[Dependency]) -> List[dict]:
    return [_dependency_component(dependency) for dependency in dependencies]


def _aibom_components(root: Path, model_inventory: ModelInventory) -> List[dict]:
    return [
        *(
            _model_artifact_component(artifact, model_inventory.manifest, root)
            for artifact in model_inventory.artifacts
        ),
        *(
            _manifest_entry_component(entry, root, MODEL_MANIFEST_NAME)
            for entry in (
                *model_inventory.manifest.models,
                *model_inventory.manifest.adapters,
            )
        ),
        *(
            _model_reference_component(reference, model_inventory.manifest)
            for reference in model_inventory.references
        ),
    ]


def write_cyclonedx_bom(path: Path, bom: dict) -> None:
    path.write_text(json.dumps(bom, indent=2) + "\n", encoding="utf-8")


def split_bom_output_paths(output_file: Path) -> Tuple[Path, Path]:
    output_text = str(output_file)
    if output_text.endswith(".cdx.json"):
        base = output_text[: -len(".cdx.json")]
        return Path(f"{base}.sbom.cdx.json"), Path(f"{base}.aibom.cdx.json")
    suffix = "".join(output_file.suffixes)
    if suffix:
        base = str(output_file)[: -len(suffix)]
        return Path(f"{base}.sbom{suffix}"), Path(f"{base}.aibom{suffix}")
    return (
        output_file.with_name(f"{output_file.name}.sbom"),
        output_file.with_name(f"{output_file.name}.aibom"),
    )


def collect_bom_dependencies(
    manifest_files: Iterable[Path],
) -> Tuple[List[Dependency], List[ExecutionError]]:
    dependencies: List[Dependency] = []
    errors: List[ExecutionError] = []
    manifest_paths = list(manifest_files)
    lock_dirs = {
        path.parent.resolve()
        for path in manifest_paths
        if path.name in {"uv.lock", "poetry.lock"}
    }
    for path in manifest_paths:
        if path.name == "pyproject.toml" and path.parent.resolve() in lock_dirs:
            continue
        parsed_dependencies, parsed_errors = _parse_bom_manifest_file(path)
        dependencies.extend(parsed_dependencies)
        errors.extend(parsed_errors)
    return _dedupe_dependencies(dependencies), errors


def _parse_bom_manifest_file(path: Path) -> Tuple[List[Dependency], List[ExecutionError]]:
    if _is_requirement_file(path.name):
        return _parse_bom_requirement_file(path)
    if path.name == "pyproject.toml":
        return _parse_bom_pyproject_file(path)
    if path.name in {"uv.lock", "poetry.lock"}:
        return _parse_bom_lock_file(path)
    return [], []


def _parse_bom_requirement_file(path: Path) -> Tuple[List[Dependency], List[ExecutionError]]:
    dependencies: List[Dependency] = []
    errors: List[ExecutionError] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return [], [
            ExecutionError(
                source=ErrorSource.STATIC,
                message="Unable to read requirements file",
                path=str(path),
                detail=str(exc),
            )
        ]

    for line_number, raw_line in enumerate(lines, start=1):
        normalized = raw_line.split("#", 1)[0].strip()
        if not normalized:
            continue
        if normalized.startswith("-"):
            errors.append(
                ExecutionError(
                    source=ErrorSource.STATIC,
                    message="Unsupported requirement line; entry was not included in BOM inventory",
                    path=f"{path}:{line_number}",
                    detail=raw_line,
                )
            )
            continue
        dependency = _dependency_from_requirement_text(normalized, path, line_number)
        if dependency:
            dependencies.append(dependency)
    return dependencies, errors


def _parse_bom_pyproject_file(path: Path) -> Tuple[List[Dependency], List[ExecutionError]]:
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        return [], [
            ExecutionError(
                source=ErrorSource.STATIC,
                message="Unable to read pyproject.toml",
                path=str(path),
                detail=str(exc),
            )
        ]

    dependencies: List[Dependency] = []
    project = data.get("project") if isinstance(data.get("project"), dict) else {}
    for spec in project.get("dependencies") or []:
        dependency = _dependency_from_requirement_text(spec, path, 1)
        if dependency:
            dependencies.append(dependency)
    optional_dependencies = project.get("optional-dependencies") or {}
    if isinstance(optional_dependencies, dict):
        for specs in optional_dependencies.values():
            for spec in specs or []:
                dependency = _dependency_from_requirement_text(spec, path, 1)
                if dependency:
                    dependencies.append(dependency)

    poetry = ((data.get("tool") or {}).get("poetry") or {})
    if isinstance(poetry, dict):
        for section_name in ("dependencies", "dev-dependencies"):
            _extend_poetry_bom_dependencies(
                dependencies,
                poetry.get(section_name) or {},
                path,
            )
        groups = poetry.get("group") or {}
        if isinstance(groups, dict):
            for group in groups.values():
                if isinstance(group, dict):
                    _extend_poetry_bom_dependencies(
                        dependencies,
                        group.get("dependencies") or {},
                        path,
                    )

    return dependencies, []


def _parse_bom_lock_file(path: Path) -> Tuple[List[Dependency], List[ExecutionError]]:
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        return [], [
            ExecutionError(
                source=ErrorSource.STATIC,
                message=f"Unable to read {path.name}",
                path=str(path),
                detail=str(exc),
            )
        ]

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
    return dependencies, []


def _dependency_from_requirement_text(
    spec: object,
    path: Path,
    line_number: int,
) -> Optional[Dependency]:
    if not isinstance(spec, str):
        return None
    normalized = spec.split(";", 1)[0].strip()
    if not normalized:
        return None
    pinned = PINNED_REQUIREMENT_RE.match(normalized)
    if pinned:
        return Dependency(
            name=pinned.group(1),
            version=pinned.group(2),
            source_file=path,
            line_number=line_number,
        )
    match = REQUIREMENT_NAME_RE.match(normalized)
    if not match:
        return None
    return Dependency(
        name=match.group(1),
        version=UNRESOLVED_VERSION,
        source_file=path,
        line_number=line_number,
    )


def _extend_poetry_bom_dependencies(
    dependencies: List[Dependency],
    section: object,
    path: Path,
) -> None:
    if not isinstance(section, dict):
        return
    for name, raw_spec in section.items():
        if name.lower() == "python":
            continue
        version = UNRESOLVED_VERSION
        if isinstance(raw_spec, str) and raw_spec.startswith("=="):
            version = raw_spec[2:].strip() or UNRESOLVED_VERSION
        elif isinstance(raw_spec, dict):
            raw_version = raw_spec.get("version")
            if isinstance(raw_version, str) and raw_version.startswith("=="):
                version = raw_version[2:].strip() or UNRESOLVED_VERSION
        dependencies.append(
            Dependency(name=name, version=version, source_file=path, line_number=1)
        )


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


def _is_requirement_file(filename: str) -> bool:
    return (
        filename == "requirements.txt"
        or (filename.startswith("requirements-") and filename.endswith(".txt"))
        or (filename.startswith("requirements.") and filename.endswith(".txt"))
    )


def _dependency_component(dependency: Dependency) -> dict:
    package_name = _normalize_pypi_name(dependency.name)
    purl = f"pkg:pypi/{quote(package_name)}"
    if dependency.version != UNRESOLVED_VERSION:
        purl = f"{purl}@{quote(dependency.version)}"
    return {
        "type": "library",
        "bom-ref": purl,
        "name": dependency.name,
        "version": dependency.version,
        "purl": purl,
        "properties": [
            _property("aegislocal:artifact-type", "software-package"),
            _property("aegislocal:ecosystem", "PyPI"),
            _property("aegislocal:source-file", str(dependency.source_file)),
            _property("aegislocal:source-line", str(dependency.line_number)),
        ],
    }


def _model_reference_component(
    reference: ModelReference,
    manifest: ModelManifest,
) -> dict:
    approved_entry = manifest.approved_model(reference.name)
    bom_ref = _model_bom_ref(reference.source, reference.name, reference.revision)
    properties = [
        _property("aegislocal:artifact-type", reference.artifact_type),
        _property("aegislocal:model-source", reference.source),
        _property("aegislocal:approved", str(approved_entry is not None).lower()),
    ]
    if reference.source_file:
        properties.append(_property("aegislocal:source-file", str(reference.source_file)))
    if reference.line_number:
        properties.append(_property("aegislocal:source-line", str(reference.line_number)))
    if reference.revision:
        properties.append(_property("aegislocal:revision", reference.revision))
    if approved_entry and approved_entry.license:
        properties.append(_property("aegislocal:license", approved_entry.license))
    if approved_entry and approved_entry.base_model:
        properties.append(_property("aegislocal:base-model", approved_entry.base_model))

    component = {
        "type": "machine-learning-model",
        "bom-ref": bom_ref,
        "name": reference.name,
        "version": reference.revision or "unresolved",
        "properties": properties,
    }
    if reference.source == "huggingface":
        component["externalReferences"] = [
            {
                "type": "distribution",
                "url": _huggingface_url(reference.name, reference.revision),
            }
        ]
    return component


def _model_artifact_component(
    artifact: ModelArtifact,
    manifest: ModelManifest,
    root: Path,
) -> dict:
    manifest_entry = manifest.artifact_entry(artifact.path, root)
    relative_path = _normalize_manifest_path(artifact.path, root)
    properties = [
        _property("aegislocal:artifact-type", artifact.artifact_type),
        _property("aegislocal:model-source", "local"),
        _property("aegislocal:source-file", str(artifact.path)),
        _property("aegislocal:format", artifact.format),
        _property("aegislocal:approved", str(bool(manifest_entry and manifest_entry.approved)).lower()),
    ]
    if manifest_entry and manifest_entry.base_model:
        properties.append(_property("aegislocal:base-model", manifest_entry.base_model))
    if manifest_entry and manifest_entry.license:
        properties.append(_property("aegislocal:license", manifest_entry.license))

    component = {
        "type": "machine-learning-model",
        "bom-ref": f"model:local/{quote(relative_path)}",
        "name": manifest_entry.name if manifest_entry else artifact.name,
        "version": artifact.sha256 or UNRESOLVED_VERSION,
        "properties": properties,
    }
    if artifact.sha256:
        component["hashes"] = [{"alg": "SHA-256", "content": artifact.sha256}]
    return component


def _manifest_entry_component(
    entry: ModelManifestEntry,
    root: Path,
    manifest_name: str,
) -> dict:
    source = entry.source or "unknown"
    version = entry.revision or entry.sha256 or "unresolved"
    bom_ref = (
        f"model:local/{quote(_normalize_configured_path(entry.path))}"
        if entry.path
        else _model_bom_ref(source, entry.name, entry.revision)
    )
    properties = [
        _property("aegislocal:artifact-type", entry.artifact_type),
        _property("aegislocal:model-source", source),
        _property("aegislocal:approved", str(entry.approved).lower()),
        _property("aegislocal:source-file", str(root / manifest_name)),
    ]
    if entry.base_model:
        properties.append(_property("aegislocal:base-model", entry.base_model))
    if entry.license:
        properties.append(_property("aegislocal:license", entry.license))
    if entry.path:
        properties.append(_property("aegislocal:path", _normalize_configured_path(entry.path)))

    component = {
        "type": "machine-learning-model",
        "bom-ref": bom_ref,
        "name": entry.name,
        "version": version,
        "properties": properties,
    }
    if entry.sha256:
        component["hashes"] = [{"alg": "SHA-256", "content": entry.sha256.removeprefix("sha256:")}]
    if source == "huggingface":
        component["externalReferences"] = [
            {
                "type": "distribution",
                "url": _huggingface_url(entry.name, entry.revision),
            }
        ]
    return component


def _dedupe_components(components: Iterable[dict]) -> List[dict]:
    seen = set()
    deduped: List[dict] = []
    for component in components:
        bom_ref = component["bom-ref"]
        if bom_ref in seen:
            continue
        seen.add(bom_ref)
        deduped.append(component)
    return sorted(deduped, key=lambda component: component["bom-ref"])


def _model_bom_ref(source: str, name: str, revision: Optional[str]) -> str:
    suffix = f"@{revision}" if revision else ""
    return f"model:{quote(source)}/{quote(name)}{suffix}"


def _huggingface_url(name: str, revision: Optional[str]) -> str:
    base_url = f"https://huggingface.co/{name}"
    return f"{base_url}/tree/{revision}" if revision else base_url


def _property(name: str, value: str) -> dict:
    return {"name": name, "value": value}


def _normalize_pypi_name(name: str) -> str:
    return name.replace("_", "-").lower()


def _safe_ref(value: str) -> str:
    return quote(value.replace(" ", "-"))


def _stable_bom_uuid(root: Path, bom_kind: str, component_refs: Iterable[str]) -> str:
    content = f"{root.name}:{bom_kind}:" + ",".join(sorted(component_refs))
    return str(uuid.uuid5(AIBOM_UUID_NAMESPACE, content))


__all__ = [
    "CYCLONEDX_SPEC_VERSION",
    "UNRESOLVED_VERSION",
    "build_cyclonedx_aibom",
    "build_cyclonedx_bom",
    "build_cyclonedx_sbom",
    "collect_bom_dependencies",
    "split_bom_output_paths",
    "write_cyclonedx_bom",
]
