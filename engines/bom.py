# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional
from urllib.parse import quote

from engines.model_scanner import (
    ModelArtifact,
    ModelManifest,
    ModelManifestEntry,
    ModelReference,
    discover_model_artifacts,
    discover_model_references,
    load_model_manifest,
)
from engines.static_scanner import Dependency


CYCLONEDX_SPEC_VERSION = "1.6"


def build_cyclonedx_bom(
    project_root: Path,
    dependencies: Iterable[Dependency],
    *,
    target_model: Optional[str],
    target_endpoint: Optional[str],
    scanner_version: str,
) -> dict:
    root = project_root.resolve()
    manifest, _errors = load_model_manifest(root)
    model_references = discover_model_references(
        root,
        target_model=target_model,
        target_endpoint=target_endpoint,
    )
    model_artifacts = discover_model_artifacts(root)
    components = _dedupe_components(
        [
            *(_dependency_component(dependency) for dependency in dependencies),
            *(
                _model_reference_component(reference, manifest)
                for reference in model_references
            ),
            *(
                _model_artifact_component(artifact, manifest, root)
                for artifact in model_artifacts
            ),
            *(
                _manifest_entry_component(entry, root, "aegislocal.models.toml")
                for entry in (*manifest.models, *manifest.adapters)
            ),
        ]
    )

    root_ref = f"pkg:generic/{_safe_ref(root.name or 'project')}"
    component_refs = [component["bom-ref"] for component in components]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{_stable_bom_uuid(root, component_refs)}",
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
                "properties": [
                    _property("aegislocal:project-root", str(root)),
                    _property("aegislocal:bom-kind", "sbom+aibom"),
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


def write_cyclonedx_bom(path: Path, bom: dict) -> None:
    path.write_text(json.dumps(bom, indent=2) + "\n", encoding="utf-8")


def _dependency_component(dependency: Dependency) -> dict:
    package_name = _normalize_pypi_name(dependency.name)
    purl = f"pkg:pypi/{quote(package_name)}@{quote(dependency.version)}"
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
    relative_path = _relative_path(artifact.path, root)
    digest = _sha256_file(artifact.path)
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

    return {
        "type": "machine-learning-model",
        "bom-ref": f"model:local/{quote(relative_path)}",
        "name": artifact.name,
        "hashes": [{"alg": "SHA-256", "content": digest}],
        "properties": properties,
    }


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


def _normalize_configured_path(path: Optional[str]) -> str:
    if not path:
        return ""
    return Path(path).as_posix().lstrip("./")


def _relative_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _sha256_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_ref(value: str) -> str:
    return quote(value.replace(" ", "-"))


def _stable_bom_uuid(root: Path, component_refs: Iterable[str]) -> str:
    import hashlib
    import uuid

    digest = hashlib.sha256()
    digest.update(str(root).encode("utf-8"))
    for ref in sorted(component_refs):
        digest.update(ref.encode("utf-8"))
    return str(uuid.UUID(digest.hexdigest()[:32]))


__all__ = ["CYCLONEDX_SPEC_VERSION", "build_cyclonedx_bom", "write_cyclonedx_bom"]
