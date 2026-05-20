# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence
from urllib.parse import quote
from uuid import NAMESPACE_URL, uuid5

from engines.static_scanner import Dependency


def write_sbom(
    *,
    project_root: Path,
    dependencies: Sequence[Dependency],
    output_path: Path,
    scanner_version: str,
) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    bom = _base_bom(project_root=project_root, kind="sbom", scanner_version=scanner_version)
    bom["components"] = [
        {
            "type": "library",
            "bom-ref": _dependency_ref(dependency.name, dependency.version),
            "name": dependency.name,
            "version": dependency.version,
            "purl": _dependency_ref(dependency.name, dependency.version),
            "properties": [
                {"name": "aegislocal:artifact-type", "value": "software-package"},
                {"name": "aegislocal:ecosystem", "value": "PyPI"},
                {"name": "aegislocal:source-file", "value": str(dependency.source_file)},
                {"name": "aegislocal:source-line", "value": str(dependency.line_number)},
            ],
        }
        for dependency in dependencies
    ]
    bom["dependencies"] = [
        {
            "ref": "pkg:generic/AegisLocal",
            "dependsOn": [component["bom-ref"] for component in bom["components"]],
        }
    ]
    _write_json(output_path, bom)
    return output_path


def write_aibom(
    *,
    project_root: Path,
    model_names: Sequence[str],
    output_path: Path,
    scanner_version: str,
) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    bom = _base_bom(project_root=project_root, kind="aibom", scanner_version=scanner_version)
    unique_models = list(dict.fromkeys(model for model in model_names if model))
    bom["components"] = [
        {
            "type": "machine-learning-model",
            "bom-ref": _model_ref(model_name),
            "name": model_name,
            "version": "unresolved",
            "properties": [
                {"name": "aegislocal:artifact-type", "value": "model"},
                {"name": "aegislocal:model-source", "value": _model_source(model_name)},
            ],
        }
        for model_name in unique_models
    ]
    bom["dependencies"] = [
        {
            "ref": "pkg:generic/AegisLocal",
            "dependsOn": [component["bom-ref"] for component in bom["components"]],
        }
    ]
    _write_json(output_path, bom)
    return output_path


def _base_bom(*, project_root: Path, kind: str, scanner_version: str) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    serial_seed = f"{project_root.resolve()}:{kind}:{now}"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid5(NAMESPACE_URL, serial_seed)}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [
                {
                    "vendor": "AegisLocal",
                    "name": "AegisLocal",
                    "version": scanner_version,
                }
            ],
            "component": {
                "type": "application",
                "bom-ref": "pkg:generic/AegisLocal",
                "name": "AegisLocal",
                "version": "unresolved",
                "properties": [
                    {
                        "name": "aegislocal:project-root",
                        "value": str(project_root.resolve()),
                    },
                    {"name": "aegislocal:bom-kind", "value": kind},
                ],
            },
        },
    }


def _dependency_ref(name: str, version: str) -> str:
    return f"pkg:pypi/{name.lower()}@{version}"


def _model_ref(model_name: str) -> str:
    source = _model_source(model_name)
    return f"model:{source}/{quote(model_name, safe='/')}"


def _model_source(model_name: str) -> str:
    return "huggingface" if "/" in model_name else "ollama"


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


__all__ = ["write_aibom", "write_sbom"]
