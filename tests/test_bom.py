# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

import json

from typer.testing import CliRunner

from engines.bom import CYCLONEDX_SPEC_VERSION, build_cyclonedx_bom, write_cyclonedx_bom
from engines.static_scanner import Dependency
from main import app


runner = CliRunner()


def test_build_cyclonedx_bom_includes_python_dependencies(tmp_path):
    dependency = Dependency(
        name="Requests",
        version="2.32.4",
        source_file=tmp_path / "requirements.txt",
        line_number=3,
    )

    bom = build_cyclonedx_bom(
        tmp_path,
        [dependency],
        target_model=None,
        target_endpoint=None,
        scanner_version="0.1.0",
    )

    component = _component_by_ref(bom, "pkg:pypi/requests@2.32.4")

    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == CYCLONEDX_SPEC_VERSION
    assert bom["metadata"]["component"]["version"] == "unresolved"
    assert component["type"] == "library"
    assert component["name"] == "Requests"
    assert component["purl"] == "pkg:pypi/requests@2.32.4"
    assert _property(component, "aegislocal:ecosystem") == "PyPI"
    assert _property(component, "aegislocal:source-line") == "3"


def test_build_cyclonedx_bom_includes_huggingface_model_references(tmp_path):
    revision = "a" * 40
    config = tmp_path / "settings.toml"
    config.write_text(
        f'model = "mistralai/Mistral-7B-Instruct-v0.3@{revision}"',
        encoding="utf-8",
    )
    manifest = tmp_path / "aegislocal.models.toml"
    manifest.write_text(
        f"""
[[models]]
name = "mistralai/Mistral-7B-Instruct-v0.3"
source = "huggingface"
revision = "{revision}"
license = "apache-2.0"
approved = true
""",
        encoding="utf-8",
    )

    bom = build_cyclonedx_bom(
        tmp_path,
        [],
        target_model=None,
        target_endpoint=None,
        scanner_version="0.1.0",
    )

    component = _component_by_ref(
        bom,
        f"model:huggingface/mistralai/Mistral-7B-Instruct-v0.3@{revision}",
    )

    assert component["type"] == "machine-learning-model"
    assert component["version"] == revision
    assert _property(component, "aegislocal:approved") == "true"
    assert _property(component, "aegislocal:license") == "apache-2.0"
    assert component["externalReferences"][0]["url"].endswith(f"/tree/{revision}")


def test_build_cyclonedx_bom_includes_local_model_hashes(tmp_path):
    model_file = tmp_path / "models" / "local.gguf"
    model_file.parent.mkdir()
    model_file.write_bytes(b"model bytes")
    manifest = tmp_path / "aegislocal.models.toml"
    manifest.write_text(
        """
[[models]]
name = "local-model"
source = "local"
path = "models/local.gguf"
license = "unknown"
approved = true
""",
        encoding="utf-8",
    )

    bom = build_cyclonedx_bom(
        tmp_path,
        [],
        target_model=None,
        target_endpoint=None,
        scanner_version="0.1.0",
    )

    component = _component_by_ref(bom, "model:local/models/local.gguf")

    assert component["type"] == "machine-learning-model"
    assert component["name"] == "local-model"
    assert component["version"] == component["hashes"][0]["content"]
    assert component["hashes"][0]["alg"] == "SHA-256"
    assert _property(component, "aegislocal:format") == "gguf"
    assert _property(component, "aegislocal:approved") == "true"


def test_write_cyclonedx_bom_writes_pretty_json(tmp_path):
    output = tmp_path / "bom.json"
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "components": [],
    }

    write_cyclonedx_bom(output, bom)

    assert json.loads(output.read_text(encoding="utf-8")) == bom
    assert output.read_text(encoding="utf-8").endswith("\n")


def test_bom_command_writes_inventory_without_default_runtime_model(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests==2.32.4\n", encoding="utf-8")
    output = tmp_path / "bom.cdx.json"

    result = runner.invoke(
        app,
        [
            "bom",
            "--project-root",
            str(tmp_path),
            "--output",
            str(output),
        ],
    )

    bom = json.loads(output.read_text(encoding="utf-8"))
    bom_refs = {component["bom-ref"] for component in bom["components"]}

    assert result.exit_code == 0
    assert "pkg:pypi/requests@2.32.4" in bom_refs
    assert "model:ollama/llama3.1%3A8b" not in bom_refs


def test_bom_command_includes_explicit_runtime_model(tmp_path):
    output = tmp_path / "bom.cdx.json"

    result = runner.invoke(
        app,
        [
            "bom",
            "--project-root",
            str(tmp_path),
            "--target-model",
            "llama3.1:8b",
            "--target-endpoint",
            "http://localhost:11434/v1/chat/completions",
            "--output",
            str(output),
        ],
    )

    bom = json.loads(output.read_text(encoding="utf-8"))
    bom_refs = {component["bom-ref"] for component in bom["components"]}

    assert result.exit_code == 0
    assert "model:ollama/llama3.1%3A8b" in bom_refs


def _component_by_ref(bom, bom_ref):
    for component in bom["components"]:
        if component["bom-ref"] == bom_ref:
            return component
    raise AssertionError(f"Missing component {bom_ref}")


def _property(component, name):
    for prop in component["properties"]:
        if prop["name"] == name:
            return prop["value"]
    raise AssertionError(f"Missing property {name}")
