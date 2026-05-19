# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

import json

from typer.testing import CliRunner

from engines.bom import (
    CYCLONEDX_SPEC_VERSION,
    UNRESOLVED_VERSION,
    build_cyclonedx_aibom,
    build_cyclonedx_bom,
    build_cyclonedx_sbom,
    collect_bom_dependencies,
    split_bom_output_paths,
    write_cyclonedx_bom,
)
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


def test_build_separate_sbom_and_aibom_documents(tmp_path):
    dependency = Dependency(
        name="fastapi",
        version=UNRESOLVED_VERSION,
        source_file=tmp_path / "requirements.txt",
        line_number=1,
    )
    config = tmp_path / "settings.toml"
    config.write_text('model = "mistralai/Mistral-7B-Instruct-v0.3"\n', encoding="utf-8")

    sbom = build_cyclonedx_sbom(
        tmp_path,
        [dependency],
        scanner_version="0.1.0",
    )
    aibom = build_cyclonedx_aibom(
        tmp_path,
        target_model=None,
        target_endpoint=None,
        scanner_version="0.1.0",
    )

    assert _metadata_property(sbom, "aegislocal:bom-kind") == "sbom"
    assert _metadata_property(aibom, "aegislocal:bom-kind") == "aibom"
    assert "pkg:pypi/fastapi" in {component["bom-ref"] for component in sbom["components"]}
    assert all(component["type"] != "machine-learning-model" for component in sbom["components"])
    assert all(not component["bom-ref"].startswith("pkg:pypi/") for component in aibom["components"])
    assert any(component["type"] == "machine-learning-model" for component in aibom["components"])


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


def test_split_bom_output_paths_prefers_cyclonedx_suffixes(tmp_path):
    sbom_path, aibom_path = split_bom_output_paths(tmp_path / "bom.cdx.json")

    assert sbom_path == tmp_path / "bom.sbom.cdx.json"
    assert aibom_path == tmp_path / "bom.aibom.cdx.json"


def test_bom_command_writes_separate_reports_without_default_runtime_model(tmp_path):
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

    sbom = json.loads((tmp_path / "bom.sbom.cdx.json").read_text(encoding="utf-8"))
    aibom = json.loads((tmp_path / "bom.aibom.cdx.json").read_text(encoding="utf-8"))
    sbom_refs = {component["bom-ref"] for component in sbom["components"]}
    aibom_refs = {component["bom-ref"] for component in aibom["components"]}

    assert result.exit_code == 0
    assert "pkg:pypi/requests@2.32.4" in sbom_refs
    assert "pkg:pypi/requests@2.32.4" not in aibom_refs
    assert "model:ollama/llama3.1%3A8b" not in aibom_refs


def test_collect_bom_dependencies_includes_unpinned_requirements(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        "\n".join(
            [
                "fastapi",
                "python-jose[cryptography]",
                "httpx>=0.27",
                "requests==2.32.4",
            ]
        ),
        encoding="utf-8",
    )

    dependencies, errors = collect_bom_dependencies([requirements])

    assert errors == []
    assert [(dependency.name, dependency.version) for dependency in dependencies] == [
        ("fastapi", UNRESOLVED_VERSION),
        ("python-jose", UNRESOLVED_VERSION),
        ("httpx", UNRESOLVED_VERSION),
        ("requests", "2.32.4"),
    ]


def test_bom_command_outputs_unpinned_requirement_components(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("fastapi\npython-jose[cryptography]\n", encoding="utf-8")
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

    sbom = json.loads((tmp_path / "bom.sbom.cdx.json").read_text(encoding="utf-8"))
    fastapi = _component_by_ref(sbom, "pkg:pypi/fastapi")
    python_jose = _component_by_ref(sbom, "pkg:pypi/python-jose")

    assert result.exit_code == 0
    assert fastapi["version"] == UNRESOLVED_VERSION
    assert python_jose["version"] == UNRESOLVED_VERSION


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

    aibom = json.loads((tmp_path / "bom.aibom.cdx.json").read_text(encoding="utf-8"))
    aibom_refs = {component["bom-ref"] for component in aibom["components"]}

    assert result.exit_code == 0
    assert "model:ollama/llama3.1%3A8b" in aibom_refs


def test_bom_command_includes_bedrock_model_from_env_variant(tmp_path):
    env_file = tmp_path / "backend" / ".env.development"
    env_file.parent.mkdir()
    env_file.write_text(
        "AWS_BEDROCK_MODEL_ID=anthropic.claude-3-sonnet-20240229-v1:0\n",
        encoding="utf-8",
    )
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

    aibom = json.loads((tmp_path / "bom.aibom.cdx.json").read_text(encoding="utf-8"))
    component = _component_by_ref(
        aibom,
        "model:bedrock/anthropic.claude-3-sonnet-20240229-v1%3A0",
    )

    assert result.exit_code == 0
    assert component["name"] == "anthropic.claude-3-sonnet-20240229-v1:0"
    assert _property(component, "aegislocal:model-source") == "bedrock"
    assert _property(component, "aegislocal:source-file") == str(env_file)


def test_bom_command_inventory_warnings_are_nonfatal_by_default(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("-e .\n", encoding="utf-8")
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

    assert result.exit_code == 0
    assert (tmp_path / "bom.sbom.cdx.json").exists()
    assert (tmp_path / "bom.aibom.cdx.json").exists()
    assert "Wrote BOMs with 1 inventory warning(s)" in result.output


def test_bom_command_strict_inventory_warnings_are_fatal(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("-e .\n", encoding="utf-8")
    output = tmp_path / "bom.cdx.json"

    result = runner.invoke(
        app,
        [
            "bom",
            "--project-root",
            str(tmp_path),
            "--output",
            str(output),
            "--strict",
        ],
    )

    assert result.exit_code == 1
    assert (tmp_path / "bom.sbom.cdx.json").exists()
    assert (tmp_path / "bom.aibom.cdx.json").exists()
    assert "Wrote BOMs with 1 inventory warning(s)" in result.output


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


def _metadata_property(bom, name):
    return _property(bom["metadata"]["component"], name)
