# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

import hashlib

from engines import model_scanner
from engines.model_scanner import (
    MODEL_SUPPLY_CHAIN_CATEGORY,
    ModelArtifact,
    ModelInventory,
    ModelManifest,
    ModelManifestEntry,
    discover_model_artifacts,
    discover_model_references,
    load_model_manifest,
    scan_model_supply_chain,
)


def test_discovers_cli_and_config_model_references(tmp_path):
    config = tmp_path / ".env"
    config.write_text(
        "\n".join(
            [
                "TARGET_MODEL=mistralai/Mistral-7B-Instruct-v0.3",
                "trust_remote_code = true",
                "LOCAL_MODEL=llama3.1:8b",
            ]
        ),
        encoding="utf-8",
    )

    references = discover_model_references(
        tmp_path,
        target_model="llama3.1:8b",
        target_endpoint="http://localhost:11434/v1/chat/completions",
    )

    assert ("llama3.1:8b", "ollama", None) in [
        (reference.name, reference.source, reference.source_file)
        for reference in references
    ]
    assert ("mistralai/Mistral-7B-Instruct-v0.3", "huggingface", config) in [
        (reference.name, reference.source, reference.source_file)
        for reference in references
    ]
    assert any(reference.artifact_type == "remote_code" for reference in references)


def test_discovers_bedrock_model_id_from_env_variant(tmp_path):
    config = tmp_path / ".env.development"
    config.write_text(
        "AWS_BEDROCK_MODEL_ID=anthropic.claude-3-sonnet-20240229-v1:0\n",
        encoding="utf-8",
    )

    references = discover_model_references(tmp_path)

    assert [(reference.name, reference.source, reference.source_file) for reference in references] == [
        ("anthropic.claude-3-sonnet-20240229-v1:0", "bedrock", config)
    ]


def test_model_scan_reports_unapproved_unpinned_and_remote_code(tmp_path):
    config = tmp_path / "settings.toml"
    config.write_text(
        """
model = "mistralai/Mistral-7B-Instruct-v0.3"
trust_remote_code = true
""",
        encoding="utf-8",
    )

    findings, errors = scan_model_supply_chain(tmp_path)

    assert errors == []
    assert {finding.category for finding in findings} == {MODEL_SUPPLY_CHAIN_CATEGORY}
    assert any("not declared as an approved model source" in finding.description for finding in findings)
    assert any("without an immutable revision" in finding.description for finding in findings)
    assert any("trust_remote_code" in finding.description for finding in findings)


def test_approved_pinned_huggingface_reference_has_no_findings(tmp_path):
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

    findings, errors = scan_model_supply_chain(tmp_path)

    assert errors == []
    assert findings == []


def test_local_model_artifacts_report_missing_hash_and_unsafe_formats(tmp_path):
    model_file = tmp_path / "models" / "unsafe.bin"
    model_file.parent.mkdir()
    model_file.write_bytes(b"model bytes")

    artifacts = discover_model_artifacts(tmp_path)
    findings, errors = scan_model_supply_chain(tmp_path)

    assert [artifact.path for artifact in artifacts] == [model_file]
    assert errors == []
    assert any("deserialization-prone" in finding.description for finding in findings)
    assert any("has no approved SHA256" in finding.description for finding in findings)


def test_manifest_hash_mismatch_is_reported(tmp_path):
    model_file = tmp_path / "models" / "model.gguf"
    model_file.parent.mkdir()
    model_file.write_bytes(b"changed")
    expected_hash = hashlib.sha256(b"original").hexdigest()
    manifest = tmp_path / "aegislocal.models.toml"
    manifest.write_text(
        f"""
[[models]]
name = "local-model"
source = "local"
path = "models/model.gguf"
sha256 = "{expected_hash}"
license = "unknown"
approved = true
""",
        encoding="utf-8",
    )

    findings, errors = scan_model_supply_chain(tmp_path)

    assert errors == []
    assert any("does not match the approved SHA256" in finding.description for finding in findings)


def test_manifest_validation_reuses_computed_artifact_hash(tmp_path, monkeypatch):
    model_file = tmp_path / "models" / "model.gguf"
    model_file.parent.mkdir()
    model_file.write_bytes(b"current")
    digest = hashlib.sha256(b"current").hexdigest()
    calls = []

    def fake_sha256_file(path):
        calls.append(path)
        return digest

    monkeypatch.setattr(model_scanner, "_sha256_file", fake_sha256_file)
    entry = ModelManifestEntry(
        name="local-model",
        source="local",
        path="models/model.gguf",
        sha256=digest,
        approved=True,
    )
    inventory = ModelInventory(
        manifest=ModelManifest(path=None, models=(entry, entry), adapters=()),
        manifest_errors=(),
        references=(),
        artifacts=(
            ModelArtifact(
                name="model.gguf",
                path=model_file,
                artifact_type="model",
                format="gguf",
            ),
        ),
    )

    findings, errors = scan_model_supply_chain(tmp_path, inventory=inventory)

    assert errors == []
    assert findings == []
    assert calls == [model_file]


def test_adapter_without_base_model_is_reported(tmp_path):
    adapter = tmp_path / "models" / "lora" / "adapter.safetensors"
    adapter.parent.mkdir(parents=True)
    adapter.write_bytes(b"adapter")
    digest = hashlib.sha256(b"adapter").hexdigest()
    manifest = tmp_path / "aegislocal.models.toml"
    manifest.write_text(
        f"""
[[adapters]]
name = "my-adapter"
source = "local"
path = "models/lora/adapter.safetensors"
sha256 = "{digest}"
approved = true
""",
        encoding="utf-8",
    )

    findings, errors = scan_model_supply_chain(tmp_path)

    assert errors == []
    assert any("does not declare its base model" in finding.description for finding in findings)


def test_load_model_manifest_reports_invalid_toml(tmp_path):
    manifest = tmp_path / "aegislocal.models.toml"
    manifest.write_text("[[models]\n", encoding="utf-8")

    loaded_manifest, errors = load_model_manifest(tmp_path)

    assert loaded_manifest.path == manifest
    assert len(errors) == 1
    assert errors[0].message == "Unable to read model provenance manifest"


def test_python_type_annotations_are_not_model_references(tmp_path):
    source = tmp_path / "app.py"
    source.write_text(
        """
from typing import Optional

model_name: Optional[str] = None
target_model: str
""",
        encoding="utf-8",
    )

    references = discover_model_references(tmp_path)

    assert references == []


def test_python_string_literal_model_assignment_is_detected(tmp_path):
    source = tmp_path / "app.py"
    source.write_text('model = "models/my-model.gguf"\n', encoding="utf-8")

    references = discover_model_references(tmp_path)

    assert [(reference.name, reference.source) for reference in references] == [
        ("models/my-model.gguf", "local")
    ]
