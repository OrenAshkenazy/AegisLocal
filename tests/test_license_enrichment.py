# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

import json

from engines import license_enrichment
from engines.license_enrichment import (
    _license_from_huggingface_model,
    _license_from_pypi_info,
    enrich_license_metadata,
)
from engines.static_scanner import Dependency


def test_license_from_pypi_prefers_expression_then_classifier():
    assert _license_from_pypi_info({"license_expression": "MIT"}) == "MIT"
    assert (
        _license_from_pypi_info(
            {
                "classifiers": [
                    "Programming Language :: Python :: 3",
                    "License :: OSI Approved :: GNU Affero General Public License v3",
                ]
            }
        )
        == "AGPL-3.0-only"
    )


def test_license_from_huggingface_model_metadata_and_tags():
    assert (
        _license_from_huggingface_model({"cardData": {"license": "apache-2.0"}})
        == "apache-2.0"
    )
    assert _license_from_huggingface_model({"tags": ["license:gpl-3.0"]}) == "gpl-3.0"


async def test_enrich_license_metadata_writes_dependency_and_model_cache(
    monkeypatch,
    tmp_path,
):
    dependency = Dependency("Example-Package", "1.2.3", tmp_path / "requirements.txt", 1)

    async def fake_deps_dev_entry(_session, _semaphore, dependency):
        return {
            "license_id": "GPL-3.0-only",
            "raw_license": "GPL-3.0-only",
            "source": "deps.dev",
            "source_url": "https://api.deps.dev/example",
        }

    async def fake_huggingface_entry(_session, _semaphore, model_name):
        return {
            "license_id": "AGPL-3.0-only",
            "raw_license": "AGPL-3.0-only",
            "source": "huggingface",
            "source_url": f"https://huggingface.co/{model_name}",
        }

    monkeypatch.setattr(
        license_enrichment,
        "_deps_dev_license_entry",
        fake_deps_dev_entry,
    )
    monkeypatch.setattr(
        license_enrichment,
        "_huggingface_license_entry",
        fake_huggingface_entry,
    )

    errors = await enrich_license_metadata(
        project_root=tmp_path,
        dependencies=[dependency],
        model_names=["org/model", "llama3.1:8b"],
    )

    cache = json.loads(
        (tmp_path / ".aegislocal" / "license-metadata-cache.json").read_text(
            encoding="utf-8"
        )
    )
    assert errors == []
    assert cache["dependencies"]["pypi:example-package@1.2.3"]["raw_license"] == (
        "GPL-3.0-only"
    )
    assert cache["models"]["huggingface:org/model"]["raw_license"] == "AGPL-3.0-only"
    assert "ollama:llama3.1:8b" not in cache["models"]


async def test_enrich_license_metadata_resolves_unique_huggingface_basename(
    monkeypatch,
    tmp_path,
):
    async def fake_fetch_json_list(_session, _semaphore, _url):
        return [
            {"id": "nomic-ai/gpt4all-lora-epoch-3"},
            {"id": "nomic-ai/gpt4all-lora"},
        ]

    async def fake_huggingface_entry(_session, _semaphore, model_name):
        return {
            "license_id": "gpl-3.0",
            "raw_license": "gpl-3.0",
            "source": "huggingface",
            "source_url": f"https://huggingface.co/{model_name}",
        }

    monkeypatch.setattr(license_enrichment, "_fetch_json_list", fake_fetch_json_list)
    monkeypatch.setattr(
        license_enrichment,
        "_huggingface_license_entry",
        fake_huggingface_entry,
    )

    errors = await enrich_license_metadata(
        project_root=tmp_path,
        dependencies=[],
        model_names=["gpt4all-lora"],
    )

    cache = json.loads(
        (tmp_path / ".aegislocal" / "license-metadata-cache.json").read_text(
            encoding="utf-8"
        )
    )
    assert errors == []
    assert cache["models"]["ollama:gpt4all-lora"]["raw_license"] == "gpl-3.0"
    assert cache["models"]["ollama:gpt4all-lora"]["resolved_model"] == (
        "nomic-ai/gpt4all-lora"
    )
