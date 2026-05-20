# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

import json

from core.models import FindingAction, Severity
from engines.license_policy import evaluate_license, run_license_policy_review
from engines.static_scanner import Dependency


def test_gpl_family_expression_rules():
    assert evaluate_license("GPL-3.0-only OR MIT") is None

    and_decision = evaluate_license("GPL-3.0-only AND MIT")
    assert and_decision is not None
    assert and_decision.should_warn is True
    assert and_decision.license_id == "GPL-3.0-ONLY"

    exception_decision = evaluate_license(
        "LGPL-2.1-or-later WITH Classpath-exception-2.0"
    )
    assert exception_decision is not None
    assert exception_decision.should_warn is True
    assert exception_decision.softer_warning is True
    assert exception_decision.exception == "CLASSPATH-EXCEPTION-2.0"

    assert evaluate_license("GPL-ish custom terms") is None


def test_license_policy_uses_sbom_over_conflicting_cache(tmp_path):
    source = tmp_path / "uv.lock"
    dependency = Dependency("example-package", "1.2.3", source, 1)
    sbom = tmp_path / "bom.sbom.cdx.json"
    sbom.write_text(
        json.dumps(
            {
                "components": [
                    {
                        "type": "library",
                        "name": "example-package",
                        "version": "1.2.3",
                        "licenses": [{"license": {"id": "MIT"}}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    cache = tmp_path / "license-metadata-cache.json"
    cache.write_text(
        json.dumps(
            {
                "dependencies": {
                    "pypi:example-package@1.2.3": {
                        "license_id": "GPL-3.0-only",
                        "raw_license": "GPL-3.0-only",
                        "source": "user",
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    findings, coverage, errors = run_license_policy_review(
        project_root=tmp_path,
        dependencies=[dependency],
        model_names=[],
        sbom_path=sbom,
        license_cache_path=cache,
    )

    assert findings == []
    assert errors == []
    assert coverage.dependencies_total == 1
    assert coverage.dependencies_with_license_metadata == 1
    assert coverage.dependencies_missing_license_metadata == 0


def test_same_priority_metadata_conflict_is_non_blocking(tmp_path):
    dependency = Dependency("example-package", "1.2.3", tmp_path / "uv.lock", 1)
    sbom = tmp_path / "bom.sbom.cdx.json"
    sbom.write_text(
        json.dumps(
            {
                "components": [
                    {
                        "type": "library",
                        "name": "example-package",
                        "version": "1.2.3",
                        "licenses": [{"license": {"id": "MIT"}}],
                    },
                    {
                        "type": "library",
                        "name": "example-package",
                        "version": "1.2.3",
                        "licenses": [{"license": {"id": "GPL-3.0-only"}}],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    findings, coverage, errors = run_license_policy_review(
        project_root=tmp_path,
        dependencies=[dependency],
        model_names=[],
        sbom_path=sbom,
    )

    assert errors == []
    assert len(findings) == 1
    assert findings[0].category == "License Metadata Conflict"
    assert findings[0].severity == Severity.INFO
    assert findings[0].action == FindingAction.WARN
    assert coverage.dependencies_total == 1
    assert coverage.dependencies_with_license_metadata == 0
    assert coverage.dependencies_missing_license_metadata == 1


def test_cache_license_metadata_creates_warning_and_coverage(tmp_path):
    dependency = Dependency("example-package", "1.2.3", tmp_path / "uv.lock", 1)
    cache = tmp_path / "license-metadata-cache.json"
    cache.write_text(
        json.dumps(
            {
                "dependencies": {
                    "pypi:example-package@1.2.3": {
                        "license_id": "AGPL-3.0-only",
                        "raw_license": "AGPL-3.0-only",
                        "source": "user",
                        "source_url": "https://example.test/source",
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    findings, coverage, errors = run_license_policy_review(
        project_root=tmp_path,
        dependencies=[dependency],
        model_names=[],
        license_cache_path=cache,
    )

    assert errors == []
    assert len(findings) == 1
    assert findings[0].category == "License Policy Review"
    assert findings[0].action == FindingAction.WARN
    assert findings[0].license_source == "cache:user | https://example.test/source"
    assert coverage.dependencies_total == 1
    assert coverage.dependencies_with_license_metadata == 1


def test_cache_only_entries_do_not_expand_review_scope(tmp_path):
    cache = tmp_path / "license-metadata-cache.json"
    cache.write_text(
        json.dumps(
            {
                "dependencies": {
                    "pypi:stale-package@9.9.9": {
                        "license_id": "GPL-3.0-only",
                        "raw_license": "GPL-3.0-only",
                        "source": "user",
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    findings, coverage, errors = run_license_policy_review(
        project_root=tmp_path,
        dependencies=[],
        model_names=[],
        license_cache_path=cache,
    )

    assert findings == []
    assert errors == []
    assert coverage.dependencies_total == 0
    assert coverage.dependencies_with_license_metadata == 0


def test_aibom_model_license_metadata_creates_model_warning(tmp_path):
    aibom = tmp_path / "bom.aibom.cdx.json"
    aibom.write_text(
        json.dumps(
            {
                "components": [
                    {
                        "type": "machine-learning-model",
                        "name": "org/model",
                        "licenses": [{"license": {"id": "LGPL-2.1-or-later"}}],
                        "properties": [
                            {
                                "name": "aegislocal:model-source",
                                "value": "huggingface",
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings, coverage, errors = run_license_policy_review(
        project_root=tmp_path,
        dependencies=[],
        model_names=["org/model"],
        aibom_path=aibom,
    )

    assert errors == []
    assert len(findings) == 1
    assert findings[0].category == "Model License Policy Review"
    assert findings[0].subject_name == "org/model"
    assert coverage.models_total == 1
    assert coverage.models_with_license_metadata == 1
