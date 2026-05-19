# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

from main import DEFAULT_ENDPOINT, DEFAULT_MODEL, run_scan
from core.console import ScanConsole
from engines.dynamic_fuzzer import DYNAMIC_CONCURRENCY, TARGET_TIMEOUT_SECONDS


async def test_license_scan_mode_generates_missing_boms(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests==2.20.0", encoding="utf-8")

    report = await run_scan(
        project_root=tmp_path,
        payload_file=tmp_path / "missing-payloads.json",
        target_endpoint=DEFAULT_ENDPOINT,
        target_model=DEFAULT_MODEL,
        target_timeout_seconds=TARGET_TIMEOUT_SECONDS,
        dynamic_concurrency=DYNAMIC_CONCURRENCY,
        judge_endpoint=DEFAULT_ENDPOINT,
        judge_model=DEFAULT_MODEL,
        fallback_judge_endpoint=None,
        fallback_judge_model=None,
        include_evidence=False,
        run_static=False,
        run_dynamic=False,
        license_scan=True,
        license_enrich=False,
        generate_bom=True,
        sbom_file=None,
        aibom_file=None,
        license_cache_file=None,
        console=ScanConsole(quiet=True),
    )

    assert (tmp_path / "bom.sbom.cdx.json").exists()
    assert (tmp_path / "bom.aibom.cdx.json").exists()
    assert report.security_result == "PASS"
    assert report.scan_type == "licenses"
    assert report.target_endpoint is None
    assert report.target_model is None
    assert report.judge_endpoint is None
    assert report.judge_model is None
    assert report.static_findings is None
    assert report.dynamic_findings is None
    assert report.dynamic_evidence is None
    assert report.license_findings == []
    assert report.license_coverage is not None
    assert report.license_coverage.dependencies_total == 1
    assert report.license_coverage.dependencies_missing_license_metadata == 1
    assert report.license_coverage.models_total == 0
    assert report.license_coverage.models_missing_license_metadata == 0
    assert report.execution_errors == []


async def test_license_scan_mode_uses_project_env_models_for_aibom(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests==2.20.0", encoding="utf-8")
    backend = tmp_path / "backend"
    backend.mkdir()
    (backend / ".env").write_text(
        "\n".join(
            [
                "AI_MAIN_MODEL=groq/qwen/qwen3-32b",
                "AI_INSIGHT_MODEL=gemini/gemini-2.5-flash",
                "AI_GUARD_MODEL=anthropic/claude-haiku-4-5-20251001",
            ]
        ),
        encoding="utf-8",
    )

    report = await run_scan(
        project_root=tmp_path,
        payload_file=tmp_path / "missing-payloads.json",
        target_endpoint=DEFAULT_ENDPOINT,
        target_model=DEFAULT_MODEL,
        target_timeout_seconds=TARGET_TIMEOUT_SECONDS,
        dynamic_concurrency=DYNAMIC_CONCURRENCY,
        judge_endpoint=DEFAULT_ENDPOINT,
        judge_model=DEFAULT_MODEL,
        fallback_judge_endpoint=None,
        fallback_judge_model=None,
        include_evidence=False,
        run_static=False,
        run_dynamic=False,
        license_scan=True,
        license_enrich=False,
        generate_bom=True,
        sbom_file=None,
        aibom_file=None,
        license_cache_file=None,
        console=ScanConsole(quiet=True),
    )

    aibom_text = (tmp_path / "bom.aibom.cdx.json").read_text(encoding="utf-8")
    assert "model:ollama/gpt4all-lora" not in aibom_text
    assert "model:huggingface/groq/qwen/qwen3-32b" in aibom_text
    assert "model:huggingface/gemini/gemini-2.5-flash" in aibom_text
    assert "model:huggingface/anthropic/claude-haiku-4-5-20251001" in aibom_text
    assert report.license_coverage is not None
    assert report.license_coverage.models_total == 3


async def test_license_scan_mode_regenerates_default_boms(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests==2.20.0", encoding="utf-8")
    (tmp_path / "bom.sbom.cdx.json").write_text("stale sbom", encoding="utf-8")
    (tmp_path / "bom.aibom.cdx.json").write_text("stale aibom", encoding="utf-8")

    await run_scan(
        project_root=tmp_path,
        payload_file=tmp_path / "missing-payloads.json",
        target_endpoint=DEFAULT_ENDPOINT,
        target_model=DEFAULT_MODEL,
        target_timeout_seconds=TARGET_TIMEOUT_SECONDS,
        dynamic_concurrency=DYNAMIC_CONCURRENCY,
        judge_endpoint=DEFAULT_ENDPOINT,
        judge_model=DEFAULT_MODEL,
        fallback_judge_endpoint=None,
        fallback_judge_model=None,
        include_evidence=False,
        run_static=False,
        run_dynamic=False,
        license_scan=True,
        license_enrich=False,
        generate_bom=True,
        sbom_file=None,
        aibom_file=None,
        license_cache_file=None,
        console=ScanConsole(quiet=True),
    )

    assert "stale" not in (tmp_path / "bom.sbom.cdx.json").read_text(encoding="utf-8")
    assert "stale" not in (tmp_path / "bom.aibom.cdx.json").read_text(encoding="utf-8")


async def test_license_scan_mode_does_not_overwrite_explicit_boms(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests==2.20.0", encoding="utf-8")
    explicit_sbom = tmp_path / "custom.sbom.json"
    explicit_aibom = tmp_path / "custom.aibom.json"
    explicit_sbom.write_text("not json", encoding="utf-8")
    explicit_aibom.write_text("not json", encoding="utf-8")

    await run_scan(
        project_root=tmp_path,
        payload_file=tmp_path / "missing-payloads.json",
        target_endpoint=DEFAULT_ENDPOINT,
        target_model=DEFAULT_MODEL,
        target_timeout_seconds=TARGET_TIMEOUT_SECONDS,
        dynamic_concurrency=DYNAMIC_CONCURRENCY,
        judge_endpoint=DEFAULT_ENDPOINT,
        judge_model=DEFAULT_MODEL,
        fallback_judge_endpoint=None,
        fallback_judge_model=None,
        include_evidence=False,
        run_static=False,
        run_dynamic=False,
        license_scan=True,
        license_enrich=False,
        generate_bom=True,
        sbom_file=explicit_sbom,
        aibom_file=explicit_aibom,
        license_cache_file=None,
        console=ScanConsole(quiet=True),
    )

    assert explicit_sbom.read_text(encoding="utf-8") == "not json"
    assert explicit_aibom.read_text(encoding="utf-8") == "not json"
