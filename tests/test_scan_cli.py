# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

import json

from typer.testing import CliRunner

from main import app


runner = CliRunner()


def test_scan_static_only_skips_payload_loading_and_dynamic_scan(tmp_path):
    result = runner.invoke(
        app,
        [
            "scan",
            "--project-root",
            str(tmp_path),
            "--payload-file",
            str(tmp_path / "missing-payloads.json"),
            "--static-only",
            "--quiet",
        ],
    )

    report = json.loads(result.output)

    assert result.exit_code == 0
    assert report["static_findings"] == []
    assert report["dynamic_findings"] == []
    assert report["dynamic_evidence"] == []
    assert report["execution_errors"] == []
    assert report["passed_audit"] is True
