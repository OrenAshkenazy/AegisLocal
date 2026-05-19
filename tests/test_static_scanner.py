# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

import asyncio

from core.models import Finding, Severity
from engines.static_scanner import (
    Dependency,
    discover_manifest_files,
    discover_requirement_files,
    parse_manifest_files,
    parse_poetry_lock_file,
    parse_pyproject_file,
    parse_requirement_file,
    parse_uv_lock_file,
)
import engines.static_scanner as static_scanner


def test_parse_pinned_requirements_and_report_unsupported_lines(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        "\n".join(
            [
                "requests==2.20.0",
                "flask[async]==2.2.5 # inline comment",
                "urllib3>=2",
                "-r requirements-dev.txt",
            ]
        ),
        encoding="utf-8",
    )

    dependencies, errors = parse_requirement_file(requirements)

    assert [(dependency.name, dependency.version) for dependency in dependencies] == [
        ("requests", "2.20.0"),
        ("flask", "2.2.5"),
    ]
    assert len(errors) == 2
    assert "Unsupported requirement line" in errors[0].message


def test_discovery_excludes_tests_fixtures_and_virtualenv_dirs(tmp_path):
    included = tmp_path / "service" / "requirements.txt"
    included.parent.mkdir()
    included.write_text("requests==2.20.0", encoding="utf-8")

    fixture = tmp_path / "tests" / "fixtures" / "requirements.txt"
    fixture.parent.mkdir(parents=True)
    fixture.write_text("vulnerable==1.0.0", encoding="utf-8")

    venv = tmp_path / ".venv" / "requirements.txt"
    venv.parent.mkdir()
    venv.write_text("ignored==1.0.0", encoding="utf-8")

    claude_worktree = tmp_path / ".claude" / "worktrees" / "copy" / "requirements.txt"
    claude_worktree.parent.mkdir(parents=True)
    claude_worktree.write_text("ignored==1.0.0", encoding="utf-8")

    codex_worktree = tmp_path / ".codex" / "worktrees" / "copy" / "requirements.txt"
    codex_worktree.parent.mkdir(parents=True)
    codex_worktree.write_text("ignored==1.0.0", encoding="utf-8")

    assert discover_requirement_files(tmp_path) == [included]


def test_discovery_includes_supported_manifest_types(tmp_path):
    paths = [
        tmp_path / "requirements.txt",
        tmp_path / "requirements-dev.txt",
        tmp_path / "requirements.prod.txt",
        tmp_path / "pyproject.toml",
        tmp_path / "uv.lock",
        tmp_path / "poetry.lock",
    ]
    for path in paths:
        path.write_text("", encoding="utf-8")

    assert discover_manifest_files(tmp_path) == sorted(paths)


def test_parse_pyproject_pep621_exact_dependencies(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
dependencies = [
  "requests==2.20.0",
  "urllib3>=2",
]

[project.optional-dependencies]
test = [
  "pytest==8.0.0",
]
""",
        encoding="utf-8",
    )

    dependencies, errors = parse_pyproject_file(pyproject)

    assert [(dependency.name, dependency.version) for dependency in dependencies] == [
        ("requests", "2.20.0"),
        ("pytest", "8.0.0"),
    ]
    assert len(errors) == 1
    assert "Unsupported dependency spec" in errors[0].message


def test_parse_pyproject_poetry_exact_dependencies(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[tool.poetry.dependencies]
python = "^3.10"
requests = "==2.20.0"
urllib3 = "^2.0"

[tool.poetry.group.dev.dependencies]
pytest = { version = "==8.0.0" }
""",
        encoding="utf-8",
    )

    dependencies, errors = parse_pyproject_file(pyproject)

    assert [(dependency.name, dependency.version) for dependency in dependencies] == [
        ("requests", "2.20.0"),
        ("pytest", "8.0.0"),
    ]
    assert len(errors) == 1
    assert "Unsupported Poetry dependency spec" in errors[0].message


def test_parse_uv_and_poetry_lock_files(tmp_path):
    uv_lock = tmp_path / "uv.lock"
    uv_lock.write_text(
        """
[[package]]
name = "requests"
version = "2.20.0"

[[package]]
name = "pytest"
version = "8.0.0"
""",
        encoding="utf-8",
    )

    poetry_lock = tmp_path / "poetry.lock"
    poetry_lock.write_text(
        """
[[package]]
name = "urllib3"
version = "1.25.0"
""",
        encoding="utf-8",
    )

    uv_dependencies, uv_errors = parse_uv_lock_file(uv_lock)
    poetry_dependencies, poetry_errors = parse_poetry_lock_file(poetry_lock)

    assert [(dependency.name, dependency.version) for dependency in uv_dependencies] == [
        ("requests", "2.20.0"),
        ("pytest", "8.0.0"),
    ]
    assert uv_errors == []
    assert [(dependency.name, dependency.version) for dependency in poetry_dependencies] == [
        ("urllib3", "1.25.0"),
    ]
    assert poetry_errors == []


def test_parse_manifest_files_dedupes_dependencies(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests==2.20.0", encoding="utf-8")
    uv_lock = tmp_path / "uv.lock"
    uv_lock.write_text(
        """
[[package]]
name = "requests"
version = "2.20.0"
""",
        encoding="utf-8",
    )

    dependencies, errors = parse_manifest_files([requirements, uv_lock, uv_lock])

    assert [(dependency.name, dependency.version, dependency.source_file.name) for dependency in dependencies] == [
        ("requests", "2.20.0", "requirements.txt"),
    ]
    assert errors == []


def test_parse_manifest_files_prefers_lockfile_over_pyproject_ranges(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
dependencies = ["requests>=2"]
""",
        encoding="utf-8",
    )
    uv_lock = tmp_path / "uv.lock"
    uv_lock.write_text(
        """
[[package]]
name = "requests"
version = "2.20.0"
""",
        encoding="utf-8",
    )

    dependencies, errors = parse_manifest_files([pyproject, uv_lock])

    assert [(dependency.name, dependency.version, dependency.source_file.name) for dependency in dependencies] == [
        ("requests", "2.20.0", "uv.lock"),
    ]
    assert errors == []


def test_select_fixed_version_from_osv_affected_ranges():
    vuln = {
        "affected": [
            {
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "2.32.4"},
                        ]
                    }
                ]
            }
        ]
    }

    assert static_scanner._select_fixed_version(vuln, "requests", "2.20.0") == "2.32.4"


def test_select_fixed_version_returns_none_when_osv_has_no_fix():
    vuln = {
        "affected": [
            {
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "events": [
                            {"introduced": "0"},
                        ]
                    }
                ]
            }
        ]
    }

    assert static_scanner._select_fixed_version(vuln, "requests", "2.20.0") is None


def test_select_fixed_version_ignores_unrelated_packages_and_downgrades():
    vuln = {
        "affected": [
            {
                "package": {"name": "other-package", "ecosystem": "PyPI"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}],
            },
            {
                "package": {"name": "requests", "ecosystem": "npm"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "8.8.8"}]}],
            },
            {
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "2.10.0"},
                            {"fixed": "2.32.4"},
                        ]
                    }
                ],
            },
        ]
    }

    assert static_scanner._select_fixed_version(vuln, "requests", "2.20.0") == "2.32.4"


def test_select_severity_prefers_database_specific_severity():
    vuln = {
        "database_specific": {"severity": "CRITICAL"},
        "severity": [{"type": "CVSS_V3", "score": "7.1"}],
    }

    assert static_scanner._select_severity(vuln) == Severity.CRITICAL


def test_select_severity_from_cvss_vector():
    vuln = {
        "severity": [
            {
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            }
        ]
    }

    assert static_scanner._select_severity(vuln) == Severity.CRITICAL


def test_select_severity_defaults_high_when_osv_has_no_supported_score():
    assert static_scanner._select_severity({}) == Severity.HIGH


def test_static_scan_dedupes_findings_across_sources_preferring_manifest(monkeypatch, tmp_path):
    requirements = tmp_path / "requirements.txt"
    uv_lock = tmp_path / "uv.lock"
    dependencies = [
        Dependency("requests", "2.20.0", uv_lock, 1),
        Dependency("requests", "2.20.0", requirements, 1),
    ]

    async def fake_query_osv(_session, dependency, _semaphore):
        return [
            Finding(
                severity=Severity.HIGH,
                category="Dependency Vulnerability",
                description="requests==2.20.0 is affected by CVE-2099-0001.",
                package_name=dependency.name,
                package_version=dependency.version,
                vulnerability_id="CVE-2099-0001",
                source_file=str(dependency.source_file),
            )
        ], []

    monkeypatch.setattr(static_scanner, "_query_osv", fake_query_osv)

    findings, errors = asyncio.run(
        static_scanner.run_static_scan(tmp_path, dependencies=dependencies)
    )

    assert errors == []
    assert len(findings) == 1
    assert findings[0].source_file == str(requirements)


def test_static_scan_groups_same_package_fix_vulnerabilities(monkeypatch, tmp_path):
    requirements = tmp_path / "requirements.txt"
    dependencies = [Dependency("aiohttp", "3.13.3", requirements, 1)]

    async def fake_query_osv(_session, dependency, _semaphore):
        return [
            Finding(
                severity=Severity.LOW,
                category="Dependency Vulnerability",
                description=f"{dependency.name}=={dependency.version} is affected by CVE-2099-0001.",
                remediation=f"Upgrade {dependency.name} from {dependency.version} to 3.13.4+.",
                fix_available=True,
                fixed_version="3.13.4",
                package_name=dependency.name,
                package_version=dependency.version,
                vulnerability_id="CVE-2099-0001",
                source_file=str(dependency.source_file),
            ),
            Finding(
                severity=Severity.HIGH,
                category="Dependency Vulnerability",
                description=f"{dependency.name}=={dependency.version} is affected by CVE-2099-0002.",
                remediation=f"Upgrade {dependency.name} from {dependency.version} to 3.13.4+.",
                fix_available=True,
                fixed_version="3.13.4",
                package_name=dependency.name,
                package_version=dependency.version,
                vulnerability_id="CVE-2099-0002",
                source_file=str(dependency.source_file),
            ),
        ], []

    monkeypatch.setattr(static_scanner, "_query_osv", fake_query_osv)

    findings, errors = asyncio.run(
        static_scanner.run_static_scan(tmp_path, dependencies=dependencies)
    )

    assert errors == []
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].vulnerability_id == "CVE-2099-0001"
    assert findings[0].vulnerability_ids == ["CVE-2099-0001", "CVE-2099-0002"]
    assert findings[0].description == (
        "aiohttp==3.13.3 is affected by 2 vulnerabilities: "
        "CVE-2099-0001, CVE-2099-0002."
    )
