from pathlib import Path

from engines.static_scanner import discover_requirement_files, parse_requirement_file


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

    assert discover_requirement_files(tmp_path) == [included]
