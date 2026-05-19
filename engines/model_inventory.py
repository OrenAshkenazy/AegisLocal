# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

import os
from pathlib import Path
from typing import List, Optional

from engines.static_scanner import EXCLUDED_DIR_NAMES


ENV_MODEL_KEY_MARKER = "MODEL"
IGNORED_ENV_SUFFIXES = (".example", ".sample", ".template")


def discover_project_model_names(project_root: Path) -> List[str]:
    models: List[str] = []
    for env_file in _discover_env_files(project_root):
        models.extend(_parse_env_model_names(env_file))
    return list(dict.fromkeys(models))


def _discover_env_files(project_root: Path) -> List[Path]:
    root = project_root.resolve()
    if not root.exists():
        return []

    env_files: List[Path] = []
    for current_root_text, dirnames, filenames in os.walk(root):
        current_root = Path(current_root_text)
        dirnames[:] = [
            dirname
            for dirname in dirnames
            if dirname not in EXCLUDED_DIR_NAMES
        ]
        for filename in filenames:
            if _is_env_file(filename):
                env_files.append(current_root / filename)
    return sorted(env_files)


def _is_env_file(filename: str) -> bool:
    if any(filename.endswith(suffix) for suffix in IGNORED_ENV_SUFFIXES):
        return False
    return filename == ".env" or filename.startswith(".env.")


def _parse_env_model_names(path: Path) -> List[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []

    models: List[str] = []
    for raw_line in lines:
        parsed = _parse_env_assignment(raw_line)
        if parsed is None:
            continue
        key, value = parsed
        if _is_model_env_key(key) and _looks_like_model_name(value):
            models.append(value)
    return models


def _parse_env_assignment(raw_line: str) -> Optional[tuple[str, str]]:
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith("export "):
        line = line[len("export ") :].strip()
    if "=" not in line:
        return None
    key, value = line.split("=", 1)
    key = key.strip()
    value = value.split("#", 1)[0].strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1].strip()
    if not key or not value:
        return None
    return key, value


def _is_model_env_key(key: str) -> bool:
    normalized = key.upper()
    return ENV_MODEL_KEY_MARKER in normalized and not normalized.endswith("_API_KEY")


def _looks_like_model_name(value: str) -> bool:
    if value.startswith(("${", "$")):
        return False
    if value.lower() in {"true", "false", "none", "null"}:
        return False
    if value.replace(".", "", 1).isdigit():
        return False
    return not any(char.isspace() for char in value)


__all__ = ["discover_project_model_names"]
