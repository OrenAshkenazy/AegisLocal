# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

import asyncio
import json
from pathlib import Path
from typing import Optional, Sequence
from urllib.parse import quote

import aiohttp

from core.models import ErrorSource, ExecutionError
from engines.license_policy import _dependency_key, _model_key
from engines.static_scanner import Dependency


DEPS_DEV_VERSION_URL = "https://api.deps.dev/v3/systems/PYPI/packages/{name}/versions/{version}"
PYPI_RELEASE_URL = "https://pypi.org/pypi/{name}/{version}/json"
HF_MODEL_URL = "https://huggingface.co/api/models/{model_name}"
HF_MODEL_SEARCH_URL = "https://huggingface.co/api/models?search={model_name}&limit=10"
LICENSE_ENRICH_TIMEOUT_SECONDS = 10
LICENSE_ENRICH_CONCURRENCY = 8

PYPI_CLASSIFIER_LICENSES = {
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: BSD License": "BSD-3-Clause",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: GNU Affero General Public License v3": "AGPL-3.0-only",
    "License :: OSI Approved :: GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
    "License :: OSI Approved :: GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)": "LGPL-2.0-only",
    "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0-only",
}


async def enrich_license_metadata(
    *,
    project_root: Path,
    dependencies: Sequence[Dependency],
    model_names: Sequence[str],
    license_cache_path: Optional[Path] = None,
) -> list[ExecutionError]:
    cache_path = _resolve_cache_path(project_root, license_cache_path)
    cache, errors = _read_cache(cache_path)
    if errors:
        return errors

    dependency_entries = cache.setdefault("dependencies", {})
    model_entries = cache.setdefault("models", {})
    if not isinstance(dependency_entries, dict) or not isinstance(model_entries, dict):
        return [
            ExecutionError(
                source=ErrorSource.STATIC,
                message="License metadata cache must contain object-valued dependencies and models",
                path=str(cache_path),
            )
        ]

    missing_dependencies = [
        dependency
        for dependency in dependencies
        if not _has_license_entry(
            dependency_entries.get(_dependency_key(dependency.name, dependency.version))
        )
    ]
    missing_models = [
        model_name
        for model_name in dict.fromkeys(model for model in model_names if model)
        if not _has_license_entry(model_entries.get(_model_key(model_name)))
    ]

    if not missing_dependencies and not missing_models:
        return []

    timeout = aiohttp.ClientTimeout(total=LICENSE_ENRICH_TIMEOUT_SECONDS)
    semaphore = asyncio.Semaphore(LICENSE_ENRICH_CONCURRENCY)
    changed = False
    async with aiohttp.ClientSession(timeout=timeout) as session:
        for dependency, entry in await _enrich_dependencies(
            session,
            semaphore,
            missing_dependencies,
        ):
            if entry is None:
                continue
            dependency_entries[_dependency_key(dependency.name, dependency.version)] = entry
            changed = True

        for model_name, entry in await _enrich_models(session, semaphore, missing_models):
            if entry is None:
                continue
            model_entries[_model_key(model_name)] = entry
            changed = True

    if changed:
        return _write_cache(cache_path, cache)
    return []


async def _enrich_dependencies(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    dependencies: Sequence[Dependency],
) -> list[tuple[Dependency, Optional[dict]]]:
    tasks = [
        _enrich_dependency(session, semaphore, dependency)
        for dependency in dependencies
    ]
    return await asyncio.gather(*tasks) if tasks else []


async def _enrich_dependency(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    dependency: Dependency,
) -> tuple[Dependency, Optional[dict]]:
    entry = await _deps_dev_license_entry(session, semaphore, dependency)
    if entry is not None:
        return dependency, entry
    entry = await _pypi_license_entry(session, semaphore, dependency)
    return dependency, entry


async def _enrich_models(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    model_names: Sequence[str],
) -> list[tuple[str, Optional[dict]]]:
    tasks = [_enrich_model(session, semaphore, model_name) for model_name in model_names]
    return await asyncio.gather(*tasks) if tasks else []


async def _enrich_model(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    model_name: str,
) -> tuple[str, Optional[dict]]:
    resolved_model_name = model_name
    if "/" not in model_name:
        if ":" in model_name:
            return model_name, None
        resolved_model_name = await _resolve_huggingface_model_name(
            session,
            semaphore,
            model_name,
        )
        if resolved_model_name is None:
            return model_name, None
    entry = await _huggingface_license_entry(session, semaphore, resolved_model_name)
    if entry is not None and resolved_model_name != model_name:
        entry["resolved_model"] = resolved_model_name
    return model_name, entry


async def _resolve_huggingface_model_name(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    model_name: str,
) -> Optional[str]:
    url = HF_MODEL_SEARCH_URL.format(model_name=quote(model_name, safe=""))
    data = await _fetch_json_list(session, semaphore, url)
    if data is None:
        return None
    exact_matches = []
    for item in data:
        if not isinstance(item, dict):
            continue
        repo_id = str(item.get("id") or "").strip()
        if repo_id.rsplit("/", 1)[-1] == model_name:
            exact_matches.append(repo_id)
    unique_matches = list(dict.fromkeys(exact_matches))
    return unique_matches[0] if len(unique_matches) == 1 else None


async def _deps_dev_license_entry(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    dependency: Dependency,
) -> Optional[dict]:
    url = DEPS_DEV_VERSION_URL.format(
        name=quote(dependency.name.lower(), safe=""),
        version=quote(dependency.version, safe=""),
    )
    data = await _fetch_json(session, semaphore, url)
    if data is None:
        return None
    licenses = [
        str(license_id).strip()
        for license_id in data.get("licenses") or []
        if str(license_id).strip()
    ]
    if not licenses:
        return None
    raw_license = " OR ".join(dict.fromkeys(licenses))
    return {
        "license_id": raw_license,
        "raw_license": raw_license,
        "source": "deps.dev",
        "source_url": url,
    }


async def _pypi_license_entry(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    dependency: Dependency,
) -> Optional[dict]:
    url = PYPI_RELEASE_URL.format(
        name=quote(dependency.name, safe=""),
        version=quote(dependency.version, safe=""),
    )
    data = await _fetch_json(session, semaphore, url)
    if data is None:
        return None
    raw_license = _license_from_pypi_info(data.get("info") or {})
    if raw_license is None:
        return None
    return {
        "license_id": raw_license,
        "raw_license": raw_license,
        "source": "pypi",
        "source_url": url,
    }


async def _huggingface_license_entry(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    model_name: str,
) -> Optional[dict]:
    url = HF_MODEL_URL.format(model_name=quote(model_name, safe="/"))
    data = await _fetch_json(session, semaphore, url)
    if data is None:
        return None
    raw_license = _license_from_huggingface_model(data)
    if raw_license is None:
        return None
    entry = {
        "license_id": raw_license,
        "raw_license": raw_license,
        "source": "huggingface",
        "source_url": f"https://huggingface.co/{model_name}",
    }
    card_data = data.get("cardData") or {}
    if isinstance(card_data, dict) and card_data.get("license_link"):
        entry["license_url"] = str(card_data["license_link"])
    return entry


async def _fetch_json(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    url: str,
) -> Optional[dict]:
    async with semaphore:
        try:
            async with session.get(url) as response:
                if response.status >= 400:
                    return None
                data = await response.json()
        except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError):
            return None
    return data if isinstance(data, dict) else None


async def _fetch_json_list(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    url: str,
) -> Optional[list]:
    async with semaphore:
        try:
            async with session.get(url) as response:
                if response.status >= 400:
                    return None
                data = await response.json()
        except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError):
            return None
    return data if isinstance(data, list) else None


def _license_from_pypi_info(info: dict) -> Optional[str]:
    license_expression = str(info.get("license_expression") or "").strip()
    if license_expression:
        return license_expression

    classifiers = info.get("classifiers") or []
    classifier_licenses = [
        PYPI_CLASSIFIER_LICENSES[classifier]
        for classifier in classifiers
        if classifier in PYPI_CLASSIFIER_LICENSES
    ]
    if classifier_licenses:
        return " OR ".join(dict.fromkeys(classifier_licenses))

    raw_license = str(info.get("license") or "").strip()
    if not raw_license or raw_license.upper() in {"UNKNOWN", "UNKNOWN LICENSE"}:
        return None
    return raw_license


def _license_from_huggingface_model(model_info: dict) -> Optional[str]:
    card_data = model_info.get("cardData") or {}
    if isinstance(card_data, dict):
        license_id = str(card_data.get("license") or "").strip()
        if license_id:
            return license_id
        license_name = str(card_data.get("license_name") or "").strip()
        if license_name:
            return license_name

    for tag in model_info.get("tags") or []:
        if not isinstance(tag, str):
            continue
        if tag.startswith("license:"):
            license_id = tag.split(":", 1)[1].strip()
            if license_id:
                return license_id
    return None


def _resolve_cache_path(project_root: Path, path: Optional[Path]) -> Path:
    if path is not None:
        return path
    return project_root / ".aegislocal" / "license-metadata-cache.json"


def _has_license_entry(entry: object) -> bool:
    return (
        isinstance(entry, dict)
        and bool(str(entry.get("raw_license") or entry.get("license_id") or "").strip())
    )


def _read_cache(path: Path) -> tuple[dict, list[ExecutionError]]:
    if not path.exists():
        return {"dependencies": {}, "models": {}}, []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        return {}, [
            ExecutionError(
                source=ErrorSource.STATIC,
                message="Unable to read license metadata cache",
                path=str(path),
                detail=str(exc),
            )
        ]
    except json.JSONDecodeError as exc:
        return {}, [
            ExecutionError(
                source=ErrorSource.STATIC,
                message="Unable to parse license metadata cache JSON",
                path=str(path),
                detail=str(exc),
            )
        ]
    if not isinstance(data, dict):
        return {}, [
            ExecutionError(
                source=ErrorSource.STATIC,
                message="License metadata cache must be a JSON object",
                path=str(path),
            )
        ]
    data.setdefault("dependencies", {})
    data.setdefault("models", {})
    return data, []


def _write_cache(path: Path, data: dict) -> list[ExecutionError]:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError as exc:
        return [
            ExecutionError(
                source=ErrorSource.STATIC,
                message="Unable to write license metadata cache",
                path=str(path),
                detail=str(exc),
            )
        ]
    return []


__all__ = ["enrich_license_metadata"]
