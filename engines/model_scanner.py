# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

from core.models import ErrorSource, ExecutionError, Finding, Severity


MODEL_MANIFEST_NAME = "aegislocal.models.toml"
MODEL_SUPPLY_CHAIN_CATEGORY = "Model Supply Chain"

EXCLUDED_DIR_NAMES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    ".worktrees",
    "__pycache__",
    "build",
    "dist",
    "env",
    "node_modules",
    "tests",
    "venv",
}

TEXT_SCAN_SUFFIXES = {
    ".env",
    ".ini",
    ".json",
    ".py",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
TEXT_SCAN_NAMES = {".env", "Dockerfile", "Modelfile"}
MODEL_FILE_SUFFIXES = {".gguf", ".safetensors", ".bin", ".pt", ".pth", ".ckpt"}
UNSAFE_MODEL_FILE_SUFFIXES = {".bin", ".pt", ".pth", ".ckpt"}

HF_MODEL_RE = re.compile(
    r"(?P<prefix>huggingface\.co/)?"
    r"(?P<name>[A-Za-z0-9][A-Za-z0-9_.-]+/[A-Za-z0-9][A-Za-z0-9_.:/-]+)"
    r"(?:@(?P<revision>[A-Za-z0-9_.-]{7,40}))?"
)
MODEL_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?:[a-z0-9]+_)*(?:target_)?(?:base_)?model(?:_id|_name)?\b\s*[:=]\s*[\"']?([^\"'\s,#]+)"
)
TRUST_REMOTE_CODE_RE = re.compile(r"(?i)\btrust_remote_code\b\s*[:=]\s*true\b")
FULL_SHA_RE = re.compile(r"^[a-fA-F0-9]{40}$")


@dataclass(frozen=True)
class ModelReference:
    name: str
    source: str
    source_file: Optional[Path]
    line_number: Optional[int]
    revision: Optional[str] = None
    artifact_type: str = "model"


@dataclass(frozen=True)
class ModelArtifact:
    name: str
    path: Path
    artifact_type: str
    format: str
    sha256: Optional[str] = None


@dataclass(frozen=True)
class ModelManifestEntry:
    name: str
    source: Optional[str] = None
    revision: Optional[str] = None
    sha256: Optional[str] = None
    license: Optional[str] = None
    approved: bool = False
    path: Optional[str] = None
    base_model: Optional[str] = None
    artifact_type: str = "model"


@dataclass(frozen=True)
class ModelManifest:
    path: Optional[Path]
    models: Tuple[ModelManifestEntry, ...]
    adapters: Tuple[ModelManifestEntry, ...]

    def approved_model(self, name: str) -> Optional[ModelManifestEntry]:
        normalized = _normalize_model_name(name)
        for entry in self.models:
            if entry.approved and _normalize_model_name(entry.name) == normalized:
                return entry
        return None

    def artifact_entry(self, artifact_path: Path, root: Path) -> Optional[ModelManifestEntry]:
        normalized_path = _normalize_manifest_path(artifact_path, root)
        entries = (*self.models, *self.adapters)
        for entry in entries:
            if entry.path and _normalize_configured_path(entry.path) == normalized_path:
                return entry
        return None


@dataclass(frozen=True)
class ModelInventory:
    manifest: ModelManifest
    manifest_errors: Tuple[ExecutionError, ...]
    references: Tuple[ModelReference, ...]
    artifacts: Tuple[ModelArtifact, ...]
    artifact_errors: Tuple[ExecutionError, ...] = ()


def _is_excluded_path(path: Path, root: Path) -> bool:
    try:
        relative_parts = path.relative_to(root).parts
    except ValueError:
        return False
    return any(part in EXCLUDED_DIR_NAMES for part in relative_parts)


def load_model_manifest(project_root: Path) -> Tuple[ModelManifest, List[ExecutionError]]:
    manifest_path = project_root / MODEL_MANIFEST_NAME
    if not manifest_path.exists():
        return ModelManifest(path=None, models=(), adapters=()), []

    try:
        with manifest_path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        error = ExecutionError(
            source=ErrorSource.STATIC,
            message="Unable to read model provenance manifest",
            path=str(manifest_path),
            detail=str(exc),
        )
        return ModelManifest(path=manifest_path, models=(), adapters=()), [error]

    return (
        ModelManifest(
            path=manifest_path,
            models=tuple(_parse_manifest_entries(data.get("models"), "model")),
            adapters=tuple(_parse_manifest_entries(data.get("adapters"), "adapter")),
        ),
        [],
    )


def _parse_manifest_entries(raw_entries: object, artifact_type: str) -> List[ModelManifestEntry]:
    if not isinstance(raw_entries, list):
        return []

    entries: List[ModelManifestEntry] = []
    for raw_entry in raw_entries:
        if not isinstance(raw_entry, dict):
            continue
        name = raw_entry.get("name")
        path = raw_entry.get("path")
        if not isinstance(name, str) and not isinstance(path, str):
            continue
        entries.append(
            ModelManifestEntry(
                name=name if isinstance(name, str) else path,
                source=_optional_string(raw_entry.get("source")),
                revision=_optional_string(raw_entry.get("revision")),
                sha256=_optional_string(raw_entry.get("sha256"))
                or _optional_string(raw_entry.get("expected_digest")),
                license=_optional_string(raw_entry.get("license")),
                approved=bool(raw_entry.get("approved")),
                path=path if isinstance(path, str) else None,
                base_model=_optional_string(raw_entry.get("base_model")),
                artifact_type=artifact_type,
            )
        )
    return entries


def discover_model_references(
    project_root: Path,
    *,
    target_model: Optional[str] = None,
    target_endpoint: Optional[str] = None,
) -> List[ModelReference]:
    root = project_root.resolve()
    references: List[ModelReference] = []
    if target_model:
        references.append(
            ModelReference(
                name=target_model,
                source=_infer_model_source(target_model, target_endpoint),
                source_file=None,
                line_number=None,
            )
        )

    text_paths, _ = _iter_model_scan_files(root)
    for path in text_paths:
        references.extend(_references_from_file(path))

    return _dedupe_model_references(references)


def discover_model_artifacts(
    project_root: Path,
    *,
    include_hashes: bool = False,
    errors: Optional[List[ExecutionError]] = None,
) -> List[ModelArtifact]:
    root = project_root.resolve()
    _, artifact_paths = _iter_model_scan_files(root)
    return _model_artifacts_from_paths(
        artifact_paths,
        include_hashes=include_hashes,
        errors=errors,
    )


def collect_model_inventory(
    project_root: Path,
    *,
    target_model: Optional[str] = None,
    target_endpoint: Optional[str] = None,
    include_hashes: bool = False,
) -> ModelInventory:
    root = project_root.resolve()
    manifest, errors = load_model_manifest(root)
    artifact_errors: List[ExecutionError] = []
    text_paths, artifact_paths = _iter_model_scan_files(root)
    references: List[ModelReference] = []
    if target_model:
        references.append(
            ModelReference(
                name=target_model,
                source=_infer_model_source(target_model, target_endpoint),
                source_file=None,
                line_number=None,
            )
        )
    for path in text_paths:
        references.extend(_references_from_file(path))
    artifacts = _model_artifacts_from_paths(
        artifact_paths,
        include_hashes=include_hashes,
        errors=artifact_errors,
    )
    return ModelInventory(
        manifest=manifest,
        manifest_errors=tuple(errors),
        artifact_errors=tuple(artifact_errors),
        references=tuple(_dedupe_model_references(references)),
        artifacts=tuple(artifacts),
    )


def scan_model_supply_chain(
    project_root: Path,
    *,
    target_model: Optional[str] = None,
    target_endpoint: Optional[str] = None,
    inventory: Optional[ModelInventory] = None,
) -> Tuple[List[Finding], List[ExecutionError]]:
    root = project_root.resolve()
    inventory = inventory or collect_model_inventory(
        root,
        target_model=target_model,
        target_endpoint=target_endpoint,
        include_hashes=True,
    )

    findings: List[Finding] = []
    hash_errors: List[ExecutionError] = []
    for reference in inventory.references:
        findings.extend(_findings_for_reference(reference, inventory.manifest))

    artifact_hashes: dict[str, str] = {
        _normalize_manifest_path(artifact.path, root): artifact.sha256
        for artifact in inventory.artifacts
        if artifact.sha256
    }
    for artifact in inventory.artifacts:
        artifact_findings, artifact_errors = _findings_for_artifact(
            artifact,
            inventory.manifest,
            root,
            artifact_hashes,
        )
        findings.extend(artifact_findings)
        hash_errors.extend(artifact_errors)

    manifest_findings, manifest_hash_errors = _findings_for_manifest(
        inventory.manifest,
        root,
        artifact_hashes,
    )
    findings.extend(manifest_findings)
    hash_errors.extend(manifest_hash_errors)
    return _dedupe_findings(findings), [
        *inventory.manifest_errors,
        *inventory.artifact_errors,
        *hash_errors,
    ]


def _iter_text_scan_files(root: Path) -> Iterable[Path]:
    text_paths, _ = _iter_model_scan_files(root)
    return text_paths


def _iter_model_scan_files(root: Path) -> Tuple[List[Path], List[Path]]:
    if not root.exists():
        return [], []

    text_paths: List[Path] = []
    artifact_paths: List[Path] = []
    for current_root_text, dirnames, filenames in os.walk(root):
        current_root = Path(current_root_text)
        dirnames[:] = [
            dirname
            for dirname in dirnames
            if not _is_excluded_path(current_root / dirname, root)
        ]
        if _is_excluded_path(current_root, root):
            continue
        for filename in filenames:
            path = current_root / filename
            if path.suffix.lower() in MODEL_FILE_SUFFIXES:
                artifact_paths.append(path)
            if path.name != MODEL_MANIFEST_NAME and _is_text_scan_file(path):
                text_paths.append(path)
    return sorted(text_paths), sorted(artifact_paths)


def _model_artifacts_from_paths(
    artifact_paths: Iterable[Path],
    *,
    include_hashes: bool,
    errors: Optional[List[ExecutionError]],
) -> List[ModelArtifact]:
    artifacts: List[ModelArtifact] = []
    for path in artifact_paths:
        suffix = path.suffix.lower()
        artifact_type = "adapter" if _looks_like_adapter_path(path) else "model"
        artifact_hash: Optional[str] = None
        if include_hashes:
            artifact_hash, hash_error = _sha256_file_or_error(
                path,
                "Unable to hash model artifact",
            )
            if hash_error and errors is not None:
                errors.append(hash_error)
        artifacts.append(
            ModelArtifact(
                name=path.name,
                path=path,
                artifact_type=artifact_type,
                format=suffix.lstrip("."),
                sha256=artifact_hash,
            )
        )
    return artifacts


def _references_from_file(path: Path) -> List[ModelReference]:
    references: List[ModelReference] = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                references.extend(_references_from_line(path, line_number, raw_line))
    except (OSError, UnicodeDecodeError):
        return []
    return references


def _references_from_line(
    path: Path,
    line_number: int,
    raw_line: str,
) -> List[ModelReference]:
    references: List[ModelReference] = []
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return references
    if TRUST_REMOTE_CODE_RE.search(line):
        references.append(
            ModelReference(
                name="trust_remote_code",
                source="runtime",
                source_file=path,
                line_number=line_number,
                artifact_type="remote_code",
            )
        )
    if _line_looks_model_related(line):
        references.extend(_hf_references_from_line(path, line_number, line))
        assignment = MODEL_ASSIGNMENT_RE.search(line)
        if assignment and _assignment_is_supported(path, assignment):
            model_name = assignment.group(1).strip()
            if model_name and model_name != "true":
                source = _infer_model_source(model_name, None)
                if source != "huggingface":
                    references.append(
                        ModelReference(
                            name=model_name,
                            source=source,
                            source_file=path,
                            line_number=line_number,
                        )
                    )
    return references


def _hf_references_from_line(path: Path, line_number: int, line: str) -> List[ModelReference]:
    references: List[ModelReference] = []
    for match in HF_MODEL_RE.finditer(line):
        name = match.group("name").rstrip(".,;)")
        if not _looks_like_huggingface_reference(line, match):
            continue
        references.append(
            ModelReference(
                name=name,
                source=_infer_model_source(name, None),
                source_file=path,
                line_number=line_number,
                revision=match.group("revision"),
            )
        )
    return references


def _findings_for_reference(
    reference: ModelReference,
    manifest: ModelManifest,
) -> List[Finding]:
    if reference.artifact_type == "remote_code":
        return [
            Finding(
                severity=Severity.HIGH,
                category=MODEL_SUPPLY_CHAIN_CATEGORY,
                description="Model loading enables trust_remote_code, allowing repository-supplied code to execute.",
                remediation="Disable trust_remote_code unless the model repository is reviewed, pinned to an immutable revision, and explicitly approved.",
                source_file=_source_file_text(reference),
                source_line=reference.line_number,
                artifact_type="remote_code",
                model_name=reference.name,
                model_source=reference.source,
            )
        ]

    findings: List[Finding] = []
    approved_entry = manifest.approved_model(reference.name)
    if approved_entry is None:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                category=MODEL_SUPPLY_CHAIN_CATEGORY,
                description=f"Model '{reference.name}' is not declared as an approved model source.",
                remediation=f"Add '{reference.name}' to {MODEL_MANIFEST_NAME} with source, license, revision or digest, and approved = true.",
                source_file=_source_file_text(reference),
                source_line=reference.line_number,
                artifact_type=reference.artifact_type,
                model_name=reference.name,
                model_source=reference.source,
            )
        )

    if reference.source == "huggingface" and not _is_pinned_revision(reference.revision):
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                category=MODEL_SUPPLY_CHAIN_CATEGORY,
                description=f"Hugging Face model '{reference.name}' is referenced without an immutable revision.",
                remediation="Pin Hugging Face models to a commit SHA, for example owner/model@<40-char-commit-sha>.",
                source_file=_source_file_text(reference),
                source_line=reference.line_number,
                artifact_type=reference.artifact_type,
                model_name=reference.name,
                model_source=reference.source,
            )
        )

    return findings


def _findings_for_artifact(
    artifact: ModelArtifact,
    manifest: ModelManifest,
    root: Path,
    artifact_hashes: dict[str, str],
) -> Tuple[List[Finding], List[ExecutionError]]:
    findings: List[Finding] = []
    errors: List[ExecutionError] = []
    manifest_entry = manifest.artifact_entry(artifact.path, root)
    source_file = str(artifact.path)
    relative_path = _normalize_manifest_path(artifact.path, root)

    if artifact.path.suffix.lower() in UNSAFE_MODEL_FILE_SUFFIXES:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                category=MODEL_SUPPLY_CHAIN_CATEGORY,
                description=f"Model artifact '{relative_path}' uses a deserialization-prone file format.",
                remediation="Prefer safetensors or GGUF artifacts from a verified source; only load pickle-based formats from trusted, hashed inputs.",
                source_file=source_file,
                artifact_type=artifact.artifact_type,
                model_name=artifact.name,
                model_source="local",
            )
        )

    if manifest_entry is None or not manifest_entry.sha256:
        actual_hash, hash_error = _artifact_sha256_or_error(
            artifact,
            root,
            artifact_hashes,
            "Unable to hash model artifact",
        )
        if hash_error:
            errors.append(hash_error)
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                category=MODEL_SUPPLY_CHAIN_CATEGORY,
                description=f"Local {artifact.artifact_type} artifact '{relative_path}' has no approved SHA256 in {MODEL_MANIFEST_NAME}.",
                remediation=_missing_artifact_hash_remediation(relative_path, actual_hash),
                source_file=source_file,
                artifact_type=artifact.artifact_type,
                model_name=artifact.name,
                model_source="local",
            )
        )

    if artifact.artifact_type == "adapter":
        if manifest_entry is None:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    category=MODEL_SUPPLY_CHAIN_CATEGORY,
                    description=f"LoRA/adapter artifact '{relative_path}' is not declared in {MODEL_MANIFEST_NAME}.",
                    remediation="Declare the adapter with its base_model, source, license, sha256, and approved = true.",
                    source_file=source_file,
                    artifact_type="adapter",
                    model_name=artifact.name,
                    model_source="local",
                )
            )
        elif not manifest_entry.base_model:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    category=MODEL_SUPPLY_CHAIN_CATEGORY,
                    description=f"LoRA/adapter artifact '{relative_path}' does not declare its base model.",
                    remediation=f"Add base_model to the adapter entry in {MODEL_MANIFEST_NAME}.",
                    source_file=source_file,
                    artifact_type="adapter",
                    model_name=artifact.name,
                    model_source="local",
                )
            )

    return findings, errors


def _findings_for_manifest(
    manifest: ModelManifest,
    root: Path,
    artifact_hashes: dict[str, str],
) -> Tuple[List[Finding], List[ExecutionError]]:
    findings: List[Finding] = []
    errors: List[ExecutionError] = []
    for entry in (*manifest.models, *manifest.adapters):
        if entry.path:
            path = root / entry.path
            if path.exists() and entry.sha256:
                actual_hash, hash_error = _cached_sha256_or_error(
                    path,
                    root,
                    artifact_hashes,
                    "Unable to hash manifest model artifact",
                )
                if hash_error:
                    errors.append(hash_error)
                    continue
                expected_hash = _normalize_sha256(entry.sha256)
                if expected_hash and actual_hash.lower() != expected_hash.lower():
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            category=MODEL_SUPPLY_CHAIN_CATEGORY,
                            description=f"{entry.artifact_type.title()} artifact '{entry.path}' does not match the approved SHA256.",
                            remediation="Re-download the artifact from a verified source or update the manifest only after reviewing the new artifact.",
                            source_file=str(path),
                            artifact_type=entry.artifact_type,
                            model_name=entry.name,
                            model_source=entry.source,
                        )
                    )
        if entry.artifact_type == "adapter" and not entry.base_model:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    category=MODEL_SUPPLY_CHAIN_CATEGORY,
                    description=f"Adapter '{entry.name}' does not declare its base model.",
                    remediation=f"Add base_model to the adapter entry in {MODEL_MANIFEST_NAME}.",
                    source_file=str(manifest.path) if manifest.path else None,
                    artifact_type="adapter",
                    model_name=entry.name,
                    model_source=entry.source,
                )
            )
    return findings, errors


def _artifact_sha256_or_error(
    artifact: ModelArtifact,
    root: Path,
    artifact_hashes: dict[str, str],
    message: str,
) -> Tuple[Optional[str], Optional[ExecutionError]]:
    if artifact.sha256:
        artifact_hashes.setdefault(_normalize_manifest_path(artifact.path, root), artifact.sha256)
        return artifact.sha256, None
    return _cached_sha256_or_error(artifact.path, root, artifact_hashes, message)


def _cached_sha256_or_error(
    path: Path,
    root: Path,
    artifact_hashes: dict[str, str],
    message: str,
) -> Tuple[Optional[str], Optional[ExecutionError]]:
    rel_path = _normalize_manifest_path(path, root)
    digest = artifact_hashes.get(rel_path)
    if digest:
        return digest, None
    digest, error = _sha256_file_or_error(path, message)
    if error:
        return None, error
    artifact_hashes[rel_path] = digest
    return digest, None


def _source_file_text(reference: ModelReference) -> Optional[str]:
    return str(reference.source_file) if reference.source_file else None


def _infer_model_source(model_name: str, endpoint: Optional[str]) -> str:
    normalized_endpoint = (endpoint or "").lower()
    if Path(model_name).suffix.lower() in MODEL_FILE_SUFFIXES:
        return "local"
    if "bedrock" in normalized_endpoint or _looks_like_bedrock_model_id(model_name):
        return "bedrock"
    if "/" in model_name:
        return "huggingface"
    if "localhost:11434" in normalized_endpoint or "ollama" in normalized_endpoint:
        return "ollama"
    return "unknown"


def _line_looks_model_related(line: str) -> bool:
    lowered = line.lower()
    return any(
        token in lowered
        for token in (
            "adapter",
            "base_model",
            "checkpoint",
            "from_pretrained",
            "huggingface",
            "hf_model",
            "model",
            "peft",
            "pretrained",
        )
    )


def _is_text_scan_file(path: Path) -> bool:
    return (
        path.name in TEXT_SCAN_NAMES
        or path.name.startswith(".env.")
        or path.suffix.lower() in TEXT_SCAN_SUFFIXES
    )


def _looks_like_bedrock_model_id(model_name: str) -> bool:
    normalized = model_name.lower()
    return normalized.startswith(
        (
            "ai21.",
            "amazon.",
            "anthropic.",
            "cohere.",
            "deepseek.",
            "meta.",
            "mistral.",
            "stability.",
            "writer.",
        )
    )


def _looks_like_huggingface_reference(line: str, match: re.Match[str]) -> bool:
    if match.group("name") == "owner/model":
        return False
    if Path(match.group("name")).suffix.lower() in MODEL_FILE_SUFFIXES:
        return False
    start = match.start("name")
    prefix = line[max(0, start - 10) : start]
    if "://" in prefix:
        return False
    if match.group("prefix"):
        return True
    lowered = line.lower()
    if "from_pretrained" not in lowered and "huggingface" not in lowered and not MODEL_ASSIGNMENT_RE.search(line):
        return False
    return " " not in match.group("name")


def _assignment_is_supported(path: Path, assignment: re.Match[str]) -> bool:
    if path.suffix.lower() != ".py":
        return True
    return '"' in assignment.group(0) or "'" in assignment.group(0)


def _looks_like_adapter_path(path: Path) -> bool:
    normalized = str(path).lower()
    return "adapter" in normalized or "lora" in normalized or "peft" in normalized


def _is_pinned_revision(revision: Optional[str]) -> bool:
    return bool(revision and FULL_SHA_RE.match(revision))


def _optional_string(value: object) -> Optional[str]:
    return value if isinstance(value, str) and value else None


def _normalize_model_name(name: str) -> str:
    return name.strip().lower()


def _normalize_manifest_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _normalize_configured_path(path: str) -> str:
    return Path(path).as_posix().lstrip("./")


def _normalize_sha256(value: str) -> Optional[str]:
    digest = value.lower().strip().removeprefix("sha256:")
    if re.fullmatch(r"[a-f0-9]{64}", digest):
        return digest
    return None


def _missing_artifact_hash_remediation(relative_path: str, actual_hash: Optional[str]) -> str:
    digest = actual_hash or "<sha256>"
    return (
        f"Record path = '{relative_path}', sha256 = '{digest}', source, license, "
        f"and approved = true in {MODEL_MANIFEST_NAME}."
    )


def _sha256_file_or_error(path: Path, message: str) -> Tuple[Optional[str], Optional[ExecutionError]]:
    try:
        return _sha256_file(path), None
    except OSError as exc:
        return None, ExecutionError(
            source=ErrorSource.STATIC,
            message=message,
            path=str(path),
            detail=str(exc),
        )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _dedupe_model_references(references: Iterable[ModelReference]) -> List[ModelReference]:
    seen = set()
    deduped: List[ModelReference] = []
    for reference in references:
        key = (
            reference.name,
            reference.source,
            str(reference.source_file),
            reference.line_number,
            reference.revision,
            reference.artifact_type,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(reference)
    return deduped


def _dedupe_findings(findings: Iterable[Finding]) -> List[Finding]:
    seen = set()
    deduped: List[Finding] = []
    for finding in findings:
        key = (
            finding.category,
            finding.description,
            finding.source_file,
            finding.source_line,
            finding.model_name,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


__all__ = [
    "MODEL_MANIFEST_NAME",
    "MODEL_SUPPLY_CHAIN_CATEGORY",
    "ModelArtifact",
    "ModelInventory",
    "ModelManifest",
    "ModelReference",
    "collect_model_inventory",
    "discover_model_artifacts",
    "discover_model_references",
    "load_model_manifest",
    "scan_model_supply_chain",
]
