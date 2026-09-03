"""Deterministic immutable evidence persistence boundary for MR-08.

This module implements one bounded local-filesystem persistence surface for
canonical MR-05 evidence manifests. It performs no subprocess, network,
provider, model, auth, controller, Human Gate, retry, fallback, Git, commit,
or push behavior.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
import errno
import hashlib
import os
import stat
from typing import NoReturn

from .canonical import canonical_json_bytes
from .contracts import SCHEMA_VERSION, validate_schema_version
from .failures import FailureCode
from .identity import require_git_commit, require_sha256, sha256_canonical


RUN_POLICY_VERSION = "MR08A-RUN-V1"
EVIDENCE_POLICY_VERSION = "MR08A-EVIDENCE-V1"

EVIDENCE_PERSISTENCE_COUNT = 1
FILESYSTEM_EVIDENCE_WRITE_COUNT = 1
SUBPROCESS_EXECUTION_COUNT = 0
NETWORK_IMPLEMENTATION_COUNT = 0
MODEL_CALL_IMPLEMENTATION_COUNT = 0
PROVIDER_CLIENT_IMPLEMENTATION_COUNT = 0
AUTH_IMPLEMENTATION_COUNT = 0
CONTROLLER_IMPLEMENTATION_COUNT = 0
HUMAN_GATE_EXECUTION_COUNT = 0
AUTO_RETRY_IMPLEMENTATION_COUNT = 0
AUTO_FALLBACK_IMPLEMENTATION_COUNT = 0


class EvidenceValidationError(ValueError):
    """A run record or evidence manifest violates the frozen MR-08 contract."""


class EvidencePersistenceError(RuntimeError):
    """Fail-closed evidence persistence error using an existing MR-05 code."""

    def __init__(self, code: FailureCode | str, message: str) -> None:
        normalized = code.value if isinstance(code, FailureCode) else str(code)
        super().__init__(message)
        self.code = normalized
        self.failure_code = normalized
        self.retry_allowed = False


@dataclass(frozen=True, slots=True)
class _ValidatedRoot:
    path: str
    state: tuple[int, int, int, int, int, int]


def _fail(code: FailureCode | str, message: str) -> NoReturn:
    raise EvidencePersistenceError(code, message)


def _state_tuple(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _identity(value: object, field_name: str) -> str:
    try:
        return require_sha256(value, field=field_name)
    except ValueError as exc:
        raise EvidenceValidationError(str(exc)) from exc


def _identities(values: object, field_name: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        raise EvidenceValidationError(f"{field_name} must be an array")
    result = tuple(_identity(value, f"{field_name}[]") for value in values)
    if not allow_empty and not result:
        raise EvidenceValidationError(f"{field_name} must not be empty")
    if len(set(result)) != len(result):
        raise EvidenceValidationError(f"{field_name} contains duplicate identities")
    return tuple(sorted(result))


def _counter_mapping(value: object) -> Mapping[str, int]:
    if not isinstance(value, Mapping) or any(type(key) is not str or not key for key in value):
        raise EvidenceValidationError("operational_counters must be an object with non-empty string keys")
    result: dict[str, int] = {}
    for key, counter in value.items():
        if type(counter) is not int or counter < 0:
            raise EvidenceValidationError("operational counter values must be non-negative integers")
        result[key] = counter
    return MappingProxyType(dict(sorted(result.items())))


@dataclass(frozen=True, slots=True)
class RunRecord:
    """Deterministic pre-result run identity with no circular result dependency."""

    repository_commit: str
    task_identity: str
    contract_identities: tuple[str, ...]
    dependency_identities: tuple[str, ...]
    input_identities: tuple[str, ...]
    schema_version: str = SCHEMA_VERSION
    schema_id: str = "mr05.run"
    policy_version: str = RUN_POLICY_VERSION
    run_identity: str | None = None

    def __post_init__(self) -> None:
        try:
            validate_schema_version(self.schema_id, self.schema_version)
            repository_commit = require_git_commit(self.repository_commit, field="repository_commit")
        except ValueError as exc:
            raise EvidenceValidationError(str(exc)) from exc
        if self.policy_version != RUN_POLICY_VERSION:
            raise EvidenceValidationError("run policy version is not frozen")
        task_identity = _identity(self.task_identity, "task_identity")
        contracts = _identities(self.contract_identities, "contract_identities")
        dependencies = _identities(self.dependency_identities, "dependency_identities")
        inputs = _identities(self.input_identities, "input_identities")
        object.__setattr__(self, "repository_commit", repository_commit)
        object.__setattr__(self, "task_identity", task_identity)
        object.__setattr__(self, "contract_identities", contracts)
        object.__setattr__(self, "dependency_identities", dependencies)
        object.__setattr__(self, "input_identities", inputs)
        computed = sha256_canonical(self.identity_payload())
        if self.run_identity is None:
            object.__setattr__(self, "run_identity", computed)
        elif _identity(self.run_identity, "run_identity") != computed:
            raise EvidenceValidationError("run_identity does not match canonical run inputs")

    def identity_payload(self) -> dict[str, object]:
        return {
            "schema_id": self.schema_id,
            "schema_version": self.schema_version,
            "policy_version": self.policy_version,
            "repository_commit": self.repository_commit,
            "task_identity": self.task_identity,
            "contract_identities": list(self.contract_identities),
            "dependency_identities": list(self.dependency_identities),
            "input_identities": list(self.input_identities),
        }

    def to_dict(self) -> dict[str, object]:
        return {**self.identity_payload(), "run_identity": self.run_identity}

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "RunRecord":
        required = {
            "schema_id", "schema_version", "policy_version", "repository_commit",
            "task_identity", "contract_identities", "dependency_identities",
            "input_identities", "run_identity",
        }
        if not isinstance(value, Mapping) or set(value) != required:
            raise EvidenceValidationError("run record fields are not exact")
        return cls(
            repository_commit=value["repository_commit"],
            task_identity=value["task_identity"],
            contract_identities=tuple(value["contract_identities"]),
            dependency_identities=tuple(value["dependency_identities"]),
            input_identities=tuple(value["input_identities"]),
            schema_version=value["schema_version"],
            schema_id=value["schema_id"],
            policy_version=value["policy_version"],
            run_identity=value["run_identity"],
        )


@dataclass(frozen=True, slots=True)
class EvidenceManifest:
    """Canonical immutable evidence manifest bound to one precomputed run identity."""

    run_identity: str
    artifact_identities: tuple[str, ...]
    provenance_identity: str
    metrics_identity: str
    operational_counters: Mapping[str, int]
    final_result_identity: str | None = None
    failure_identities: tuple[str, ...] = ()
    schema_version: str = SCHEMA_VERSION
    schema_id: str = "mr05.evidence_manifest"
    policy_version: str = EVIDENCE_POLICY_VERSION
    manifest_identity: str | None = None

    def __post_init__(self) -> None:
        try:
            validate_schema_version(self.schema_id, self.schema_version)
        except ValueError as exc:
            raise EvidenceValidationError(str(exc)) from exc
        if self.policy_version != EVIDENCE_POLICY_VERSION:
            raise EvidenceValidationError("evidence policy version is not frozen")
        run_identity = _identity(self.run_identity, "run_identity")
        artifacts = _identities(self.artifact_identities, "artifact_identities")
        provenance_identity = _identity(self.provenance_identity, "provenance_identity")
        metrics_identity = _identity(self.metrics_identity, "metrics_identity")
        failures = _identities(self.failure_identities, "failure_identities", allow_empty=True)
        final_result_identity = None if self.final_result_identity is None else _identity(
            self.final_result_identity, "final_result_identity"
        )
        counters = _counter_mapping(self.operational_counters)
        object.__setattr__(self, "run_identity", run_identity)
        object.__setattr__(self, "artifact_identities", artifacts)
        object.__setattr__(self, "provenance_identity", provenance_identity)
        object.__setattr__(self, "metrics_identity", metrics_identity)
        object.__setattr__(self, "failure_identities", failures)
        object.__setattr__(self, "final_result_identity", final_result_identity)
        object.__setattr__(self, "operational_counters", counters)
        computed = sha256_canonical(self.identity_payload())
        if self.manifest_identity is None:
            object.__setattr__(self, "manifest_identity", computed)
        elif _identity(self.manifest_identity, "manifest_identity") != computed:
            raise EvidenceValidationError("manifest_identity does not match canonical manifest inputs")

    def identity_payload(self) -> dict[str, object]:
        return {
            "schema_id": self.schema_id,
            "schema_version": self.schema_version,
            "policy_version": self.policy_version,
            "run_identity": self.run_identity,
            "artifact_identities": list(self.artifact_identities),
            "provenance_identity": self.provenance_identity,
            "metrics_identity": self.metrics_identity,
            "final_result_identity": self.final_result_identity,
            "failure_identities": list(self.failure_identities),
            "operational_counters": dict(self.operational_counters),
        }

    def to_dict(self) -> dict[str, object]:
        return {**self.identity_payload(), "manifest_identity": self.manifest_identity}

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "EvidenceManifest":
        required = {
            "schema_id", "schema_version", "policy_version", "run_identity",
            "artifact_identities", "provenance_identity", "metrics_identity",
            "final_result_identity", "failure_identities", "operational_counters",
            "manifest_identity",
        }
        if not isinstance(value, Mapping) or set(value) != required:
            raise EvidenceValidationError("evidence manifest fields are not exact")
        return cls(
            run_identity=value["run_identity"],
            artifact_identities=tuple(value["artifact_identities"]),
            provenance_identity=value["provenance_identity"],
            metrics_identity=value["metrics_identity"],
            final_result_identity=value["final_result_identity"],
            failure_identities=tuple(value["failure_identities"]),
            operational_counters=value["operational_counters"],
            schema_version=value["schema_version"],
            schema_id=value["schema_id"],
            policy_version=value["policy_version"],
            manifest_identity=value["manifest_identity"],
        )


@dataclass(frozen=True, slots=True)
class PersistenceResult:
    """Observed persistence result; it grants no workflow or execution authority."""

    run_identity: str
    manifest_identity: str
    approved_root_identity: str
    relative_path: str
    content_sha256: str
    byte_count: int
    human_approval: bool = False
    controller_progress_authority: bool = False
    source_write_authority: bool = False
    git_authority: bool = False
    model_provider_authority: bool = False


def build_run_record(
    *,
    repository_commit: str,
    task_identity: str,
    contract_identities: Sequence[str],
    dependency_identities: Sequence[str],
    input_identities: Sequence[str],
) -> RunRecord:
    return RunRecord(
        repository_commit=repository_commit,
        task_identity=task_identity,
        contract_identities=tuple(contract_identities),
        dependency_identities=tuple(dependency_identities),
        input_identities=tuple(input_identities),
    )


def build_evidence_manifest(
    *,
    run_identity: str,
    artifact_identities: Sequence[str],
    provenance_identity: str,
    metrics_identity: str,
    operational_counters: Mapping[str, int],
    final_result_identity: str | None = None,
    failure_identities: Sequence[str] = (),
) -> EvidenceManifest:
    return EvidenceManifest(
        run_identity=run_identity,
        artifact_identities=tuple(artifact_identities),
        provenance_identity=provenance_identity,
        metrics_identity=metrics_identity,
        final_result_identity=final_result_identity,
        failure_identities=tuple(failure_identities),
        operational_counters=operational_counters,
    )


def _validated_root(value: object) -> _ValidatedRoot:
    if type(value) is not str or not value or "\x00" in value or "\n" in value or "\r" in value:
        _fail(FailureCode.INVALID_SCHEMA, "approved_root must be a non-empty path string")
    if not os.path.isabs(value) or os.path.normpath(value) != value:
        _fail(FailureCode.SOURCE_PATH_ESCAPE, "approved_root must be an exact normalized absolute path")
    try:
        info = os.lstat(value)
    except OSError as exc:
        _fail(FailureCode.SOURCE_PATH_ESCAPE, f"approved_root cannot be inspected: {exc}")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or os.path.realpath(value) != value:
        _fail(FailureCode.SOURCE_PATH_ESCAPE, "approved_root is linked, substituted, or not a directory")
    return _ValidatedRoot(value, _state_tuple(info))


def approved_root_identity(approved_root: object) -> str:
    """Compute root identity without another filesystem resolution."""
    if type(approved_root) is not str or not approved_root:
        _fail(FailureCode.INVALID_SCHEMA, "approved_root identity input must be a path string")
    return sha256_canonical({
        "schema_version": SCHEMA_VERSION,
        "evidence_policy_version": EVIDENCE_POLICY_VERSION,
        "approved_root": approved_root,
    })


def _relative_path(value: object) -> str:
    if type(value) is not str or not value or "\x00" in value or "\n" in value or "\r" in value:
        _fail(FailureCode.INVALID_SCHEMA, "relative_path must be a non-empty string")
    if value.startswith("/") or "\\" in value:
        _fail(FailureCode.SOURCE_PATH_ESCAPE, "relative_path must use relative POSIX components")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        _fail(FailureCode.SOURCE_PATH_ESCAPE, "relative_path contains an unsafe component")
    return value


def _directory_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _temp_flags() -> int:
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _open_directory(parent_fd: int, name: str) -> int:
    try:
        child_fd = os.open(name, _directory_flags(), dir_fd=parent_fd)
        child = os.fstat(child_fd)
        entry = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        _fail(FailureCode.SOURCE_PATH_ESCAPE, f"evidence directory traversal failed closed: {exc}")
    if not stat.S_ISDIR(child.st_mode) or stat.S_ISLNK(entry.st_mode):
        os.close(child_fd)
        _fail(FailureCode.SOURCE_PATH_ESCAPE, "evidence path component is not a real directory")
    if (child.st_dev, child.st_ino) != (entry.st_dev, entry.st_ino):
        os.close(child_fd)
        _fail(FailureCode.SOURCE_PATH_ESCAPE, "evidence directory entry substitution detected")
    return child_fd


def _destination_absent(parent_fd: int, name: str) -> None:
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return
        _fail(FailureCode.SOURCE_PATH_ESCAPE, f"final evidence entry cannot be inspected: {exc}")
    if stat.S_ISLNK(info.st_mode):
        _fail(FailureCode.SOURCE_PATH_ESCAPE, "final evidence destination is a symlink")
    _fail(FailureCode.DUPLICATE_CONFLICT, "final evidence destination already exists")


def _temp_name(manifest_identity: str) -> str:
    return f".mr08-{manifest_identity}.tmp"


def _write_exact(fd: int, data: bytes) -> None:
    try:
        written = os.write(fd, data)
    except OSError as exc:
        _fail(FailureCode.MR05_INTERNAL_INVARIANT, f"evidence write failed: {exc}")
    if written != len(data):
        _fail(FailureCode.HASH_MISMATCH, "evidence write was partial or short")


def _verify_temp_bytes(fd: int, expected: bytes) -> None:
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError as exc:
        _fail(FailureCode.MR05_INTERNAL_INVARIANT, f"temporary evidence verification read failed: {exc}")
    actual = b"".join(chunks)
    if len(actual) != len(expected) or hashlib.sha256(actual).digest() != hashlib.sha256(expected).digest():
        _fail(FailureCode.HASH_MISMATCH, "temporary evidence bytes do not match canonical manifest bytes")


def _publish_no_replace(parent_fd: int, temp_name: str, final_name: str) -> None:
    try:
        os.link(
            temp_name,
            final_name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )
    except FileExistsError:
        _fail(FailureCode.DUPLICATE_CONFLICT, "final evidence destination appeared during publication")
    except OSError as exc:
        if exc.errno == errno.EEXIST:
            _fail(FailureCode.DUPLICATE_CONFLICT, "final evidence destination appeared during publication")
        _fail(FailureCode.MR05_INTERNAL_INVARIANT, f"no-replace evidence publication failed: {exc}")


def persist_evidence(
    *,
    approved_root: object,
    relative_path: object,
    manifest: EvidenceManifest | Mapping[str, object],
) -> PersistenceResult:
    """Persist one canonical manifest exactly once under an authorized root.

    Runtime failures intentionally leave any already-created temporary/final
    filesystem state untouched for read-only reconciliation. There is no
    automatic cleanup or retry path.
    """
    try:
        record = manifest if isinstance(manifest, EvidenceManifest) else EvidenceManifest.from_mapping(manifest)
    except (EvidenceValidationError, TypeError, ValueError) as exc:
        _fail(FailureCode.INVALID_SCHEMA, f"evidence manifest is invalid: {exc}")
    path = _relative_path(relative_path)
    root = _validated_root(approved_root)
    root_identity = approved_root_identity(root.path)
    canonical = record.canonical_bytes()
    expected_sha = hashlib.sha256(canonical).hexdigest()

    root_fd: int | None = None
    parent_fd: int | None = None
    opened_dirs: list[int] = []
    temp_fd: int | None = None
    temp_name = _temp_name(record.manifest_identity)
    try:
        try:
            root_fd = os.open(root.path, _directory_flags())
        except OSError as exc:
            _fail(FailureCode.SOURCE_PATH_ESCAPE, f"approved_root open failed closed: {exc}")
        opened_root = os.fstat(root_fd)
        if not stat.S_ISDIR(opened_root.st_mode) or _state_tuple(opened_root) != root.state:
            _fail(FailureCode.SOURCE_PATH_ESCAPE, "approved_root substitution detected after validation")
        parent_fd = root_fd
        parts = path.split("/")
        for part in parts[:-1]:
            child_fd = _open_directory(parent_fd, part)
            opened_dirs.append(child_fd)
            parent_fd = child_fd
        final_name = parts[-1]
        _destination_absent(parent_fd, final_name)
        try:
            temp_fd = os.open(temp_name, _temp_flags(), 0o600, dir_fd=parent_fd)
        except FileExistsError:
            _fail(FailureCode.DUPLICATE_CONFLICT, "exclusive temporary evidence object already exists")
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                _fail(FailureCode.DUPLICATE_CONFLICT, "exclusive temporary evidence object already exists")
            _fail(FailureCode.MR05_INTERNAL_INVARIANT, f"temporary evidence creation failed: {exc}")
        temp_before = os.fstat(temp_fd)
        if not stat.S_ISREG(temp_before.st_mode):
            _fail(FailureCode.MR05_INTERNAL_INVARIANT, "temporary evidence object is not a regular file")
        _write_exact(temp_fd, canonical)
        temp_after_write = os.fstat(temp_fd)
        if temp_after_write.st_size != len(canonical):
            _fail(FailureCode.HASH_MISMATCH, "temporary evidence byte count mismatch")
        try:
            os.fsync(temp_fd)
        except OSError as exc:
            _fail(FailureCode.MR05_INTERNAL_INVARIANT, f"temporary evidence fsync failed: {exc}")
        _verify_temp_bytes(temp_fd, canonical)
        _publish_no_replace(parent_fd, temp_name, final_name)
        try:
            os.fsync(parent_fd)
        except OSError as exc:
            _fail(FailureCode.MR05_INTERNAL_INVARIANT, f"evidence directory fsync after publication failed: {exc}")
        try:
            final_info = os.stat(final_name, dir_fd=parent_fd, follow_symlinks=False)
            temp_info = os.fstat(temp_fd)
        except OSError as exc:
            _fail(FailureCode.MR05_INTERNAL_INVARIANT, f"final evidence identity verification failed: {exc}")
        if stat.S_ISLNK(final_info.st_mode) or not stat.S_ISREG(final_info.st_mode):
            _fail(FailureCode.HASH_MISMATCH, "final evidence object is not the published regular file")
        if (final_info.st_dev, final_info.st_ino) != (temp_info.st_dev, temp_info.st_ino):
            _fail(FailureCode.HASH_MISMATCH, "final evidence identity differs from verified temporary object")
        if final_info.st_size != len(canonical):
            _fail(FailureCode.HASH_MISMATCH, "final evidence byte count mismatch")
        try:
            os.unlink(temp_name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except OSError as exc:
            _fail(FailureCode.MR05_INTERNAL_INVARIANT, f"successful-publication temporary-link cleanup failed: {exc}")
        return PersistenceResult(
            run_identity=record.run_identity,
            manifest_identity=record.manifest_identity,
            approved_root_identity=root_identity,
            relative_path=path,
            content_sha256=expected_sha,
            byte_count=len(canonical),
        )
    finally:
        if temp_fd is not None:
            os.close(temp_fd)
        for fd in reversed(opened_dirs):
            os.close(fd)
        if root_fd is not None:
            os.close(root_fd)


__all__ = (
    "RUN_POLICY_VERSION", "EVIDENCE_POLICY_VERSION", "EVIDENCE_PERSISTENCE_COUNT",
    "FILESYSTEM_EVIDENCE_WRITE_COUNT", "SUBPROCESS_EXECUTION_COUNT",
    "NETWORK_IMPLEMENTATION_COUNT", "MODEL_CALL_IMPLEMENTATION_COUNT",
    "PROVIDER_CLIENT_IMPLEMENTATION_COUNT", "AUTH_IMPLEMENTATION_COUNT",
    "CONTROLLER_IMPLEMENTATION_COUNT", "HUMAN_GATE_EXECUTION_COUNT",
    "AUTO_RETRY_IMPLEMENTATION_COUNT", "AUTO_FALLBACK_IMPLEMENTATION_COUNT",
    "EvidenceValidationError", "EvidencePersistenceError", "RunRecord",
    "EvidenceManifest", "PersistenceResult", "build_run_record",
    "build_evidence_manifest", "approved_root_identity", "persist_evidence",
)
