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


# Frozen MR05B run / evidence-manifest / final-result compatibility layer.
FROZEN_RUN_SCHEMA_ID = "mr05.run"
FROZEN_EVIDENCE_MANIFEST_SCHEMA_ID = "mr05.evidence_manifest"
FINAL_RESULT_SCHEMA_ID = "mr05.final_result"
FINAL_RESULT_IMPLEMENTATION_COUNT = 1
FINAL_RESULT_EXECUTION_COUNT = 0
FINAL_RESULT_HUMAN_APPROVAL_EXECUTION_COUNT = 0
FINAL_RESULT_STATE_TRANSITION_EXECUTION_COUNT = 0
FINAL_RESULT_NETWORK_IMPLEMENTATION_COUNT = 0
FINAL_RESULT_PROVIDER_CLIENT_IMPLEMENTATION_COUNT = 0
FINAL_RESULT_MODEL_CALL_IMPLEMENTATION_COUNT = 0
FINAL_RESULT_AUTH_IMPLEMENTATION_COUNT = 0
FINAL_RESULT_GIT_OPERATION_COUNT = 0
_MAX_I64 = 9223372036854775807
_FROZEN_RUN_STATES = ("RAW","DISCOVERED","NORMALIZED","PACKAGED","GUARDED","CLOUD_READY","PROPOSED","VERIFIED_DENY","VERIFIED_ESCALATE","VERIFIED_PASS_FOR_REVIEW","HUMAN_APPROVED","HUMAN_REJECTED","HUMAN_REWORK","HUMAN_MORE_EVIDENCE","FAILED")
_FINAL_TERMINAL_STATES = ("VERIFIED_DENY","VERIFIED_ESCALATE","VERIFIED_PASS_FOR_REVIEW","HUMAN_APPROVED","HUMAN_REJECTED","HUMAN_REWORK","HUMAN_MORE_EVIDENCE","FAILED")
_VERIFICATION_RESULTS = ("DENY","ESCALATE","PASS_FOR_REVIEW")
_HUMAN_DECISIONS = ("APPROVE","REJECT","REQUEST_REWORK","REQUEST_MORE_EVIDENCE")
_DECISIONS_BY_VERIFICATION = {"DENY":("REJECT",),"ESCALATE":("REJECT","REQUEST_REWORK","REQUEST_MORE_EVIDENCE"),"PASS_FOR_REVIEW":("APPROVE","REJECT","REQUEST_REWORK","REQUEST_MORE_EVIDENCE")}
_REQUIRED_POLICY_VERSIONS = {"canonical_json":"MR05-CANONICAL-JSON-1.0.0","failure":"1.0.0","provenance":"1.0.0","evidence_manifest":"1.0.0"}
_REQUIRED_AUTHORITY_POSTURE = {"trust":"LEVEL 0","write_authority":"NONE","stage_authority":"NONE","commit_authority":"NONE","push_authority":"NONE","live_cloud_execution_authority":"NONE"}
_REQUIRED_BYTE_BUDGET_KEYS = {"budget_identity","max_raw_bytes","max_normalized_bytes","max_package_bytes","max_cloud_context_bytes","byte_budget_policy_version","overflow_policy","silent_truncation"}


def _plain_mapping(value: object, field_name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise EvidenceValidationError(f"{field_name} must be an object")
    if any(type(key) is not str for key in value):
        raise EvidenceValidationError(f"{field_name} keys must be exact strings")
    return MappingProxyType(dict(value))


def _no_unpaired_surrogate(value: str, field_name: str) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise EvidenceValidationError(f"{field_name} contains an unpaired surrogate") from exc


def _frozen_byte_budget(value: object) -> Mapping[str, object]:
    row = _plain_mapping(value, "byte_budget")
    if set(row) != _REQUIRED_BYTE_BUDGET_KEYS:
        raise EvidenceValidationError("byte_budget fields are not exact")
    normalized = dict(row)
    normalized["budget_identity"] = _identity(row["budget_identity"], "byte_budget.budget_identity")
    for name in ("max_raw_bytes","max_normalized_bytes","max_package_bytes","max_cloud_context_bytes"):
        item = row[name]
        if type(item) is not int or not 1 <= item <= _MAX_I64:
            raise EvidenceValidationError(f"byte_budget.{name} must be a positive bounded integer")
    if row["byte_budget_policy_version"] != "1.0.0" or row["overflow_policy"] != "BLOCK_OR_DETERMINISTIC_REPACK" or row["silent_truncation"] is not False:
        raise EvidenceValidationError("byte_budget policy is not frozen")
    return MappingProxyType(normalized)


def _exact_frozen_mapping(value: object, expected: Mapping[str, str], field_name: str) -> Mapping[str, str]:
    row = _plain_mapping(value, field_name)
    if dict(row) != dict(expected):
        raise EvidenceValidationError(f"{field_name} does not match the frozen contract")
    return MappingProxyType(dict(expected))


@dataclass(frozen=True, slots=True)
class FrozenRunRecord:
    task_identity: str
    source_set_identity: str
    discovery_identity: str
    normalization_identity: str
    mr03_result_identity: str
    mr04_result_identity: str
    byte_budget: Mapping[str, object]
    policy_versions: Mapping[str, str]
    state: str
    authority_posture: Mapping[str, str]
    observational_metadata: Mapping[str, object] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION
    run_identity: str | None = None

    def __post_init__(self) -> None:
        try:
            validate_schema_version(FROZEN_RUN_SCHEMA_ID, self.schema_version)
        except ValueError as exc:
            raise EvidenceValidationError(str(exc)) from exc
        for name in ("task_identity","source_set_identity","discovery_identity","normalization_identity","mr03_result_identity","mr04_result_identity"):
            object.__setattr__(self, name, _identity(getattr(self, name), name))
        object.__setattr__(self, "byte_budget", _frozen_byte_budget(self.byte_budget))
        object.__setattr__(self, "policy_versions", _exact_frozen_mapping(self.policy_versions, _REQUIRED_POLICY_VERSIONS, "policy_versions"))
        if type(self.state) is not str or self.state not in _FROZEN_RUN_STATES:
            raise EvidenceValidationError("run state is outside the frozen state machine")
        object.__setattr__(self, "authority_posture", _exact_frozen_mapping(self.authority_posture, _REQUIRED_AUTHORITY_POSTURE, "authority_posture"))
        object.__setattr__(self, "observational_metadata", _plain_mapping(self.observational_metadata, "observational_metadata"))
        computed = sha256_canonical(self.identity_payload())
        if self.run_identity is None:
            object.__setattr__(self, "run_identity", computed)
        elif _identity(self.run_identity, "run_identity") != computed:
            raise EvidenceValidationError("run_identity does not match frozen run inputs")

    def identity_payload(self) -> dict[str, object]:
        return {"schema_version":self.schema_version,"task_identity":self.task_identity,"source_set_identity":self.source_set_identity,"discovery_identity":self.discovery_identity,"normalization_identity":self.normalization_identity,"mr03_result_identity":self.mr03_result_identity,"mr04_result_identity":self.mr04_result_identity,"byte_budget_policy_version":self.byte_budget["byte_budget_policy_version"],"byte_budget_identity":self.byte_budget["budget_identity"]}

    def to_dict(self) -> dict[str, object]:
        return {"schema_version":self.schema_version,"run_identity":self.run_identity,"task_identity":self.task_identity,"source_set_identity":self.source_set_identity,"discovery_identity":self.discovery_identity,"normalization_identity":self.normalization_identity,"mr03_result_identity":self.mr03_result_identity,"mr04_result_identity":self.mr04_result_identity,"byte_budget":dict(self.byte_budget),"policy_versions":dict(self.policy_versions),"state":self.state,"authority_posture":dict(self.authority_posture),"observational_metadata":dict(self.observational_metadata)}

    def canonical_bytes(self) -> bytes:
        qualified = FrozenRunRecord.from_mapping(self.to_dict())
        return canonical_json_bytes(qualified.to_dict(), identity_critical=False)

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "FrozenRunRecord":
        required={"schema_version","run_identity","task_identity","source_set_identity","discovery_identity","normalization_identity","mr03_result_identity","mr04_result_identity","byte_budget","policy_versions","state","authority_posture","observational_metadata"}
        if not isinstance(value, Mapping) or set(value) != required:
            raise EvidenceValidationError("frozen run fields are not exact")
        return cls(task_identity=value["task_identity"],source_set_identity=value["source_set_identity"],discovery_identity=value["discovery_identity"],normalization_identity=value["normalization_identity"],mr03_result_identity=value["mr03_result_identity"],mr04_result_identity=value["mr04_result_identity"],byte_budget=value["byte_budget"],policy_versions=value["policy_versions"],state=value["state"],authority_posture=value["authority_posture"],observational_metadata=value["observational_metadata"],schema_version=value["schema_version"],run_identity=value["run_identity"])


def build_frozen_run_record(*, task_identity: str, source_set_identity: str, discovery_identity: str, normalization_identity: str, mr03_result_identity: str, mr04_result_identity: str, byte_budget: Mapping[str, object], state: str, observational_metadata: Mapping[str, object] | None = None) -> FrozenRunRecord:
    return FrozenRunRecord(task_identity=task_identity,source_set_identity=source_set_identity,discovery_identity=discovery_identity,normalization_identity=normalization_identity,mr03_result_identity=mr03_result_identity,mr04_result_identity=mr04_result_identity,byte_budget=byte_budget,policy_versions=_REQUIRED_POLICY_VERSIONS,state=state,authority_posture=_REQUIRED_AUTHORITY_POSTURE,observational_metadata={} if observational_metadata is None else observational_metadata)


@dataclass(frozen=True, slots=True)
class FrozenEvidenceArtifact:
    relative_path: str
    byte_size: int
    sha256: str
    artifact_type: str
    schema_version: str | None

    def __post_init__(self) -> None:
        if type(self.relative_path) is not str or not self.relative_path or self.relative_path.startswith("/"):
            raise EvidenceValidationError("artifact relative_path must be a non-absolute string")
        _no_unpaired_surrogate(self.relative_path, "artifact relative_path")
        parts = self.relative_path.split("/")
        windows_drive_style = (
            len(self.relative_path) >= 2
            and self.relative_path[0].isalpha()
            and self.relative_path[1] == ":"
        )
        if (
            "\x00" in self.relative_path
            or "\n" in self.relative_path
            or "\r" in self.relative_path
            or "\\" in self.relative_path
            or windows_drive_style
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise EvidenceValidationError("artifact relative_path is not an exact normalized relative POSIX path")
        if type(self.byte_size) is not int or not 0 <= self.byte_size <= _MAX_I64:
            raise EvidenceValidationError("artifact byte_size must be a non-negative bounded integer")
        object.__setattr__(self, "sha256", _identity(self.sha256, "artifact sha256"))
        if type(self.artifact_type) is not str or not 1 <= len(self.artifact_type) <= 128:
            raise EvidenceValidationError("artifact_type must contain 1..128 characters")
        _no_unpaired_surrogate(self.artifact_type, "artifact_type")
        if "\x00" in self.artifact_type:
            raise EvidenceValidationError("artifact_type contains NUL")
        if self.schema_version is not None:
            if type(self.schema_version) is not str:
                raise EvidenceValidationError("artifact schema_version must be string or null")
            _no_unpaired_surrogate(self.schema_version, "artifact schema_version")
            if "\x00" in self.schema_version:
                raise EvidenceValidationError("artifact schema_version contains NUL")

    def to_dict(self) -> dict[str, object]:
        return {"relative_path":self.relative_path,"byte_size":self.byte_size,"sha256":self.sha256,"artifact_type":self.artifact_type,"schema_version":self.schema_version}

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "FrozenEvidenceArtifact":
        required={"relative_path","byte_size","sha256","artifact_type","schema_version"}
        if not isinstance(value, Mapping) or set(value) != required:
            raise EvidenceValidationError("evidence artifact fields are not exact")
        return cls(relative_path=value["relative_path"],byte_size=value["byte_size"],sha256=value["sha256"],artifact_type=value["artifact_type"],schema_version=value["schema_version"])


def _frozen_artifact(value: object) -> FrozenEvidenceArtifact:
    if isinstance(value, FrozenEvidenceArtifact):
        return FrozenEvidenceArtifact.from_mapping(value.to_dict())
    if isinstance(value, Mapping):
        return FrozenEvidenceArtifact.from_mapping(value)
    raise EvidenceValidationError("evidence artifact is not a frozen artifact record")


@dataclass(frozen=True, slots=True)
class FrozenEvidenceManifest:
    run_identity: str
    artifacts: tuple[FrozenEvidenceArtifact, ...]
    observational_metadata: Mapping[str, object] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION
    manifest_identity: str | None = None

    def __post_init__(self) -> None:
        try:
            validate_schema_version(FROZEN_EVIDENCE_MANIFEST_SCHEMA_ID, self.schema_version)
        except ValueError as exc:
            raise EvidenceValidationError(str(exc)) from exc
        object.__setattr__(self, "run_identity", _identity(self.run_identity, "run_identity"))
        if isinstance(self.artifacts, (str, bytes)) or not isinstance(self.artifacts, Sequence):
            raise EvidenceValidationError("artifacts must be an array")
        artifacts = tuple(_frozen_artifact(item) for item in self.artifacts)
        if tuple(item.relative_path for item in artifacts) != tuple(sorted(item.relative_path for item in artifacts)):
            raise EvidenceValidationError("artifacts must be sorted by relative_path")
        if len({item.relative_path for item in artifacts}) != len(artifacts):
            raise EvidenceValidationError("artifact relative_path values must be unique")
        if any(item.artifact_type == FINAL_RESULT_SCHEMA_ID for item in artifacts):
            raise EvidenceValidationError("pre-final manifest must not contain a final-result artifact")
        object.__setattr__(self, "artifacts", artifacts)
        object.__setattr__(self, "observational_metadata", _plain_mapping(self.observational_metadata, "observational_metadata"))
        computed = sha256_canonical(self.identity_payload())
        if self.manifest_identity is None:
            object.__setattr__(self, "manifest_identity", computed)
        elif _identity(self.manifest_identity, "manifest_identity") != computed:
            raise EvidenceValidationError("manifest_identity does not match frozen manifest inputs")

    @property
    def artifact_count(self) -> int:
        return len(self.artifacts)

    def identity_payload(self) -> dict[str, object]:
        return {"schema_version":self.schema_version,"run_identity":self.run_identity,"artifact_count":self.artifact_count,"artifacts":[item.to_dict() for item in self.artifacts]}

    def to_dict(self) -> dict[str, object]:
        result={**self.identity_payload(),"manifest_identity":self.manifest_identity}
        if self.observational_metadata:
            result["observational_metadata"]=dict(self.observational_metadata)
        return result

    def canonical_bytes(self) -> bytes:
        qualified=FrozenEvidenceManifest.from_mapping(self.to_dict())
        return canonical_json_bytes(qualified.to_dict(), identity_critical=False)

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "FrozenEvidenceManifest":
        required={"schema_version","run_identity","artifact_count","artifacts","manifest_identity"}; allowed=required|{"observational_metadata"}
        if not isinstance(value, Mapping) or required-set(value) or set(value)-allowed:
            raise EvidenceValidationError("frozen evidence manifest fields are not exact")
        if type(value["artifact_count"]) is not int or value["artifact_count"] < 0:
            raise EvidenceValidationError("artifact_count must be a non-negative integer")
        if not isinstance(value["artifacts"], (list, tuple)):
            raise EvidenceValidationError("artifacts must be an array")
        artifacts=tuple(_frozen_artifact(item) for item in value["artifacts"])
        if value["artifact_count"] != len(artifacts):
            raise EvidenceValidationError("artifact_count does not equal artifacts length")
        if "observational_metadata" in value and value["observational_metadata"] is None:
            raise EvidenceValidationError("observational_metadata must not be null")
        return cls(run_identity=value["run_identity"],artifacts=artifacts,observational_metadata=value.get("observational_metadata",{}),schema_version=value["schema_version"],manifest_identity=value["manifest_identity"])


@dataclass(frozen=True, slots=True)
class FinalResultRecord:
    run_identity: str
    terminal_state: str
    verification_result: str
    human_decision_if_any: str | None
    failure_if_any: str | None
    proposal_identity_if_any: str | None
    evidence_manifest_identity: str
    metrics_identity: str
    observational_metadata: Mapping[str, object] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION
    final_result_identity: str | None = None

    def __post_init__(self) -> None:
        try:
            validate_schema_version(FINAL_RESULT_SCHEMA_ID, self.schema_version)
        except ValueError as exc:
            raise EvidenceValidationError(str(exc)) from exc
        object.__setattr__(self, "run_identity", _identity(self.run_identity, "run_identity"))
        if type(self.terminal_state) is not str or self.terminal_state not in _FINAL_TERMINAL_STATES:
            raise EvidenceValidationError("terminal_state is outside the frozen final-result enum")
        if type(self.verification_result) is not str or self.verification_result not in _VERIFICATION_RESULTS:
            raise EvidenceValidationError("verification_result is outside the frozen enum")
        if self.human_decision_if_any is not None and (type(self.human_decision_if_any) is not str or self.human_decision_if_any not in _HUMAN_DECISIONS):
            raise EvidenceValidationError("human_decision_if_any is outside the frozen enum")
        object.__setattr__(self, "failure_if_any", None if self.failure_if_any is None else _identity(self.failure_if_any, "failure_if_any"))
        object.__setattr__(self, "proposal_identity_if_any", None if self.proposal_identity_if_any is None else _identity(self.proposal_identity_if_any, "proposal_identity_if_any"))
        object.__setattr__(self, "evidence_manifest_identity", _identity(self.evidence_manifest_identity, "evidence_manifest_identity"))
        object.__setattr__(self, "metrics_identity", _identity(self.metrics_identity, "metrics_identity"))
        object.__setattr__(self, "observational_metadata", _plain_mapping(self.observational_metadata, "observational_metadata"))
        _validate_final_terminal_semantics(self)
        computed=sha256_canonical(self.identity_payload())
        if self.final_result_identity is None:
            object.__setattr__(self, "final_result_identity", computed)
        elif _identity(self.final_result_identity, "final_result_identity") != computed:
            raise EvidenceValidationError("final_result_identity does not match frozen final inputs")

    def identity_payload(self) -> dict[str, object]:
        return {"schema_version":self.schema_version,"run_identity":self.run_identity,"terminal_state":self.terminal_state,"verification_result":self.verification_result,"human_decision_if_any":self.human_decision_if_any,"failure_if_any":self.failure_if_any,"proposal_identity_if_any":self.proposal_identity_if_any,"evidence_manifest_identity":self.evidence_manifest_identity,"metrics_identity":self.metrics_identity}

    def to_dict(self) -> dict[str, object]:
        result={**self.identity_payload(),"final_result_identity":self.final_result_identity}
        if self.observational_metadata:
            result["observational_metadata"]=dict(self.observational_metadata)
        return result

    def canonical_bytes(self) -> bytes:
        raise EvidenceValidationError(
            "FinalResult canonicalization requires exact qualified upstream dependencies"
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "FinalResultRecord":
        required={"schema_version","run_identity","terminal_state","verification_result","human_decision_if_any","failure_if_any","proposal_identity_if_any","evidence_manifest_identity","metrics_identity","final_result_identity"}; allowed=required|{"observational_metadata"}
        if not isinstance(value, Mapping) or required-set(value) or set(value)-allowed:
            raise EvidenceValidationError("final-result fields are not exact")
        if "observational_metadata" in value and value["observational_metadata"] is None:
            raise EvidenceValidationError("observational_metadata must not be null")
        return cls(run_identity=value["run_identity"],terminal_state=value["terminal_state"],verification_result=value["verification_result"],human_decision_if_any=value["human_decision_if_any"],failure_if_any=value["failure_if_any"],proposal_identity_if_any=value["proposal_identity_if_any"],evidence_manifest_identity=value["evidence_manifest_identity"],metrics_identity=value["metrics_identity"],observational_metadata=value.get("observational_metadata",{}),schema_version=value["schema_version"],final_result_identity=value["final_result_identity"])


def _validate_final_terminal_semantics(record: FinalResultRecord) -> None:
    if record.proposal_identity_if_any is None:
        raise EvidenceValidationError("FinalResult v1 requires a qualified proposal identity")
    state=record.terminal_state; verification=record.verification_result; decision=record.human_decision_if_any; failure=record.failure_if_any
    if state == "VERIFIED_DENY": valid=verification == "DENY" and decision is None and failure is None
    elif state == "VERIFIED_ESCALATE": valid=verification == "ESCALATE" and decision is None and failure is None
    elif state == "VERIFIED_PASS_FOR_REVIEW": valid=verification == "PASS_FOR_REVIEW" and decision is None and failure is None
    elif state == "HUMAN_APPROVED": valid=verification == "PASS_FOR_REVIEW" and decision == "APPROVE" and failure is None
    elif state == "HUMAN_REJECTED": valid=decision == "REJECT" and failure is None
    elif state == "HUMAN_REWORK": valid=verification in ("ESCALATE","PASS_FOR_REVIEW") and decision == "REQUEST_REWORK" and failure is None
    elif state == "HUMAN_MORE_EVIDENCE": valid=verification in ("ESCALATE","PASS_FOR_REVIEW") and decision == "REQUEST_MORE_EVIDENCE" and failure is None
    else: valid=failure is not None and (decision is None or decision in _DECISIONS_BY_VERIFICATION[verification])
    if not valid:
        raise EvidenceValidationError("final-result fields do not match the frozen terminal-state semantics")



def _qualified_frozen_run(value: object) -> FrozenRunRecord:
    if isinstance(value, FrozenRunRecord): return FrozenRunRecord.from_mapping(value.to_dict())
    if isinstance(value, Mapping): return FrozenRunRecord.from_mapping(value)
    raise EvidenceValidationError("run_record must be a qualified frozen run")


def _qualified_frozen_manifest(value: object) -> FrozenEvidenceManifest:
    if isinstance(value, FrozenEvidenceManifest): return FrozenEvidenceManifest.from_mapping(value.to_dict())
    if isinstance(value, Mapping): return FrozenEvidenceManifest.from_mapping(value)
    raise EvidenceValidationError("manifest must be a qualified frozen pre-final manifest")


def _qualified_failure_records(values: object) -> tuple[object, ...]:
    from .failures import Failure
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise EvidenceValidationError("verifier_failure_records must be an array")
    records=[]
    for value in values:
        try:
            record=Failure.from_mapping(value.to_dict() if isinstance(value,Failure) else value)
        except (TypeError,ValueError,AttributeError) as exc:
            raise EvidenceValidationError(f"verifier failure record is invalid: {exc}") from exc
        records.append(record)
    identities=[record.failure_identity for record in records]
    if len(set(identities)) != len(identities):
        raise EvidenceValidationError("verifier_failure_records contain duplicate identities")
    return tuple(records)


@dataclass(frozen=True, slots=True)
class _QualifiedFinalUpstream:
    run: object
    bounded_context: object
    disclosure: object
    cloud_context: object
    cloud_request: object
    proposal: object
    metric: object
    legacy_verifier: object
    verification: object
    verifier_failures: tuple[object, ...]
    gate: object | None
    decision: object | None
    failure: object | None


def _qualified_upstream_records(
    *,
    run_record: object,
    bounded_context_record: object,
    disclosure_record: object,
    cloud_context_record: object,
    cloud_request_record: object,
    proposal_record: object,
    verification_record: object,
    metrics_record: object,
    legacy_verifier_result: object,
    verifier_failure_records: object=(),
    human_gate_record: object=None,
    human_decision_record: object=None,
    failure_record: object=None,
) -> _QualifiedFinalUpstream:
    from . import (
        cloud_boundary as cloud_boundary_module,
        context_builder as context_builder_module,
        disclosure as disclosure_module,
        human_gate as human_gate_module,
        metrics as metrics_module,
        proposal as proposal_module,
        verifier as verifier_module,
    )
    from .failures import Failure

    run=_qualified_frozen_run(run_record)
    verifier_failures=_qualified_failure_records(verifier_failure_records)
    try:
        bounded_context=context_builder_module.BoundedContextPackage.from_mapping(
            bounded_context_record.to_dict()
            if isinstance(bounded_context_record,context_builder_module.BoundedContextPackage)
            else bounded_context_record
        )
        disclosure=disclosure_module.DisclosureRecord.from_mapping(
            disclosure_record.to_dict()
            if isinstance(disclosure_record,disclosure_module.DisclosureRecord)
            else disclosure_record
        )
        cloud_context=cloud_boundary_module.CloudContext.from_mapping(
            cloud_context_record.to_dict()
            if isinstance(cloud_context_record,cloud_boundary_module.CloudContext)
            else cloud_context_record
        )
        cloud_request=cloud_boundary_module.CloudRequest.from_mapping(
            cloud_request_record.to_dict()
            if isinstance(cloud_request_record,cloud_boundary_module.CloudRequest)
            else cloud_request_record
        )
        proposal=proposal_module.CloudProposal.from_mapping(
            proposal_record.to_dict()
            if isinstance(proposal_record,proposal_module.CloudProposal)
            else proposal_record
        )
        metric=metrics_module.Metrics.from_mapping(
            metrics_record.to_dict()
            if isinstance(metrics_record,metrics_module.Metrics)
            else metrics_record
        )
        legacy_verifier=verifier_module.VerifierResult.from_mapping(
            legacy_verifier_result.to_dict()
            if isinstance(legacy_verifier_result,verifier_module.VerifierResult)
            else legacy_verifier_result,
            failure_records=verifier_failures,
        )
        verification=verifier_module.VerificationRecord.from_mapping(
            verification_record.to_dict()
            if isinstance(verification_record,verifier_module.VerificationRecord)
            else verification_record
        )
    except (TypeError,ValueError,AttributeError,KeyError) as exc:
        raise EvidenceValidationError(f"authoritative upstream record is invalid: {exc}") from exc

    package_inputs=bounded_context.input_identities
    for field, expected in (
        ("task_identity",run.task_identity),
        ("source_set_identity",run.source_set_identity),
        ("discovery_identity",run.discovery_identity),
        ("normalization_identity",run.normalization_identity),
    ):
        if package_inputs[field] != expected:
            raise EvidenceValidationError(f"bounded context {field} is not bound to the frozen run")

    expected_context_budget={
        "budget_identity":run.byte_budget["budget_identity"],
        "max_cloud_context_bytes":run.byte_budget["max_cloud_context_bytes"],
        "overflow_policy":run.byte_budget["overflow_policy"],
        "silent_truncation":run.byte_budget["silent_truncation"],
    }
    try:
        reconstructed_context=cloud_boundary_module.admit_cloud_context(
            bounded_context,
            disclosure,
            run_identity=run.run_identity,
            mr03_package_identity=run.mr03_result_identity,
            mr04_result_identity=run.mr04_result_identity,
            byte_budget=expected_context_budget,
            estimated_token_metadata=dict(cloud_context.estimated_token_metadata),
            prohibited_assumptions=tuple(cloud_context.prohibited_assumptions),
            observational_metadata=(
                None
                if cloud_context.observational_metadata is None
                else dict(cloud_context.observational_metadata)
            ),
        )
    except (TypeError,ValueError,AttributeError,KeyError) as exc:
        raise EvidenceValidationError(f"cloud context cannot be authoritatively reconstructed: {exc}") from exc
    if reconstructed_context.to_dict() != cloud_context.to_dict():
        raise EvidenceValidationError("supplied cloud context does not equal authoritative reconstruction")

    for observed, expected, label in (
        (cloud_context.run_identity,run.run_identity,"run_identity"),
        (cloud_context.task_identity,run.task_identity,"task_identity"),
        (cloud_context.source_set_identity,run.source_set_identity,"source_set_identity"),
        (cloud_context.mr03_package_identity,run.mr03_result_identity,"mr03_package_identity"),
        (cloud_context.mr04_result_identity,run.mr04_result_identity,"mr04_result_identity"),
    ):
        if observed != expected:
            raise EvidenceValidationError(f"cloud context {label} is not bound to the frozen run")

    try:
        reconstructed_request=cloud_boundary_module.build_cloud_request(
            cloud_context,
            model_identifier=cloud_request.model_identifier,
            human_authorization_reference=cloud_request.human_authorization_reference,
            observational_metadata=(
                None
                if cloud_request.observational_metadata is None
                else dict(cloud_request.observational_metadata)
            ),
        )
    except (TypeError,ValueError,AttributeError,KeyError) as exc:
        raise EvidenceValidationError(f"cloud request cannot be authoritatively reconstructed: {exc}") from exc
    if reconstructed_request.to_dict() != cloud_request.to_dict():
        raise EvidenceValidationError("supplied cloud request does not equal authoritative reconstruction")
    if cloud_request.run_identity != run.run_identity:
        raise EvidenceValidationError("cloud request is not bound to the frozen run")
    if cloud_request.context_identity != cloud_context.context_identity:
        raise EvidenceValidationError("cloud request is not bound to the qualified cloud context")

    if metric.metrics_identity != bounded_context.metrics_identity:
        raise EvidenceValidationError("metrics are not bound to the qualified bounded context")
    if metric.metrics_identity != legacy_verifier.metrics_identity:
        raise EvidenceValidationError("metrics are not bound to the qualified legacy verifier result")

    legacy_inputs=legacy_verifier.input_identities
    for field, expected in (
        ("task_identity",run.task_identity),
        ("source_set_identity",run.source_set_identity),
        ("discovery_identity",run.discovery_identity),
        ("normalization_identity",run.normalization_identity),
        ("context_identity",cloud_context.context_identity),
    ):
        if legacy_inputs[field] != expected:
            raise EvidenceValidationError(f"legacy verifier {field} is not bound to the authoritative chain")
    if tuple(legacy_verifier.dependency_binding_identities) != tuple(bounded_context.dependency_binding_identities):
        raise EvidenceValidationError("legacy verifier dependency bindings do not match the qualified bounded context")
    if legacy_verifier.provenance_identity != bounded_context.provenance_identity:
        raise EvidenceValidationError("legacy verifier provenance identity does not match the qualified bounded context")

    required_verifier_failure_ids=tuple(legacy_verifier.failure_identities)
    supplied_verifier_failure_ids=tuple(sorted(record.failure_identity for record in verifier_failures))
    if supplied_verifier_failure_ids != required_verifier_failure_ids:
        raise EvidenceValidationError("verifier failure evidence set does not exactly match legacy verifier failure identities")
    if any(record.run_identity != run.run_identity for record in verifier_failures):
        raise EvidenceValidationError("verifier failure record is not bound to the frozen run")

    if proposal.run_identity != run.run_identity:
        raise EvidenceValidationError("proposal is not bound to the frozen run")
    if proposal.task_identity != run.task_identity:
        raise EvidenceValidationError("proposal task identity is not bound to the frozen run")
    if proposal.request_identity != cloud_request.request_identity:
        raise EvidenceValidationError("proposal request identity is not bound to the qualified cloud request")
    if proposal.bound_context_identity != cloud_context.context_identity:
        raise EvidenceValidationError("proposal context identity is not bound to the qualified cloud context")
    if proposal.bound_mr03_package_identity != run.mr03_result_identity or proposal.bound_mr03_package_identity != cloud_context.mr03_package_identity:
        raise EvidenceValidationError("proposal MR03 identity is not bound to the authoritative chain")
    if proposal.bound_mr04_result_identity != run.mr04_result_identity or proposal.bound_mr04_result_identity != cloud_context.mr04_result_identity:
        raise EvidenceValidationError("proposal MR04 identity is not bound to the authoritative chain")

    try:
        adapted_verification=verifier_module.validate_verification_adapter(
            verification,
            proposal=proposal,
            context=cloud_context,
            legacy_result=legacy_verifier,
            failure_records=verifier_failures,
        )
    except (TypeError,ValueError,AttributeError,KeyError) as exc:
        raise EvidenceValidationError(f"public verification is not authoritative-adapter qualified: {exc}") from exc
    if adapted_verification != verification:
        raise EvidenceValidationError("authoritative verification adapter changed the supplied public verification")

    gate=None
    if human_gate_record is not None:
        try:
            gate=human_gate_module.HumanGateRecord.from_mapping(
                human_gate_record.to_dict()
                if isinstance(human_gate_record,human_gate_module.HumanGateRecord)
                else human_gate_record
            )
        except (TypeError,ValueError,AttributeError) as exc:
            raise EvidenceValidationError(f"Human Gate record is invalid: {exc}") from exc
    decision=None
    if human_decision_record is not None:
        if gate is None:
            raise EvidenceValidationError("Human Decision requires its qualified Human Gate record")
        try:
            decision=human_gate_module.HumanDecisionRecord.from_mapping(
                human_decision_record.to_dict()
                if isinstance(human_decision_record,human_gate_module.HumanDecisionRecord)
                else human_decision_record,
                human_gate=gate,
            )
        except (TypeError,ValueError,AttributeError) as exc:
            raise EvidenceValidationError(f"Human Decision record is invalid: {exc}") from exc
    failure=None
    if failure_record is not None:
        try:
            failure=Failure.from_mapping(
                failure_record.to_dict() if isinstance(failure_record,Failure) else failure_record
            )
        except (TypeError,ValueError,AttributeError) as exc:
            raise EvidenceValidationError(f"Failure record is invalid: {exc}") from exc

    if verification.proposal_identity != proposal.proposal_identity:
        raise EvidenceValidationError("verification is not bound to the proposal")
    if gate is not None:
        if gate.run_identity != run.run_identity or gate.proposal_identity != proposal.proposal_identity:
            raise EvidenceValidationError("Human Gate is not bound to the run/proposal")
        if gate.task_identity != proposal.task_identity:
            raise EvidenceValidationError("Human Gate task identity is not bound to the proposal")
        if gate.verification_identity != verification.verification_identity:
            raise EvidenceValidationError("Human Gate is not bound to the verification")
        if gate.package_identity != proposal.bound_package_identity:
            raise EvidenceValidationError("Human Gate package identity is not bound to the proposal transport metadata")
        if gate.context_identity != proposal.bound_context_identity:
            raise EvidenceValidationError("Human Gate context identity is not bound to the proposal")
        if gate.verification_result != verification.verification_result:
            raise EvidenceValidationError("Human Gate verification result is not bound to the verification")
    if decision is not None and decision.human_gate_identity != gate.human_gate_identity:
        raise EvidenceValidationError("Human Decision is not bound to the Human Gate")
    if failure is not None:
        if failure.run_identity != run.run_identity:
            raise EvidenceValidationError("Failure is not bound to the frozen run")
        allowed_related_identities={
            run.run_identity,
            proposal.proposal_identity,
            verification.verification_identity,
            metric.metrics_identity,
        }
        if gate is not None:
            allowed_related_identities.add(gate.human_gate_identity)
        if decision is not None:
            allowed_related_identities.add(decision.decision_identity)
        if failure.related_identity not in allowed_related_identities:
            raise EvidenceValidationError("Failure related_identity is not bound to a qualified upstream record")

    return _QualifiedFinalUpstream(
        run=run,
        bounded_context=bounded_context,
        disclosure=disclosure,
        cloud_context=cloud_context,
        cloud_request=cloud_request,
        proposal=proposal,
        metric=metric,
        legacy_verifier=legacy_verifier,
        verification=verification,
        verifier_failures=verifier_failures,
        gate=gate,
        decision=decision,
        failure=failure,
    )


def _artifact_from_bytes(relative_path: str, artifact_type: str, schema_version: str|None, content: bytes) -> FrozenEvidenceArtifact:
    return FrozenEvidenceArtifact(relative_path=relative_path,byte_size=len(content),sha256=hashlib.sha256(content).hexdigest(),artifact_type=artifact_type,schema_version=schema_version)


def _required_upstream_artifacts(records: _QualifiedFinalUpstream) -> tuple[FrozenEvidenceArtifact,...]:
    from . import cloud_boundary as cloud_boundary_module, disclosure as disclosure_module, human_gate as human_gate_module, proposal as proposal_module, verifier as verifier_module
    artifacts=[
        _artifact_from_bytes("cloud/context.json",cloud_boundary_module.CLOUD_CONTEXT_SCHEMA_ID,records.cloud_context.schema_version,records.cloud_context.canonical_bytes()),
        _artifact_from_bytes("cloud/request.json",cloud_boundary_module.CLOUD_REQUEST_SCHEMA_ID,records.cloud_request.schema_version,records.cloud_request.canonical_bytes()),
        _artifact_from_bytes("context/bounded_context.json",records.bounded_context.schema_id,records.bounded_context.schema_version,records.bounded_context.canonical_bytes()),
        _artifact_from_bytes("disclosure/disclosure.json",disclosure_module.DISCLOSURE_SCHEMA_ID,records.disclosure.schema_version,canonical_json_bytes(records.disclosure.to_dict(),identity_critical=False)),
        _artifact_from_bytes("metrics/metrics.json","mr05.metrics",records.metric.schema_version,records.metric.canonical_bytes()),
        _artifact_from_bytes("proposal/proposal.json","mr05.cloud_proposal",records.proposal.schema_version,proposal_module.canonical_cloud_proposal_bytes(records.proposal)),
        _artifact_from_bytes("run/run.json",FROZEN_RUN_SCHEMA_ID,records.run.schema_version,records.run.canonical_bytes()),
        _artifact_from_bytes("verification/legacy_verifier.json",records.legacy_verifier.schema_id,records.legacy_verifier.schema_version,verifier_module.canonical_verifier_bytes(records.legacy_verifier)),
        _artifact_from_bytes("verification/verification.json","mr05.verification",records.verification.schema_version,verifier_module.canonical_verification_bytes(records.verification)),
    ]
    for verifier_failure in records.verifier_failures:
        artifacts.append(_artifact_from_bytes(
            f"verification/failures/{verifier_failure.failure_identity}.json",
            "mr05.failure",
            verifier_failure.schema_version,
            verifier_failure.canonical_bytes(),
        ))
    if records.gate is not None:
        artifacts.append(_artifact_from_bytes("human_gate/human_gate.json","mr05.human_gate",records.gate.schema_version,human_gate_module.canonical_human_gate_bytes(records.gate)))
    if records.decision is not None:
        artifacts.append(_artifact_from_bytes("human_gate/human_decision.json","mr05.human_decision",records.decision.schema_version,human_gate_module.canonical_human_decision_bytes(records.decision)))
    if records.failure is not None:
        artifacts.append(_artifact_from_bytes("failure/failure.json","mr05.failure",records.failure.schema_version,records.failure.canonical_bytes()))
    return tuple(sorted(artifacts,key=lambda item:item.relative_path))


def build_pre_final_evidence_manifest(
    *,
    run_record: object,
    bounded_context_record: object,
    disclosure_record: object,
    cloud_context_record: object,
    cloud_request_record: object,
    proposal_record: object,
    verification_record: object,
    metrics_record: object,
    legacy_verifier_result: object,
    verifier_failure_records: object=(),
    human_gate_record: object=None,
    human_decision_record: object=None,
    failure_record: object=None,
    additional_artifacts: Sequence[object]=(),
    observational_metadata: Mapping[str,object]|None=None,
) -> FrozenEvidenceManifest:
    records=_qualified_upstream_records(
        run_record=run_record,
        bounded_context_record=bounded_context_record,
        disclosure_record=disclosure_record,
        cloud_context_record=cloud_context_record,
        cloud_request_record=cloud_request_record,
        proposal_record=proposal_record,
        verification_record=verification_record,
        metrics_record=metrics_record,
        legacy_verifier_result=legacy_verifier_result,
        verifier_failure_records=verifier_failure_records,
        human_gate_record=human_gate_record,
        human_decision_record=human_decision_record,
        failure_record=failure_record,
    )
    required=list(_required_upstream_artifacts(records))
    extras=[_frozen_artifact(item) for item in additional_artifacts]
    return FrozenEvidenceManifest(
        run_identity=records.run.run_identity,
        artifacts=tuple(sorted(required+extras,key=lambda item:item.relative_path)),
        observational_metadata={} if observational_metadata is None else observational_metadata,
    )


def _require_manifest_members(manifest: FrozenEvidenceManifest, expected: Sequence[FrozenEvidenceArtifact]) -> None:
    by_path={item.relative_path:item for item in manifest.artifacts}
    for item in expected:
        if by_path.get(item.relative_path) != item:
            raise EvidenceValidationError(f"pre-final manifest does not bind exact upstream bytes for {item.relative_path}")


def build_final_result(
    *,
    terminal_state: str,
    run_record: object,
    manifest: object,
    bounded_context_record: object,
    disclosure_record: object,
    cloud_context_record: object,
    cloud_request_record: object,
    metrics_record: object,
    proposal_record: object,
    verification_record: object,
    legacy_verifier_result: object,
    verifier_failure_records: object=(),
    human_gate_record: object=None,
    human_decision_record: object=None,
    failure_record: object=None,
    observational_metadata: Mapping[str,object]|None=None,
) -> FinalResultRecord:
    records=_qualified_upstream_records(
        run_record=run_record,
        bounded_context_record=bounded_context_record,
        disclosure_record=disclosure_record,
        cloud_context_record=cloud_context_record,
        cloud_request_record=cloud_request_record,
        proposal_record=proposal_record,
        verification_record=verification_record,
        metrics_record=metrics_record,
        legacy_verifier_result=legacy_verifier_result,
        verifier_failure_records=verifier_failure_records,
        human_gate_record=human_gate_record,
        human_decision_record=human_decision_record,
        failure_record=failure_record,
    )
    frozen_manifest=_qualified_frozen_manifest(manifest)
    if records.run.state != terminal_state:
        raise EvidenceValidationError("frozen run state does not match final terminal_state")
    if frozen_manifest.run_identity != records.run.run_identity:
        raise EvidenceValidationError("pre-final manifest is not bound to the frozen run")
    _require_manifest_members(frozen_manifest,_required_upstream_artifacts(records))
    return FinalResultRecord(
        run_identity=records.run.run_identity,
        terminal_state=terminal_state,
        verification_result=records.verification.verification_result,
        human_decision_if_any=None if records.decision is None else records.decision.decision,
        failure_if_any=None if records.failure is None else records.failure.failure_identity,
        proposal_identity_if_any=records.proposal.proposal_identity,
        evidence_manifest_identity=frozen_manifest.manifest_identity,
        metrics_identity=records.metric.metrics_identity,
        observational_metadata={} if observational_metadata is None else observational_metadata,
    )


def canonical_final_result_bytes(
    value: FinalResultRecord | Mapping[str, object],
    *,
    run_record: object,
    manifest: object,
    bounded_context_record: object,
    disclosure_record: object,
    cloud_context_record: object,
    cloud_request_record: object,
    metrics_record: object,
    proposal_record: object,
    verification_record: object,
    legacy_verifier_result: object,
    verifier_failure_records: object=(),
    human_gate_record: object=None,
    human_decision_record: object=None,
    failure_record: object=None,
) -> bytes:
    record=value if isinstance(value,FinalResultRecord) else FinalResultRecord.from_mapping(value)
    expected=build_final_result(
        terminal_state=record.terminal_state,
        run_record=run_record,
        manifest=manifest,
        bounded_context_record=bounded_context_record,
        disclosure_record=disclosure_record,
        cloud_context_record=cloud_context_record,
        cloud_request_record=cloud_request_record,
        metrics_record=metrics_record,
        proposal_record=proposal_record,
        verification_record=verification_record,
        legacy_verifier_result=legacy_verifier_result,
        verifier_failure_records=verifier_failure_records,
        human_gate_record=human_gate_record,
        human_decision_record=human_decision_record,
        failure_record=failure_record,
        observational_metadata=dict(record.observational_metadata),
    )
    if expected != record:
        raise EvidenceValidationError("FinalResult record does not match exact qualified upstream dependencies")
    return canonical_json_bytes(expected.to_dict(),identity_critical=False)


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
    "FROZEN_RUN_SCHEMA_ID", "FROZEN_EVIDENCE_MANIFEST_SCHEMA_ID", "FINAL_RESULT_SCHEMA_ID",
    "FINAL_RESULT_IMPLEMENTATION_COUNT", "FINAL_RESULT_EXECUTION_COUNT",
    "FINAL_RESULT_HUMAN_APPROVAL_EXECUTION_COUNT", "FINAL_RESULT_STATE_TRANSITION_EXECUTION_COUNT",
    "FINAL_RESULT_NETWORK_IMPLEMENTATION_COUNT", "FINAL_RESULT_PROVIDER_CLIENT_IMPLEMENTATION_COUNT",
    "FINAL_RESULT_MODEL_CALL_IMPLEMENTATION_COUNT", "FINAL_RESULT_AUTH_IMPLEMENTATION_COUNT",
    "FINAL_RESULT_GIT_OPERATION_COUNT", "FrozenRunRecord", "FrozenEvidenceArtifact",
    "FrozenEvidenceManifest", "FinalResultRecord", "build_frozen_run_record",
    "build_pre_final_evidence_manifest", "build_final_result", "canonical_final_result_bytes",
)
