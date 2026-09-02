"""Operational immutable source-acquisition boundary for MR-07.

This module performs one bounded local-filesystem capture under an explicitly
approved root and returns the existing MR-05 CapturedSource data model.
It has no subprocess, network, provider, model, auth, controller, human-gate,
evidence-persistence, retry, or fallback behavior.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import errno
import hashlib
import os
import stat
from typing import NoReturn

from .contracts import SCHEMA_VERSION
from .discovery import (
    CLASSIFICATIONS,
    CONTENT_KINDS,
    SOURCE_TYPES,
    CapturedSource,
    DiscoveryValidationError,
    SourceDescriptor,
    source_descriptor_identity,
    validate_relative_path,
    validate_source_alias,
)
from .failures import FailureCode
from .identity import sha256_canonical


ACQUISITION_POLICY_VERSION = "MR07A-SOURCE-ACQUISITION-V1"

FILESYSTEM_SOURCE_READ_COUNT = 1
FILESYSTEM_DEPENDENCY_EXECUTION_COUNT = 0
SUBPROCESS_EXECUTION_COUNT = 0
NETWORK_IMPLEMENTATION_COUNT = 0
MODEL_CALL_IMPLEMENTATION_COUNT = 0
PROVIDER_CLIENT_IMPLEMENTATION_COUNT = 0
AUTH_IMPLEMENTATION_COUNT = 0
CONTROLLER_IMPLEMENTATION_COUNT = 0
HUMAN_GATE_EXECUTION_COUNT = 0
EVIDENCE_PERSISTENCE_COUNT = 0
AUTO_RETRY_IMPLEMENTATION_COUNT = 0
AUTO_FALLBACK_IMPLEMENTATION_COUNT = 0


class SourceAcquisitionError(RuntimeError):
    """Fail-closed source-acquisition error using an existing MR-05 code."""

    def __init__(self, code: FailureCode | str, message: str) -> None:
        normalized = code.value if isinstance(code, FailureCode) else str(code)
        super().__init__(message)
        self.code = normalized
        self.failure_code = normalized
        self.retry_allowed = False


@dataclass(frozen=True, slots=True)
class AcquisitionResult:
    """Immutable capture plus deterministic root/capture identities."""

    captured_source: CapturedSource
    approved_root_identity: str
    capture_identity: str


@dataclass(frozen=True, slots=True)
class _ValidatedRoot:
    path: str
    state: tuple[int, int, int, int, int, int]


def _fail(code: FailureCode | str, message: str) -> NoReturn:
    raise SourceAcquisitionError(code, message)


def _state_tuple(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _validated_root(value: object) -> _ValidatedRoot:
    if type(value) is not str or not value or "\x00" in value or "\n" in value or "\r" in value:
        _fail(FailureCode.INVALID_SCHEMA, "approved_root must be a non-empty path string")
    if not os.path.isabs(value):
        _fail(FailureCode.SOURCE_PATH_ESCAPE, "approved_root must be absolute")
    if os.path.normpath(value) != value:
        _fail(FailureCode.SOURCE_PATH_ESCAPE, "approved_root is not an exact normalized path")
    try:
        info = os.lstat(value)
    except FileNotFoundError:
        _fail(FailureCode.SOURCE_PATH_ESCAPE, "approved_root does not exist")
    except OSError as exc:
        _fail(FailureCode.SOURCE_PATH_ESCAPE, f"approved_root cannot be inspected: {exc}")
    if stat.S_ISLNK(info.st_mode):
        _fail(FailureCode.SOURCE_PATH_ESCAPE, "approved_root must not be a symlink")
    if not stat.S_ISDIR(info.st_mode):
        _fail(FailureCode.SOURCE_PATH_ESCAPE, "approved_root must be a directory")
    if os.path.realpath(value) != value:
        _fail(FailureCode.SOURCE_PATH_ESCAPE, "approved_root realpath substitution detected")
    return _ValidatedRoot(value, _state_tuple(info))


def approved_root_identity(approved_root: object) -> str:
    """Compute identity from an already-authorized exact root path.

    This function intentionally performs no filesystem resolution. The capture
    boundary calls it only after its single  operation.
    """
    if type(approved_root) is not str or not approved_root:
        _fail(FailureCode.INVALID_SCHEMA, "approved_root identity input must be a path string")
    return sha256_canonical({
        "schema_version": SCHEMA_VERSION,
        "acquisition_policy_version": ACQUISITION_POLICY_VERSION,
        "approved_root": approved_root,
    })


def _validated_relative_path(value: object) -> str:
    try:
        return validate_relative_path(value)
    except DiscoveryValidationError as exc:
        _fail(FailureCode.SOURCE_PATH_ESCAPE, str(exc))
    except (TypeError, ValueError) as exc:
        _fail(FailureCode.SOURCE_PATH_ESCAPE, str(exc))


def _validate_metadata(*, source_type: object, source_alias: object, classification: object,
                       provenance_owner: object, content_kind: object,
                       observational_metadata: object) -> tuple[str, str, str, str, str | None, Mapping[str, object]]:
    if type(source_type) is not str or source_type not in SOURCE_TYPES:
        _fail(FailureCode.INVALID_SCHEMA, "source_type is invalid")
    try:
        alias = validate_source_alias(source_alias)
    except (DiscoveryValidationError, TypeError, ValueError) as exc:
        _fail(FailureCode.INVALID_SCHEMA, f"source_alias is invalid: {exc}")
    if type(classification) is not str or classification not in CLASSIFICATIONS:
        _fail(FailureCode.INVALID_SCHEMA, "classification is invalid")
    if type(provenance_owner) is not str or not provenance_owner or len(provenance_owner) > 512:
        _fail(FailureCode.INVALID_SCHEMA, "provenance_owner is invalid")
    if "\x00" in provenance_owner or "\n" in provenance_owner or "\r" in provenance_owner:
        _fail(FailureCode.INVALID_SCHEMA, "provenance_owner contains an unsafe character")
    if content_kind is not None and (type(content_kind) is not str or content_kind not in CONTENT_KINDS):
        _fail(FailureCode.INVALID_SCHEMA, "content_kind is invalid")
    if not isinstance(observational_metadata, Mapping):
        _fail(FailureCode.INVALID_SCHEMA, "observational_metadata must be a mapping")
    return source_type, alias, classification, provenance_owner, content_kind, observational_metadata


def _directory_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _file_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    return flags


def _open_component(name: str, *, parent_fd: int, directory: bool) -> int:
    flags = _directory_flags() if directory else _file_flags()
    try:
        return os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        _fail(FailureCode.MR05_MISSING_SOURCE, "requested source does not exist")
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            _fail(FailureCode.MR05_MISSING_SOURCE, "requested source does not exist")
        _fail(FailureCode.SOURCE_PATH_ESCAPE, f"descriptor-relative source open failed closed: {exc}")


def _verify_directory_entry(parent_fd: int, name: str, child_fd: int) -> None:
    child = os.fstat(child_fd)
    if not stat.S_ISDIR(child.st_mode):
        _fail(FailureCode.SOURCE_PATH_ESCAPE, "intermediate source component is not a directory")
    try:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        _fail(FailureCode.SOURCE_PATH_ESCAPE, f"source directory entry changed during traversal: {exc}")
    if stat.S_ISLNK(current.st_mode) or (current.st_dev, current.st_ino) != (child.st_dev, child.st_ino):
        _fail(FailureCode.SOURCE_PATH_ESCAPE, "source directory entry substitution detected")


def _read_regular_file_once(root: _ValidatedRoot, relative_path: str) -> bytes:
    root_fd: int | None = None
    parent_fd: int | None = None
    opened_dirs: list[int] = []
    final_fd: int | None = None
    try:
        try:
            root_fd = os.open(root.path, _directory_flags())
        except OSError as exc:
            _fail(FailureCode.SOURCE_PATH_ESCAPE, f"approved_root open failed closed: {exc}")
        root_opened = os.fstat(root_fd)
        if not stat.S_ISDIR(root_opened.st_mode) or _state_tuple(root_opened) != root.state:
            _fail(FailureCode.SOURCE_PATH_ESCAPE, "approved_root substitution detected after validation")
        parent_fd = root_fd
        parts = relative_path.split("/")
        for part in parts[:-1]:
            child_fd = _open_component(part, parent_fd=parent_fd, directory=True)
            opened_dirs.append(child_fd)
            _verify_directory_entry(parent_fd, part, child_fd)
            parent_fd = child_fd
        final_fd = _open_component(parts[-1], parent_fd=parent_fd, directory=False)
        before = os.fstat(final_fd)
        if not stat.S_ISREG(before.st_mode):
            _fail(FailureCode.UNSUPPORTED_INPUT, "opened source is not a regular file")
        try:
            entry = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            _fail(FailureCode.SOURCE_PATH_ESCAPE, f"source entry changed during capture: {exc}")
        if stat.S_ISLNK(entry.st_mode) or (entry.st_dev, entry.st_ino) != (before.st_dev, before.st_ino):
            _fail(FailureCode.SOURCE_PATH_ESCAPE, "final source entry substitution detected")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(final_fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(final_fd)
        if _state_tuple(before) != _state_tuple(after):
            _fail(FailureCode.HASH_MISMATCH, "source changed during immutable capture")
        raw = b"".join(chunks)
        if len(raw) != after.st_size:
            _fail(FailureCode.HASH_MISMATCH, "captured byte count does not match opened source")
        return raw
    finally:
        if final_fd is not None:
            os.close(final_fd)
        for fd in reversed(opened_dirs):
            os.close(fd)
        if root_fd is not None:
            os.close(root_fd)


def _descriptor(*, source_type: str, source_alias: str, relative_path: str, raw_bytes: bytes,
                classification: str, provenance_owner: str, content_kind: str | None,
                observational_metadata: Mapping[str, object]) -> SourceDescriptor:
    digest = hashlib.sha256(raw_bytes).hexdigest()
    mapping: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "source_type": source_type,
        "canonical_locator": {"source_alias": source_alias, "relative_path": relative_path},
        "content_identity": {"algorithm": "SHA-256", "sha256": digest},
        "content_size_bytes": len(raw_bytes),
        "classification": classification,
        "immutability_status": "IMMUTABLE_CAPTURE",
        "availability_status": "AVAILABLE",
        "provenance_owner": provenance_owner,
    }
    if content_kind is not None:
        mapping["content_kind"] = content_kind
    if observational_metadata:
        mapping["observational_metadata"] = dict(observational_metadata)
    try:
        mapping["source_id"] = source_descriptor_identity(mapping)
        return SourceDescriptor.from_mapping(mapping)
    except DiscoveryValidationError as exc:
        _fail(FailureCode.INVALID_SCHEMA, f"source descriptor is invalid: {exc}")


def capture_source(*, approved_root: object, relative_path: object, source_alias: object,
                   provenance_owner: object, source_type: object = "LOCAL_FILE",
                   classification: object = "INTERNAL", content_kind: object = None,
                   observational_metadata: object = None) -> AcquisitionResult:
    root = _validated_root(approved_root)
    path = _validated_relative_path(relative_path)
    metadata = {} if observational_metadata is None else observational_metadata
    validated_type, alias, validated_classification, owner, validated_kind, observations = _validate_metadata(
        source_type=source_type, source_alias=source_alias, classification=classification,
        provenance_owner=provenance_owner, content_kind=content_kind, observational_metadata=metadata)
    root_identity = approved_root_identity(root.path)
    raw = _read_regular_file_once(root, path)
    descriptor = _descriptor(source_type=validated_type, source_alias=alias, relative_path=path,
        raw_bytes=raw, classification=validated_classification, provenance_owner=owner,
        content_kind=validated_kind, observational_metadata=observations)
    captured = CapturedSource(descriptor=descriptor, raw_bytes=raw)
    capture_identity = sha256_canonical({
        "schema_version": SCHEMA_VERSION,
        "acquisition_policy_version": ACQUISITION_POLICY_VERSION,
        "approved_root_identity": root_identity,
        "source_descriptor_identity": descriptor.source_id,
        "content_sha256": descriptor.content_sha256,
        "content_size_bytes": descriptor.content_size_bytes,
    })
    return AcquisitionResult(captured_source=captured, approved_root_identity=root_identity,
                             capture_identity=capture_identity)


__all__ = (
    "ACQUISITION_POLICY_VERSION", "FILESYSTEM_SOURCE_READ_COUNT",
    "FILESYSTEM_DEPENDENCY_EXECUTION_COUNT", "SUBPROCESS_EXECUTION_COUNT",
    "NETWORK_IMPLEMENTATION_COUNT", "MODEL_CALL_IMPLEMENTATION_COUNT",
    "PROVIDER_CLIENT_IMPLEMENTATION_COUNT", "AUTH_IMPLEMENTATION_COUNT",
    "CONTROLLER_IMPLEMENTATION_COUNT", "HUMAN_GATE_EXECUTION_COUNT",
    "EVIDENCE_PERSISTENCE_COUNT", "AUTO_RETRY_IMPLEMENTATION_COUNT",
    "AUTO_FALLBACK_IMPLEMENTATION_COUNT", "SourceAcquisitionError", "AcquisitionResult",
    "approved_root_identity", "capture_source",
)
