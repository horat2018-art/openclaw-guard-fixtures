"""Deterministic SHA-256 and schema-bound identity primitives."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping

from .canonical import canonical_identity_bytes
from .contracts import (
    MR03_EXPECTED_COMMIT,
    MR04_EXPECTED_COMMIT,
    MR05A_CONTRACT_SHA256,
    MR05B_CONTRACT_SET_SHA256,
    MR05B_MASTER_CONTRACT_SHA256,
    MR05C_FROZEN_SKELETON_PATHSET_SHA256,
    MR05C_MATERIALIZATION_IDENTITY_SHA256,
    SCHEMA_VERSION,
    validate_schema_version,
)


IDENTITY_ALGORITHM = "SHA-256 over exact canonical UTF-8 bytes"
PATHSET_CANONICALIZATION = "UTF-8 repository-relative raw lexical sort one path per line LF exactly one terminal LF"
CONTENTSET_CANONICALIZATION = "sorted relative_path,size,sha256 records; compact UTF-8 JSON; one final LF"
IDENTITY_COMPUTATION_STATUS = "IMPLEMENTED_DETERMINISTIC_CORE"
HASH_ALGORITHM = "SHA256"
SHA256_LENGTH = 64
SHA256_PATTERN = r"^[0-9a-f]{64}$"
GIT_COMMIT_LENGTH = 40
GIT_COMMIT_PATTERN = r"^[0-9a-f]{40}$"

_SHA256_RE = re.compile(SHA256_PATTERN)
_GIT_COMMIT_RE = re.compile(GIT_COMMIT_PATTERN)


class IdentityValidationError(ValueError):
    """An identity input is not a valid frozen identity value."""


def sha256_bytes(data: bytes | bytearray | memoryview) -> str:
    """Hash exact bytes and return lowercase hexadecimal SHA-256."""

    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise IdentityValidationError("SHA-256 input must be bytes-like")
    try:
        return hashlib.sha256(bytes(data)).hexdigest()
    except (TypeError, ValueError) as exc:
        raise IdentityValidationError("SHA-256 input is invalid") from exc


def sha256_canonical(value: object) -> str:
    """Hash an identity-bearing value after frozen canonical serialization."""

    return sha256_bytes(canonical_identity_bytes(value))


def is_sha256(value: object) -> bool:
    """Return whether value is exactly a lowercase 64-character SHA-256."""

    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def require_sha256(value: object, *, field: str = "identity") -> str:
    """Return a valid lowercase SHA-256 or fail closed."""

    if not is_sha256(value):
        raise IdentityValidationError(f"{field} must be lowercase 64-character SHA-256")
    return value


def is_git_commit(value: object) -> bool:
    """Return whether value is a lowercase 40-character Git object id."""

    return isinstance(value, str) and _GIT_COMMIT_RE.fullmatch(value) is not None


def require_git_commit(value: object, *, field: str = "commit") -> str:
    """Return a valid frozen Git commit identity or fail closed."""

    if not is_git_commit(value):
        raise IdentityValidationError(f"{field} must be lowercase 40-character Git commit id")
    return value


def identity_from_fields(
    fields: Mapping[str, object],
    *,
    schema_version: str = SCHEMA_VERSION,
) -> str:
    """Hash fields with an explicit, exact schema-version binding."""

    if not isinstance(fields, Mapping):
        raise IdentityValidationError("identity fields must be a mapping")
    if schema_version != SCHEMA_VERSION:
        raise IdentityValidationError("unsupported identity schema version")
    payload = dict(fields)
    if "schema_version" in payload and payload["schema_version"] != schema_version:
        raise IdentityValidationError("identity schema version mismatch")
    payload["schema_version"] = schema_version
    return sha256_canonical(payload)


def schema_bound_identity(schema_id: str, fields: Mapping[str, object]) -> str:
    """Hash fields only when their schema id/version is frozen and supported."""

    if not isinstance(fields, Mapping):
        raise IdentityValidationError("identity fields must be a mapping")
    version = fields.get("schema_version", SCHEMA_VERSION)
    try:
        validate_schema_version(schema_id, version)
    except (TypeError, ValueError) as exc:
        raise IdentityValidationError(str(exc)) from exc
    return identity_from_fields(fields, schema_version=version)


# Explicit alias used by callers that name the operation by its output.
identity_sha256 = sha256_canonical


__all__ = (
    "IDENTITY_ALGORITHM", "PATHSET_CANONICALIZATION", "CONTENTSET_CANONICALIZATION",
    "IDENTITY_COMPUTATION_STATUS", "HASH_ALGORITHM", "SHA256_LENGTH", "SHA256_PATTERN",
    "GIT_COMMIT_LENGTH", "GIT_COMMIT_PATTERN", "IdentityValidationError", "sha256_bytes",
    "sha256_canonical", "identity_sha256", "is_sha256", "require_sha256", "is_git_commit",
    "require_git_commit", "identity_from_fields", "schema_bound_identity",
)
