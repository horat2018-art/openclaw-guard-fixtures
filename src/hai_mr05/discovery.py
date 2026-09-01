"""Pure-data deterministic discovery primitives for MR-05.

This module deliberately operates only on caller-supplied source descriptors.
It does not inspect a machine, acquire bytes from a path, or invoke another
phase. A caller may supply a :class:`CapturedSource` when it already owns an
immutable byte capture; the bytes are checked and then never exposed by the
resulting discovery manifest.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from .canonical import canonical_json_bytes
from .contracts import SCHEMA_VERSION, validate_schema_version
from .failures import FailureCode, phase_not_implemented
from .identity import require_sha256, schema_bound_identity, sha256_bytes


DISCOVERY_POLICY_VERSION = SCHEMA_VERSION
SOURCE_SET_POLICY_VERSION = SCHEMA_VERSION
DUPLICATE_POLICY = "EXACT_IDENTITY_DEDUP_CONFLICTING_IDENTITY_REJECT"
MODEL_CALL_COUNT = 0

SOURCE_TYPES = frozenset(
    {"LOCAL_FILE", "STRUCTURED_EVIDENCE", "MANIFEST", "CONTRACT", "EXCERPT"}
)
CONTENT_KINDS = frozenset({"JSON", "TEXT", "BINARY"})
CLASSIFICATIONS = frozenset(
    {"PUBLIC", "INTERNAL", "PROTECTED", "SECRET_LIKE", "UNKNOWN"}
)
IMMUTABILITY_STATUSES = frozenset(
    {"IMMUTABLE_CAPTURE", "READ_ONLY_VERIFIED", "UNKNOWN"}
)
AVAILABILITY_STATUSES = frozenset({"AVAILABLE", "MISSING", "UNREADABLE", "CHANGED"})

_TASK_TYPES = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")


class DiscoveryValidationError(ValueError):
    """A supplied discovery value is malformed or unsafe."""

    def __init__(self, message: str, code: FailureCode | str = FailureCode.INVALID_SCHEMA) -> None:
        super().__init__(message)
        self.code = code.value if isinstance(code, FailureCode) else code
        self.failure_code = self.code
        self.retry_allowed = False


class DiscoverySelectionError(DiscoveryValidationError):
    """A valid candidate set cannot satisfy the explicit selection policy."""


DiscoveryError = DiscoveryValidationError
SourcePathError = DiscoveryValidationError


def _error(message: str, code: FailureCode | str = FailureCode.INVALID_SCHEMA) -> None:
    raise DiscoveryValidationError(message, code)


def _require_mapping(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _error(f"{context} must be an object")
    for key in value:
        if not isinstance(key, str):
            _error(f"{context} contains a non-string field name")
    return value


def _exact_fields(
    value: Mapping[str, object],
    required: set[str],
    optional: set[str],
    context: str,
) -> None:
    actual = set(value)
    missing = required - actual
    unknown = actual - required - optional
    if missing or unknown:
        detail: list[str] = []
        if missing:
            detail.append(f"missing={sorted(missing)!r}")
        if unknown:
            detail.append(f"unknown={sorted(unknown)!r}")
        _error(f"{context} fields are not exact ({', '.join(detail)})")


def _text(
    value: object,
    context: str,
    *,
    minimum: int = 1,
    maximum: int = 4096,
    line_free: bool = False,
) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        _error(f"{context} must contain {minimum}..{maximum} characters")
    if "\x00" in value:
        _error(f"{context} must not contain NUL", FailureCode.SOURCE_PATH_ESCAPE)
    if line_free and ("\n" in value or "\r" in value):
        _error(f"{context} must not contain a line separator", FailureCode.SOURCE_PATH_ESCAPE)
    return value


def _hash(value: object, context: str) -> str:
    try:
        return require_sha256(value, field=context)
    except ValueError as exc:
        _error(str(exc), FailureCode.INVALID_SCHEMA)
    raise AssertionError("unreachable")


def _integer(value: object, context: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= 9223372036854775807:
        _error(f"{context} must be an integer >= {minimum}")
    return value


def _boolean(value: object, context: str) -> bool:
    if type(value) is not bool:
        _error(f"{context} must be boolean")
    return value


def _enum(value: object, choices: frozenset[str], context: str) -> str:
    if not isinstance(value, str) or value not in choices:
        _error(f"{context} is outside the frozen enum")
    return value


def _sequence(value: object, context: str, *, minimum: int = 0) -> tuple[object, ...]:
    if not isinstance(value, (list, tuple)):
        _error(f"{context} must be an array")
    if len(value) < minimum:
        _error(f"{context} must contain at least {minimum} item(s)")
    return tuple(value)


def _sort_text(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(sorted(values, key=lambda value: value.encode("utf-8")))


def _freeze(value: object) -> object:
    """Copy JSON-shaped observations so caller mutation cannot affect a result."""

    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(child) for key, child in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(child) for child in value)
    return value


def _plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _plain(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_plain(child) for child in value]
    if isinstance(value, list):
        return [_plain(child) for child in value]
    return value


def _observations(value: object, context: str) -> MappingProxyType:
    if not isinstance(value, Mapping):
        _error(f"{context} must be an object")
    try:
        canonical_json_bytes(value, identity_critical=False)
    except (TypeError, ValueError) as exc:
        _error(f"{context} is not canonical JSON: {exc}")
    frozen = _freeze(value)
    if not isinstance(frozen, MappingProxyType):
        raise AssertionError("mapping freeze failed")
    return frozen


def validate_relative_path(value: object, *, context: str = "relative_path") -> str:
    """Validate a logical UTF-8 POSIX relative path without touching a path."""

    path = _text(value, context, maximum=2048, line_free=True)
    if path.startswith("/") or "\\" in path:
        _error(f"{context} is not an unambiguous POSIX relative path", FailureCode.SOURCE_PATH_ESCAPE)
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        _error(f"{context} contains an unsafe relative component", FailureCode.SOURCE_PATH_ESCAPE)
    return path


def validate_source_alias(value: object, *, context: str = "source_alias") -> str:
    alias = _text(value, context, maximum=256, line_free=True)
    if alias in {".", ".."} or "/" in alias or "\\" in alias:
        _error(f"{context} is not an unambiguous source alias", FailureCode.SOURCE_PATH_ESCAPE)
    return alias


def canonical_locator_from_parts(source_alias: str, relative_path: str) -> str:
    """Return the frozen logical locator form ``alias/relative/path``."""

    alias = validate_source_alias(source_alias)
    path = validate_relative_path(relative_path)
    return f"{alias}/{path}"


def validate_canonical_locator(value: object, *, context: str = "canonical_locator") -> str:
    """Validate the logical locator emitted in source references."""

    locator = _text(value, context, maximum=2048, line_free=True)
    if locator.startswith("/") or "\\" in locator:
        _error(f"{context} is not an unambiguous POSIX locator", FailureCode.SOURCE_PATH_ESCAPE)
    parts = locator.split("/")
    if len(parts) < 2 or any(part in {"", ".", ".."} for part in parts):
        _error(f"{context} contains an unsafe relative component", FailureCode.SOURCE_PATH_ESCAPE)
    validate_source_alias(parts[0], context=f"{context} source alias")
    return locator


def _validate_content_identity(value: object, context: str = "content_identity") -> dict[str, str]:
    mapping = _require_mapping(value, context)
    _exact_fields(mapping, {"algorithm", "sha256"}, set(), context)
    if mapping["algorithm"] != "SHA-256":
        _error(f"{context}.algorithm must be SHA-256")
    return {"algorithm": "SHA-256", "sha256": _hash(mapping["sha256"], f"{context}.sha256")}


def _validate_locator_object(value: object) -> dict[str, str]:
    mapping = _require_mapping(value, "canonical_locator")
    _exact_fields(mapping, {"source_alias", "relative_path"}, set(), "canonical_locator")
    alias = validate_source_alias(mapping["source_alias"])
    path = validate_relative_path(mapping["relative_path"])
    return {"source_alias": alias, "relative_path": path}


def _source_identity_payload(mapping: Mapping[str, object]) -> dict[str, object]:
    """Validate and return exactly the frozen source identity projection."""

    _exact_fields(
        mapping,
        {
            "schema_version",
            "source_type",
            "canonical_locator",
            "content_identity",
            "content_size_bytes",
            "classification",
            "immutability_status",
            "availability_status",
            "provenance_owner",
        },
        {"source_id", "content_kind", "observational_metadata"},
        "source descriptor",
    )
    version = mapping["schema_version"]
    try:
        validate_schema_version("mr05.source", version)
    except (TypeError, ValueError) as exc:
        _error(str(exc))
    source_type = _enum(mapping["source_type"], SOURCE_TYPES, "source_type")
    locator = _validate_locator_object(mapping["canonical_locator"])
    content_identity = _validate_content_identity(mapping["content_identity"])
    size = _integer(mapping["content_size_bytes"], "content_size_bytes")
    classification = _enum(mapping["classification"], CLASSIFICATIONS, "classification")
    immutability = _enum(mapping["immutability_status"], IMMUTABILITY_STATUSES, "immutability_status")
    availability = _enum(mapping["availability_status"], AVAILABILITY_STATUSES, "availability_status")
    owner = _text(mapping["provenance_owner"], "provenance_owner", maximum=512)
    if "content_kind" in mapping:
        _enum(mapping["content_kind"], CONTENT_KINDS, "content_kind")
    if "observational_metadata" in mapping:
        _observations(mapping["observational_metadata"], "observational_metadata")
    return {
        "schema_version": version,
        "source_type": source_type,
        "canonical_locator": locator,
        "content_identity": content_identity,
        "content_size_bytes": size,
        "classification": classification,
        "immutability_status": immutability,
        "availability_status": availability,
        "provenance_owner": owner,
    }


def source_descriptor_identity(value: Mapping[str, object] | "SourceDescriptor") -> str:
    """Compute a source identity from its exact semantic descriptor fields.

    A declared ``source_id`` is checked when present; it is never invented in
    a descriptor accepted at a boundary.
    """

    if isinstance(value, SourceDescriptor):
        return value.source_id
    mapping = _require_mapping(value, "source descriptor")
    payload = _source_identity_payload(mapping)
    computed = schema_bound_identity("mr05.source", payload)
    if "source_id" in mapping:
        declared = _hash(mapping["source_id"], "source_id")
        if declared != computed:
            _error("source_id does not match canonical descriptor", FailureCode.HASH_MISMATCH)
    return computed


@dataclass(frozen=True, slots=True)
class SourceDescriptor:
    """Immutable schema-shaped metadata for one already-supplied source."""

    schema_version: str
    source_id: str
    source_type: str
    source_alias: str
    relative_path: str
    content_sha256: str
    content_size_bytes: int
    classification: str
    immutability_status: str
    availability_status: str
    provenance_owner: str
    content_kind: str | None = None
    observational_metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            _error("unsupported source schema version")
        declared = _hash(self.source_id, "source_id")
        source_mapping: dict[str, object] = {
            "schema_version": self.schema_version,
            "source_id": declared,
            "source_type": self.source_type,
            "canonical_locator": {
                "source_alias": self.source_alias,
                "relative_path": self.relative_path,
            },
            "content_identity": {"algorithm": "SHA-256", "sha256": self.content_sha256},
            "content_size_bytes": self.content_size_bytes,
            "classification": self.classification,
            "immutability_status": self.immutability_status,
            "availability_status": self.availability_status,
            "provenance_owner": self.provenance_owner,
        }
        if self.content_kind is not None:
            source_mapping["content_kind"] = self.content_kind
        if self.observational_metadata:
            source_mapping["observational_metadata"] = self.observational_metadata
        payload = _source_identity_payload(source_mapping)
        computed = schema_bound_identity("mr05.source", payload)
        if declared != computed:
            _error("source_id does not match canonical descriptor", FailureCode.HASH_MISMATCH)
        observations = _observations(self.observational_metadata, "observational_metadata")
        object.__setattr__(self, "source_id", declared)
        object.__setattr__(self, "source_alias", validate_source_alias(self.source_alias))
        object.__setattr__(self, "relative_path", validate_relative_path(self.relative_path))
        object.__setattr__(self, "content_sha256", _hash(self.content_sha256, "content_sha256"))
        object.__setattr__(self, "content_size_bytes", _integer(self.content_size_bytes, "content_size_bytes"))
        object.__setattr__(self, "source_type", _enum(self.source_type, SOURCE_TYPES, "source_type"))
        object.__setattr__(self, "classification", _enum(self.classification, CLASSIFICATIONS, "classification"))
        object.__setattr__(self, "immutability_status", _enum(self.immutability_status, IMMUTABILITY_STATUSES, "immutability_status"))
        object.__setattr__(self, "availability_status", _enum(self.availability_status, AVAILABILITY_STATUSES, "availability_status"))
        object.__setattr__(self, "provenance_owner", _text(self.provenance_owner, "provenance_owner", maximum=512))
        if self.content_kind is not None:
            object.__setattr__(self, "content_kind", _enum(self.content_kind, CONTENT_KINDS, "content_kind"))
        object.__setattr__(self, "observational_metadata", observations)

    @property
    def canonical_locator(self) -> str:
        return canonical_locator_from_parts(self.source_alias, self.relative_path)

    @property
    def identity_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "source_type": self.source_type,
            "canonical_locator": {
                "source_alias": self.source_alias,
                "relative_path": self.relative_path,
            },
            "content_identity": {"algorithm": "SHA-256", "sha256": self.content_sha256},
            "content_size_bytes": self.content_size_bytes,
            "classification": self.classification,
            "immutability_status": self.immutability_status,
            "availability_status": self.availability_status,
            "provenance_owner": self.provenance_owner,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "SourceDescriptor":
        mapping = _require_mapping(value, "source descriptor")
        payload = _source_identity_payload(mapping)
        _exact_fields(
            mapping,
            {
                "schema_version",
                "source_id",
                "source_type",
                "canonical_locator",
                "content_identity",
                "content_size_bytes",
                "classification",
                "immutability_status",
                "availability_status",
                "provenance_owner",
            },
            {"content_kind", "observational_metadata"},
            "source descriptor",
        )
        locator = payload["canonical_locator"]
        content_identity = payload["content_identity"]
        if not isinstance(locator, dict) or not isinstance(content_identity, dict):
            raise AssertionError("validated source payload shape changed")
        return cls(
            schema_version=payload["schema_version"],
            source_id=mapping["source_id"],
            source_type=payload["source_type"],
            source_alias=locator["source_alias"],
            relative_path=locator["relative_path"],
            content_sha256=content_identity["sha256"],
            content_size_bytes=payload["content_size_bytes"],
            classification=payload["classification"],
            immutability_status=payload["immutability_status"],
            availability_status=payload["availability_status"],
            provenance_owner=payload["provenance_owner"],
            content_kind=mapping.get("content_kind"),
            observational_metadata=mapping.get("observational_metadata", {}),
        )

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "source_id": self.source_id,
            "source_type": self.source_type,
            "canonical_locator": {
                "source_alias": self.source_alias,
                "relative_path": self.relative_path,
            },
            "content_identity": {"algorithm": "SHA-256", "sha256": self.content_sha256},
            "content_size_bytes": self.content_size_bytes,
            "classification": self.classification,
            "immutability_status": self.immutability_status,
            "availability_status": self.availability_status,
            "provenance_owner": self.provenance_owner,
        }
        if self.content_kind is not None:
            result["content_kind"] = self.content_kind
        if self.observational_metadata:
            result["observational_metadata"] = _plain(self.observational_metadata)
        return result


@dataclass(frozen=True, slots=True)
class CapturedSource:
    """A caller-owned byte capture bound to one source descriptor."""

    descriptor: SourceDescriptor
    raw_bytes: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.descriptor, SourceDescriptor):
            _error("captured source descriptor is invalid")
        if type(self.raw_bytes) is not bytes:
            _error("raw_bytes must be bytes")
        if len(self.raw_bytes) != self.descriptor.content_size_bytes:
            _error("captured byte count does not match descriptor", FailureCode.HASH_MISMATCH)
        if sha256_bytes(self.raw_bytes) != self.descriptor.content_sha256:
            _error("captured bytes do not match descriptor", FailureCode.HASH_MISMATCH)

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "CapturedSource":
        mapping = _require_mapping(value, "captured source")
        _exact_fields(mapping, {"descriptor", "raw_bytes"}, set(), "captured source")
        descriptor_value = mapping["descriptor"]
        if isinstance(descriptor_value, SourceDescriptor):
            descriptor = descriptor_value
        else:
            descriptor = SourceDescriptor.from_mapping(_require_mapping(descriptor_value, "descriptor"))
        return cls(descriptor=descriptor, raw_bytes=mapping["raw_bytes"])


@dataclass(frozen=True, slots=True)
class SourceReference:
    """The exact source-reference payload used by discovery output."""

    source_id: str
    canonical_locator: str
    content_sha256: str
    content_size_bytes: int
    source_set_identity: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_id", _hash(self.source_id, "source_id"))
        object.__setattr__(self, "canonical_locator", validate_canonical_locator(self.canonical_locator))
        object.__setattr__(self, "content_sha256", _hash(self.content_sha256, "content_sha256"))
        object.__setattr__(self, "content_size_bytes", _integer(self.content_size_bytes, "content_size_bytes"))
        object.__setattr__(self, "source_set_identity", _hash(self.source_set_identity, "source_set_identity"))

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "SourceReference":
        mapping = _require_mapping(value, "source reference")
        _exact_fields(
            mapping,
            {"source_id", "canonical_locator", "content_sha256", "content_size_bytes", "source_set_identity"},
            set(),
            "source reference",
        )
        return cls(
            source_id=mapping["source_id"],
            canonical_locator=mapping["canonical_locator"],
            content_sha256=mapping["content_sha256"],
            content_size_bytes=mapping["content_size_bytes"],
            source_set_identity=mapping["source_set_identity"],
        )

    @classmethod
    def from_descriptor(cls, descriptor: SourceDescriptor, source_set_identity: str) -> "SourceReference":
        if not isinstance(descriptor, SourceDescriptor):
            _error("source reference descriptor is invalid")
        return cls(
            source_id=descriptor.source_id,
            canonical_locator=descriptor.canonical_locator,
            content_sha256=descriptor.content_sha256,
            content_size_bytes=descriptor.content_size_bytes,
            source_set_identity=source_set_identity,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "source_id": self.source_id,
            "canonical_locator": self.canonical_locator,
            "content_sha256": self.content_sha256,
            "content_size_bytes": self.content_size_bytes,
            "source_set_identity": self.source_set_identity,
        }


@dataclass(frozen=True, slots=True)
class ExcludedSource:
    source_id: str
    canonical_locator: str
    reason_code: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_id", _hash(self.source_id, "source_id"))
        object.__setattr__(self, "canonical_locator", validate_canonical_locator(self.canonical_locator))
        object.__setattr__(self, "reason_code", _text(self.reason_code, "reason_code", maximum=128, line_free=True))

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "ExcludedSource":
        mapping = _require_mapping(value, "excluded source")
        _exact_fields(mapping, {"source_id", "canonical_locator", "reason_code"}, set(), "excluded source")
        return cls(
            source_id=mapping["source_id"],
            canonical_locator=mapping["canonical_locator"],
            reason_code=mapping["reason_code"],
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "source_id": self.source_id,
            "canonical_locator": self.canonical_locator,
            "reason_code": self.reason_code,
        }


def _source_ref_sort_key(value: SourceReference) -> tuple[bytes, bytes, bytes, bytes]:
    return (
        value.source_id.encode("ascii"),
        value.canonical_locator.encode("utf-8"),
        value.content_sha256.encode("ascii"),
        str(value.content_size_bytes).encode("ascii"),
    )


def _excluded_sort_key(value: ExcludedSource) -> tuple[bytes, bytes, bytes]:
    return (
        value.canonical_locator.encode("utf-8"),
        value.source_id.encode("ascii"),
        value.reason_code.encode("utf-8"),
    )


def _descriptor_from_value(value: object) -> SourceDescriptor:
    if isinstance(value, CapturedSource):
        return value.descriptor
    if isinstance(value, SourceDescriptor):
        return value
    if isinstance(value, Mapping):
        if set(value) == {"descriptor", "raw_bytes"}:
            return CapturedSource.from_mapping(value).descriptor
        return SourceDescriptor.from_mapping(value)
    _error("source candidate must be a source descriptor or explicit capture")
    raise AssertionError("unreachable")


def _descriptor_list(value: object) -> tuple[SourceDescriptor, ...]:
    values = _sequence(value, "source candidates", minimum=1)
    return tuple(_descriptor_from_value(item) for item in values)


@dataclass(frozen=True, slots=True)
class SourceSet:
    """Canonical source-set metadata and its deterministic identity."""

    schema_version: str
    source_set_policy_version: str
    sources: tuple[SourceReference, ...]
    ordered_source_descriptor_identities: tuple[str, ...]
    duplicate_policy: str
    source_set_identity: str
    observational_metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION or self.source_set_policy_version != SOURCE_SET_POLICY_VERSION:
            _error("unsupported source-set schema version")
        sources = tuple(self.sources)
        if not sources or any(not isinstance(item, SourceReference) for item in sources):
            _error("source set requires at least one valid source")
        if self.duplicate_policy != DUPLICATE_POLICY:
            _error("unsupported duplicate policy")
        ids = tuple(self.ordered_source_descriptor_identities)
        if any(not isinstance(item, str) for item in ids):
            _error("ordered source descriptor identities must be strings")
        for item in ids:
            _hash(item, "ordered_source_descriptor_identity")
        if len(ids) != len(set(ids)) or len(ids) != len(sources):
            _error("source-set identity list and source list must be one-to-one")
        if set(ids) != {item.source_id for item in sources}:
            _error("source-set identities do not bind source references")
        expected_ids = tuple(sorted(ids, key=lambda item: item.encode("ascii")))
        if ids != expected_ids:
            _error("source descriptor identities are not canonically ordered")
        expected_sources = tuple(sorted(sources, key=_source_ref_sort_key))
        if sources != expected_sources:
            _error("source-set sources are not canonically ordered")
        payload = {
            "schema_version": self.schema_version,
            "source_set_policy_version": self.source_set_policy_version,
            "ordered_source_descriptor_identities": list(ids),
            "duplicate_policy": self.duplicate_policy,
        }
        computed = schema_bound_identity("mr05.source_set", payload)
        declared = _hash(self.source_set_identity, "source_set_identity")
        if declared != computed:
            _error("source_set_identity does not match canonical source set", FailureCode.HASH_MISMATCH)
        if any(item.source_set_identity != computed for item in sources):
            _error("source references are not bound to source_set_identity", FailureCode.HASH_MISMATCH)
        observations = _observations(self.observational_metadata, "observational_metadata")
        object.__setattr__(self, "sources", sources)
        object.__setattr__(self, "ordered_source_descriptor_identities", ids)
        object.__setattr__(self, "source_set_identity", declared)
        object.__setattr__(self, "observational_metadata", observations)

    @property
    def identity_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "source_set_policy_version": self.source_set_policy_version,
            "ordered_source_descriptor_identities": list(self.ordered_source_descriptor_identities),
            "duplicate_policy": self.duplicate_policy,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "SourceSet":
        mapping = _require_mapping(value, "source set")
        _exact_fields(
            mapping,
            {
                "schema_version",
                "source_set_policy_version",
                "sources",
                "ordered_source_descriptor_identities",
                "duplicate_policy",
                "source_set_identity",
            },
            {"observational_metadata"},
            "source set",
        )
        raw_sources = _sequence(mapping["sources"], "source set.sources", minimum=1)
        source_entries: list[dict[str, object]] = []
        for item in raw_sources:
            entry = _require_mapping(item, "source set source")
            _exact_fields(
                entry,
                {"source_id", "canonical_locator", "content_sha256", "content_size_bytes"},
                set(),
                "source set source",
            )
            source_entries.append(
                {
                    "source_id": _hash(entry["source_id"], "source_id"),
                    "canonical_locator": validate_canonical_locator(entry["canonical_locator"]),
                    "content_sha256": _hash(entry["content_sha256"], "content_sha256"),
                    "content_size_bytes": _integer(entry["content_size_bytes"], "content_size_bytes"),
                }
            )
        raw_ids = _sequence(
            mapping["ordered_source_descriptor_identities"],
            "ordered_source_descriptor_identities",
            minimum=1,
        )
        ids = tuple(_hash(item, "ordered_source_descriptor_identity") for item in raw_ids)
        if mapping["schema_version"] != SCHEMA_VERSION or mapping["source_set_policy_version"] != SOURCE_SET_POLICY_VERSION:
            _error("unsupported source-set schema version")
        source_set_payload = {
            "schema_version": SCHEMA_VERSION,
            "source_set_policy_version": SOURCE_SET_POLICY_VERSION,
            "ordered_source_descriptor_identities": list(ids),
            "duplicate_policy": mapping["duplicate_policy"],
        }
        computed_source_set_id = schema_bound_identity("mr05.source_set", source_set_payload)
        sources = tuple(
            SourceReference(
                source_id=entry["source_id"],
                canonical_locator=entry["canonical_locator"],
                content_sha256=entry["content_sha256"],
                content_size_bytes=entry["content_size_bytes"],
                source_set_identity=computed_source_set_id,
            )
            for entry in source_entries
        )
        return cls(
            schema_version=mapping["schema_version"],
            source_set_policy_version=mapping["source_set_policy_version"],
            sources=sources,
            ordered_source_descriptor_identities=ids,
            duplicate_policy=mapping["duplicate_policy"],
            source_set_identity=mapping["source_set_identity"],
            observational_metadata=mapping.get("observational_metadata", {}),
        )

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "source_set_policy_version": self.source_set_policy_version,
            "sources": [
                {
                    "source_id": item.source_id,
                    "canonical_locator": item.canonical_locator,
                    "content_sha256": item.content_sha256,
                    "content_size_bytes": item.content_size_bytes,
                }
                for item in self.sources
            ],
            "ordered_source_descriptor_identities": list(self.ordered_source_descriptor_identities),
            "duplicate_policy": self.duplicate_policy,
            "source_set_identity": self.source_set_identity,
        }
        if self.observational_metadata:
            result["observational_metadata"] = _plain(self.observational_metadata)
        return result


def build_source_set(
    sources: Sequence[Mapping[str, object] | SourceDescriptor | CapturedSource],
    *,
    observational_metadata: Mapping[str, object] | None = None,
) -> SourceSet:
    """Build a source set from explicit descriptors, rejecting conflicts."""

    descriptors = _descriptor_list(sources)
    by_locator: dict[str, SourceDescriptor] = {}
    by_id: dict[str, SourceDescriptor] = {}
    unique: list[SourceDescriptor] = []
    for descriptor in descriptors:
        prior_id = by_id.get(descriptor.source_id)
        if prior_id is not None:
            if prior_id.to_dict() != descriptor.to_dict():
                _error("same source identity has conflicting descriptor data", FailureCode.DUPLICATE_CONFLICT)
            continue
        prior_locator = by_locator.get(descriptor.canonical_locator)
        if prior_locator is not None:
            if prior_locator.content_sha256 != descriptor.content_sha256:
                _error("same logical source has conflicting content identity", FailureCode.DUPLICATE_CONFLICT)
            if prior_locator.source_id != descriptor.source_id:
                _error("same logical source has conflicting descriptor identity", FailureCode.DUPLICATE_CONFLICT)
            continue
        by_id[descriptor.source_id] = descriptor
        by_locator[descriptor.canonical_locator] = descriptor
        unique.append(descriptor)
    if not unique:
        _error("source set must not be empty")
    ordered_descriptors = sorted(unique, key=lambda item: item.source_id.encode("ascii"))
    descriptor_ids = tuple(item.source_id for item in ordered_descriptors)
    source_set_payload = {
        "schema_version": SCHEMA_VERSION,
        "source_set_policy_version": SOURCE_SET_POLICY_VERSION,
        "ordered_source_descriptor_identities": list(descriptor_ids),
        "duplicate_policy": DUPLICATE_POLICY,
    }
    source_set_id = schema_bound_identity("mr05.source_set", source_set_payload)
    refs = tuple(
        sorted(
            (SourceReference.from_descriptor(item, source_set_id) for item in unique),
            key=_source_ref_sort_key,
        )
    )
    return SourceSet(
        schema_version=SCHEMA_VERSION,
        source_set_policy_version=SOURCE_SET_POLICY_VERSION,
        sources=refs,
        ordered_source_descriptor_identities=descriptor_ids,
        duplicate_policy=DUPLICATE_POLICY,
        source_set_identity=source_set_id,
        observational_metadata={} if observational_metadata is None else observational_metadata,
    )


def compute_source_set_identity(
    sources: Sequence[Mapping[str, object] | SourceDescriptor | CapturedSource],
) -> str:
    return build_source_set(sources).source_set_identity


source_set_identity = compute_source_set_identity


def _validate_text_array(value: object, context: str, *, minimum: int = 0, maximum: int = 2048) -> tuple[str, ...]:
    raw = _sequence(value, context, minimum=minimum)
    result = tuple(_text(item, f"{context} item", maximum=maximum) for item in raw)
    if len(set(result)) != len(result):
        _error(f"{context} contains duplicates")
    return result


def _validate_task(value: Mapping[str, object]) -> dict[str, object]:
    _exact_fields(
        value,
        {
            "schema_version",
            "task_id",
            "task_type",
            "task_text",
            "requested_output_type",
            "allowed_scope",
            "prohibited_scope",
            "human_constraints",
            "source_scope",
            "risk_class_if_known",
        },
        {"observational_metadata"},
        "task",
    )
    try:
        validate_schema_version("mr05.task", value["schema_version"])
    except (TypeError, ValueError) as exc:
        _error(str(exc))
    task_id = _text(value["task_id"], "task_id", maximum=256)
    task_type = _text(value["task_type"], "task_type", maximum=64)
    if _TASK_TYPES.fullmatch(task_type) is None:
        _error("task_type is outside the frozen pattern")
    task_text = _text(value["task_text"], "task_text", maximum=32768)
    requested = _enum(
        value["requested_output_type"],
        frozenset({"STRUCTURED", "REPORT", "OPTIONS", "EVIDENCE_REVIEW"}),
        "requested_output_type",
    )
    allowed_scope = _validate_text_array(value["allowed_scope"], "allowed_scope", maximum=1024)
    prohibited_scope = _validate_text_array(value["prohibited_scope"], "prohibited_scope", maximum=1024)
    constraints = _require_mapping(value["human_constraints"], "human_constraints")
    _exact_fields(
        constraints,
        {
            "approval_required",
            "no_execution",
            "no_external_side_effects",
            "trust_level",
            "live_cloud_allowed",
            "local_model_source_authority",
        },
        set(),
        "human_constraints",
    )
    if _boolean(constraints["approval_required"], "approval_required") is not True:
        _error("approval_required is frozen to true")
    if _boolean(constraints["no_execution"], "no_execution") is not True:
        _error("no_execution is frozen to true")
    if _boolean(constraints["no_external_side_effects"], "no_external_side_effects") is not True:
        _error("no_external_side_effects is frozen to true")
    if _boolean(constraints["live_cloud_allowed"], "live_cloud_allowed") is not False:
        _error("live_cloud_allowed is frozen to false")
    if _boolean(constraints["local_model_source_authority"], "local_model_source_authority") is not False:
        _error("local_model_source_authority is frozen to false")
    if constraints["trust_level"] != "LEVEL 0":
        _error("trust_level is frozen to LEVEL 0")
    scope = _require_mapping(value["source_scope"], "source_scope")
    _exact_fields(
        scope,
        {"approved_source_aliases"},
        {"allowed_source_types", "required_references", "required_source_ids"},
        "source_scope",
    )
    aliases = tuple(
        validate_source_alias(item, context="approved_source_alias")
        for item in _sequence(scope["approved_source_aliases"], "approved_source_aliases", minimum=1)
    )
    if len(set(aliases)) != len(aliases):
        _error("approved_source_aliases contains duplicates")
    if "allowed_source_types" in scope:
        allowed_types = _validate_text_array(scope["allowed_source_types"], "allowed_source_types", maximum=64)
        for item in allowed_types:
            _enum(item, SOURCE_TYPES, "allowed_source_types item")
    else:
        allowed_types = None
    if "required_references" in scope:
        required_references = tuple(
            validate_canonical_locator(item, context="required_reference")
            for item in _sequence(scope["required_references"], "required_references")
        )
        if len(set(required_references)) != len(required_references):
            _error("required_references contains duplicates")
    else:
        required_references = None
    if "required_source_ids" in scope:
        required_source_ids = tuple(
            _hash(item, "required_source_id")
            for item in _sequence(scope["required_source_ids"], "required_source_ids")
        )
        if len(set(required_source_ids)) != len(required_source_ids):
            _error("required_source_ids contains duplicates")
    else:
        required_source_ids = None
    risk = _enum(value["risk_class_if_known"], frozenset({"LOW", "MEDIUM", "HIGH", "UNKNOWN"}), "risk_class_if_known")
    result: dict[str, object] = {
        "schema_version": value["schema_version"],
        "task_id": task_id,
        "task_type": task_type,
        "task_text": task_text,
        "requested_output_type": requested,
        "allowed_scope": list(allowed_scope),
        "prohibited_scope": list(prohibited_scope),
        "human_constraints": {
            "approval_required": True,
            "no_execution": True,
            "no_external_side_effects": True,
            "trust_level": "LEVEL 0",
            "live_cloud_allowed": False,
            "local_model_source_authority": False,
        },
        "source_scope": {"approved_source_aliases": list(aliases)},
        "risk_class_if_known": risk,
    }
    result_scope = result["source_scope"]
    if not isinstance(result_scope, dict):
        raise AssertionError("validated task scope shape changed")
    if allowed_types is not None:
        result_scope["allowed_source_types"] = list(allowed_types)
    if required_references is not None:
        result_scope["required_references"] = list(required_references)
    if required_source_ids is not None:
        result_scope["required_source_ids"] = list(required_source_ids)
    if "observational_metadata" in value:
        result["observational_metadata"] = _plain(_observations(value["observational_metadata"], "observational_metadata"))
    return result


def task_identity(value: Mapping[str, object]) -> str:
    """Validate a frozen task and derive its deterministic semantic identity."""

    task = _validate_task(_require_mapping(value, "task"))
    scope = task["source_scope"]
    if not isinstance(scope, dict):
        raise AssertionError("validated task scope shape changed")
    identity_scope: dict[str, object] = {
        "approved_source_aliases": list(_sort_text(tuple(scope["approved_source_aliases"])))
    }
    for key in ("allowed_source_types", "required_references", "required_source_ids"):
        if key in scope:
            values = scope[key]
            if not isinstance(values, list):
                raise AssertionError("validated task list shape changed")
            identity_scope[key] = list(_sort_text(tuple(values)))
    identity_payload = {
        "schema_version": task["schema_version"],
        "task_id": task["task_id"],
        "task_type": task["task_type"],
        "task_text": task["task_text"],
        "requested_output_type": task["requested_output_type"],
        "allowed_scope": list(_sort_text(tuple(task["allowed_scope"]))),
        "prohibited_scope": list(_sort_text(tuple(task["prohibited_scope"]))),
        "human_constraints": task["human_constraints"],
        "source_scope": identity_scope,
        "risk_class_if_known": task["risk_class_if_known"],
    }
    return schema_bound_identity("mr05.task", identity_payload)


def _budget(
    max_item_count: object,
    max_bytes: object,
    budget: object | None,
) -> tuple[int, int]:
    if budget is not None:
        if max_item_count is not None or max_bytes is not None:
            _error("budget and individual budget fields cannot both be supplied")
        mapping = _require_mapping(budget, "discovery_budget")
        _exact_fields(mapping, {"max_item_count", "max_bytes"}, set(), "discovery_budget")
        max_item_count = mapping["max_item_count"]
        max_bytes = mapping["max_bytes"]
    if max_item_count is None or max_bytes is None:
        _error("positive max_item_count and max_bytes are mandatory")
    return (
        _integer(max_item_count, "max_item_count", minimum=1),
        _integer(max_bytes, "max_bytes", minimum=1),
    )


def _scope_for_no_task(
    approved_source_aliases: object,
    allowed_source_types: object,
    required_references: object,
    required_source_ids: object,
) -> tuple[tuple[str, ...], tuple[str, ...] | None, tuple[str, ...], tuple[str, ...]]:
    aliases = tuple(
        validate_source_alias(item, context="approved_source_alias")
        for item in _sequence(approved_source_aliases, "approved_source_aliases", minimum=1)
    )
    if len(set(aliases)) != len(aliases):
        _error("approved_source_aliases contains duplicates")
    if allowed_source_types is None:
        allowed_types = None
    else:
        allowed_types_raw = _validate_text_array(allowed_source_types, "allowed_source_types", maximum=64)
        allowed_types = tuple(_enum(item, SOURCE_TYPES, "allowed_source_types item") for item in allowed_types_raw)
    refs = tuple(validate_canonical_locator(item, context="required_reference") for item in _sequence(required_references, "required_references"))
    ids = tuple(_hash(item, "required_source_id") for item in _sequence(required_source_ids, "required_source_ids"))
    if len(set(refs)) != len(refs) or len(set(ids)) != len(ids):
        _error("required source selectors contain duplicates")
    return aliases, allowed_types, refs, ids


def _discovery_identity_payload(
    *,
    task_id: str,
    source_set_id: str,
    selected: Sequence[SourceReference],
    excluded: Sequence[ExcludedSource],
    reasons: Sequence[str],
    total_items: int,
    total_bytes: int,
) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "task_identity": task_id,
        "source_set_identity": source_set_id,
        "selected_sources": [item.to_dict() for item in selected],
        "excluded_sources": [item.to_dict() for item in excluded],
        "selection_reason_codes": list(reasons),
        "total_selected_items": total_items,
        "total_selected_bytes": total_bytes,
        "discovery_policy_version": DISCOVERY_POLICY_VERSION,
        "model_call_count": MODEL_CALL_COUNT,
    }


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    """Canonical, immutable discovery manifest."""

    schema_version: str
    task_identity: str
    source_set_identity: str
    selected_sources: tuple[SourceReference, ...]
    excluded_sources: tuple[ExcludedSource, ...]
    selection_reason_codes: tuple[str, ...]
    total_selected_items: int
    total_selected_bytes: int
    discovery_policy_version: str
    model_call_count: int
    discovery_identity: str | None = None
    observational_metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION or self.discovery_policy_version != DISCOVERY_POLICY_VERSION:
            _error("unsupported discovery schema version")
        task_id = _hash(self.task_identity, "task_identity")
        source_set_id = _hash(self.source_set_identity, "source_set_identity")
        selected = tuple(self.selected_sources)
        excluded = tuple(self.excluded_sources)
        if not selected or any(not isinstance(item, SourceReference) for item in selected):
            _error("discovery requires at least one selected source")
        if any(item.source_set_identity != source_set_id for item in selected):
            _error("selected source reference is not bound to source_set_identity", FailureCode.HASH_MISMATCH)
        if any(not isinstance(item, ExcludedSource) for item in excluded):
            _error("excluded_sources contains an invalid record")
        if selected != tuple(sorted(selected, key=_source_ref_sort_key)):
            _error("selected_sources are not canonically ordered")
        if excluded != tuple(sorted(excluded, key=_excluded_sort_key)):
            _error("excluded_sources are not canonically ordered")
        reasons = tuple(self.selection_reason_codes)
        if any(not isinstance(item, str) or not 1 <= len(item) <= 128 for item in reasons):
            _error("selection_reason_codes contains an invalid value")
        if reasons != _sort_text(reasons):
            _error("selection_reason_codes are not canonically ordered")
        total_items = _integer(self.total_selected_items, "total_selected_items", minimum=1)
        total_bytes = _integer(self.total_selected_bytes, "total_selected_bytes", minimum=1)
        if total_items != len(selected) or total_bytes != sum(item.content_size_bytes for item in selected):
            _error("discovery totals do not match selected sources")
        if type(self.model_call_count) is not int or self.model_call_count != MODEL_CALL_COUNT:
            _error("model_call_count is frozen to zero")
        observations = _observations(self.observational_metadata, "observational_metadata")
        payload = _discovery_identity_payload(
            task_id=task_id,
            source_set_id=source_set_id,
            selected=selected,
            excluded=excluded,
            reasons=reasons,
            total_items=total_items,
            total_bytes=total_bytes,
        )
        computed = schema_bound_identity("mr05.discovery", payload)
        declared = computed if self.discovery_identity is None else _hash(self.discovery_identity, "discovery_identity")
        if declared != computed:
            _error("discovery_identity does not match canonical result", FailureCode.HASH_MISMATCH)
        object.__setattr__(self, "task_identity", task_id)
        object.__setattr__(self, "source_set_identity", source_set_id)
        object.__setattr__(self, "selected_sources", selected)
        object.__setattr__(self, "excluded_sources", excluded)
        object.__setattr__(self, "selection_reason_codes", reasons)
        object.__setattr__(self, "total_selected_items", total_items)
        object.__setattr__(self, "total_selected_bytes", total_bytes)
        object.__setattr__(self, "model_call_count", MODEL_CALL_COUNT)
        object.__setattr__(self, "discovery_identity", declared)
        object.__setattr__(self, "observational_metadata", observations)

    @property
    def identity_payload(self) -> dict[str, object]:
        return _discovery_identity_payload(
            task_id=self.task_identity,
            source_set_id=self.source_set_identity,
            selected=self.selected_sources,
            excluded=self.excluded_sources,
            reasons=self.selection_reason_codes,
            total_items=self.total_selected_items,
            total_bytes=self.total_selected_bytes,
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "DiscoveryResult":
        mapping = _require_mapping(value, "discovery result")
        _exact_fields(
            mapping,
            {
                "schema_version",
                "task_identity",
                "source_set_identity",
                "selected_sources",
                "excluded_sources",
                "selection_reason_codes",
                "total_selected_items",
                "total_selected_bytes",
                "discovery_policy_version",
                "model_call_count",
                "discovery_identity",
            },
            {"observational_metadata"},
            "discovery result",
        )
        selected = tuple(SourceReference.from_mapping(item) for item in _sequence(mapping["selected_sources"], "selected_sources", minimum=1))
        excluded = tuple(ExcludedSource.from_mapping(item) for item in _sequence(mapping["excluded_sources"], "excluded_sources"))
        reasons = tuple(_text(item, "selection_reason_code", maximum=128, line_free=True) for item in _sequence(mapping["selection_reason_codes"], "selection_reason_codes"))
        return cls(
            schema_version=mapping["schema_version"],
            task_identity=mapping["task_identity"],
            source_set_identity=mapping["source_set_identity"],
            selected_sources=selected,
            excluded_sources=excluded,
            selection_reason_codes=reasons,
            total_selected_items=mapping["total_selected_items"],
            total_selected_bytes=mapping["total_selected_bytes"],
            discovery_policy_version=mapping["discovery_policy_version"],
            model_call_count=mapping["model_call_count"],
            discovery_identity=mapping["discovery_identity"],
            observational_metadata=mapping.get("observational_metadata", {}),
        )

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "task_identity": self.task_identity,
            "source_set_identity": self.source_set_identity,
            "selected_sources": [item.to_dict() for item in self.selected_sources],
            "excluded_sources": [item.to_dict() for item in self.excluded_sources],
            "selection_reason_codes": list(self.selection_reason_codes),
            "total_selected_items": self.total_selected_items,
            "total_selected_bytes": self.total_selected_bytes,
            "discovery_policy_version": self.discovery_policy_version,
            "model_call_count": self.model_call_count,
            "discovery_identity": self.discovery_identity,
        }
        if self.observational_metadata:
            result["observational_metadata"] = _plain(self.observational_metadata)
        return result

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict(), identity_critical=False)


def discover(
    task_or_candidates: Mapping[str, object] | Sequence[object],
    candidates: Sequence[object] | None = None,
    *,
    max_item_count: int | None = None,
    max_bytes: int | None = None,
    budget: Mapping[str, object] | None = None,
    task_identity_value: str | None = None,
    source_set_identity_value: str | None = None,
    approved_source_aliases: Sequence[str] | None = None,
    allowed_source_types: Sequence[str] | None = None,
    required_references: Sequence[str] | None = None,
    required_source_ids: Sequence[str] | None = None,
    observational_metadata: Mapping[str, object] | None = None,
) -> DiscoveryResult:
    """Select supplied descriptors under an explicit deterministic allowlist.

    The primary form is ``discover(task, candidates, max_item_count=...,
    max_bytes=...)``. The lower-level form accepts candidates as the first
    argument and requires ``task_identity_value`` plus the explicit scope
    selectors. Both forms compute the source-set identity from the supplied
    descriptors and reject a caller-declared identity that differs.
    """

    item_limit, byte_limit = _budget(max_item_count, max_bytes, budget)
    if candidates is not None:
        task = _validate_task(_require_mapping(task_or_candidates, "task"))
        derived_task_id = task_identity(task)
        if task_identity_value is not None and _hash(task_identity_value, "task_identity") != derived_task_id:
            _error("declared task identity does not match task", FailureCode.HASH_MISMATCH)
        task_id = derived_task_id
        scope = task["source_scope"]
        if not isinstance(scope, dict):
            raise AssertionError("validated task scope shape changed")
        aliases = tuple(scope["approved_source_aliases"])
        allowed_types = tuple(scope["allowed_source_types"]) if "allowed_source_types" in scope else None
        refs = tuple(scope["required_references"]) if "required_references" in scope else tuple()
        ids = tuple(scope["required_source_ids"]) if "required_source_ids" in scope else tuple()
        if any(argument is not None for argument in (approved_source_aliases, allowed_source_types, required_references, required_source_ids)):
            _error("task scope and explicit scope selectors cannot both be supplied")
        raw_candidates = candidates
    else:
        if isinstance(task_or_candidates, Mapping):
            _error("candidate sequence is mandatory")
        raw_candidates = task_or_candidates
        if task_identity_value is None:
            _error("task_identity_value is mandatory without a task")
        task_id = _hash(task_identity_value, "task_identity")
        if approved_source_aliases is None:
            _error("approved_source_aliases are mandatory without a task")
        aliases, allowed_types, refs, ids = _scope_for_no_task(
            approved_source_aliases,
            allowed_source_types,
            tuple() if required_references is None else required_references,
            tuple() if required_source_ids is None else required_source_ids,
        )
    descriptors = _descriptor_list(raw_candidates)
    source_set = build_source_set(descriptors)
    if source_set_identity_value is not None and _hash(source_set_identity_value, "source_set_identity") != source_set.source_set_identity:
        _error("declared source-set identity does not match descriptors", FailureCode.HASH_MISMATCH)
    source_set_id = source_set.source_set_identity
    selected_descriptors: list[SourceDescriptor] = []
    excluded: list[ExcludedSource] = []
    approved_aliases = set(aliases)
    allowed_type_set = None if allowed_types is None else set(allowed_types)
    for descriptor in descriptors:
        reason: str | None = None
        if descriptor.source_alias not in approved_aliases:
            reason = "SOURCE_ALIAS_NOT_APPROVED"
        elif allowed_type_set is not None and descriptor.source_type not in allowed_type_set:
            reason = "SOURCE_TYPE_NOT_APPROVED"
        elif descriptor.availability_status != "AVAILABLE":
            reason = "SOURCE_UNAVAILABLE"
        elif descriptor.immutability_status == "UNKNOWN":
            reason = "SOURCE_IMMUTABILITY_UNVERIFIED"
        if reason is None:
            selected_descriptors.append(descriptor)
        else:
            excluded.append(ExcludedSource(descriptor.source_id, descriptor.canonical_locator, reason))
    selected_by_id = {item.source_id: item for item in selected_descriptors}
    selected_descriptors = list(selected_by_id.values())
    selected_ids = {item.source_id for item in selected_descriptors}
    selected_locators = {item.canonical_locator for item in selected_descriptors}
    missing_ids = [item for item in ids if item not in selected_ids]
    missing_refs = [item for item in refs if item not in selected_locators]
    if missing_ids or missing_refs:
        _error("required source is absent or excluded", FailureCode.MISSING_REQUIRED_ARTIFACT)
    if not selected_descriptors:
        _error("allowlist selected no available source", FailureCode.MR05_MISSING_SOURCE)
    selected = tuple(
        sorted(
            (SourceReference.from_descriptor(item, source_set_id) for item in selected_descriptors),
            key=_source_ref_sort_key,
        )
    )
    total_items = len(selected)
    total_bytes = sum(item.content_size_bytes for item in selected)
    if total_items > item_limit or total_bytes > byte_limit:
        _error("explicit discovery budget exceeded", FailureCode.UNSUPPORTED_INPUT)
    if total_bytes < 1:
        _error("selected source bytes must be positive", FailureCode.INVALID_SCHEMA)
    excluded_sorted = tuple(sorted(excluded, key=_excluded_sort_key))
    reasons = ("ALLOWLIST_MATCH",)
    return DiscoveryResult(
        schema_version=SCHEMA_VERSION,
        task_identity=task_id,
        source_set_identity=source_set_id,
        selected_sources=selected,
        excluded_sources=excluded_sorted,
        selection_reason_codes=reasons,
        total_selected_items=total_items,
        total_selected_bytes=total_bytes,
        discovery_policy_version=DISCOVERY_POLICY_VERSION,
        model_call_count=MODEL_CALL_COUNT,
        observational_metadata={} if observational_metadata is None else observational_metadata,
    )


def discover_candidates(
    candidates: Sequence[object],
    *,
    task_identity: str,
    source_set_identity: str | None = None,
    max_item_count: int | None = None,
    max_bytes: int | None = None,
    budget: Mapping[str, object] | None = None,
    approved_source_aliases: Sequence[str],
    allowed_source_types: Sequence[str] | None = None,
    required_references: Sequence[str] = (),
    required_source_ids: Sequence[str] = (),
    observational_metadata: Mapping[str, object] | None = None,
) -> DiscoveryResult:
    """Explicit no-task wrapper around :func:`discover`."""

    return discover(
        candidates,
        max_item_count=max_item_count,
        max_bytes=max_bytes,
        budget=budget,
        task_identity_value=task_identity,
        source_set_identity_value=source_set_identity,
        approved_source_aliases=approved_source_aliases,
        allowed_source_types=allowed_source_types,
        required_references=required_references,
        required_source_ids=required_source_ids,
        observational_metadata=observational_metadata,
    )


def canonical_discovery_bytes(value: DiscoveryResult | Mapping[str, object]) -> bytes:
    result = value if isinstance(value, DiscoveryResult) else DiscoveryResult.from_mapping(value)
    return result.canonical_bytes()


def not_implemented(*args: object, **kwargs: object) -> None:
    """Retain the legacy phase marker for callers that explicitly use it."""

    del args, kwargs
    phase_not_implemented("discovery")


__all__ = (
    "DISCOVERY_POLICY_VERSION",
    "SOURCE_SET_POLICY_VERSION",
    "DUPLICATE_POLICY",
    "MODEL_CALL_COUNT",
    "SOURCE_TYPES",
    "CONTENT_KINDS",
    "CLASSIFICATIONS",
    "IMMUTABILITY_STATUSES",
    "AVAILABILITY_STATUSES",
    "DiscoveryValidationError",
    "DiscoverySelectionError",
    "DiscoveryError",
    "SourcePathError",
    "SourceDescriptor",
    "CapturedSource",
    "SourceReference",
    "SourceSet",
    "ExcludedSource",
    "DiscoveryResult",
    "validate_relative_path",
    "validate_source_alias",
    "canonical_locator_from_parts",
    "validate_canonical_locator",
    "source_descriptor_identity",
    "build_source_set",
    "compute_source_set_identity",
    "source_set_identity",
    "task_identity",
    "discover",
    "discover_candidates",
    "canonical_discovery_bytes",
    "not_implemented",
)
