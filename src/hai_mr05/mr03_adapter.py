"""Pure-data binding primitives for the frozen MR-03 dependency.

This module binds caller-supplied MR-05 identities to a declarative snapshot
of MR-03.  It never resolves, imports, invokes, or verifies the dependency.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import NoReturn

from .canonical import canonical_identity_bytes
from .contracts import MR03_EXPECTED_COMMIT, MR04_EXPECTED_COMMIT, SCHEMA_VERSION
from .discovery import DiscoveryResult, SourceReference, validate_canonical_locator
from .failures import FailureCode, phase_not_implemented
from .identity import identity_from_fields, require_git_commit, require_sha256
from .normalization import NormalizationResult


BINDING_SCHEMA_ID = "mr05.dependency_binding"
DEPENDENCY_BINDING_SCHEMA_ID = BINDING_SCHEMA_ID
DEPENDENCY_BINDING_SCHEMA_VERSION = SCHEMA_VERSION

MR03_EXPECTED_PARENT = "44ef1ef7f202c8a7ff85cb8f3a329d9ef76fd5e3"
MR03_EXPECTED_TREE = "09dfcd9ff69362ae019b2876a66ec78d54008337"
MR03_COMMITTED_FILESET_SHA256 = "3e85d8eebc1eef05a5ee6e9f18701e0686cb21c0cec6599df32ec09e1168dc48"
MR03_INTERFACE_IDENTITY = "MR03-PACKAGE-V1"

MR04_EXPECTED_PARENT = "85c3f65e23aba4c7307b5870d73c8192a72b46f5"
MR04_EXPECTED_TREE = "a8944259034b699c285e2b8551ad60e3ee79d5c2"
MR04_CONTENTSET_SHA256 = "a1da9509f5e5acc102be249978323bc9706cc893f178f96b70b9317750687b5f"
MR04_PATHSET_SHA256 = "2b58d0ee14b2c8280b608ea9a8717228c68675d15630a80a2d06f63212ba4640"
MR04_IMPLEMENTATION_CONTRACT_SHA256 = "0e110454fdd399db1564a2f7fdc581faabbea190ba0d668fc674243bbb414e32"

MR03_EXECUTION_IMPLEMENTATION_COUNT = 0
MR04_EXECUTION_IMPLEMENTATION_COUNT = 0
SUBPROCESS_EXECUTION_COUNT = 0
FILESYSTEM_DEPENDENCY_EXECUTION_COUNT = 0
NETWORK_IMPLEMENTATION_COUNT = 0
MODEL_CALL_IMPLEMENTATION_COUNT = 0
AUTH_IMPLEMENTATION_COUNT = 0
BOUNDED_CONTEXT_IMPLEMENTATION_COUNT = 0
VERIFIER_IMPLEMENTATION_COUNT = 0
CONTROLLER_IMPLEMENTATION_COUNT = 0
AUTO_RETRY_IMPLEMENTATION_COUNT = 0
AUTO_FALLBACK_IMPLEMENTATION_COUNT = 0


class DependencyBindingValidationError(ValueError):
    """A dependency binding is malformed or violates a frozen invariant."""

    def __init__(
        self,
        message: str,
        code: FailureCode | str = FailureCode.INVALID_SCHEMA,
    ) -> None:
        super().__init__(message)
        self.code = code.value if isinstance(code, FailureCode) else code
        self.failure_code = self.code
        self.retry_allowed = False


DependencyBindingError = DependencyBindingValidationError
AdapterValidationError = DependencyBindingValidationError

_BINDING_FIELDS = frozenset(
    {
        "schema_version",
        "dependency_role",
        "dependency_logical_id",
        "expected_dependency_class",
        "dependency_contract_identity",
        "dependency_version_identity",
        "dependency_content_identity",
        "dependency_snapshot",
        "source_ref",
        "input_binding",
        "binding_identity",
    }
)
_SEMANTIC_FIELDS = _BINDING_FIELDS - {"binding_identity"}
_CONTENT_KINDS = frozenset({"COMMITTED_FILESET", "CONTENTSET"})
_ROLES = frozenset({"MR03_PACKAGER", "MR04_GUARD"})
_LOGICAL_IDS = frozenset({"MR03", "MR04"})
_CLASSES = frozenset(
    {
        "FROZEN_MR03_EVIDENCE_PACKAGER",
        "FROZEN_MR04_LOWER_LEVEL_COMPOSITION",
    }
)


def _error(
    message: str,
    code: FailureCode | str = FailureCode.INVALID_SCHEMA,
) -> NoReturn:
    raise DependencyBindingValidationError(message, code)


def _require_mapping(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _error(f"{context} must be an object")
    if any(not isinstance(key, str) for key in value):
        _error(f"{context} contains a non-string field name")
    return value


def _exact_fields(
    value: Mapping[str, object],
    required: set[str] | frozenset[str],
    optional: set[str] | frozenset[str],
    context: str,
) -> None:
    actual = set(value)
    missing = set(required) - actual
    unknown = actual - set(required) - set(optional)
    if missing or unknown:
        detail: list[str] = []
        if missing:
            detail.append(f"missing={sorted(missing)!r}")
        if unknown:
            detail.append(f"unknown={sorted(unknown)!r}")
        _error(f"{context} fields are not exact ({', '.join(detail)})")


def _text(value: object, context: str, *, maximum: int = 256) -> str:
    if type(value) is not str or not 1 <= len(value) <= maximum:
        _error(f"{context} must contain 1..{maximum} characters")
    if "\x00" in value or "\n" in value or "\r" in value:
        _error(f"{context} contains an unsafe character", FailureCode.SOURCE_PATH_ESCAPE)
    return value


def _sha(value: object, context: str) -> str:
    try:
        return require_sha256(value, field=context)
    except ValueError as exc:
        _error(str(exc), FailureCode.INVALID_SCHEMA)


def _git_commit(value: object, context: str) -> str:
    try:
        return require_git_commit(value, field=context)
    except ValueError as exc:
        _error(str(exc), FailureCode.INVALID_SCHEMA)


def _integer(value: object, context: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= 9223372036854775807:
        _error(f"{context} must be an integer >= {minimum}")
    return value


def _enum(value: object, choices: frozenset[str], context: str) -> str:
    if type(value) is not str or value not in choices:
        _error(f"{context} is outside the frozen enum")
    return value


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(child) for key, child in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(child) for child in value)
    return value


def _plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _plain(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(child) for child in value]
    return value


def _expected_dependency(role: str) -> dict[str, object]:
    if role == "MR03_PACKAGER":
        return {
            "dependency_role": "MR03_PACKAGER",
            "dependency_logical_id": "MR03",
            "expected_dependency_class": "FROZEN_MR03_EVIDENCE_PACKAGER",
            "dependency_contract_identity": None,
            "dependency_version_identity": MR03_INTERFACE_IDENTITY,
            "dependency_content_identity": {
                "kind": "COMMITTED_FILESET",
                "sha256": MR03_COMMITTED_FILESET_SHA256,
            },
            "dependency_snapshot": {
                "commit": MR03_EXPECTED_COMMIT,
                "parent": MR03_EXPECTED_PARENT,
                "tree": MR03_EXPECTED_TREE,
                "pathset_sha256": None,
            },
        }
    if role == "MR04_GUARD":
        return {
            "dependency_role": "MR04_GUARD",
            "dependency_logical_id": "MR04",
            "expected_dependency_class": "FROZEN_MR04_LOWER_LEVEL_COMPOSITION",
            "dependency_contract_identity": MR04_IMPLEMENTATION_CONTRACT_SHA256,
            "dependency_version_identity": None,
            "dependency_content_identity": {
                "kind": "CONTENTSET",
                "sha256": MR04_CONTENTSET_SHA256,
            },
            "dependency_snapshot": {
                "commit": MR04_EXPECTED_COMMIT,
                "parent": MR04_EXPECTED_PARENT,
                "tree": MR04_EXPECTED_TREE,
                "pathset_sha256": MR04_PATHSET_SHA256,
            },
        }
    _error("unsupported dependency role")


def _validate_content_identity(value: object) -> dict[str, str]:
    mapping = _require_mapping(value, "dependency_content_identity")
    _exact_fields(mapping, {"kind", "sha256"}, set(), "dependency_content_identity")
    return {
        "kind": _enum(mapping["kind"], _CONTENT_KINDS, "dependency_content_identity.kind"),
        "sha256": _sha(mapping["sha256"], "dependency_content_identity.sha256"),
    }


def _validate_snapshot(value: object) -> dict[str, object]:
    mapping = _require_mapping(value, "dependency_snapshot")
    _exact_fields(
        mapping,
        {"commit", "parent", "tree", "pathset_sha256"},
        set(),
        "dependency_snapshot",
    )
    pathset = mapping["pathset_sha256"]
    if pathset is not None:
        pathset = _sha(pathset, "dependency_snapshot.pathset_sha256")
    return {
        "commit": _git_commit(mapping["commit"], "dependency_snapshot.commit"),
        "parent": _git_commit(mapping["parent"], "dependency_snapshot.parent"),
        "tree": _git_commit(mapping["tree"], "dependency_snapshot.tree"),
        "pathset_sha256": pathset,
    }


def _validate_source_ref(value: object) -> dict[str, object]:
    mapping = _require_mapping(value, "source_ref")
    _exact_fields(
        mapping,
        {
            "schema_version",
            "source_id",
            "canonical_locator",
            "content_sha256",
            "content_size_bytes",
            "source_set_identity",
        },
        set(),
        "source_ref",
    )
    if mapping["schema_version"] != SCHEMA_VERSION:
        _error("unsupported source_ref schema version")
    try:
        locator = validate_canonical_locator(
            mapping["canonical_locator"],
            context="source_ref.canonical_locator",
        )
    except ValueError as exc:
        _error(str(exc), FailureCode.SOURCE_PATH_ESCAPE)
    return {
        "schema_version": SCHEMA_VERSION,
        "source_id": _sha(mapping["source_id"], "source_ref.source_id"),
        "canonical_locator": locator,
        "content_sha256": _sha(mapping["content_sha256"], "source_ref.content_sha256"),
        "content_size_bytes": _integer(mapping["content_size_bytes"], "source_ref.content_size_bytes"),
        "source_set_identity": _sha(mapping["source_set_identity"], "source_ref.source_set_identity"),
    }


def _validate_input_binding(value: object, role: str) -> dict[str, object]:
    mapping = _require_mapping(value, "input_binding")
    _exact_fields(
        mapping,
        {
            "task_identity",
            "source_set_identity",
            "discovery_identity",
            "normalization_identity",
            "upstream_dependency_identity",
        },
        set(),
        "input_binding",
    )
    upstream = mapping["upstream_dependency_identity"]
    if upstream is not None:
        upstream = _sha(upstream, "input_binding.upstream_dependency_identity")
    elif role == "MR04_GUARD":
        _error("MR04 input binding requires an upstream dependency identity")
    if role == "MR03_PACKAGER" and upstream is not None:
        _error("MR03 input binding must not declare an upstream dependency identity")
    return {
        "task_identity": _sha(mapping["task_identity"], "input_binding.task_identity"),
        "source_set_identity": _sha(mapping["source_set_identity"], "input_binding.source_set_identity"),
        "discovery_identity": _sha(mapping["discovery_identity"], "input_binding.discovery_identity"),
        "normalization_identity": _sha(mapping["normalization_identity"], "input_binding.normalization_identity"),
        "upstream_dependency_identity": upstream,
    }


def _validate_semantic_mapping(
    value: Mapping[str, object] | DependencyBinding,
    *,
    expected_role: str | None = None,
) -> tuple[dict[str, object], str | None]:
    if isinstance(value, DependencyBinding):
        mapping = value.to_dict()
    else:
        mapping = _require_mapping(value, "dependency binding")
    _exact_fields(mapping, _SEMANTIC_FIELDS, {"binding_identity"}, "dependency binding")
    schema_version = mapping["schema_version"]
    if schema_version != SCHEMA_VERSION:
        _error("unsupported dependency binding schema version")
    role = _enum(mapping["dependency_role"], _ROLES, "dependency_role")
    if expected_role is not None and role != expected_role:
        _error("dependency role does not match adapter")
    expected = _expected_dependency(role)
    logical_id = _enum(mapping["dependency_logical_id"], _LOGICAL_IDS, "dependency_logical_id")
    dependency_class = _enum(
        mapping["expected_dependency_class"],
        _CLASSES,
        "expected_dependency_class",
    )
    if logical_id != expected["dependency_logical_id"]:
        _error("dependency logical identity conflicts with dependency role")
    if dependency_class != expected["expected_dependency_class"]:
        _error("dependency class conflicts with dependency role")

    contract_identity = mapping["dependency_contract_identity"]
    if contract_identity is not None:
        contract_identity = _sha(contract_identity, "dependency_contract_identity")
    version_identity = mapping["dependency_version_identity"]
    if version_identity is not None:
        version_identity = _text(version_identity, "dependency_version_identity")
    if contract_identity is None and version_identity is None:
        _error("at least one dependency contract or version identity is required")
    if contract_identity != expected["dependency_contract_identity"]:
        _error("dependency contract identity conflicts with frozen dependency")
    if version_identity != expected["dependency_version_identity"]:
        _error("dependency version identity conflicts with frozen dependency")

    content_identity = _validate_content_identity(mapping["dependency_content_identity"])
    if content_identity != expected["dependency_content_identity"]:
        _error("dependency content identity conflicts with frozen dependency")
    snapshot = _validate_snapshot(mapping["dependency_snapshot"])
    if snapshot != expected["dependency_snapshot"]:
        _error("dependency snapshot conflicts with frozen dependency")
    source_ref = _validate_source_ref(mapping["source_ref"])
    input_binding = _validate_input_binding(mapping["input_binding"], role)

    semantic: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "dependency_role": role,
        "dependency_logical_id": logical_id,
        "expected_dependency_class": dependency_class,
        "dependency_contract_identity": contract_identity,
        "dependency_version_identity": version_identity,
        "dependency_content_identity": content_identity,
        "dependency_snapshot": snapshot,
        "source_ref": source_ref,
        "input_binding": input_binding,
    }
    declared: str | None = None
    if "binding_identity" in mapping:
        declared = _sha(mapping["binding_identity"], "binding_identity")
    return semantic, declared


def _identity_payload(semantic: Mapping[str, object]) -> dict[str, object]:
    return {
        "binding_schema_id": BINDING_SCHEMA_ID,
        **_plain(semantic),
    }


def _compute_binding_identity(semantic: Mapping[str, object]) -> str:
    return identity_from_fields(_identity_payload(semantic), schema_version=SCHEMA_VERSION)


def _source_ref_input(value: object) -> object:
    if isinstance(value, SourceReference):
        return {
            "schema_version": SCHEMA_VERSION,
            **value.to_dict(),
        }
    return value


def _coerce_discovery(value: object) -> DiscoveryResult:
    if isinstance(value, DiscoveryResult):
        return value
    if isinstance(value, Mapping):
        try:
            return DiscoveryResult.from_mapping(value)
        except ValueError as exc:
            _error(str(exc), getattr(exc, "code", FailureCode.INVALID_SCHEMA))
    _error("discovery_result must be a DiscoveryResult or mapping")


def _coerce_normalization(value: object) -> NormalizationResult:
    if isinstance(value, NormalizationResult):
        return value
    if isinstance(value, Mapping):
        try:
            return NormalizationResult.from_mapping(value)
        except ValueError as exc:
            _error(str(exc), getattr(exc, "code", FailureCode.INVALID_SCHEMA))
    _error("normalization_result must be a NormalizationResult or mapping")


def _record_input(value: object) -> Mapping[str, object] | DependencyBinding:
    if isinstance(value, DependencyBinding):
        return value
    return _require_mapping(value, "dependency binding")


def _bind_dependency(
    record: Mapping[str, object] | DependencyBinding,
    *,
    expected_role: str,
    discovery_result: DiscoveryResult | Mapping[str, object],
    normalization_result: NormalizationResult | Mapping[str, object],
    source_ref: SourceReference | Mapping[str, object],
    upstream_dependency_identity: object,
) -> DependencyBinding:
    discovery = _coerce_discovery(discovery_result)
    normalization = _coerce_normalization(normalization_result)
    if normalization.discovery_identity != discovery.discovery_identity:
        _error("normalization result is not bound to discovery", FailureCode.HASH_MISMATCH)

    supplied_source_ref = _validate_source_ref(_source_ref_input(source_ref))
    if supplied_source_ref["source_set_identity"] != discovery.source_set_identity:
        _error("source_ref is not bound to discovery source set", FailureCode.HASH_MISMATCH)
    if not any(
        supplied_source_ref == {"schema_version": SCHEMA_VERSION, **selected.to_dict()}
        for selected in discovery.selected_sources
    ):
        _error("source_ref does not match a selected discovery source", FailureCode.HASH_MISMATCH)

    binding_input = _record_input(record)
    semantic, declared = _validate_semantic_mapping(
        binding_input,
        expected_role=expected_role,
    )
    if semantic["source_ref"] != supplied_source_ref:
        _error("declared source_ref does not match supplied source_ref", FailureCode.HASH_MISMATCH)

    if expected_role == "MR03_PACKAGER":
        upstream = None
    else:
        upstream = _sha(upstream_dependency_identity, "upstream_dependency_identity")
    expected_input = {
        "task_identity": discovery.task_identity,
        "source_set_identity": discovery.source_set_identity,
        "discovery_identity": discovery.discovery_identity,
        "normalization_identity": normalization.normalization_identity,
        "upstream_dependency_identity": upstream,
    }
    if semantic["input_binding"] != expected_input:
        _error("input_binding does not match supplied MR-05 identities", FailureCode.HASH_MISMATCH)

    computed = _compute_binding_identity(semantic)
    if declared is not None and declared != computed:
        _error("binding_identity does not match canonical binding", FailureCode.HASH_MISMATCH)
    return DependencyBinding(**semantic, binding_identity=computed)


@dataclass(frozen=True, slots=True)
class DependencyBinding:
    """Immutable declarative binding of MR-05 data to one frozen dependency."""

    schema_version: str
    dependency_role: str
    dependency_logical_id: str
    expected_dependency_class: str
    dependency_contract_identity: str | None
    dependency_version_identity: str | None
    dependency_content_identity: Mapping[str, object]
    dependency_snapshot: Mapping[str, object]
    source_ref: Mapping[str, object]
    input_binding: Mapping[str, object]
    binding_identity: str | None = None

    def __post_init__(self) -> None:
        raw: dict[str, object] = {
            "schema_version": self.schema_version,
            "dependency_role": self.dependency_role,
            "dependency_logical_id": self.dependency_logical_id,
            "expected_dependency_class": self.expected_dependency_class,
            "dependency_contract_identity": self.dependency_contract_identity,
            "dependency_version_identity": self.dependency_version_identity,
            "dependency_content_identity": self.dependency_content_identity,
            "dependency_snapshot": self.dependency_snapshot,
            "source_ref": self.source_ref,
            "input_binding": self.input_binding,
        }
        if self.binding_identity is not None:
            raw["binding_identity"] = self.binding_identity
        semantic, declared = _validate_semantic_mapping(raw)
        computed = _compute_binding_identity(semantic)
        if declared is not None and declared != computed:
            _error("binding_identity does not match canonical binding", FailureCode.HASH_MISMATCH)
        object.__setattr__(self, "schema_version", semantic["schema_version"])
        object.__setattr__(self, "dependency_role", semantic["dependency_role"])
        object.__setattr__(self, "dependency_logical_id", semantic["dependency_logical_id"])
        object.__setattr__(self, "expected_dependency_class", semantic["expected_dependency_class"])
        object.__setattr__(self, "dependency_contract_identity", semantic["dependency_contract_identity"])
        object.__setattr__(self, "dependency_version_identity", semantic["dependency_version_identity"])
        object.__setattr__(self, "dependency_content_identity", _freeze(semantic["dependency_content_identity"]))
        object.__setattr__(self, "dependency_snapshot", _freeze(semantic["dependency_snapshot"]))
        object.__setattr__(self, "source_ref", _freeze(semantic["source_ref"]))
        object.__setattr__(self, "input_binding", _freeze(semantic["input_binding"]))
        object.__setattr__(self, "binding_identity", computed)

    @property
    def identity_payload(self) -> dict[str, object]:
        """Return the exact semantic preimage used for ``binding_identity``."""

        return _identity_payload(
            {
                "schema_version": self.schema_version,
                "dependency_role": self.dependency_role,
                "dependency_logical_id": self.dependency_logical_id,
                "expected_dependency_class": self.expected_dependency_class,
                "dependency_contract_identity": self.dependency_contract_identity,
                "dependency_version_identity": self.dependency_version_identity,
                "dependency_content_identity": self.dependency_content_identity,
                "dependency_snapshot": self.dependency_snapshot,
                "source_ref": self.source_ref,
                "input_binding": self.input_binding,
            }
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "dependency_role": self.dependency_role,
            "dependency_logical_id": self.dependency_logical_id,
            "expected_dependency_class": self.expected_dependency_class,
            "dependency_contract_identity": self.dependency_contract_identity,
            "dependency_version_identity": self.dependency_version_identity,
            "dependency_content_identity": _plain(self.dependency_content_identity),
            "dependency_snapshot": _plain(self.dependency_snapshot),
            "source_ref": _plain(self.source_ref),
            "input_binding": _plain(self.input_binding),
            "binding_identity": self.binding_identity,
        }

    def canonical_bytes(self) -> bytes:
        """Return canonical bytes for the complete immutable record."""

        return canonical_identity_bytes(self.to_dict())

    def canonical_identity_bytes(self) -> bytes:
        """Return canonical bytes for the identity preimage."""

        return canonical_identity_bytes(self.identity_payload)

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "DependencyBinding":
        mapping = _require_mapping(value, "dependency binding")
        _exact_fields(mapping, _BINDING_FIELDS, set(), "dependency binding")
        return cls(
            schema_version=mapping["schema_version"],
            dependency_role=mapping["dependency_role"],
            dependency_logical_id=mapping["dependency_logical_id"],
            expected_dependency_class=mapping["expected_dependency_class"],
            dependency_contract_identity=mapping["dependency_contract_identity"],
            dependency_version_identity=mapping["dependency_version_identity"],
            dependency_content_identity=mapping["dependency_content_identity"],
            dependency_snapshot=mapping["dependency_snapshot"],
            source_ref=mapping["source_ref"],
            input_binding=mapping["input_binding"],
            binding_identity=mapping["binding_identity"],
        )


DependencyBindingRecord = DependencyBinding
MR03DependencyBinding = DependencyBinding


def bind_mr03_dependency(
    record: Mapping[str, object] | DependencyBinding,
    discovery_result: DiscoveryResult | Mapping[str, object],
    normalization_result: NormalizationResult | Mapping[str, object],
    source_ref: SourceReference | Mapping[str, object],
) -> DependencyBinding:
    """Bind supplied MR-05 identities to the frozen MR-03 declaration."""

    return _bind_dependency(
        record,
        expected_role="MR03_PACKAGER",
        discovery_result=discovery_result,
        normalization_result=normalization_result,
        source_ref=source_ref,
        upstream_dependency_identity=None,
    )


def compute_binding_identity(value: Mapping[str, object] | DependencyBinding) -> str:
    """Recompute a binding identity from validated semantic fields."""

    if isinstance(value, DependencyBinding):
        return value.binding_identity
    semantic, _ = _validate_semantic_mapping(_require_mapping(value, "dependency binding"))
    return _compute_binding_identity(semantic)


def canonical_dependency_binding_bytes(
    value: Mapping[str, object] | DependencyBinding,
) -> bytes:
    """Canonicalize a complete binding record without changing it."""

    binding = value if isinstance(value, DependencyBinding) else DependencyBinding.from_mapping(value)
    return binding.canonical_bytes()


dependency_binding_identity = compute_binding_identity
binding_identity_for = compute_binding_identity


def not_implemented(*args: object, **kwargs: object) -> None:
    """Retain the explicit fail-closed marker for operational composition."""

    del args, kwargs
    phase_not_implemented("mr03_adapter")


__all__ = (
    "BINDING_SCHEMA_ID",
    "DEPENDENCY_BINDING_SCHEMA_ID",
    "DEPENDENCY_BINDING_SCHEMA_VERSION",
    "MR03_EXPECTED_COMMIT",
    "MR03_EXPECTED_PARENT",
    "MR03_EXPECTED_TREE",
    "MR03_COMMITTED_FILESET_SHA256",
    "MR03_INTERFACE_IDENTITY",
    "MR04_EXPECTED_COMMIT",
    "MR04_EXPECTED_PARENT",
    "MR04_EXPECTED_TREE",
    "MR04_CONTENTSET_SHA256",
    "MR04_PATHSET_SHA256",
    "MR04_IMPLEMENTATION_CONTRACT_SHA256",
    "MR03_EXECUTION_IMPLEMENTATION_COUNT",
    "MR04_EXECUTION_IMPLEMENTATION_COUNT",
    "SUBPROCESS_EXECUTION_COUNT",
    "FILESYSTEM_DEPENDENCY_EXECUTION_COUNT",
    "NETWORK_IMPLEMENTATION_COUNT",
    "MODEL_CALL_IMPLEMENTATION_COUNT",
    "AUTH_IMPLEMENTATION_COUNT",
    "BOUNDED_CONTEXT_IMPLEMENTATION_COUNT",
    "VERIFIER_IMPLEMENTATION_COUNT",
    "CONTROLLER_IMPLEMENTATION_COUNT",
    "AUTO_RETRY_IMPLEMENTATION_COUNT",
    "AUTO_FALLBACK_IMPLEMENTATION_COUNT",
    "DependencyBindingValidationError",
    "DependencyBindingError",
    "AdapterValidationError",
    "DependencyBinding",
    "DependencyBindingRecord",
    "MR03DependencyBinding",
    "bind_mr03_dependency",
    "compute_binding_identity",
    "dependency_binding_identity",
    "binding_identity_for",
    "canonical_dependency_binding_bytes",
    "not_implemented",
)
