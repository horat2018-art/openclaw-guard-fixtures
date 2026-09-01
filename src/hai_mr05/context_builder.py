"""Deterministic, pure-data bounded-context construction for MR-05.

This module consumes only already-produced immutable MR-05 records.  It does
not acquire source bytes, resolve dependencies, call a model, or perform any
operational action.  The output is an atomic metadata package: every eligible
item is included, and an over-budget package is rejected rather than repacked.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import NoReturn

from .canonical import canonical_identity_bytes, canonical_json_bytes
from .contracts import SCHEMA_VERSION
from .discovery import DiscoveryResult, SourceReference
from .failures import FailureCode, phase_not_implemented
from .identity import require_sha256, sha256_canonical
from .metrics import MAX_METRIC_VALUE, Metrics
from .mr03_adapter import DependencyBinding
from .normalization import (
    NormalizedItem,
    NormalizationResult,
    ProvenanceReference,
)
from .provenance import ProvenanceChain


CONTEXT_SCHEMA_ID = "mr05.bounded_context_package"
CONTEXT_SCHEMA_VERSION = SCHEMA_VERSION
CONSTRUCTION_POLICY_VERSION = "MR05-BOUNDED-CONTEXT-CONSTRUCTION-1.0.0"
ITEM_SCHEMA_ID = "mr05.normalized_item"
ITEM_TYPE = "NORMALIZED_ITEM"
BOUNDED_CONTEXT_OVERFLOW_POLICY = "BLOCK_ENTIRE_CONTEXT_NO_REPACK"
PARTIAL_ITEM_TRUNCATION = "NOT_ALLOWED"
MAX_CONTEXT_ITEM_COUNT = "NOT_APPLICABLE"
TOKEN_ESTIMATE_AUTHORITY = "ADVISORY_ONLY"
MODEL_CALL_COUNT = 0

# The context builder is the one authorized implementation in this phase.
BOUNDED_CONTEXT_IMPLEMENTATION_COUNT = 1
MR03_EXECUTION_IMPLEMENTATION_COUNT = 0
MR04_EXECUTION_IMPLEMENTATION_COUNT = 0
FILESYSTEM_SOURCE_READ_COUNT = 0
FILESYSTEM_DEPENDENCY_EXECUTION_COUNT = 0
SUBPROCESS_EXECUTION_COUNT = 0
NETWORK_IMPLEMENTATION_COUNT = 0
MODEL_CALL_IMPLEMENTATION_COUNT = 0
AUTH_IMPLEMENTATION_COUNT = 0
VERIFIER_IMPLEMENTATION_COUNT = 0
CONTROLLER_IMPLEMENTATION_COUNT = 0
AUTO_RETRY_IMPLEMENTATION_COUNT = 0
AUTO_FALLBACK_IMPLEMENTATION_COUNT = 0

ELIGIBLE_CLASSIFICATIONS = frozenset({"PUBLIC"})
ELIGIBLE_CURRENT_VALIDITY = frozenset(
    {"VALID", "VALID_WITH_SCOPE_LIMITATION", "AUTHORITATIVE_TERMINAL_POLICY"}
)
OMISSION_REASONS = frozenset(
    {
        "INTERNAL_DISCLOSURE_POLICY_REQUIRED",
        "PROTECTED_CONTENT",
        "SECRET_LIKE_CONTENT",
        "UNKNOWN_CLASSIFICATION",
        "SUPERSEDED",
        "INVALIDATED",
        "HISTORICAL_BLOCK_ONLY",
        "UNKNOWN_VALIDITY",
    }
)

_REQUIRED_PACKAGE_FIELDS = frozenset(
    {
        "schema_id",
        "schema_version",
        "construction_policy_version",
        "max_context_bytes",
        "input_identities",
        "context_items",
        "context_item_count",
        "context_byte_count",
        "included_item_identities",
        "omitted_item_identities",
        "dependency_binding_identities",
        "provenance_identity",
        "metrics_identity",
        "context_identity",
    }
)
_REQUIRED_INPUT_IDENTITY_FIELDS = frozenset(
    {"task_identity", "source_set_identity", "discovery_identity", "normalization_identity"}
)
_REQUIRED_CONTEXT_ITEM_FIELDS = frozenset(
    {"item_identity", "item_type", "content", "source_refs", "required"}
)
_REQUIRED_CONTEXT_CONTENT_FIELDS = frozenset(
    {
        "artifact_type",
        "classification",
        "current_validity",
        "phase_id",
        "provenance",
        "supersession",
    }
)
_REQUIRED_OMITTED_FIELDS = frozenset({"item_identity", "omission_reason"})
_REQUIRED_SOURCE_REF_FIELDS = frozenset(
    {"source_id", "canonical_locator", "content_sha256", "content_size_bytes", "source_set_identity"}
)
_CONTEXT_IDENTITY_FIELDS = (
    "schema_id",
    "schema_version",
    "construction_policy_version",
    "max_context_bytes",
    "input_identities",
    "context_items",
    "context_item_count",
    "context_byte_count",
    "included_item_identities",
    "omitted_item_identities",
    "dependency_binding_identities",
    "provenance_identity",
    "metrics_identity",
)


class ContextBuildValidationError(ValueError):
    """A bounded-context input or output violates the frozen contract."""

    def __init__(
        self,
        message: str,
        code: FailureCode | str = FailureCode.INVALID_SCHEMA,
    ) -> None:
        super().__init__(message)
        self.code = code.value if isinstance(code, FailureCode) else code
        self.failure_code = self.code
        self.retry_allowed = False


ContextBuilderValidationError = ContextBuildValidationError
ContextBuildError = ContextBuildValidationError
BoundedContextValidationError = ContextBuildValidationError


def _fail(
    message: str,
    code: FailureCode | str = FailureCode.INVALID_SCHEMA,
) -> NoReturn:
    raise ContextBuildValidationError(message, code)


def _failure_code(exc: BaseException) -> str:
    value = getattr(exc, "code", getattr(exc, "failure_code", FailureCode.INVALID_SCHEMA))
    if isinstance(value, FailureCode):
        return value.value
    if isinstance(value, str) and value:
        return value
    return FailureCode.INVALID_SCHEMA.value


def _mapping(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _fail(f"{context} must be an object")
    if any(not isinstance(key, str) for key in value):
        _fail(f"{context} contains a non-string field name")
    return value


def _exact_fields(
    value: Mapping[str, object],
    required: frozenset[str],
    context: str,
) -> None:
    actual = set(value)
    missing = required - actual
    unknown = actual - required
    if missing or unknown:
        details: list[str] = []
        if missing:
            details.append(f"missing={sorted(missing)!r}")
        if unknown:
            details.append(f"unknown={sorted(unknown)!r}")
        _fail(f"{context} fields are not exact ({', '.join(details)})")


def _sequence(value: object, context: str) -> tuple[object, ...]:
    if not isinstance(value, (list, tuple)):
        _fail(f"{context} must be an array")
    return tuple(value)


def _text(value: object, context: str, *, maximum: int = 4096) -> str:
    if type(value) is not str or not 1 <= len(value) <= maximum:
        _fail(f"{context} must contain 1..{maximum} characters")
    if "\x00" in value or "\n" in value or "\r" in value:
        _fail(f"{context} contains an unsafe character", FailureCode.SOURCE_PATH_ESCAPE)
    return value


def _sha(value: object, context: str) -> str:
    try:
        return require_sha256(value, field=context)
    except ValueError as exc:
        _fail(str(exc), FailureCode.INVALID_SCHEMA)
    raise AssertionError("unreachable")


def _integer(value: object, context: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= MAX_METRIC_VALUE:
        _fail(f"{context} must be an integer in the frozen range")
    return value


def _boolean(value: object, context: str) -> bool:
    if type(value) is not bool:
        _fail(f"{context} must be boolean")
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


def _coerce(
    value: object,
    expected_type: type[object],
    context: str,
    parser: object,
) -> object:
    if isinstance(value, expected_type):
        return value
    if not isinstance(value, Mapping):
        _fail(f"{context} must be an accepted immutable record", FailureCode.UNSUPPORTED_INPUT)
    try:
        return parser(value)  # type: ignore[operator]
    except Exception as exc:
        _fail(str(exc), _failure_code(exc))
    raise AssertionError("unreachable")


def _coerce_discovery(value: object) -> DiscoveryResult:
    result = _coerce(value, DiscoveryResult, "discovery_result", DiscoveryResult.from_mapping)
    if not isinstance(result, DiscoveryResult):
        raise AssertionError("discovery coercion changed type")
    return result


def _coerce_normalization(value: object) -> NormalizationResult:
    result = _coerce(
        value,
        NormalizationResult,
        "normalization_result",
        NormalizationResult.from_mapping,
    )
    if not isinstance(result, NormalizationResult):
        raise AssertionError("normalization coercion changed type")
    return result


def _coerce_binding(value: object) -> DependencyBinding:
    result = _coerce(
        value,
        DependencyBinding,
        "dependency_binding",
        DependencyBinding.from_mapping,
    )
    if not isinstance(result, DependencyBinding):
        raise AssertionError("dependency coercion changed type")
    return result


def _coerce_provenance(value: object) -> ProvenanceChain:
    result = _coerce(
        value,
        ProvenanceChain,
        "provenance_chain",
        ProvenanceChain.from_mapping,
    )
    if not isinstance(result, ProvenanceChain):
        raise AssertionError("provenance coercion changed type")
    return result


def _coerce_metrics(value: object) -> Metrics:
    result = _coerce(value, Metrics, "metrics", Metrics.from_mapping)
    if not isinstance(result, Metrics):
        raise AssertionError("metrics coercion changed type")
    return result


def _source_key(value: SourceReference | NormalizedItem) -> tuple[str, str, str, int]:
    return (
        value.source_id,
        value.canonical_locator,
        value.content_sha256,
        value.content_size_bytes,
    )


def normalized_item_identity(item: NormalizedItem) -> str:
    """Return the derived identity for one validated normalized item."""

    if not isinstance(item, NormalizedItem):
        _fail("normalized item must be a NormalizedItem", FailureCode.UNSUPPORTED_INPUT)
    preimage = {
        "item_schema_id": ITEM_SCHEMA_ID,
        "schema_version": CONTEXT_SCHEMA_VERSION,
        "normalized_item": item.to_dict(),
    }
    try:
        return sha256_canonical(preimage)
    except (TypeError, ValueError) as exc:
        _fail(str(exc), FailureCode.HASH_MISMATCH)
    raise AssertionError("unreachable")


def compute_item_identity(item: NormalizedItem) -> str:
    """Named alias for :func:`normalized_item_identity`."""

    return normalized_item_identity(item)


def _validate_source_membership(
    discovery: DiscoveryResult,
    normalization: NormalizationResult,
) -> tuple[dict[tuple[str, str, str, int], SourceReference], dict[tuple[str, str, str, int], str]]:
    references: dict[tuple[str, str, str, int], SourceReference] = {}
    source_ids: set[str] = set()
    for reference in discovery.selected_sources:
        key = _source_key(reference)
        if key in references or reference.source_id in source_ids:
            _fail("discovery selected sources contain a duplicate identity", FailureCode.DUPLICATE_CONFLICT)
        references[key] = reference
        source_ids.add(reference.source_id)

    if normalization.discovery_identity != discovery.discovery_identity:
        _fail("normalization result is not bound to discovery", FailureCode.HASH_MISMATCH)
    if not normalization.normalized_items:
        _fail("zero normalized items cannot form a bounded context", FailureCode.PROVENANCE_GAP)
    if normalization.input_bytes != discovery.total_selected_bytes:
        _fail("normalization input bytes do not match discovery", FailureCode.HASH_MISMATCH)

    identities: dict[tuple[str, str, str, int], str] = {}
    seen_keys: set[tuple[str, str, str, int]] = set()
    selected_locators = {reference.canonical_locator for reference in discovery.selected_sources}
    for item in normalization.normalized_items:
        key = _source_key(item)
        if key not in references:
            if item.source_id in source_ids or item.canonical_locator in selected_locators:
                _fail(
                    "normalized item source identity conflicts with discovery",
                    FailureCode.HASH_MISMATCH,
                )
            _fail("normalized item does not match a selected discovery source", FailureCode.PROVENANCE_GAP)
        if key in seen_keys:
            _fail("normalized items contain a duplicate source identity", FailureCode.DUPLICATE_CONFLICT)
        seen_keys.add(key)
        item_identity = normalized_item_identity(item)
        if item_identity in identities.values():
            _fail("normalized items contain a duplicate item identity", FailureCode.DUPLICATE_CONFLICT)
        identities[key] = item_identity

    if seen_keys != set(references):
        _fail("normalized items do not exactly cover selected sources", FailureCode.PROVENANCE_GAP)
    return references, identities


def _binding_source_reference(
    binding: DependencyBinding,
    discovery: DiscoveryResult,
) -> SourceReference:
    raw = _mapping(binding.source_ref, "dependency_binding.source_ref")
    _exact_fields(raw, frozenset({"schema_version"}) | _REQUIRED_SOURCE_REF_FIELDS, "dependency_binding.source_ref")
    if raw["schema_version"] != CONTEXT_SCHEMA_VERSION:
        _fail("unsupported dependency source_ref schema version", FailureCode.MR05_UNKNOWN_SCHEMA_MAJOR)
    try:
        reference = SourceReference.from_mapping(
            {key: raw[key] for key in _REQUIRED_SOURCE_REF_FIELDS}
        )
    except Exception as exc:
        _fail(str(exc), _failure_code(exc))
    if reference.source_set_identity != discovery.source_set_identity:
        _fail("dependency source_ref is not bound to discovery source set", FailureCode.HASH_MISMATCH)
    if not any(reference.to_dict() == selected.to_dict() for selected in discovery.selected_sources):
        _fail("dependency source_ref is not a selected discovery source", FailureCode.HASH_MISMATCH)
    return reference


def _validate_bindings(
    values: object,
    discovery: DiscoveryResult,
    normalization: NormalizationResult,
) -> tuple[str, ...]:
    raw_bindings = _sequence(values, "dependency_bindings")
    if len(raw_bindings) != 2:
        _fail("exactly two dependency bindings are required", FailureCode.INVALID_SCHEMA)
    bindings = tuple(_coerce_binding(value) for value in raw_bindings)
    roles = {binding.dependency_role for binding in bindings}
    if len(roles) != len(bindings):
        _fail("dependency bindings contain a duplicate role", FailureCode.DUPLICATE_CONFLICT)
    if roles != {"MR03_PACKAGER", "MR04_GUARD"}:
        _fail("dependency roles must be exactly MR03_PACKAGER and MR04_GUARD", FailureCode.INVALID_SCHEMA)
    if len({binding.binding_identity for binding in bindings}) != len(bindings):
        _fail("dependency bindings contain duplicate identities", FailureCode.DUPLICATE_CONFLICT)

    expected_input = {
        "task_identity": discovery.task_identity,
        "source_set_identity": discovery.source_set_identity,
        "discovery_identity": discovery.discovery_identity,
        "normalization_identity": normalization.normalization_identity,
    }
    for binding in bindings:
        if binding.binding_identity is None:
            _fail("dependency binding identity is missing", FailureCode.INVALID_SCHEMA)
        _sha(binding.binding_identity, "binding_identity")
        _binding_source_reference(binding, discovery)
        supplied = _mapping(binding.input_binding, "dependency_binding.input_binding")
        for field, expected in expected_input.items():
            if supplied.get(field) != expected:
                _fail(
                    f"dependency input binding does not match {field}",
                    FailureCode.HASH_MISMATCH,
                )
        if binding.dependency_role == "MR03_PACKAGER":
            if supplied.get("upstream_dependency_identity") is not None:
                _fail("MR03 binding must not have an upstream dependency", FailureCode.HASH_MISMATCH)
        elif supplied.get("upstream_dependency_identity") is None:
            _fail("MR04 binding must have an upstream dependency", FailureCode.HASH_MISMATCH)

    return tuple(
        sorted(
            (binding.binding_identity for binding in bindings if binding.binding_identity is not None),
            key=lambda value: value.encode("ascii"),
        )
    )


def _validate_provenance(
    chain: ProvenanceChain,
    discovery: DiscoveryResult,
    normalization: NormalizationResult,
    dependency_binding_identities: tuple[str, ...],
    metrics: Metrics,
) -> str:
    node_values = tuple(node.identity_value for node in chain.nodes)
    if len(node_values) != len(set(node_values)):
        _fail("provenance contains duplicate identity values", FailureCode.DUPLICATE_CONFLICT)
    node_set = set(node_values)
    required = {
        discovery.task_identity,
        discovery.source_set_identity,
        discovery.discovery_identity,
        normalization.normalization_identity,
        metrics.metrics_identity,
        *dependency_binding_identities,
    }
    if not required.issubset(node_set):
        _fail("provenance does not cover all required input identities", FailureCode.PROVENANCE_GAP)
    if any(
        edge.from_identity not in node_set or edge.to_identity not in node_set
        for edge in chain.edges
    ):
        _fail("provenance edge refers to an unknown identity", FailureCode.PROVENANCE_GAP)
    if chain.provenance_identity is None:
        _fail("provenance identity is missing", FailureCode.PROVENANCE_GAP)
    return _sha(chain.provenance_identity, "provenance_identity")


def _omission_reason(item: NormalizedItem) -> str | None:
    if item.classification != "PUBLIC":
        return {
            "INTERNAL": "INTERNAL_DISCLOSURE_POLICY_REQUIRED",
            "PROTECTED": "PROTECTED_CONTENT",
            "SECRET_LIKE": "SECRET_LIKE_CONTENT",
            "UNKNOWN": "UNKNOWN_CLASSIFICATION",
        }[item.classification]
    if item.current_validity not in ELIGIBLE_CURRENT_VALIDITY:
        return {
            "SUPERSEDED": "SUPERSEDED",
            "INVALIDATED_SPECIFICALLY": "INVALIDATED",
            "HISTORICAL_BLOCK_ONLY": "HISTORICAL_BLOCK_ONLY",
            "UNKNOWN": "UNKNOWN_VALIDITY",
        }[item.current_validity]
    return None


def _mandatory_failure(item: NormalizedItem, reason: str) -> FailureCode:
    if item.classification == "SECRET_LIKE":
        return FailureCode.SECRET_RISK
    if item.classification in {"INTERNAL", "UNKNOWN"}:
        return FailureCode.MR05_DISCLOSURE_DENIED
    if item.classification == "PROTECTED":
        return FailureCode.PROTECTED_CONTENT_SELECTED
    if reason == "UNKNOWN_VALIDITY":
        return FailureCode.UNKNOWN_VALIDITY
    return FailureCode.PROVENANCE_GAP


def _context_item(
    item: NormalizedItem,
    source_reference: SourceReference,
    item_identity: str,
) -> "BoundedContextItem":
    content = {
        "artifact_type": item.artifact_type,
        "classification": item.classification,
        "current_validity": item.current_validity,
        "phase_id": item.phase_id,
        "provenance": item.provenance.to_dict(),
        "supersession": item.supersession,
    }
    return BoundedContextItem(
        item_identity=item_identity,
        item_type=ITEM_TYPE,
        content=content,
        source_refs=(source_reference.to_dict(),),
        required=item.mandatory,
    )


@dataclass(frozen=True, slots=True)
class BoundedContextItem:
    """One atomic, identity-bound normalized metadata item."""

    item_identity: str
    item_type: str
    content: Mapping[str, object]
    source_refs: tuple[Mapping[str, object], ...]
    required: bool

    def __post_init__(self) -> None:
        item_identity = _sha(self.item_identity, "item_identity")
        if self.item_type != ITEM_TYPE:
            _fail("unsupported bounded-context item type", FailureCode.UNSUPPORTED_INPUT)
        content = _mapping(self.content, "context item content")
        _exact_fields(content, _REQUIRED_CONTEXT_CONTENT_FIELDS, "context item content")
        source_values = _sequence(self.source_refs, "context item source_refs")
        if len(source_values) != 1:
            _fail("each context item requires exactly one source reference", FailureCode.PROVENANCE_GAP)
        raw_source = _mapping(source_values[0], "context item source_ref")
        _exact_fields(raw_source, _REQUIRED_SOURCE_REF_FIELDS, "context item source_ref")
        try:
            source_reference = SourceReference.from_mapping(raw_source)
            provenance = ProvenanceReference.from_mapping(content["provenance"])
            normalized = NormalizedItem(
                source_id=source_reference.source_id,
                canonical_locator=source_reference.canonical_locator,
                content_sha256=source_reference.content_sha256,
                content_size_bytes=source_reference.content_size_bytes,
                phase_id=content["phase_id"],
                artifact_type=content["artifact_type"],
                current_validity=content["current_validity"],
                supersession=content["supersession"],
                classification=content["classification"],
                mandatory=_boolean(self.required, "context item required"),
                provenance=provenance,
            )
            if normalized.classification not in ELIGIBLE_CLASSIFICATIONS:
                _fail("context item classification is not admitted", FailureCode.MR05_DISCLOSURE_DENIED)
            if normalized.current_validity not in ELIGIBLE_CURRENT_VALIDITY:
                code = (
                    FailureCode.UNKNOWN_VALIDITY
                    if normalized.current_validity == "UNKNOWN"
                    else FailureCode.PROVENANCE_GAP
                )
                _fail("context item validity is not current", code)
        except ContextBuildValidationError:
            raise
        except Exception as exc:
            _fail(str(exc), _failure_code(exc))
        if normalized_item_identity(normalized) != item_identity:
            _fail("context item identity does not match its canonical projection", FailureCode.HASH_MISMATCH)
        object.__setattr__(self, "item_identity", item_identity)
        object.__setattr__(self, "item_type", ITEM_TYPE)
        object.__setattr__(self, "content", _freeze(_plain(content)))
        object.__setattr__(self, "source_refs", tuple(_freeze(_plain(source)) for source in source_values))
        object.__setattr__(self, "required", normalized.mandatory)

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "BoundedContextItem":
        mapping = _mapping(value, "context item")
        _exact_fields(mapping, _REQUIRED_CONTEXT_ITEM_FIELDS, "context item")
        return cls(
            item_identity=mapping["item_identity"],
            item_type=mapping["item_type"],
            content=mapping["content"],
            source_refs=tuple(_sequence(mapping["source_refs"], "context item source_refs")),
            required=mapping["required"],
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "item_identity": self.item_identity,
            "item_type": self.item_type,
            "content": _plain(self.content),
            "source_refs": [_plain(source) for source in self.source_refs],
            "required": self.required,
        }


ContextItem = BoundedContextItem


@dataclass(frozen=True, slots=True)
class OmittedContextItem:
    """An identity-only record for a non-mandatory item not admitted."""

    item_identity: str
    omission_reason: str

    def __post_init__(self) -> None:
        item_identity = _sha(self.item_identity, "omitted_item_identity")
        if type(self.omission_reason) is not str or self.omission_reason not in OMISSION_REASONS:
            _fail("unsupported omission reason", FailureCode.INVALID_SCHEMA)
        object.__setattr__(self, "item_identity", item_identity)
        object.__setattr__(self, "omission_reason", self.omission_reason)

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "OmittedContextItem":
        mapping = _mapping(value, "omitted context item")
        _exact_fields(mapping, _REQUIRED_OMITTED_FIELDS, "omitted context item")
        return cls(
            item_identity=mapping["item_identity"],
            omission_reason=mapping["omission_reason"],
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "item_identity": self.item_identity,
            "omission_reason": self.omission_reason,
        }


OmittedItem = OmittedContextItem


def _input_identities(value: Mapping[str, object]) -> dict[str, str]:
    _exact_fields(value, _REQUIRED_INPUT_IDENTITY_FIELDS, "input_identities")
    return {
        field: _sha(value[field], f"input_identities.{field}")
        for field in (
            "task_identity",
            "source_set_identity",
            "discovery_identity",
            "normalization_identity",
        )
    }


def _body_payload(
    *,
    schema_id: str,
    schema_version: str,
    construction_policy_version: str,
    max_context_bytes: int,
    input_identities: Mapping[str, object],
    context_items: tuple[BoundedContextItem, ...],
    context_item_count: int,
    included_item_identities: tuple[str, ...],
    omitted_item_identities: tuple[OmittedContextItem, ...],
    dependency_binding_identities: tuple[str, ...],
    provenance_identity: str,
    metrics_identity: str,
) -> dict[str, object]:
    return {
        "schema_id": schema_id,
        "schema_version": schema_version,
        "construction_policy_version": construction_policy_version,
        "max_context_bytes": max_context_bytes,
        "input_identities": _plain(input_identities),
        "context_items": [item.to_dict() for item in context_items],
        "context_item_count": context_item_count,
        "included_item_identities": list(included_item_identities),
        "omitted_item_identities": [item.to_dict() for item in omitted_item_identities],
        "dependency_binding_identities": list(dependency_binding_identities),
        "provenance_identity": provenance_identity,
        "metrics_identity": metrics_identity,
    }


def _identity_payload(
    *,
    body: Mapping[str, object],
    context_byte_count: int,
) -> dict[str, object]:
    payload = dict(body)
    payload["context_byte_count"] = context_byte_count
    return {field: payload[field] for field in _CONTEXT_IDENTITY_FIELDS}


@dataclass(frozen=True, slots=True)
class BoundedContextPackage:
    """Immutable deterministic bounded-context package."""

    schema_id: str
    schema_version: str
    construction_policy_version: str
    max_context_bytes: int
    input_identities: Mapping[str, object]
    context_items: tuple[BoundedContextItem, ...]
    context_item_count: int
    context_byte_count: int
    included_item_identities: tuple[str, ...]
    omitted_item_identities: tuple[OmittedContextItem, ...]
    dependency_binding_identities: tuple[str, ...]
    provenance_identity: str
    metrics_identity: str
    context_identity: str

    def __post_init__(self) -> None:
        if self.schema_id != CONTEXT_SCHEMA_ID:
            _fail("unknown bounded-context schema", FailureCode.MR05_UNKNOWN_SCHEMA_MAJOR)
        if self.schema_version != CONTEXT_SCHEMA_VERSION:
            _fail("unsupported bounded-context schema version", FailureCode.MR05_UNKNOWN_SCHEMA_MAJOR)
        if self.construction_policy_version != CONSTRUCTION_POLICY_VERSION:
            _fail("unsupported bounded-context construction policy", FailureCode.INVALID_SCHEMA)
        max_bytes = _integer(self.max_context_bytes, "max_context_bytes", minimum=1)
        identities = _input_identities(_mapping(self.input_identities, "input_identities"))
        items = tuple(self.context_items)
        if not items or any(not isinstance(item, BoundedContextItem) for item in items):
            _fail("context_items must contain at least one valid item", FailureCode.PROVENANCE_GAP)
        source_set_identity = identities["source_set_identity"]
        for item in items:
            if any(
                source["source_set_identity"] != source_set_identity
                for source in item.source_refs
            ):
                _fail("context item source_ref is outside the input source set", FailureCode.HASH_MISMATCH)
        item_ids = tuple(item.item_identity for item in items)
        if len(set(item_ids)) != len(item_ids):
            _fail("context_items contain duplicate identities", FailureCode.DUPLICATE_CONFLICT)
        if item_ids != tuple(sorted(item_ids, key=lambda value: value.encode("ascii"))):
            _fail("context_items are not canonically ordered", FailureCode.NONDETERMINISTIC_OUTPUT)
        included = tuple(self.included_item_identities)
        if any(not isinstance(value, str) for value in included):
            _fail("included_item_identities contains a non-string", FailureCode.INVALID_SCHEMA)
        included = tuple(_sha(value, "included_item_identity") for value in included)
        if included != item_ids:
            _fail("included item identities do not match context items", FailureCode.HASH_MISMATCH)
        omitted = tuple(self.omitted_item_identities)
        if any(not isinstance(item, OmittedContextItem) for item in omitted):
            _fail("omitted_item_identities contains an invalid record", FailureCode.INVALID_SCHEMA)
        omitted_ids = tuple(item.item_identity for item in omitted)
        if len(set(omitted_ids)) != len(omitted_ids):
            _fail("omitted item identities contain duplicates", FailureCode.DUPLICATE_CONFLICT)
        if omitted_ids != tuple(sorted(omitted_ids, key=lambda value: value.encode("ascii"))):
            _fail("omitted item identities are not canonically ordered", FailureCode.NONDETERMINISTIC_OUTPUT)
        if set(item_ids) & set(omitted_ids):
            _fail("an item cannot be both included and omitted", FailureCode.HASH_MISMATCH)
        dependencies = tuple(self.dependency_binding_identities)
        if len(dependencies) != 2 or len(set(dependencies)) != 2:
            _fail("exactly two distinct dependency binding identities are required", FailureCode.INVALID_SCHEMA)
        dependencies = tuple(_sha(value, "dependency_binding_identity") for value in dependencies)
        if dependencies != tuple(sorted(dependencies, key=lambda value: value.encode("ascii"))):
            _fail("dependency binding identities are not canonically ordered", FailureCode.NONDETERMINISTIC_OUTPUT)
        provenance_identity = _sha(self.provenance_identity, "provenance_identity")
        metrics_identity = _sha(self.metrics_identity, "metrics_identity")
        item_count = _integer(self.context_item_count, "context_item_count")
        if item_count != len(items):
            _fail("context_item_count does not match context_items", FailureCode.HASH_MISMATCH)
        byte_count = _integer(self.context_byte_count, "context_byte_count")
        body = _body_payload(
            schema_id=CONTEXT_SCHEMA_ID,
            schema_version=CONTEXT_SCHEMA_VERSION,
            construction_policy_version=CONSTRUCTION_POLICY_VERSION,
            max_context_bytes=max_bytes,
            input_identities=identities,
            context_items=items,
            context_item_count=item_count,
            included_item_identities=included,
            omitted_item_identities=omitted,
            dependency_binding_identities=dependencies,
            provenance_identity=provenance_identity,
            metrics_identity=metrics_identity,
        )
        computed_byte_count = len(canonical_json_bytes(body))
        if byte_count != computed_byte_count:
            _fail("context_byte_count does not match canonical context body", FailureCode.HASH_MISMATCH)
        if byte_count > max_bytes:
            _fail("context exceeds max_context_bytes", FailureCode.MR05_CONTEXT_OVER_BYTE_BUDGET)
        payload = _identity_payload(body=body, context_byte_count=byte_count)
        computed_identity = sha256_canonical(payload)
        declared_identity = _sha(self.context_identity, "context_identity")
        if declared_identity != computed_identity:
            _fail("context_identity does not match canonical package", FailureCode.HASH_MISMATCH)
        object.__setattr__(self, "schema_id", CONTEXT_SCHEMA_ID)
        object.__setattr__(self, "schema_version", CONTEXT_SCHEMA_VERSION)
        object.__setattr__(self, "construction_policy_version", CONSTRUCTION_POLICY_VERSION)
        object.__setattr__(self, "max_context_bytes", max_bytes)
        object.__setattr__(self, "input_identities", _freeze(identities))
        object.__setattr__(self, "context_items", items)
        object.__setattr__(self, "context_item_count", item_count)
        object.__setattr__(self, "context_byte_count", byte_count)
        object.__setattr__(self, "included_item_identities", included)
        object.__setattr__(self, "omitted_item_identities", omitted)
        object.__setattr__(self, "dependency_binding_identities", dependencies)
        object.__setattr__(self, "provenance_identity", provenance_identity)
        object.__setattr__(self, "metrics_identity", metrics_identity)
        object.__setattr__(self, "context_identity", declared_identity)

    @property
    def identity_payload(self) -> dict[str, object]:
        """Return the exact identity preimage, excluding context_identity."""

        body = _body_payload(
            schema_id=self.schema_id,
            schema_version=self.schema_version,
            construction_policy_version=self.construction_policy_version,
            max_context_bytes=self.max_context_bytes,
            input_identities=self.input_identities,
            context_items=self.context_items,
            context_item_count=self.context_item_count,
            included_item_identities=self.included_item_identities,
            omitted_item_identities=self.omitted_item_identities,
            dependency_binding_identities=self.dependency_binding_identities,
            provenance_identity=self.provenance_identity,
            metrics_identity=self.metrics_identity,
        )
        return _identity_payload(body=body, context_byte_count=self.context_byte_count)

    def canonical_identity_bytes(self) -> bytes:
        """Return canonical bytes for the context identity preimage."""

        return canonical_identity_bytes(self.identity_payload)

    def to_dict(self) -> dict[str, object]:
        body = _body_payload(
            schema_id=self.schema_id,
            schema_version=self.schema_version,
            construction_policy_version=self.construction_policy_version,
            max_context_bytes=self.max_context_bytes,
            input_identities=self.input_identities,
            context_items=self.context_items,
            context_item_count=self.context_item_count,
            included_item_identities=self.included_item_identities,
            omitted_item_identities=self.omitted_item_identities,
            dependency_binding_identities=self.dependency_binding_identities,
            provenance_identity=self.provenance_identity,
            metrics_identity=self.metrics_identity,
        )
        body["context_byte_count"] = self.context_byte_count
        body["context_identity"] = self.context_identity
        return body

    def canonical_bytes(self) -> bytes:
        """Return the complete canonical package bytes."""

        return canonical_json_bytes(self.to_dict())

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "BoundedContextPackage":
        mapping = _mapping(value, "bounded-context package")
        _exact_fields(mapping, _REQUIRED_PACKAGE_FIELDS, "bounded-context package")
        context_items = tuple(
            BoundedContextItem.from_mapping(item)
            for item in _sequence(mapping["context_items"], "context_items")
        )
        omitted = tuple(
            OmittedContextItem.from_mapping(item)
            for item in _sequence(mapping["omitted_item_identities"], "omitted_item_identities")
        )
        return cls(
            schema_id=mapping["schema_id"],
            schema_version=mapping["schema_version"],
            construction_policy_version=mapping["construction_policy_version"],
            max_context_bytes=mapping["max_context_bytes"],
            input_identities=mapping["input_identities"],
            context_items=context_items,
            context_item_count=mapping["context_item_count"],
            context_byte_count=mapping["context_byte_count"],
            included_item_identities=tuple(
                _sequence(mapping["included_item_identities"], "included_item_identities")
            ),
            omitted_item_identities=omitted,
            dependency_binding_identities=tuple(
                _sequence(mapping["dependency_binding_identities"], "dependency_binding_identities")
            ),
            provenance_identity=mapping["provenance_identity"],
            metrics_identity=mapping["metrics_identity"],
            context_identity=mapping["context_identity"],
        )


ContextPackage = BoundedContextPackage
BoundedContext = BoundedContextPackage


def build_context(
    discovery_result: DiscoveryResult | Mapping[str, object],
    normalization_result: NormalizationResult | Mapping[str, object],
    dependency_bindings: object,
    provenance_chain: ProvenanceChain | Mapping[str, object],
    metrics: Metrics | Mapping[str, object],
    max_context_bytes: int,
) -> BoundedContextPackage:
    """Build an atomic bounded context from already-produced pure data."""

    discovery = _coerce_discovery(discovery_result)
    normalization = _coerce_normalization(normalization_result)
    chain = _coerce_provenance(provenance_chain)
    metric_record = _coerce_metrics(metrics)
    max_bytes = _integer(max_context_bytes, "max_context_bytes", minimum=1)
    if metric_record.model_call_count != MODEL_CALL_COUNT or metric_record.model_retry_count != 0:
        _fail("metrics indicate model use or retry", FailureCode.UNSUPPORTED_INPUT)
    source_references, item_identity_sources = _validate_source_membership(discovery, normalization)
    dependency_ids = _validate_bindings(dependency_bindings, discovery, normalization)
    provenance_id = _validate_provenance(
        chain,
        discovery,
        normalization,
        dependency_ids,
        metric_record,
    )

    included: list[BoundedContextItem] = []
    omitted: list[OmittedContextItem] = []
    for item in normalization.normalized_items:
        item_identity = item_identity_sources[_source_key(item)]
        reason = _omission_reason(item)
        if reason is not None:
            if item.mandatory:
                _fail(
                    "mandatory item is excluded by bounded-context policy",
                    _mandatory_failure(item, reason),
                )
            omitted.append(OmittedContextItem(item_identity, reason))
            continue
        reference = source_references[_source_key(item)]
        included.append(_context_item(item, reference, item_identity))

    included.sort(key=lambda item: item.item_identity.encode("ascii"))
    omitted.sort(key=lambda item: item.item_identity.encode("ascii"))
    if not included:
        _fail("zero eligible context items cannot form a package", FailureCode.PROVENANCE_GAP)
    included_tuple = tuple(included)
    omitted_tuple = tuple(omitted)
    included_ids = tuple(item.item_identity for item in included_tuple)
    input_identities = {
        "task_identity": discovery.task_identity,
        "source_set_identity": discovery.source_set_identity,
        "discovery_identity": discovery.discovery_identity,
        "normalization_identity": normalization.normalization_identity,
    }
    body = _body_payload(
        schema_id=CONTEXT_SCHEMA_ID,
        schema_version=CONTEXT_SCHEMA_VERSION,
        construction_policy_version=CONSTRUCTION_POLICY_VERSION,
        max_context_bytes=max_bytes,
        input_identities=input_identities,
        context_items=included_tuple,
        context_item_count=len(included_tuple),
        included_item_identities=included_ids,
        omitted_item_identities=omitted_tuple,
        dependency_binding_identities=dependency_ids,
        provenance_identity=provenance_id,
        metrics_identity=metric_record.metrics_identity,
    )
    context_byte_count = len(canonical_json_bytes(body))
    if context_byte_count > max_bytes:
        _fail(
            "bounded context exceeds the explicit byte budget",
            FailureCode.MR05_CONTEXT_OVER_BYTE_BUDGET,
        )
    context_identity = sha256_canonical(
        _identity_payload(body=body, context_byte_count=context_byte_count)
    )
    return BoundedContextPackage(
        schema_id=CONTEXT_SCHEMA_ID,
        schema_version=CONTEXT_SCHEMA_VERSION,
        construction_policy_version=CONSTRUCTION_POLICY_VERSION,
        max_context_bytes=max_bytes,
        input_identities=input_identities,
        context_items=included_tuple,
        context_item_count=len(included_tuple),
        context_byte_count=context_byte_count,
        included_item_identities=included_ids,
        omitted_item_identities=omitted_tuple,
        dependency_binding_identities=dependency_ids,
        provenance_identity=provenance_id,
        metrics_identity=metric_record.metrics_identity,
        context_identity=context_identity,
    )


def build_bounded_context(
    discovery_result: DiscoveryResult | Mapping[str, object],
    normalization_result: NormalizationResult | Mapping[str, object],
    dependency_bindings: object,
    provenance_chain: ProvenanceChain | Mapping[str, object],
    metrics: Metrics | Mapping[str, object],
    max_context_bytes: int,
) -> BoundedContextPackage:
    """Descriptive alias for :func:`build_context`."""

    return build_context(
        discovery_result,
        normalization_result,
        dependency_bindings,
        provenance_chain,
        metrics,
        max_context_bytes=max_context_bytes,
    )


def construct_bounded_context(
    discovery_result: DiscoveryResult | Mapping[str, object],
    normalization_result: NormalizationResult | Mapping[str, object],
    dependency_bindings: object,
    provenance_chain: ProvenanceChain | Mapping[str, object],
    metrics: Metrics | Mapping[str, object],
    max_context_bytes: int,
) -> BoundedContextPackage:
    """Construction-oriented alias for :func:`build_context`."""

    return build_context(
        discovery_result,
        normalization_result,
        dependency_bindings,
        provenance_chain,
        metrics,
        max_context_bytes=max_context_bytes,
    )


def construct_context(
    discovery_result: DiscoveryResult | Mapping[str, object],
    normalization_result: NormalizationResult | Mapping[str, object],
    dependency_bindings: object,
    provenance_chain: ProvenanceChain | Mapping[str, object],
    metrics: Metrics | Mapping[str, object],
    max_context_bytes: int,
) -> BoundedContextPackage:
    """Short alias for :func:`build_context`."""

    return build_context(
        discovery_result,
        normalization_result,
        dependency_bindings,
        provenance_chain,
        metrics,
        max_context_bytes=max_context_bytes,
    )


def compute_context_identity(value: BoundedContextPackage | Mapping[str, object]) -> str:
    """Recompute and return a validated package identity."""

    package = value if isinstance(value, BoundedContextPackage) else BoundedContextPackage.from_mapping(value)
    return sha256_canonical(package.identity_payload)


def context_identity_for(value: BoundedContextPackage | Mapping[str, object]) -> str:
    """Named alias for :func:`compute_context_identity`."""

    return compute_context_identity(value)


def canonical_context_bytes(value: BoundedContextPackage | Mapping[str, object]) -> bytes:
    """Return canonical complete package bytes after exact validation."""

    package = value if isinstance(value, BoundedContextPackage) else BoundedContextPackage.from_mapping(value)
    return package.canonical_bytes()


def not_implemented(*args: object, **kwargs: object) -> None:
    """Retain the legacy non-operational marker for callers using it directly."""

    del args, kwargs
    phase_not_implemented("context_builder")


__all__ = (
    "CONTEXT_SCHEMA_ID",
    "CONTEXT_SCHEMA_VERSION",
    "CONSTRUCTION_POLICY_VERSION",
    "ITEM_SCHEMA_ID",
    "ITEM_TYPE",
    "BOUNDED_CONTEXT_OVERFLOW_POLICY",
    "PARTIAL_ITEM_TRUNCATION",
    "MAX_CONTEXT_ITEM_COUNT",
    "TOKEN_ESTIMATE_AUTHORITY",
    "MODEL_CALL_COUNT",
    "BOUNDED_CONTEXT_IMPLEMENTATION_COUNT",
    "MR03_EXECUTION_IMPLEMENTATION_COUNT",
    "MR04_EXECUTION_IMPLEMENTATION_COUNT",
    "FILESYSTEM_SOURCE_READ_COUNT",
    "FILESYSTEM_DEPENDENCY_EXECUTION_COUNT",
    "SUBPROCESS_EXECUTION_COUNT",
    "NETWORK_IMPLEMENTATION_COUNT",
    "MODEL_CALL_IMPLEMENTATION_COUNT",
    "AUTH_IMPLEMENTATION_COUNT",
    "VERIFIER_IMPLEMENTATION_COUNT",
    "CONTROLLER_IMPLEMENTATION_COUNT",
    "AUTO_RETRY_IMPLEMENTATION_COUNT",
    "AUTO_FALLBACK_IMPLEMENTATION_COUNT",
    "ELIGIBLE_CLASSIFICATIONS",
    "ELIGIBLE_CURRENT_VALIDITY",
    "OMISSION_REASONS",
    "ContextBuildValidationError",
    "ContextBuilderValidationError",
    "ContextBuildError",
    "BoundedContextValidationError",
    "BoundedContextItem",
    "ContextItem",
    "OmittedContextItem",
    "OmittedItem",
    "BoundedContextPackage",
    "ContextPackage",
    "BoundedContext",
    "normalized_item_identity",
    "compute_item_identity",
    "build_context",
    "build_bounded_context",
    "construct_bounded_context",
    "construct_context",
    "compute_context_identity",
    "context_identity_for",
    "canonical_context_bytes",
    "not_implemented",
)
