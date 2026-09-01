"""Pure-data deterministic normalization primitives for MR-05.

Normalization accepts an already materialized discovery result and explicit
row metadata. It validates and canonically orders those rows; it does not
acquire source data, make a security decision, or invoke another phase.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType

from .canonical import canonical_json_bytes
from .contracts import SCHEMA_VERSION, validate_schema_version
from .discovery import (
    CLASSIFICATIONS,
    DiscoveryResult,
    SourceReference,
    validate_canonical_locator,
)
from .failures import FailureCode, phase_not_implemented
from .identity import require_sha256, schema_bound_identity


NORMALIZATION_POLICY_VERSION = SCHEMA_VERSION
VALIDITY_VALUES = frozenset(
    {
        "VALID",
        "VALID_WITH_SCOPE_LIMITATION",
        "SUPERSEDED",
        "INVALIDATED_SPECIFICALLY",
        "HISTORICAL_BLOCK_ONLY",
        "AUTHORITATIVE_TERMINAL_POLICY",
        "UNKNOWN",
    }
)
SUPERSESSION_VALUES = frozenset(
    {"NONE", "EXPLICIT_SUPERSEDED", "EXPLICIT_INVALIDATED"}
)


class NormalizationValidationError(ValueError):
    """A supplied normalization value is malformed or unsafe."""

    def __init__(self, message: str, code: FailureCode | str = FailureCode.INVALID_SCHEMA) -> None:
        super().__init__(message)
        self.code = code.value if isinstance(code, FailureCode) else code
        self.failure_code = self.code
        self.retry_allowed = False


NormalizationError = NormalizationValidationError


def _error(message: str, code: FailureCode | str = FailureCode.INVALID_SCHEMA) -> None:
    raise NormalizationValidationError(message, code)


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


def _text(value: object, context: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        _error(f"{context} must contain 1..{maximum} characters")
    if "\x00" in value:
        _error(f"{context} must not contain NUL", FailureCode.SOURCE_PATH_ESCAPE)
    return value


def _hash(value: object, context: str) -> str:
    try:
        return require_sha256(value, field=context)
    except ValueError as exc:
        _error(str(exc))
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


def _freeze(value: object) -> object:
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


@dataclass(frozen=True, slots=True)
class ProvenanceReference:
    """Immutable row provenance bound to the row's source identity."""

    source_id: str
    canonical_locator: str
    content_sha256: str
    phase_id: str
    artifact_type: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_id", _hash(self.source_id, "provenance.source_id"))
        object.__setattr__(self, "canonical_locator", validate_canonical_locator(self.canonical_locator, context="provenance.canonical_locator"))
        object.__setattr__(self, "content_sha256", _hash(self.content_sha256, "provenance.content_sha256"))
        object.__setattr__(self, "phase_id", _text(self.phase_id, "provenance.phase_id", maximum=256))
        object.__setattr__(self, "artifact_type", _text(self.artifact_type, "provenance.artifact_type", maximum=256))

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "ProvenanceReference":
        mapping = _require_mapping(value, "provenance")
        _exact_fields(
            mapping,
            {"source_id", "canonical_locator", "content_sha256", "phase_id", "artifact_type"},
            set(),
            "provenance",
        )
        return cls(
            source_id=mapping["source_id"],
            canonical_locator=mapping["canonical_locator"],
            content_sha256=mapping["content_sha256"],
            phase_id=mapping["phase_id"],
            artifact_type=mapping["artifact_type"],
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "source_id": self.source_id,
            "canonical_locator": self.canonical_locator,
            "content_sha256": self.content_sha256,
            "phase_id": self.phase_id,
            "artifact_type": self.artifact_type,
        }


@dataclass(frozen=True, slots=True)
class NormalizedItem:
    """One canonical normalization row; raw byte identity is retained."""

    source_id: str
    canonical_locator: str
    content_sha256: str
    content_size_bytes: int
    phase_id: str
    artifact_type: str
    current_validity: str
    supersession: str
    classification: str
    mandatory: bool
    provenance: ProvenanceReference
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            _error("unsupported normalized-item schema version")
        source_id = _hash(self.source_id, "source_id")
        locator = validate_canonical_locator(self.canonical_locator)
        content_hash = _hash(self.content_sha256, "content_sha256")
        size = _integer(self.content_size_bytes, "content_size_bytes")
        phase_id = _text(self.phase_id, "phase_id", maximum=256)
        artifact_type = _text(self.artifact_type, "artifact_type", maximum=256)
        validity = _enum(self.current_validity, VALIDITY_VALUES, "current_validity")
        supersession = _enum(self.supersession, SUPERSESSION_VALUES, "supersession")
        classification = _enum(self.classification, CLASSIFICATIONS, "classification")
        mandatory = _boolean(self.mandatory, "mandatory")
        if not isinstance(self.provenance, ProvenanceReference):
            _error("provenance must be a ProvenanceReference", FailureCode.PROVENANCE_GAP)
        if (
            self.provenance.source_id != source_id
            or self.provenance.canonical_locator != locator
            or self.provenance.content_sha256 != content_hash
            or self.provenance.phase_id != phase_id
            or self.provenance.artifact_type != artifact_type
        ):
            _error("provenance does not exactly bind the normalized row", FailureCode.PROVENANCE_GAP)
        if supersession == "NONE" and validity in {"SUPERSEDED", "INVALIDATED_SPECIFICALLY"}:
            _error("superseded or invalidated validity requires an explicit relation", FailureCode.INVALID_SCHEMA)
        if supersession == "EXPLICIT_SUPERSEDED" and validity != "SUPERSEDED":
            _error("explicit supersession must preserve SUPERSEDED validity", FailureCode.INVALID_SCHEMA)
        if supersession == "EXPLICIT_INVALIDATED" and validity != "INVALIDATED_SPECIFICALLY":
            _error("explicit invalidation must preserve INVALIDATED_SPECIFICALLY validity", FailureCode.INVALID_SCHEMA)
        object.__setattr__(self, "source_id", source_id)
        object.__setattr__(self, "canonical_locator", locator)
        object.__setattr__(self, "content_sha256", content_hash)
        object.__setattr__(self, "content_size_bytes", size)
        object.__setattr__(self, "phase_id", phase_id)
        object.__setattr__(self, "artifact_type", artifact_type)
        object.__setattr__(self, "current_validity", validity)
        object.__setattr__(self, "supersession", supersession)
        object.__setattr__(self, "classification", classification)
        object.__setattr__(self, "mandatory", mandatory)

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "NormalizedItem":
        mapping = _require_mapping(value, "normalized item")
        _exact_fields(
            mapping,
            {
                "source_id",
                "canonical_locator",
                "content_sha256",
                "content_size_bytes",
                "phase_id",
                "artifact_type",
                "current_validity",
                "supersession",
                "classification",
                "mandatory",
                "provenance",
            },
            set(),
            "normalized item",
        )
        return cls(
            schema_version=SCHEMA_VERSION,
            source_id=mapping["source_id"],
            canonical_locator=mapping["canonical_locator"],
            content_sha256=mapping["content_sha256"],
            content_size_bytes=mapping["content_size_bytes"],
            phase_id=mapping["phase_id"],
            artifact_type=mapping["artifact_type"],
            current_validity=mapping["current_validity"],
            supersession=mapping["supersession"],
            classification=mapping["classification"],
            mandatory=mapping["mandatory"],
            provenance=ProvenanceReference.from_mapping(mapping["provenance"]),
        )

    @classmethod
    def from_source(
        cls,
        source: SourceReference | Mapping[str, object],
        *,
        phase_id: str,
        artifact_type: str,
        current_validity: str,
        supersession: str,
        classification: str,
        mandatory: bool,
    ) -> "NormalizedItem":
        reference = source if isinstance(source, SourceReference) else SourceReference.from_mapping(source)
        provenance = ProvenanceReference(
            source_id=reference.source_id,
            canonical_locator=reference.canonical_locator,
            content_sha256=reference.content_sha256,
            phase_id=phase_id,
            artifact_type=artifact_type,
        )
        return cls(
            schema_version=SCHEMA_VERSION,
            source_id=reference.source_id,
            canonical_locator=reference.canonical_locator,
            content_sha256=reference.content_sha256,
            content_size_bytes=reference.content_size_bytes,
            phase_id=phase_id,
            artifact_type=artifact_type,
            current_validity=current_validity,
            supersession=supersession,
            classification=classification,
            mandatory=mandatory,
            provenance=provenance,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "source_id": self.source_id,
            "canonical_locator": self.canonical_locator,
            "content_sha256": self.content_sha256,
            "content_size_bytes": self.content_size_bytes,
            "phase_id": self.phase_id,
            "artifact_type": self.artifact_type,
            "current_validity": self.current_validity,
            "supersession": self.supersession,
            "classification": self.classification,
            "mandatory": self.mandatory,
            "provenance": self.provenance.to_dict(),
        }


# Names used by callers that describe the row rather than the implementation.
NormalizationItem = NormalizedItem


def _item_sort_key(item: NormalizedItem) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    return (
        item.phase_id.encode("utf-8"),
        item.artifact_type.encode("utf-8"),
        item.canonical_locator.encode("utf-8"),
        item.content_sha256.encode("ascii"),
        canonical_json_bytes(item.to_dict()),
    )


def _normalization_identity_payload(
    *,
    discovery_identity: str,
    items: Sequence[NormalizedItem],
    input_bytes: int,
    output_bytes: int,
) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "discovery_identity": discovery_identity,
        "normalized_items": [item.to_dict() for item in items],
        "normalization_policy_version": NORMALIZATION_POLICY_VERSION,
        "input_bytes": input_bytes,
        "output_bytes": output_bytes,
    }


@dataclass(frozen=True, slots=True)
class NormalizationResult:
    """Canonical, immutable normalization result bound to discovery."""

    schema_version: str
    discovery_identity: str
    normalized_items: tuple[NormalizedItem, ...]
    normalization_policy_version: str
    input_bytes: int
    output_bytes: int
    normalization_identity: str | None = None
    observational_metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION or self.normalization_policy_version != NORMALIZATION_POLICY_VERSION:
            _error("unsupported normalization schema version")
        discovery_id = _hash(self.discovery_identity, "discovery_identity")
        items = tuple(self.normalized_items)
        if any(not isinstance(item, NormalizedItem) for item in items):
            _error("normalized_items contains an invalid row")
        ordered = tuple(sorted(items, key=_item_sort_key))
        if items != ordered:
            _error("normalized_items are not canonically ordered")
        input_bytes = _integer(self.input_bytes, "input_bytes")
        output_bytes = _integer(self.output_bytes, "output_bytes")
        expected_output = len(canonical_json_bytes([item.to_dict() for item in items]))
        if output_bytes != expected_output:
            _error("output_bytes does not match canonical normalized rows")
        observations = _observations(self.observational_metadata, "observational_metadata")
        payload = _normalization_identity_payload(
            discovery_identity=discovery_id,
            items=items,
            input_bytes=input_bytes,
            output_bytes=output_bytes,
        )
        computed = schema_bound_identity("mr05.normalization", payload)
        declared = computed if self.normalization_identity is None else _hash(self.normalization_identity, "normalization_identity")
        if declared != computed:
            _error("normalization_identity does not match canonical result", FailureCode.HASH_MISMATCH)
        object.__setattr__(self, "discovery_identity", discovery_id)
        object.__setattr__(self, "normalized_items", items)
        object.__setattr__(self, "input_bytes", input_bytes)
        object.__setattr__(self, "output_bytes", output_bytes)
        object.__setattr__(self, "normalization_identity", declared)
        object.__setattr__(self, "observational_metadata", observations)

    @property
    def identity_payload(self) -> dict[str, object]:
        return _normalization_identity_payload(
            discovery_identity=self.discovery_identity,
            items=self.normalized_items,
            input_bytes=self.input_bytes,
            output_bytes=self.output_bytes,
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "NormalizationResult":
        mapping = _require_mapping(value, "normalization result")
        _exact_fields(
            mapping,
            {
                "schema_version",
                "discovery_identity",
                "normalized_items",
                "normalization_policy_version",
                "input_bytes",
                "output_bytes",
                "normalization_identity",
            },
            {"observational_metadata"},
            "normalization result",
        )
        items = tuple(
            NormalizedItem.from_mapping(item)
            for item in _sequence(mapping["normalized_items"], "normalized_items")
        )
        return cls(
            schema_version=mapping["schema_version"],
            discovery_identity=mapping["discovery_identity"],
            normalized_items=items,
            normalization_policy_version=mapping["normalization_policy_version"],
            input_bytes=mapping["input_bytes"],
            output_bytes=mapping["output_bytes"],
            normalization_identity=mapping["normalization_identity"],
            observational_metadata=mapping.get("observational_metadata", {}),
        )

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "discovery_identity": self.discovery_identity,
            "normalized_items": [item.to_dict() for item in self.normalized_items],
            "normalization_policy_version": self.normalization_policy_version,
            "input_bytes": self.input_bytes,
            "output_bytes": self.output_bytes,
            "normalization_identity": self.normalization_identity,
        }
        if self.observational_metadata:
            result["observational_metadata"] = _plain(self.observational_metadata)
        return result

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict(), identity_critical=False)


def _source_key(value: SourceReference | NormalizedItem) -> tuple[str, str, str, int]:
    return (
        value.source_id,
        value.canonical_locator,
        value.content_sha256,
        value.content_size_bytes,
    )


def _multiset(values: Sequence[SourceReference | NormalizedItem]) -> dict[tuple[str, str, str, int], int]:
    result: dict[tuple[str, str, str, int], int] = {}
    for value in values:
        key = _source_key(value)
        result[key] = result.get(key, 0) + 1
    return result


def normalize(
    discovery: DiscoveryResult | Mapping[str, object],
    items: Sequence[NormalizedItem | Mapping[str, object]],
    *,
    input_bytes: int | None = None,
    output_bytes: int | None = None,
    observational_metadata: Mapping[str, object] | None = None,
) -> NormalizationResult:
    """Validate and canonically serialize rows bound to a discovery result."""

    if isinstance(discovery, DiscoveryResult):
        discovery_result = discovery
    else:
        discovery_result = DiscoveryResult.from_mapping(_require_mapping(discovery, "discovery"))
    raw_items = _sequence(items, "normalized_items")
    parsed_items = tuple(
        item if isinstance(item, NormalizedItem) else NormalizedItem.from_mapping(item)
        for item in raw_items
    )
    references = discovery_result.selected_sources
    if _multiset(parsed_items) != _multiset(references):
        _error("normalized rows do not exactly cover discovery source references", FailureCode.PROVENANCE_GAP)
    derived_input_bytes = sum(item.content_size_bytes for item in parsed_items)
    if derived_input_bytes != discovery_result.total_selected_bytes:
        _error("normalized input byte total does not match discovery", FailureCode.HASH_MISMATCH)
    ordered_items = tuple(sorted(parsed_items, key=_item_sort_key))
    derived_output_bytes = len(canonical_json_bytes([item.to_dict() for item in ordered_items]))
    if input_bytes is not None and _integer(input_bytes, "input_bytes") != derived_input_bytes:
        _error("declared input_bytes does not match source references", FailureCode.HASH_MISMATCH)
    if output_bytes is not None and _integer(output_bytes, "output_bytes") != derived_output_bytes:
        _error("declared output_bytes does not match canonical rows", FailureCode.HASH_MISMATCH)
    return NormalizationResult(
        schema_version=SCHEMA_VERSION,
        discovery_identity=discovery_result.discovery_identity,
        normalized_items=ordered_items,
        normalization_policy_version=NORMALIZATION_POLICY_VERSION,
        input_bytes=derived_input_bytes,
        output_bytes=derived_output_bytes,
        observational_metadata={} if observational_metadata is None else observational_metadata,
    )


def normalize_rows(
    discovery: DiscoveryResult | Mapping[str, object],
    items: Sequence[NormalizedItem | Mapping[str, object]],
    **kwargs: object,
) -> NormalizationResult:
    """Named alias for :func:`normalize`."""

    return normalize(discovery, items, **kwargs)  # type: ignore[arg-type]


def canonical_normalization_bytes(value: NormalizationResult | Mapping[str, object]) -> bytes:
    result = value if isinstance(value, NormalizationResult) else NormalizationResult.from_mapping(value)
    return result.canonical_bytes()


def not_implemented(*args: object, **kwargs: object) -> None:
    """Retain the legacy phase marker for callers that explicitly use it."""

    del args, kwargs
    phase_not_implemented("normalization")


__all__ = (
    "NORMALIZATION_POLICY_VERSION",
    "VALIDITY_VALUES",
    "SUPERSESSION_VALUES",
    "NormalizationValidationError",
    "NormalizationError",
    "ProvenanceReference",
    "NormalizedItem",
    "NormalizationItem",
    "NormalizationResult",
    "normalize",
    "normalize_rows",
    "canonical_normalization_bytes",
    "not_implemented",
)
