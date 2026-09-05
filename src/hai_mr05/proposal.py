"""Deterministic parser for the frozen MR-05 structured cloud proposal.

This module validates already-supplied proposal data against the frozen
mr05.cloud_proposal / 1.0.0 record shape and recomputes the proposal identity
from the authoritative MR05B master identity definition. It performs no
provider/model call, network access, authentication, retry, fallback, verifier
decision, human-gate action, state transition, filesystem I/O, or Git action.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import NoReturn

from .canonical import CanonicalizationError, canonical_json_bytes, parse_json_no_duplicates
from .contracts import (
    SCHEMA_VERSION,
    UnknownSchemaMajorVersionError,
    UnsupportedSchemaVersionError,
    validate_schema_version,
)
from .failures import FailureCode, phase_not_implemented
from .identity import IdentityValidationError, require_sha256, sha256_canonical

PROPOSAL_SCHEMA_ID = "mr05.cloud_proposal"
PROPOSAL_SCHEMA_VERSION = SCHEMA_VERSION
PROPOSAL_STRUCTURAL_AUTHORITY = "MR05B_CONTRACT_SET_SHA256"
PROPOSAL_IDENTITY_AUTHORITY = "MR05B_MASTER_CONTRACT_SHA256"

PROPOSAL_PARSE_IMPLEMENTATION_COUNT = 1
PROPOSAL_IDENTITY_VALIDATION_IMPLEMENTATION_COUNT = 1
FILESYSTEM_SOURCE_READ_COUNT = 0
FILESYSTEM_WRITE_IMPLEMENTATION_COUNT = 0
SUBPROCESS_EXECUTION_COUNT = 0
NETWORK_IMPLEMENTATION_COUNT = 0
PROVIDER_CLIENT_IMPLEMENTATION_COUNT = 0
MODEL_CALL_IMPLEMENTATION_COUNT = 0
MODEL_ROUTING_IMPLEMENTATION_COUNT = 0
AUTH_IMPLEMENTATION_COUNT = 0
AUTO_RETRY_IMPLEMENTATION_COUNT = 0
AUTO_FALLBACK_IMPLEMENTATION_COUNT = 0
LIVE_CLOUD_EXECUTION_COUNT = 0
VERIFIER_DECISION_IMPLEMENTATION_COUNT = 0
HUMAN_GATE_EXECUTION_COUNT = 0
STATE_TRANSITION_EXECUTION_COUNT = 0
GIT_OPERATION_COUNT = 0

PROPOSAL_IDENTITY_PREIMAGE = (
    "schema_version", "request_identity", "run_identity", "task_identity",
    "bound_mr03_package_identity", "bound_mr04_result_identity",
    "bound_context_identity", "claims", "source_refs", "recommendation",
    "uncertainty", "escalation_flags",
)
PROPOSAL_IDENTITY_EXCLUSIONS = (
    "proposal_id", "proposal_identity", "bound_package_identity",
    "proposer_metadata", "free_form_prose", "observational_metadata",
)

_REQUIRED_PROPOSAL_FIELDS = frozenset({
    "schema_version", "proposal_id", "proposal_identity", "request_identity",
    "run_identity", "task_identity", "bound_package_identity",
    "bound_context_identity", "bound_mr03_package_identity",
    "bound_mr04_result_identity", "claims", "source_refs", "recommendation",
    "uncertainty", "escalation_flags", "proposer_metadata",
})
_OPTIONAL_PROPOSAL_FIELDS = frozenset({"free_form_prose", "observational_metadata"})
_SOURCE_REF_FIELDS = frozenset({
    "source_id", "canonical_locator", "content_sha256", "content_size_bytes",
    "source_set_identity",
})
_CLAIM_FIELDS = frozenset({
    "claim_id", "claim_type", "claim_text_or_structured_value", "source_refs",
    "confidence_or_uncertainty",
})
_CONFIDENCE_FIELDS = frozenset({"level", "basis"})
_RECOMMENDATION_FIELDS = frozenset({"kind", "content"})
_UNCERTAINTY_FIELDS = frozenset({"level", "items"})
_PROPOSER_REQUIRED_FIELDS = frozenset({"model_identifier", "provider_request_id", "attempt_number"})
_PROPOSER_OPTIONAL_FIELDS = frozenset({"usage_if_available"})
_LEVEL_VALUES = frozenset({"LOW", "MEDIUM", "HIGH", "UNKNOWN"})
_RECOMMENDATION_KIND_VALUES = frozenset({"OPTION", "SUMMARY", "REQUEST_MORE_EVIDENCE", "NONE"})
_MAX_INT = 9223372036854775807


class ProposalValidationError(ValueError):
    """A structured cloud proposal violates the frozen deterministic contract."""

    def __init__(self, message: str, code: FailureCode | str = FailureCode.PROPOSER_SCHEMA_INVALID) -> None:
        super().__init__(message)
        self.code = code.value if isinstance(code, FailureCode) else code
        self.failure_code = self.code
        self.retry_allowed = False


def _fail(message: str, code: FailureCode | str = FailureCode.PROPOSER_SCHEMA_INVALID) -> NoReturn:
    raise ProposalValidationError(message, code)


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        _fail(f"{field} must be a string-keyed object")
    return value


def _exact_fields(value: Mapping[str, object], required: frozenset[str], field: str, optional: frozenset[str] = frozenset()) -> None:
    actual = set(value)
    if required - actual or actual - required - optional:
        _fail(f"{field} fields are not exact")


def _optional_non_null(
    value: Mapping[str, object],
    field: str,
    record: str,
) -> object | None:
    if field not in value:
        return None
    child = value[field]
    if child is None:
        _fail(f"{record}.{field} must not be null when present")
    return child


def _sequence(value: object, field: str, *, minimum: int = 0) -> tuple[object, ...]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        _fail(f"{field} must be an array")
    result = tuple(value)
    if len(result) < minimum:
        _fail(f"{field} must contain at least {minimum} item(s)")
    return result


def _text(value: object, field: str, *, minimum: int = 1, maximum: int) -> str:
    if type(value) is not str or not minimum <= len(value) <= maximum:
        _fail(f"{field} must contain {minimum}..{maximum} characters")
    if "\x00" in value or any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        _fail(f"{field} contains invalid Unicode")
    return value


def _integer(value: object, field: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum or value > _MAX_INT:
        _fail(f"{field} must be an integer in the frozen range")
    return value


def _sha(value: object, field: str) -> str:
    try:
        return require_sha256(value, field=field)
    except (IdentityValidationError, TypeError, ValueError) as exc:
        _fail(str(exc))
    raise AssertionError("unreachable")


def _enum(value: object, field: str, allowed: frozenset[str]) -> str:
    if type(value) is not str or value not in allowed:
        _fail(f"{field} is outside the frozen enum")
    return value


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            _fail("JSON object keys must be strings")
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


def _identity_json_value(value: object, field: str) -> object:
    try:
        canonical_json_bytes(value, identity_critical=True)
    except (CanonicalizationError, TypeError, ValueError) as exc:
        _fail(f"{field} is not valid identity-critical JSON: {exc}")
    return _freeze(value)


def _metadata_json_object(value: object, field: str) -> Mapping[str, object]:
    row = _mapping(value, field)
    try:
        canonical_json_bytes(row, identity_critical=False)
    except (CanonicalizationError, TypeError, ValueError) as exc:
        _fail(f"{field} is not valid JSON metadata: {exc}")
    frozen = _freeze(row)
    if not isinstance(frozen, Mapping):
        raise AssertionError("metadata freezing changed type")
    return frozen


def _require_sorted_unique(keys: Sequence[object], field: str) -> None:
    if len(set(keys)) != len(keys):
        _fail(f"{field} contains duplicates", FailureCode.NONDETERMINISTIC_OUTPUT)
    if list(keys) != sorted(keys):
        _fail(f"{field} is not in frozen lexical order", FailureCode.NONDETERMINISTIC_OUTPUT)


@dataclass(frozen=True, slots=True)
class ProposalSourceRef:
    source_id: str
    canonical_locator: str
    content_sha256: str
    content_size_bytes: int
    source_set_identity: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_id", _sha(self.source_id, "source_ref.source_id"))
        object.__setattr__(self, "canonical_locator", _text(self.canonical_locator, "source_ref.canonical_locator", maximum=2048))
        object.__setattr__(self, "content_sha256", _sha(self.content_sha256, "source_ref.content_sha256"))
        object.__setattr__(self, "content_size_bytes", _integer(self.content_size_bytes, "source_ref.content_size_bytes"))
        object.__setattr__(self, "source_set_identity", _sha(self.source_set_identity, "source_ref.source_set_identity"))

    @property
    def order_key(self) -> tuple[str, str]:
        return (self.source_id, self.canonical_locator)

    def to_dict(self) -> dict[str, object]:
        return {
            "source_id": self.source_id,
            "canonical_locator": self.canonical_locator,
            "content_sha256": self.content_sha256,
            "content_size_bytes": self.content_size_bytes,
            "source_set_identity": self.source_set_identity,
        }

    @classmethod
    def from_mapping(cls, value: object) -> "ProposalSourceRef":
        row = _mapping(value, "source_ref")
        _exact_fields(row, _SOURCE_REF_FIELDS, "source_ref")
        return cls(**row)


def _source_refs(
    value: object,
    field: str,
    *,
    require_set_order: bool = True,
) -> tuple[ProposalSourceRef, ...]:
    refs = tuple(item if isinstance(item, ProposalSourceRef) else ProposalSourceRef.from_mapping(item) for item in _sequence(value, field, minimum=1))
    if require_set_order:
        _require_sorted_unique(tuple(ref.order_key for ref in refs), field)
    return refs


@dataclass(frozen=True, slots=True)
class ClaimConfidence:
    level: str
    basis: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "level", _enum(self.level, "claim.confidence.level", _LEVEL_VALUES))
        object.__setattr__(self, "basis", _text(self.basis, "claim.confidence.basis", minimum=0, maximum=1024))

    def to_dict(self) -> dict[str, object]:
        return {"level": self.level, "basis": self.basis}

    @classmethod
    def from_mapping(cls, value: object) -> "ClaimConfidence":
        row = _mapping(value, "claim.confidence_or_uncertainty")
        _exact_fields(row, _CONFIDENCE_FIELDS, "claim.confidence_or_uncertainty")
        return cls(**row)


@dataclass(frozen=True, slots=True)
class ProposalClaim:
    claim_id: str
    claim_type: str
    claim_text_or_structured_value: object
    source_refs: tuple[ProposalSourceRef, ...]
    confidence_or_uncertainty: ClaimConfidence

    def __post_init__(self) -> None:
        claim_id = _text(self.claim_id, "claim.claim_id", maximum=256)
        claim_type = _text(self.claim_type, "claim.claim_type", maximum=128)
        content = self.claim_text_or_structured_value
        if type(content) is str:
            content = _text(content, "claim.claim_text_or_structured_value", minimum=0, maximum=8192)
        elif isinstance(content, Mapping) or (isinstance(content, Sequence) and not isinstance(content, (str, bytes, bytearray))):
            content = _identity_json_value(content, "claim.claim_text_or_structured_value")
        else:
            _fail("claim.claim_text_or_structured_value is outside the frozen schema")
        refs = _source_refs(self.source_refs, f"claim[{claim_id}].source_refs", require_set_order=False)
        confidence = self.confidence_or_uncertainty if isinstance(self.confidence_or_uncertainty, ClaimConfidence) else ClaimConfidence.from_mapping(self.confidence_or_uncertainty)
        object.__setattr__(self, "claim_id", claim_id)
        object.__setattr__(self, "claim_type", claim_type)
        object.__setattr__(self, "claim_text_or_structured_value", content)
        object.__setattr__(self, "source_refs", refs)
        object.__setattr__(self, "confidence_or_uncertainty", confidence)

    def to_dict(self) -> dict[str, object]:
        return {
            "claim_id": self.claim_id,
            "claim_type": self.claim_type,
            "claim_text_or_structured_value": _plain(self.claim_text_or_structured_value),
            "source_refs": [ref.to_dict() for ref in self.source_refs],
            "confidence_or_uncertainty": self.confidence_or_uncertainty.to_dict(),
        }

    @classmethod
    def from_mapping(cls, value: object) -> "ProposalClaim":
        row = _mapping(value, "claim")
        _exact_fields(row, _CLAIM_FIELDS, "claim")
        return cls(**row)


def _claims(value: object) -> tuple[ProposalClaim, ...]:
    claims = tuple(item if isinstance(item, ProposalClaim) else ProposalClaim.from_mapping(item) for item in _sequence(value, "claims", minimum=1))
    _require_sorted_unique(tuple(claim.claim_id for claim in claims), "claims")
    return claims


@dataclass(frozen=True, slots=True)
class ProposalRecommendation:
    kind: str
    content: object

    def __post_init__(self) -> None:
        kind = _enum(self.kind, "recommendation.kind", _RECOMMENDATION_KIND_VALUES)
        content = self.content
        if type(content) is str:
            content = _text(content, "recommendation.content", minimum=0, maximum=8192)
        elif isinstance(content, Mapping):
            content = _identity_json_value(content, "recommendation.content")
        else:
            _fail("recommendation.content is outside the frozen schema")
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "content", content)

    def to_dict(self) -> dict[str, object]:
        return {"kind": self.kind, "content": _plain(self.content)}

    @classmethod
    def from_mapping(cls, value: object) -> "ProposalRecommendation":
        row = _mapping(value, "recommendation")
        _exact_fields(row, _RECOMMENDATION_FIELDS, "recommendation")
        return cls(**row)


@dataclass(frozen=True, slots=True)
class ProposalUncertainty:
    level: str
    items: tuple[str, ...]

    def __post_init__(self) -> None:
        level = _enum(self.level, "uncertainty.level", _LEVEL_VALUES)
        items = tuple(_text(item, f"uncertainty.items[{index}]", minimum=0, maximum=2048) for index, item in enumerate(_sequence(self.items, "uncertainty.items")))
        object.__setattr__(self, "level", level)
        object.__setattr__(self, "items", items)

    def to_dict(self) -> dict[str, object]:
        return {"level": self.level, "items": list(self.items)}

    @classmethod
    def from_mapping(cls, value: object) -> "ProposalUncertainty":
        row = _mapping(value, "uncertainty")
        _exact_fields(row, _UNCERTAINTY_FIELDS, "uncertainty")
        return cls(**row)


@dataclass(frozen=True, slots=True)
class ProposerMetadata:
    model_identifier: str
    provider_request_id: str
    attempt_number: int
    usage_if_available: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "model_identifier", _text(self.model_identifier, "proposer_metadata.model_identifier", maximum=256))
        object.__setattr__(self, "provider_request_id", _text(self.provider_request_id, "proposer_metadata.provider_request_id", minimum=0, maximum=512))
        object.__setattr__(self, "attempt_number", _integer(self.attempt_number, "proposer_metadata.attempt_number", minimum=1))
        if self.usage_if_available is not None:
            object.__setattr__(self, "usage_if_available", _metadata_json_object(self.usage_if_available, "proposer_metadata.usage_if_available"))

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "model_identifier": self.model_identifier,
            "provider_request_id": self.provider_request_id,
            "attempt_number": self.attempt_number,
        }
        if self.usage_if_available is not None:
            out["usage_if_available"] = _plain(self.usage_if_available)
        return out

    @classmethod
    def from_mapping(cls, value: object) -> "ProposerMetadata":
        row = _mapping(value, "proposer_metadata")
        _exact_fields(row, _PROPOSER_REQUIRED_FIELDS, "proposer_metadata", _PROPOSER_OPTIONAL_FIELDS)
        return cls(
            model_identifier=row["model_identifier"],
            provider_request_id=row["provider_request_id"],
            attempt_number=row["attempt_number"],
            usage_if_available=_optional_non_null(
                row, "usage_if_available", "proposer_metadata"
            ),
        )


@dataclass(frozen=True, slots=True)
class CloudProposal:
    """Exact mr05.cloud_proposal / 1.0.0 structured record."""

    schema_version: str
    proposal_id: str
    proposal_identity: str
    request_identity: str
    run_identity: str
    task_identity: str
    bound_package_identity: str
    bound_context_identity: str
    bound_mr03_package_identity: str
    bound_mr04_result_identity: str
    claims: tuple[ProposalClaim, ...]
    source_refs: tuple[ProposalSourceRef, ...]
    recommendation: ProposalRecommendation
    uncertainty: ProposalUncertainty
    escalation_flags: tuple[str, ...]
    proposer_metadata: ProposerMetadata
    free_form_prose: str | None = None
    observational_metadata: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        try:
            schema_version = validate_schema_version(PROPOSAL_SCHEMA_ID, self.schema_version)
        except UnknownSchemaMajorVersionError as exc:
            _fail(str(exc), FailureCode.MR05_UNKNOWN_SCHEMA_MAJOR)
        except (UnsupportedSchemaVersionError, TypeError, ValueError) as exc:
            _fail(str(exc))
        normalized = {
            "request_identity": _sha(self.request_identity, "request_identity"),
            "run_identity": _sha(self.run_identity, "run_identity"),
            "task_identity": _sha(self.task_identity, "task_identity"),
            "bound_package_identity": _sha(self.bound_package_identity, "bound_package_identity"),
            "bound_context_identity": _sha(self.bound_context_identity, "bound_context_identity"),
            "bound_mr03_package_identity": _sha(self.bound_mr03_package_identity, "bound_mr03_package_identity"),
            "bound_mr04_result_identity": _sha(self.bound_mr04_result_identity, "bound_mr04_result_identity"),
        }
        claims = _claims(self.claims)
        source_refs = _source_refs(self.source_refs, "source_refs")
        recommendation = self.recommendation if isinstance(self.recommendation, ProposalRecommendation) else ProposalRecommendation.from_mapping(self.recommendation)
        uncertainty = self.uncertainty if isinstance(self.uncertainty, ProposalUncertainty) else ProposalUncertainty.from_mapping(self.uncertainty)
        escalation_flags = tuple(_text(item, f"escalation_flags[{index}]", maximum=256) for index, item in enumerate(_sequence(self.escalation_flags, "escalation_flags")))
        _require_sorted_unique(escalation_flags, "escalation_flags")
        proposer_metadata = self.proposer_metadata if isinstance(self.proposer_metadata, ProposerMetadata) else ProposerMetadata.from_mapping(self.proposer_metadata)
        free_form_prose = None if self.free_form_prose is None else _text(self.free_form_prose, "free_form_prose", minimum=0, maximum=16384)
        observational_metadata = None if self.observational_metadata is None else _metadata_json_object(self.observational_metadata, "observational_metadata")
        object.__setattr__(self, "schema_version", schema_version)
        for field, value in normalized.items():
            object.__setattr__(self, field, value)
        object.__setattr__(self, "claims", claims)
        object.__setattr__(self, "source_refs", source_refs)
        object.__setattr__(self, "recommendation", recommendation)
        object.__setattr__(self, "uncertainty", uncertainty)
        object.__setattr__(self, "escalation_flags", escalation_flags)
        object.__setattr__(self, "proposer_metadata", proposer_metadata)
        object.__setattr__(self, "free_form_prose", free_form_prose)
        object.__setattr__(self, "observational_metadata", observational_metadata)
        declared_identity = _sha(self.proposal_identity, "proposal_identity")
        proposal_id = _sha(self.proposal_id, "proposal_id")
        try:
            recomputed = sha256_canonical(self.identity_payload)
        except (CanonicalizationError, IdentityValidationError, TypeError, ValueError) as exc:
            _fail(f"proposal identity preimage is invalid: {exc}")
        if declared_identity != recomputed:
            _fail("proposal_identity does not match authoritative semantic preimage", FailureCode.HASH_MISMATCH)
        if proposal_id != recomputed:
            _fail("proposal_id must equal recomputed proposal_identity", FailureCode.HASH_MISMATCH)
        object.__setattr__(self, "proposal_identity", declared_identity)
        object.__setattr__(self, "proposal_id", proposal_id)

    @property
    def identity_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "request_identity": self.request_identity,
            "run_identity": self.run_identity,
            "task_identity": self.task_identity,
            "bound_mr03_package_identity": self.bound_mr03_package_identity,
            "bound_mr04_result_identity": self.bound_mr04_result_identity,
            "bound_context_identity": self.bound_context_identity,
            "claims": [claim.to_dict() for claim in self.claims],
            "source_refs": [ref.to_dict() for ref in self.source_refs],
            "recommendation": self.recommendation.to_dict(),
            "uncertainty": self.uncertainty.to_dict(),
            "escalation_flags": list(self.escalation_flags),
        }

    def to_dict(self) -> dict[str, object]:
        out = dict(self.identity_payload)
        out["proposal_id"] = self.proposal_id
        out["proposal_identity"] = self.proposal_identity
        out["bound_package_identity"] = self.bound_package_identity
        out["proposer_metadata"] = self.proposer_metadata.to_dict()
        if self.free_form_prose is not None:
            out["free_form_prose"] = self.free_form_prose
        if self.observational_metadata is not None:
            out["observational_metadata"] = _plain(self.observational_metadata)
        return out

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict(), identity_critical=False)

    @classmethod
    def from_mapping(cls, value: object) -> "CloudProposal":
        row = _mapping(value, "cloud proposal")
        _exact_fields(row, _REQUIRED_PROPOSAL_FIELDS, "cloud proposal", _OPTIONAL_PROPOSAL_FIELDS)
        free_form_prose = _optional_non_null(row, "free_form_prose", "cloud proposal")
        observational_metadata = _optional_non_null(
            row, "observational_metadata", "cloud proposal"
        )
        return cls(
            schema_version=row["schema_version"], proposal_id=row["proposal_id"],
            proposal_identity=row["proposal_identity"], request_identity=row["request_identity"],
            run_identity=row["run_identity"], task_identity=row["task_identity"],
            bound_package_identity=row["bound_package_identity"], bound_context_identity=row["bound_context_identity"],
            bound_mr03_package_identity=row["bound_mr03_package_identity"], bound_mr04_result_identity=row["bound_mr04_result_identity"],
            claims=row["claims"], source_refs=row["source_refs"], recommendation=row["recommendation"],
            uncertainty=row["uncertainty"], escalation_flags=row["escalation_flags"], proposer_metadata=row["proposer_metadata"],
            free_form_prose=free_form_prose, observational_metadata=observational_metadata,
        )


def parse_cloud_proposal(value: CloudProposal | Mapping[str, object]) -> CloudProposal:
    return CloudProposal.from_mapping(value.to_dict()) if isinstance(value, CloudProposal) else CloudProposal.from_mapping(value)


def parse_cloud_proposal_json(data: str | bytes) -> CloudProposal:
    try:
        value = parse_json_no_duplicates(data, identity_critical=False)
    except CanonicalizationError as exc:
        _fail(f"malformed cloud proposal JSON: {exc}")
    return CloudProposal.from_mapping(value)


def compute_proposal_identity(value: CloudProposal | Mapping[str, object]) -> str:
    record = parse_cloud_proposal(value)
    try:
        return sha256_canonical(record.identity_payload)
    except (CanonicalizationError, IdentityValidationError, TypeError, ValueError) as exc:
        _fail(f"proposal identity preimage is invalid: {exc}")
    raise AssertionError("unreachable")


def canonical_cloud_proposal_bytes(value: CloudProposal | Mapping[str, object]) -> bytes:
    return parse_cloud_proposal(value).canonical_bytes()


def not_implemented(*args: object, **kwargs: object) -> None:
    del args, kwargs
    phase_not_implemented("proposal")


__all__ = tuple(name for name in globals() if name.isupper()) + (
    "ProposalValidationError", "ProposalSourceRef", "ClaimConfidence",
    "ProposalClaim", "ProposalRecommendation", "ProposalUncertainty",
    "ProposerMetadata", "CloudProposal", "parse_cloud_proposal",
    "parse_cloud_proposal_json", "compute_proposal_identity",
    "canonical_cloud_proposal_bytes", "not_implemented",
)
