"""Stable MR-05 failure codes and immutable fail-closed value objects."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any
from collections.abc import Mapping

from .contracts import SCHEMA_VERSION


class MR05PhaseNotImplementedError(NotImplementedError):
    """A production boundary intentionally unavailable in this phase."""


def phase_not_implemented(component: str) -> None:
    """Fail closed for an operational boundary outside the current scope."""

    raise MR05PhaseNotImplementedError(f"MR05_NOT_IMPLEMENTED:{component}")


class FailureValidationError(ValueError):
    """A failure envelope is malformed or violates frozen semantics."""


class FailureOwner(str, Enum):
    DISCOVERY = "DISCOVERY"
    NORMALIZATION = "NORMALIZATION"
    MR03 = "MR03"
    MR04 = "MR04"
    CONTEXT_BUILD = "CONTEXT_BUILD"
    DISCLOSURE = "DISCLOSURE"
    MODEL_BOUNDARY = "MODEL_BOUNDARY"
    PROPOSAL_SCHEMA = "PROPOSAL_SCHEMA"
    PROPOSAL_BINDING = "PROPOSAL_BINDING"
    VERIFICATION = "VERIFICATION"
    HUMAN_GATE = "HUMAN_GATE"
    INTERNAL_INVARIANT = "INTERNAL_INVARIANT"


class FailureSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FailureState(str, Enum):
    RAW = "RAW"
    DISCOVERED = "DISCOVERED"
    NORMALIZED = "NORMALIZED"
    PACKAGED = "PACKAGED"
    GUARDED = "GUARDED"
    CLOUD_READY = "CLOUD_READY"
    PROPOSED = "PROPOSED"
    VERIFIED_DENY = "VERIFIED_DENY"
    VERIFIED_ESCALATE = "VERIFIED_ESCALATE"
    VERIFIED_PASS_FOR_REVIEW = "VERIFIED_PASS_FOR_REVIEW"
    FAILED = "FAILED"


class FailureCode(str, Enum):
    UNSUPPORTED_INPUT = "UNSUPPORTED_INPUT"
    SOURCE_PATH_ESCAPE = "SOURCE_PATH_ESCAPE"
    HASH_MISMATCH = "HASH_MISMATCH"
    INVALID_SCHEMA = "INVALID_SCHEMA"
    DUPLICATE_CONFLICT = "DUPLICATE_CONFLICT"
    PROVENANCE_GAP = "PROVENANCE_GAP"
    MISSING_REQUIRED_ARTIFACT = "MISSING_REQUIRED_ARTIFACT"
    AMBIGUOUS_PRECEDENCE = "AMBIGUOUS_PRECEDENCE"
    UNKNOWN_VALIDITY = "UNKNOWN_VALIDITY"
    PROTECTED_CONTENT_SELECTED = "PROTECTED_CONTENT_SELECTED"
    SECRET_RISK = "SECRET_RISK"
    MR03_IDENTITY_MISMATCH = "MR03_IDENTITY_MISMATCH"
    PROPOSER_SCHEMA_INVALID = "PROPOSER_SCHEMA_INVALID"
    PROPOSAL_SOURCE_REF_INVALID = "PROPOSAL_SOURCE_REF_INVALID"
    PROPOSAL_PACKAGE_BINDING_MISMATCH = "PROPOSAL_PACKAGE_BINDING_MISMATCH"
    NONDETERMINISTIC_OUTPUT = "NONDETERMINISTIC_OUTPUT"
    MR05_MISSING_SOURCE = "MR05_MISSING_SOURCE"
    MR05_MR03_OUTPUT_INVALID_SCHEMA = "MR05_MR03_OUTPUT_INVALID_SCHEMA"
    MR05_MR03_CALL_TIMEOUT = "MR05_MR03_CALL_TIMEOUT"
    MR05_MR03_CALL_FAILURE = "MR05_MR03_CALL_FAILURE"
    MR05_MR04_DEPENDENCY_IDENTITY_MISMATCH = "MR05_MR04_DEPENDENCY_IDENTITY_MISMATCH"
    MR05_CONTEXT_OVER_BYTE_BUDGET = "MR05_CONTEXT_OVER_BYTE_BUDGET"
    MR05_DISCLOSURE_DENIED = "MR05_DISCLOSURE_DENIED"
    MR05_MODEL_UNAUTHORIZED = "MR05_MODEL_UNAUTHORIZED"
    MR05_MODEL_TIMEOUT = "MR05_MODEL_TIMEOUT"
    MR05_MODEL_PROVIDER_ERROR = "MR05_MODEL_PROVIDER_ERROR"
    MR05_MODEL_MALFORMED_OUTPUT = "MR05_MODEL_MALFORMED_OUTPUT"
    MR05_PROPOSAL_MISSING_SOURCE_REF = "MR05_PROPOSAL_MISSING_SOURCE_REF"
    MR05_PROPOSAL_UNSUPPORTED_CLAIM = "MR05_PROPOSAL_UNSUPPORTED_CLAIM"
    MR05_PROPOSAL_REPLAY_BLOCKED = "MR05_PROPOSAL_REPLAY_BLOCKED"
    MR05_VERIFY_CONTRADICTION = "MR05_VERIFY_CONTRADICTION"
    MR05_VERIFIER_EXCEPTION = "MR05_VERIFIER_EXCEPTION"
    MR05_HUMAN_GATE_INVALID = "MR05_HUMAN_GATE_INVALID"
    MR05_UNKNOWN_SCHEMA_MAJOR = "MR05_UNKNOWN_SCHEMA_MAJOR"
    MR05_INTERNAL_INVARIANT = "MR05_INTERNAL_INVARIANT"


FAILURE_CODE_OWNERS = MappingProxyType(
    {
        FailureCode.UNSUPPORTED_INPUT: FailureOwner.DISCOVERY,
        FailureCode.SOURCE_PATH_ESCAPE: FailureOwner.DISCOVERY,
        FailureCode.HASH_MISMATCH: FailureOwner.INTERNAL_INVARIANT,
        FailureCode.INVALID_SCHEMA: FailureOwner.PROPOSAL_SCHEMA,
        FailureCode.DUPLICATE_CONFLICT: FailureOwner.DISCOVERY,
        FailureCode.PROVENANCE_GAP: FailureOwner.CONTEXT_BUILD,
        FailureCode.MISSING_REQUIRED_ARTIFACT: FailureOwner.DISCOVERY,
        FailureCode.AMBIGUOUS_PRECEDENCE: FailureOwner.VERIFICATION,
        FailureCode.UNKNOWN_VALIDITY: FailureOwner.VERIFICATION,
        FailureCode.PROTECTED_CONTENT_SELECTED: FailureOwner.DISCLOSURE,
        FailureCode.SECRET_RISK: FailureOwner.DISCLOSURE,
        FailureCode.MR03_IDENTITY_MISMATCH: FailureOwner.MR03,
        FailureCode.PROPOSER_SCHEMA_INVALID: FailureOwner.PROPOSAL_SCHEMA,
        FailureCode.PROPOSAL_SOURCE_REF_INVALID: FailureOwner.PROPOSAL_BINDING,
        FailureCode.PROPOSAL_PACKAGE_BINDING_MISMATCH: FailureOwner.PROPOSAL_BINDING,
        FailureCode.NONDETERMINISTIC_OUTPUT: FailureOwner.INTERNAL_INVARIANT,
        FailureCode.MR05_MISSING_SOURCE: FailureOwner.DISCOVERY,
        FailureCode.MR05_MR03_OUTPUT_INVALID_SCHEMA: FailureOwner.MR03,
        FailureCode.MR05_MR03_CALL_TIMEOUT: FailureOwner.MR03,
        FailureCode.MR05_MR03_CALL_FAILURE: FailureOwner.MR03,
        FailureCode.MR05_MR04_DEPENDENCY_IDENTITY_MISMATCH: FailureOwner.MR04,
        FailureCode.MR05_CONTEXT_OVER_BYTE_BUDGET: FailureOwner.CONTEXT_BUILD,
        FailureCode.MR05_DISCLOSURE_DENIED: FailureOwner.DISCLOSURE,
        FailureCode.MR05_MODEL_UNAUTHORIZED: FailureOwner.MODEL_BOUNDARY,
        FailureCode.MR05_MODEL_TIMEOUT: FailureOwner.MODEL_BOUNDARY,
        FailureCode.MR05_MODEL_PROVIDER_ERROR: FailureOwner.MODEL_BOUNDARY,
        FailureCode.MR05_MODEL_MALFORMED_OUTPUT: FailureOwner.PROPOSAL_SCHEMA,
        FailureCode.MR05_PROPOSAL_MISSING_SOURCE_REF: FailureOwner.PROPOSAL_BINDING,
        FailureCode.MR05_PROPOSAL_UNSUPPORTED_CLAIM: FailureOwner.PROPOSAL_BINDING,
        FailureCode.MR05_PROPOSAL_REPLAY_BLOCKED: FailureOwner.PROPOSAL_BINDING,
        FailureCode.MR05_VERIFY_CONTRADICTION: FailureOwner.VERIFICATION,
        FailureCode.MR05_VERIFIER_EXCEPTION: FailureOwner.VERIFICATION,
        FailureCode.MR05_HUMAN_GATE_INVALID: FailureOwner.HUMAN_GATE,
        FailureCode.MR05_UNKNOWN_SCHEMA_MAJOR: FailureOwner.INTERNAL_INVARIANT,
        FailureCode.MR05_INTERNAL_INVARIANT: FailureOwner.INTERNAL_INVARIANT,
    }
)

# Generic semantic labels map to the exact frozen MR-05B code. The map avoids
# inventing a second code string for a meaning already represented by MR-05B.
SEMANTIC_FAILURE_CODE_MAP = MappingProxyType(
    {
        "UNKNOWN_STATE": FailureCode.MR05_INTERNAL_INVARIANT,
        "MISSING_PROVENANCE": FailureCode.PROVENANCE_GAP,
        "IDENTITY_MISMATCH": FailureCode.HASH_MISMATCH,
        "DEPENDENCY_IDENTITY_MISMATCH": FailureCode.MR05_MR04_DEPENDENCY_IDENTITY_MISMATCH,
        "MODEL_TIMEOUT": FailureCode.MR05_MODEL_TIMEOUT,
        "MODEL_MALFORMED_OUTPUT": FailureCode.MR05_MODEL_MALFORMED_OUTPUT,
        "SOURCE_REF_INVALID": FailureCode.PROPOSAL_SOURCE_REF_INVALID,
        "PROTECTED_CONTENT_POLICY_FAILURE": FailureCode.PROTECTED_CONTENT_SELECTED,
        "VERIFIER_EXCEPTION": FailureCode.MR05_VERIFIER_EXCEPTION,
        "UNKNOWN_SCHEMA_MAJOR_VERSION": FailureCode.MR05_UNKNOWN_SCHEMA_MAJOR,
    }
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _coerce_code(value: FailureCode | str) -> FailureCode:
    try:
        return value if isinstance(value, FailureCode) else FailureCode(value)
    except (TypeError, ValueError) as exc:
        raise FailureValidationError(f"unknown failure code: {value!r}") from exc


def _coerce_owner(value: FailureOwner | str) -> FailureOwner:
    try:
        return value if isinstance(value, FailureOwner) else FailureOwner(value)
    except (TypeError, ValueError) as exc:
        raise FailureValidationError(f"unknown failure owner: {value!r}") from exc


def _coerce_severity(value: FailureSeverity | str) -> FailureSeverity:
    try:
        return value if isinstance(value, FailureSeverity) else FailureSeverity(value)
    except (TypeError, ValueError) as exc:
        raise FailureValidationError(f"unknown failure severity: {value!r}") from exc


def _coerce_state(value: FailureState | str) -> FailureState:
    try:
        return value if isinstance(value, FailureState) else FailureState(value)
    except (TypeError, ValueError) as exc:
        raise FailureValidationError(f"unknown failure state: {value!r}") from exc


def _require_identity(value: object, *, field: str, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise FailureValidationError(f"{field} must be lowercase SHA-256")
    return value


def _plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _plain(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_plain(child) for child in value]
    if isinstance(value, list):
        return [_plain(child) for child in value]
    return value


def failure_code_for_semantic(name: str) -> FailureCode:
    """Return the exact frozen code for a semantic label."""

    try:
        return SEMANTIC_FAILURE_CODE_MAP[name]
    except (KeyError, TypeError) as exc:
        raise FailureValidationError(f"unknown failure semantic: {name!r}") from exc


def failure_owner_for(code: FailureCode | str) -> FailureOwner:
    """Return the single frozen owner for a failure code."""

    normalized = _coerce_code(code)
    return FAILURE_CODE_OWNERS[normalized]


@dataclass(frozen=True, slots=True)
class Failure:
    """Immutable machine-readable failure envelope; retry is always forbidden."""

    schema_version: str
    failure_code: FailureCode | str
    failure_owner: FailureOwner | str
    severity: FailureSeverity | str
    state: FailureState | str
    run_identity: str
    related_identity: str | None
    message: str
    retry_allowed: bool = False
    human_escalation_required: bool = False
    safe_details: Mapping[str, object] = field(default_factory=dict)
    observational_metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise FailureValidationError("unsupported failure schema version")
        code = _coerce_code(self.failure_code)
        owner = _coerce_owner(self.failure_owner)
        severity = _coerce_severity(self.severity)
        state = _coerce_state(self.state)
        if FAILURE_CODE_OWNERS[code] is not owner:
            raise FailureValidationError("failure owner does not match failure code")
        _require_identity(self.run_identity, field="run_identity")
        _require_identity(self.related_identity, field="related_identity", nullable=True)
        if not isinstance(self.message, str) or not 1 <= len(self.message) <= 1024:
            raise FailureValidationError("message must contain 1..1024 characters")
        if type(self.retry_allowed) is not bool or self.retry_allowed:
            raise FailureValidationError("retry_allowed is frozen to false")
        if type(self.human_escalation_required) is not bool:
            raise FailureValidationError("human_escalation_required must be boolean")
        if not isinstance(self.safe_details, Mapping) or not isinstance(self.observational_metadata, Mapping):
            raise FailureValidationError("details must be mappings")
        if self.safe_details:
            raise FailureValidationError("safe_details must be empty under frozen schema")
        object.__setattr__(self, "failure_code", code)
        object.__setattr__(self, "failure_owner", owner)
        object.__setattr__(self, "severity", severity)
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "safe_details", MappingProxyType(dict(self.safe_details)))
        object.__setattr__(self, "observational_metadata", MappingProxyType(dict(self.observational_metadata)))

    @property
    def failure_identity(self) -> str:
        """Return the stable identity excluding free-form message/observation."""

        from .canonical import canonical_identity_bytes

        identity_inputs = {
            "schema_version": self.schema_version,
            "failure_code": self.failure_code.value,
            "failure_owner": self.failure_owner.value,
            "severity": self.severity.value,
            "state": self.state.value,
            "run_identity": self.run_identity,
            "related_identity": self.related_identity,
            "retry_allowed": self.retry_allowed,
            "human_escalation_required": self.human_escalation_required,
        }
        return hashlib.sha256(canonical_identity_bytes(identity_inputs)).hexdigest()

    def to_dict(self) -> dict[str, object]:
        """Return a machine-readable representation with stable enum values."""

        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "failure_code": self.failure_code.value,
            "failure_owner": self.failure_owner.value,
            "severity": self.severity.value,
            "state": self.state.value,
            "run_identity": self.run_identity,
            "related_identity": self.related_identity,
            "message": self.message,
            "retry_allowed": self.retry_allowed,
            "human_escalation_required": self.human_escalation_required,
            "failure_identity": self.failure_identity,
        }
        if self.safe_details:
            result["safe_details"] = _plain(self.safe_details)
        if self.observational_metadata:
            result["observational_metadata"] = _plain(self.observational_metadata)
        return result

    def canonical_bytes(self) -> bytes:
        """Return stable representation bytes; observations are not identity inputs."""

        from .canonical import canonical_json_bytes

        return canonical_json_bytes(self.to_dict(), identity_critical=False)

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "Failure":
        """Construct an envelope while rejecting missing and unknown fields."""

        required = {
            "schema_version", "failure_code", "failure_owner", "severity", "state",
            "run_identity", "related_identity", "message", "retry_allowed",
            "human_escalation_required", "failure_identity",
        }
        allowed = required | {"safe_details", "observational_metadata", "failure_identity"}
        if not isinstance(value, Mapping):
            raise FailureValidationError("failure envelope must be a mapping")
        missing = required - set(value)
        unknown = set(value) - allowed
        if missing or unknown:
            raise FailureValidationError("failure envelope fields are not exact")
        failure_identity = _require_identity(value["failure_identity"], field="failure_identity")
        result = cls(
            schema_version=value["schema_version"],
            failure_code=value["failure_code"],
            failure_owner=value["failure_owner"],
            severity=value["severity"],
            state=value["state"],
            run_identity=value["run_identity"],
            related_identity=value["related_identity"],
            message=value["message"],
            retry_allowed=value["retry_allowed"],
            human_escalation_required=value["human_escalation_required"],
            safe_details=value.get("safe_details", {}),
            observational_metadata=value.get("observational_metadata", {}),
        )
        if failure_identity != result.failure_identity:
            raise FailureValidationError("failure identity mismatch")
        return result


__all__ = (
    "MR05PhaseNotImplementedError", "phase_not_implemented", "FailureValidationError",
    "FailureOwner", "FailureSeverity", "FailureState", "FailureCode", "FAILURE_CODE_OWNERS",
    "SEMANTIC_FAILURE_CODE_MAP", "failure_code_for_semantic", "failure_owner_for", "Failure",
)
