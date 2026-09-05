"""Deterministic, pure-data disclosure policy records for MR-05.

This boundary classifies already-supplied disclosure metadata. It never reads
source bytes, builds cloud context, calls a provider/model, authenticates,
retries, falls back, changes workflow state, or performs Git operations.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import NoReturn

from .contracts import (
    SCHEMA_VERSION,
    UnknownSchemaMajorVersionError,
    UnsupportedSchemaVersionError,
    validate_schema_version,
)
from .failures import FailureCode, phase_not_implemented
from .identity import require_sha256


DISCLOSURE_SCHEMA_ID = "mr05.disclosure"
DISCLOSURE_SCHEMA_VERSION = SCHEMA_VERSION
DISCLOSURE_POLICY_VERSION = "1.0.0"

CLASSIFICATION_VALUES = (
    "PUBLIC",
    "INTERNAL",
    "PROTECTED",
    "SECRET_LIKE",
    "UNKNOWN",
)
DISCLOSURE_RESULT_VALUES = ("ALLOW", "ESCALATE", "DENY")
FINDING_ACTION_VALUES = ("ALLOW", "REDACT", "DENY", "ESCALATE")
DISCLOSURE_RESULT_PRECEDENCE = ("DENY", "ESCALATE", "ALLOW")
DISCLOSURE_RESULT_PRECEDENCE_EXPRESSION = "DENY > ESCALATE > ALLOW"

CLASSIFICATION_RESULT_FLOOR = MappingProxyType(
    {
        "PUBLIC": "ALLOW",
        "INTERNAL": "ESCALATE",
        "PROTECTED": "DENY",
        "SECRET_LIKE": "DENY",
        "UNKNOWN": "DENY",
    }
)
FINDING_ACTION_RESULT_FLOOR = MappingProxyType(
    {
        "ALLOW": "ALLOW",
        "REDACT": "ESCALATE",
        "ESCALATE": "ESCALATE",
        "DENY": "DENY",
    }
)
_RESULT_RANK = MappingProxyType({"ALLOW": 0, "ESCALATE": 1, "DENY": 2})

DISCLOSURE_IMPLEMENTATION_COUNT = 1
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
STATE_TRANSITION_EXECUTION_COUNT = 0
GIT_OPERATION_COUNT = 0
CONTEXT_BUILDER_INTEGRATION_COUNT = 0
CLOUD_REQUEST_BUILD_COUNT = 0

_REQUIRED_RECORD_FIELDS = frozenset(
    {"schema_version", "classification", "disclosure_result", "policy_version", "findings"}
)
_OPTIONAL_RECORD_FIELDS = frozenset({"observational_metadata"})
_REQUIRED_FINDING_FIELDS = frozenset({"code", "action"})
_OPTIONAL_FINDING_FIELDS = frozenset({"source_id"})


class DisclosureValidationError(ValueError):
    """A disclosure record violates the frozen deterministic contract."""

    def __init__(
        self,
        message: str,
        code: FailureCode | str = FailureCode.INVALID_SCHEMA,
    ) -> None:
        super().__init__(message)
        self.code = code.value if isinstance(code, FailureCode) else code
        self.failure_code = self.code
        self.retry_allowed = False


def _fail(
    message: str,
    code: FailureCode | str = FailureCode.INVALID_SCHEMA,
) -> NoReturn:
    raise DisclosureValidationError(message, code)


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        _fail(f"{field} must be a string-keyed mapping")
    return value


def _exact_fields(
    value: Mapping[str, object],
    required: frozenset[str],
    optional: frozenset[str],
    field: str,
) -> None:
    actual = set(value)
    if not required.issubset(actual) or actual - required - optional:
        _fail(f"{field} fields are not exact")


def _sequence(value: object, field: str) -> tuple[object, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        _fail(f"{field} must be an array")
    return tuple(value)


def _text(value: object, field: str, *, minimum: int = 1, maximum: int) -> str:
    if type(value) is not str or not minimum <= len(value) <= maximum:
        _fail(f"{field} length is invalid")
    return value


def _sha(value: object, field: str) -> str:
    try:
        return require_sha256(value, field=field)
    except (TypeError, ValueError) as exc:
        _fail(str(exc), FailureCode.INVALID_SCHEMA)
    raise AssertionError("unreachable")


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            _fail("observational_metadata must use string keys")
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


def _observational_metadata(value: object) -> Mapping[str, object] | None:
    if value is None:
        return None
    row = _mapping(value, "observational_metadata")
    frozen = _freeze(row)
    if not isinstance(frozen, Mapping):
        raise AssertionError("metadata freezing changed type")
    return frozen


def _classification(value: object) -> str:
    if type(value) is not str or value not in CLASSIFICATION_VALUES:
        _fail("unknown disclosure classification")
    return value


def _result(value: object) -> str:
    if type(value) is not str or value not in DISCLOSURE_RESULT_VALUES:
        _fail("unknown disclosure result")
    return value


def _policy_version(value: object) -> str:
    if value != DISCLOSURE_POLICY_VERSION:
        _fail("unsupported disclosure policy version")
    return DISCLOSURE_POLICY_VERSION


@dataclass(frozen=True, slots=True)
class DisclosureFinding:
    """One ordered disclosure-policy finding."""

    code: str
    action: str
    source_id: str | None = None

    def __post_init__(self) -> None:
        code = _text(self.code, "finding.code", maximum=128)
        action = self.action
        if type(action) is not str or action not in FINDING_ACTION_VALUES:
            _fail("unknown disclosure finding action")
        source_id = self.source_id
        if source_id is not None:
            source_id = _sha(source_id, "finding.source_id")
        object.__setattr__(self, "code", code)
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "source_id", source_id)

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {"code": self.code, "action": self.action}
        if self.source_id is not None:
            out["source_id"] = self.source_id
        return out

    @classmethod
    def from_mapping(cls, value: object) -> "DisclosureFinding":
        row = _mapping(value, "disclosure finding")
        _exact_fields(
            row,
            _REQUIRED_FINDING_FIELDS,
            _OPTIONAL_FINDING_FIELDS,
            "disclosure finding",
        )
        return cls(
            code=row["code"],
            action=row["action"],
            source_id=row.get("source_id"),
        )


def _finding(value: object) -> DisclosureFinding:
    if isinstance(value, DisclosureFinding):
        return DisclosureFinding.from_mapping(value.to_dict())
    return DisclosureFinding.from_mapping(value)


def _findings(value: object) -> tuple[DisclosureFinding, ...]:
    return tuple(_finding(item) for item in _sequence(value, "findings"))


def disclosure_result_for(
    classification: object,
    findings: object = (),
) -> str:
    """Return the most restrictive deterministic result for supplied metadata."""

    normalized_classification = _classification(classification)
    normalized_findings = _findings(findings)
    result = CLASSIFICATION_RESULT_FLOOR[normalized_classification]
    for finding in normalized_findings:
        candidate = FINDING_ACTION_RESULT_FLOOR[finding.action]
        if _RESULT_RANK[candidate] > _RESULT_RANK[result]:
            result = candidate
    return result


@dataclass(frozen=True, slots=True)
class DisclosureRecord:
    """Canonical disclosure-policy record; no independent disclosure identity exists."""

    schema_version: str
    classification: str
    disclosure_result: str
    policy_version: str
    findings: tuple[DisclosureFinding, ...]
    observational_metadata: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        try:
            validate_schema_version(DISCLOSURE_SCHEMA_ID, self.schema_version)
        except UnknownSchemaMajorVersionError as exc:
            _fail(str(exc), FailureCode.MR05_UNKNOWN_SCHEMA_MAJOR)
        except (UnsupportedSchemaVersionError, TypeError, ValueError) as exc:
            _fail(str(exc), FailureCode.INVALID_SCHEMA)
        classification = _classification(self.classification)
        declared_result = _result(self.disclosure_result)
        policy_version = _policy_version(self.policy_version)
        findings = _findings(self.findings)
        expected_result = disclosure_result_for(classification, findings)
        if declared_result != expected_result:
            _fail("disclosure_result does not match deterministic policy projection")
        metadata = _observational_metadata(self.observational_metadata)
        object.__setattr__(self, "classification", classification)
        object.__setattr__(self, "disclosure_result", declared_result)
        object.__setattr__(self, "policy_version", policy_version)
        object.__setattr__(self, "findings", findings)
        object.__setattr__(self, "observational_metadata", metadata)

    @property
    def cloud_eligible(self) -> bool:
        """Return policy eligibility only; this performs no cloud/context action."""

        return self.disclosure_result == "ALLOW"

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "schema_version": self.schema_version,
            "classification": self.classification,
            "disclosure_result": self.disclosure_result,
            "policy_version": self.policy_version,
            "findings": [finding.to_dict() for finding in self.findings],
        }
        if self.observational_metadata is not None:
            out["observational_metadata"] = _plain(self.observational_metadata)
        return out

    @classmethod
    def from_mapping(cls, value: object) -> "DisclosureRecord":
        row = _mapping(value, "disclosure record")
        _exact_fields(
            row,
            _REQUIRED_RECORD_FIELDS,
            _OPTIONAL_RECORD_FIELDS,
            "disclosure record",
        )
        return cls(
            schema_version=row["schema_version"],
            classification=row["classification"],
            disclosure_result=row["disclosure_result"],
            policy_version=row["policy_version"],
            findings=_findings(row["findings"]),
            observational_metadata=row.get("observational_metadata"),
        )


def build_disclosure(
    *,
    classification: object,
    findings: object = (),
    observational_metadata: object | None = None,
) -> DisclosureRecord:
    """Build a deterministic disclosure record from already-supplied metadata."""

    normalized_classification = _classification(classification)
    normalized_findings = _findings(findings)
    return DisclosureRecord(
        schema_version=DISCLOSURE_SCHEMA_VERSION,
        classification=normalized_classification,
        disclosure_result=disclosure_result_for(normalized_classification, normalized_findings),
        policy_version=DISCLOSURE_POLICY_VERSION,
        findings=normalized_findings,
        observational_metadata=_observational_metadata(observational_metadata),
    )


def not_implemented(*args: object, **kwargs: object) -> None:
    """Preserve the legacy operational placeholder as a fail-closed boundary."""

    del args, kwargs
    phase_not_implemented("disclosure")


__all__ = (
    "DISCLOSURE_SCHEMA_ID",
    "DISCLOSURE_SCHEMA_VERSION",
    "DISCLOSURE_POLICY_VERSION",
    "CLASSIFICATION_VALUES",
    "DISCLOSURE_RESULT_VALUES",
    "FINDING_ACTION_VALUES",
    "DISCLOSURE_RESULT_PRECEDENCE",
    "DISCLOSURE_RESULT_PRECEDENCE_EXPRESSION",
    "CLASSIFICATION_RESULT_FLOOR",
    "FINDING_ACTION_RESULT_FLOOR",
    "DisclosureValidationError",
    "DisclosureFinding",
    "DisclosureRecord",
    "disclosure_result_for",
    "build_disclosure",
    "not_implemented",
)
