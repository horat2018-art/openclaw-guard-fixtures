"""Deterministic pure-data Human Gate and Human Decision records for MR-05.

This boundary validates and identity-binds already supplied review records. It
never performs Human approval, workflow progression, filesystem/network/model
actions, authentication, retry/fallback, or Git mutation. Approval is a record
only and grants no execution authority.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import NoReturn

from .canonical import canonical_json_bytes
from .contracts import (
    SCHEMA_VERSION,
    UnknownSchemaMajorVersionError,
    UnsupportedSchemaVersionError,
    validate_schema_version,
)
from .failures import FailureCode, phase_not_implemented
from .identity import require_sha256, sha256_canonical

HUMAN_GATE_SCHEMA_ID = "mr05.human_gate"
HUMAN_DECISION_SCHEMA_ID = "mr05.human_decision"
HUMAN_GATE_SCHEMA_VERSION = SCHEMA_VERSION
HUMAN_DECISION_SCHEMA_VERSION = SCHEMA_VERSION

HUMAN_ACTION_VALUES = (
    "APPROVE",
    "REJECT",
    "REQUEST_REWORK",
    "REQUEST_MORE_EVIDENCE",
)
VERIFICATION_RESULT_VALUES = ("DENY", "ESCALATE", "PASS_FOR_REVIEW")
HUMAN_ACTION_OPTIONS_BY_VERIFICATION_RESULT = MappingProxyType({
    "DENY": ("REJECT",),
    "ESCALATE": ("REJECT", "REQUEST_REWORK", "REQUEST_MORE_EVIDENCE"),
    "PASS_FOR_REVIEW": ("APPROVE", "REJECT", "REQUEST_REWORK", "REQUEST_MORE_EVIDENCE"),
})

HUMAN_GATE_IDENTITY_PREIMAGE = (
    "schema_version",
    "run_identity",
    "task_identity",
    "proposal_identity",
    "verification_identity",
    "package_identity",
    "context_identity",
    "task_summary",
    "proposal_summary",
    "verification_result",
    "reason_codes",
    "source_refs",
    "uncertainties",
    "evidence_pointers",
)
HUMAN_DECISION_IDENTITY_PREIMAGE = (
    "schema_version",
    "human_gate_identity",
    "decision",
    "decision_reason",
    "decision_scope",
    "human_authority_reference",
)

HUMAN_GATE_IMPLEMENTATION_COUNT = 1
AUTO_EXECUTE_AFTER_APPROVAL_COUNT = 0
HUMAN_APPROVAL_EXECUTION_COUNT = 0
HUMAN_DECISION_SIDE_EFFECT_COUNT = 0
STATE_TRANSITION_EXECUTION_COUNT = 0
FILESYSTEM_WRITE_IMPLEMENTATION_COUNT = 0
SUBPROCESS_EXECUTION_COUNT = 0
NETWORK_IMPLEMENTATION_COUNT = 0
PROVIDER_CLIENT_IMPLEMENTATION_COUNT = 0
MODEL_CALL_IMPLEMENTATION_COUNT = 0
MODEL_ROUTING_IMPLEMENTATION_COUNT = 0
AUTH_IMPLEMENTATION_COUNT = 0
AUTO_RETRY_IMPLEMENTATION_COUNT = 0
AUTO_FALLBACK_IMPLEMENTATION_COUNT = 0
GIT_OPERATION_COUNT = 0


class HumanGateValidationError(ValueError):
    """A Human Gate or Human Decision record violates the frozen contract."""

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
    raise HumanGateValidationError(message, code)


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        _fail(f"{field} must be a string-keyed mapping")
    return value


def _exact_fields(value: Mapping[str, object], required: set[str], optional: set[str], field: str) -> None:
    actual = set(value)
    if not required.issubset(actual) or actual - required - optional:
        _fail(f"{field} fields are not exact")


def _text(value: object, field: str, *, minimum: int = 1, maximum: int) -> str:
    if type(value) is not str or not minimum <= len(value) <= maximum:
        _fail(f"{field} length is invalid")
    if "\x00" in value or "\n" in value or "\r" in value:
        _fail(f"{field} contains an unsafe character")
    return value


def _sha(value: object, field: str) -> str:
    try:
        return require_sha256(value, field=field)
    except (TypeError, ValueError) as exc:
        _fail(str(exc))
    raise AssertionError("unreachable")


def _sequence(value: object, field: str) -> tuple[object, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        _fail(f"{field} must be an array")
    return tuple(value)


def _string_sequence(value: object, field: str, *, minimum: int, maximum: int) -> tuple[str, ...]:
    out = tuple(_text(item, field, minimum=minimum, maximum=maximum) for item in _sequence(value, field))
    return out


def _project_action_options(verification_result: str) -> tuple[str, ...]:
    try:
        return HUMAN_ACTION_OPTIONS_BY_VERIFICATION_RESULT[verification_result]
    except KeyError:
        _fail("unknown verification_result")
    raise AssertionError("unreachable")


def _action_options(value: object, verification_result: str) -> tuple[str, ...]:
    items = _sequence(value, "human_action_options")
    if not items:
        _fail("human_action_options must not be empty")
    out: list[str] = []
    for item in items:
        if type(item) is not str or item not in HUMAN_ACTION_VALUES:
            _fail("unknown human action option")
        out.append(item)
    if len(set(out)) != len(out):
        _fail("human_action_options contains duplicates")
    projected = _project_action_options(verification_result)
    if tuple(out) != projected:
        _fail(
            "human_action_options do not match verification_result",
            FailureCode.MR05_HUMAN_GATE_INVALID,
        )
    return projected


def _evidence_pointers(value: object) -> tuple[str, ...]:
    out: list[str] = []
    for item in _sequence(value, "evidence_pointers"):
        pointer = _text(item, "evidence_pointer", maximum=2048)
        if pointer.startswith("/") or any(part == ".." for part in pointer.split("/")):
            _fail("evidence_pointer is not a safe relative path")
        out.append(pointer)
    return tuple(sorted(out))


def _source_ref(value: object) -> Mapping[str, object]:
    row = _mapping(value, "source_ref")
    required = {"source_id", "canonical_locator", "content_sha256", "content_size_bytes", "source_set_identity"}
    _exact_fields(row, required, set(), "source_ref")
    size = row["content_size_bytes"]
    if type(size) is not int or size < 0 or size > 9223372036854775807:
        _fail("content_size_bytes is invalid")
    return MappingProxyType({
        "source_id": _sha(row["source_id"], "source_id"),
        "canonical_locator": _text(row["canonical_locator"], "canonical_locator", maximum=2048),
        "content_sha256": _sha(row["content_sha256"], "content_sha256"),
        "content_size_bytes": size,
        "source_set_identity": _sha(row["source_set_identity"], "source_set_identity"),
    })


def _source_refs(value: object) -> tuple[Mapping[str, object], ...]:
    rows = tuple(_source_ref(item) for item in _sequence(value, "source_refs"))
    return tuple(sorted(rows, key=lambda row: (row["source_id"], row["canonical_locator"])))


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
    return MappingProxyType(dict(row))


@dataclass(frozen=True, slots=True)
class HumanGateRecord:
    schema_version: str
    run_identity: str
    task_identity: str
    proposal_identity: str
    verification_identity: str
    package_identity: str
    context_identity: str
    task_summary: str
    proposal_summary: str
    verification_result: str
    reason_codes: tuple[str, ...]
    source_refs: tuple[Mapping[str, object], ...]
    uncertainties: tuple[str, ...]
    evidence_pointers: tuple[str, ...]
    human_action_options: tuple[str, ...]
    human_gate_identity: str
    observational_metadata: Mapping[str, object] | None = None

    @property
    def identity_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "run_identity": self.run_identity,
            "task_identity": self.task_identity,
            "proposal_identity": self.proposal_identity,
            "verification_identity": self.verification_identity,
            "package_identity": self.package_identity,
            "context_identity": self.context_identity,
            "task_summary": self.task_summary,
            "proposal_summary": self.proposal_summary,
            "verification_result": self.verification_result,
            "reason_codes": list(self.reason_codes),
            "source_refs": _plain(self.source_refs),
            "uncertainties": list(self.uncertainties),
            "evidence_pointers": list(self.evidence_pointers),
        }

    def to_dict(self) -> dict[str, object]:
        out = self.identity_payload
        out["human_action_options"] = list(self.human_action_options)
        out["human_gate_identity"] = self.human_gate_identity
        if self.observational_metadata is not None:
            out["observational_metadata"] = _plain(self.observational_metadata)
        return out

    @classmethod
    def from_mapping(cls, value: object) -> "HumanGateRecord":
        row = _mapping(value, "human_gate")
        required = set(HUMAN_GATE_IDENTITY_PREIMAGE) | {
            "human_action_options",
            "human_gate_identity",
        }
        _exact_fields(row, required, {"observational_metadata"}, "human_gate")
        try:
            validate_schema_version(HUMAN_GATE_SCHEMA_ID, row["schema_version"])
        except UnknownSchemaMajorVersionError as exc:
            _fail(str(exc), FailureCode.MR05_UNKNOWN_SCHEMA_MAJOR)
        except (UnsupportedSchemaVersionError, TypeError, ValueError) as exc:
            _fail(str(exc), FailureCode.INVALID_SCHEMA)
        verification_result = row["verification_result"]
        if type(verification_result) is not str or verification_result not in VERIFICATION_RESULT_VALUES:
            _fail("unknown verification_result")
        record = cls(
            schema_version=HUMAN_GATE_SCHEMA_VERSION,
            run_identity=_sha(row["run_identity"], "run_identity"),
            task_identity=_sha(row["task_identity"], "task_identity"),
            proposal_identity=_sha(row["proposal_identity"], "proposal_identity"),
            verification_identity=_sha(row["verification_identity"], "verification_identity"),
            package_identity=_sha(row["package_identity"], "package_identity"),
            context_identity=_sha(row["context_identity"], "context_identity"),
            task_summary=_text(row["task_summary"], "task_summary", minimum=0, maximum=8192),
            proposal_summary=_text(row["proposal_summary"], "proposal_summary", minimum=0, maximum=8192),
            verification_result=verification_result,
            reason_codes=tuple(sorted(_string_sequence(
                row["reason_codes"], "reason_code", minimum=1, maximum=256
            ))),
            source_refs=_source_refs(row["source_refs"]),
            uncertainties=_string_sequence(
                row["uncertainties"], "uncertainty", minimum=0, maximum=2048
            ),
            evidence_pointers=_evidence_pointers(row["evidence_pointers"]),
            human_action_options=_action_options(
                row["human_action_options"], verification_result
            ),
            human_gate_identity=_sha(row["human_gate_identity"], "human_gate_identity"),
            observational_metadata=_observational_metadata(row.get("observational_metadata")),
        )
        expected = sha256_canonical(record.identity_payload)
        if record.human_gate_identity != expected:
            _fail("human_gate_identity mismatch", FailureCode.HASH_MISMATCH)
        return record


def _qualified_human_gate(value: object) -> HumanGateRecord:
    if not isinstance(value, HumanGateRecord):
        _fail(
            "an exact qualified HumanGateRecord is required",
            FailureCode.MR05_HUMAN_GATE_INVALID,
        )
    reparsed = HumanGateRecord.from_mapping(value.to_dict())
    if reparsed != value:
        _fail(
            "Human Gate record is not canonically qualified",
            FailureCode.MR05_HUMAN_GATE_INVALID,
        )
    return reparsed


@dataclass(frozen=True, slots=True)
class HumanDecisionRecord:
    schema_version: str
    human_gate_identity: str
    decision: str
    decision_reason: str
    decision_scope: str
    human_authority_reference: str
    decision_identity: str
    observational_metadata: Mapping[str, object] | None = None

    @property
    def identity_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "human_gate_identity": self.human_gate_identity,
            "decision": self.decision,
            "decision_reason": self.decision_reason,
            "decision_scope": self.decision_scope,
            "human_authority_reference": self.human_authority_reference,
        }

    def to_dict(self) -> dict[str, object]:
        out = self.identity_payload
        out["decision_identity"] = self.decision_identity
        if self.observational_metadata is not None:
            out["observational_metadata"] = _plain(self.observational_metadata)
        return out

    @classmethod
    def from_mapping(
        cls,
        value: object,
        *,
        human_gate: object | None = None,
    ) -> "HumanDecisionRecord":
        gate = _qualified_human_gate(human_gate)
        row = _mapping(value, "human_decision")
        required = set(HUMAN_DECISION_IDENTITY_PREIMAGE) | {"decision_identity"}
        _exact_fields(row, required, {"observational_metadata"}, "human_decision")
        try:
            validate_schema_version(HUMAN_DECISION_SCHEMA_ID, row["schema_version"])
        except UnknownSchemaMajorVersionError as exc:
            _fail(str(exc), FailureCode.MR05_UNKNOWN_SCHEMA_MAJOR)
        except (UnsupportedSchemaVersionError, TypeError, ValueError) as exc:
            _fail(str(exc), FailureCode.INVALID_SCHEMA)
        human_gate_identity = _sha(row["human_gate_identity"], "human_gate_identity")
        if human_gate_identity != gate.human_gate_identity:
            _fail(
                "human decision is bound to the wrong Human Gate identity",
                FailureCode.MR05_HUMAN_GATE_INVALID,
            )
        decision = row["decision"]
        if type(decision) is not str or decision not in HUMAN_ACTION_VALUES:
            _fail("unknown human decision", FailureCode.MR05_HUMAN_GATE_INVALID)
        if decision not in gate.human_action_options:
            _fail(
                "human decision is not legal for the Human Gate verification result",
                FailureCode.MR05_HUMAN_GATE_INVALID,
            )
        record = cls(
            schema_version=HUMAN_DECISION_SCHEMA_VERSION,
            human_gate_identity=human_gate_identity,
            decision=decision,
            decision_reason=_text(row["decision_reason"], "decision_reason", maximum=8192),
            decision_scope=_text(row["decision_scope"], "decision_scope", maximum=2048),
            human_authority_reference=_text(row["human_authority_reference"], "human_authority_reference", maximum=2048),
            decision_identity=_sha(row["decision_identity"], "decision_identity"),
            observational_metadata=_observational_metadata(row.get("observational_metadata")),
        )
        expected = sha256_canonical(record.identity_payload)
        if record.decision_identity != expected:
            _fail("decision_identity mismatch", FailureCode.HASH_MISMATCH)
        return record


def build_human_gate(**fields: object) -> HumanGateRecord:
    payload = dict(fields)
    if "human_action_options" in payload:
        _fail(
            "caller-defined human_action_options are prohibited",
            FailureCode.MR05_HUMAN_GATE_INVALID,
        )
    payload.setdefault("schema_version", HUMAN_GATE_SCHEMA_VERSION)
    _exact_fields(
        payload,
        set(HUMAN_GATE_IDENTITY_PREIMAGE),
        {"observational_metadata"},
        "human_gate_builder",
    )
    try:
        validate_schema_version(HUMAN_GATE_SCHEMA_ID, payload["schema_version"])
    except UnknownSchemaMajorVersionError as exc:
        _fail(str(exc), FailureCode.MR05_UNKNOWN_SCHEMA_MAJOR)
    except (UnsupportedSchemaVersionError, TypeError, ValueError) as exc:
        _fail(str(exc), FailureCode.INVALID_SCHEMA)
    verification_result = payload["verification_result"]
    if type(verification_result) is not str or verification_result not in VERIFICATION_RESULT_VALUES:
        _fail("unknown verification_result")
    identity_payload: dict[str, object] = {
        "schema_version": HUMAN_GATE_SCHEMA_VERSION,
        "run_identity": _sha(payload["run_identity"], "run_identity"),
        "task_identity": _sha(payload["task_identity"], "task_identity"),
        "proposal_identity": _sha(payload["proposal_identity"], "proposal_identity"),
        "verification_identity": _sha(payload["verification_identity"], "verification_identity"),
        "package_identity": _sha(payload["package_identity"], "package_identity"),
        "context_identity": _sha(payload["context_identity"], "context_identity"),
        "task_summary": _text(payload["task_summary"], "task_summary", minimum=0, maximum=8192),
        "proposal_summary": _text(payload["proposal_summary"], "proposal_summary", minimum=0, maximum=8192),
        "verification_result": verification_result,
        "reason_codes": list(sorted(_string_sequence(
            payload["reason_codes"], "reason_code", minimum=1, maximum=256
        ))),
        "source_refs": _plain(_source_refs(payload["source_refs"])),
        "uncertainties": list(_string_sequence(
            payload["uncertainties"], "uncertainty", minimum=0, maximum=2048
        )),
        "evidence_pointers": list(_evidence_pointers(payload["evidence_pointers"])),
    }
    record_payload = dict(identity_payload)
    record_payload["human_action_options"] = list(
        _project_action_options(verification_result)
    )
    record_payload["human_gate_identity"] = sha256_canonical(identity_payload)
    if "observational_metadata" in payload:
        record_payload["observational_metadata"] = payload["observational_metadata"]
    return HumanGateRecord.from_mapping(record_payload)


def build_human_decision(
    *,
    human_gate: object | None = None,
    **fields: object,
) -> HumanDecisionRecord:
    gate = _qualified_human_gate(human_gate)
    payload = dict(fields)
    if "human_gate_identity" in payload:
        _fail(
            "caller-defined human_gate_identity is prohibited",
            FailureCode.MR05_HUMAN_GATE_INVALID,
        )
    payload.setdefault("schema_version", HUMAN_DECISION_SCHEMA_VERSION)
    builder_required = set(HUMAN_DECISION_IDENTITY_PREIMAGE) - {"human_gate_identity"}
    _exact_fields(
        payload,
        builder_required,
        {"observational_metadata"},
        "human_decision_builder",
    )
    payload["human_gate_identity"] = gate.human_gate_identity
    decision = payload["decision"]
    if type(decision) is not str or decision not in HUMAN_ACTION_VALUES:
        _fail("unknown human decision", FailureCode.MR05_HUMAN_GATE_INVALID)
    if decision not in gate.human_action_options:
        _fail(
            "human decision is not legal for the Human Gate verification result",
            FailureCode.MR05_HUMAN_GATE_INVALID,
        )
    payload["decision_identity"] = sha256_canonical({
        key: payload[key] for key in HUMAN_DECISION_IDENTITY_PREIMAGE
    })
    return HumanDecisionRecord.from_mapping(payload, human_gate=gate)


def canonical_human_gate_bytes(record: HumanGateRecord) -> bytes:
    if not isinstance(record, HumanGateRecord):
        _fail("record must be HumanGateRecord")
    return canonical_json_bytes(record.to_dict())


def canonical_human_decision_bytes(record: HumanDecisionRecord) -> bytes:
    if not isinstance(record, HumanDecisionRecord):
        _fail("record must be HumanDecisionRecord")
    return canonical_json_bytes(record.to_dict())


def not_implemented(*args: object, **kwargs: object) -> None:
    del args, kwargs
    phase_not_implemented("human_gate")


__all__ = (
    "HUMAN_GATE_SCHEMA_ID", "HUMAN_DECISION_SCHEMA_ID", "HUMAN_GATE_SCHEMA_VERSION",
    "HUMAN_DECISION_SCHEMA_VERSION", "HUMAN_ACTION_VALUES", "VERIFICATION_RESULT_VALUES",
    "HUMAN_ACTION_OPTIONS_BY_VERIFICATION_RESULT",
    "HUMAN_GATE_IDENTITY_PREIMAGE", "HUMAN_DECISION_IDENTITY_PREIMAGE",
    "HUMAN_GATE_IMPLEMENTATION_COUNT", "AUTO_EXECUTE_AFTER_APPROVAL_COUNT",
    "HUMAN_APPROVAL_EXECUTION_COUNT", "HUMAN_DECISION_SIDE_EFFECT_COUNT",
    "STATE_TRANSITION_EXECUTION_COUNT", "FILESYSTEM_WRITE_IMPLEMENTATION_COUNT",
    "SUBPROCESS_EXECUTION_COUNT", "NETWORK_IMPLEMENTATION_COUNT",
    "PROVIDER_CLIENT_IMPLEMENTATION_COUNT", "MODEL_CALL_IMPLEMENTATION_COUNT",
    "MODEL_ROUTING_IMPLEMENTATION_COUNT", "AUTH_IMPLEMENTATION_COUNT",
    "AUTO_RETRY_IMPLEMENTATION_COUNT", "AUTO_FALLBACK_IMPLEMENTATION_COUNT",
    "GIT_OPERATION_COUNT", "HumanGateValidationError", "HumanGateRecord",
    "HumanDecisionRecord", "build_human_gate", "build_human_decision",
    "canonical_human_gate_bytes", "canonical_human_decision_bytes", "not_implemented",
)
