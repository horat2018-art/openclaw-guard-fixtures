"""Deterministic, pure-data verifier-contract primitives for MR-05.

The verifier consumes already-supplied records.  It never discovers files,
executes a dependency, calls a model, performs a network/auth operation, or
changes workflow state.  Every identity and decision is recomputed from the
frozen contract; malformed or unknown data fails closed.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import NoReturn

from .canonical import canonical_identity_bytes, canonical_json_bytes
from .contracts import (
    MR05A_CONTRACT_SHA256,
    MR05B_CONTRACT_SET_SHA256,
    MR05B_MASTER_CONTRACT_SHA256,
    SCHEMA_VERSION,
)
from .failures import (
    Failure,
    FailureCode,
    FailureOwner,
    FailureSeverity,
    phase_not_implemented,
)
from .identity import require_sha256, sha256_bytes, sha256_canonical


VERIFIER_RESULT_SCHEMA_ID = "mr05.verifier_result"
VERIFIER_RULE_SCHEMA_ID = "mr05.verifier_rule"
VERIFIER_CHECK_SCHEMA_ID = "mr05.verifier_check"
VERIFIER_SCHEMA_ID = VERIFIER_RESULT_SCHEMA_ID
VERIFIER_SCHEMA_VERSION = SCHEMA_VERSION
VERIFICATION_POLICY_VERSION = "MR05-VERIFIER-POLICY-1.0.0"
VERIFIER_POLICY_VERSION = VERIFICATION_POLICY_VERSION

VERIFIER_DECISION_VALUES = ("DENY", "ESCALATE", "PASS_FOR_REVIEW")
VERIFIER_DECISION_PRECEDENCE = ("DENY", "ESCALATE", "PASS_FOR_REVIEW")
VERIFIER_DECISION_PRECEDENCE_EXPRESSION = "DENY > ESCALATE > PASS_FOR_REVIEW"
CHECK_RESULT_VALUES = ("PASS", "FAIL", "UNKNOWN")
CHECK_PASS_REASON = "CHECK_PASS"
MISSING_REQUIRED_EVIDENCE_BEHAVIOR = "DENY"
PASS_FOR_REVIEW_IS_APPROVAL = "NO"

VERIFIER_IDENTITY_PREIMAGE = (
    "schema_id",
    "schema_version",
    "verification_policy_version",
    "input_identities",
    "dependency_binding_identities",
    "provenance_identity",
    "metrics_identity",
    "contract_identities",
    "rule_identities",
    "checks",
    "missing_rule_ids",
    "failure_identities",
    "decision",
    "decision_reason_code",
)

INPUT_IDENTITY_FIELDS = (
    "task_identity",
    "source_set_identity",
    "discovery_identity",
    "normalization_identity",
    "context_identity",
)
RULE_OWNER_VALUES = tuple(owner.value for owner in FailureOwner if owner is not FailureOwner.HUMAN_GATE)
RULE_SEVERITY_VALUES = tuple(severity.value for severity in FailureSeverity)

# This phase has no operational surface.  VERIFIER_IMPLEMENTATION_COUNT is a
# materialization marker; every execution/side-effect counter remains zero.
VERIFIER_IMPLEMENTATION_COUNT = 1
LIVE_VERIFICATION_EXECUTION_COUNT = 0
CONTROLLER_IMPLEMENTATION_COUNT = 0
OPERATIONAL_ORCHESTRATION_IMPLEMENTATION_COUNT = 0
MR03_EXECUTION_IMPLEMENTATION_COUNT = 0
MR04_EXECUTION_IMPLEMENTATION_COUNT = 0
FILESYSTEM_SOURCE_READ_COUNT = 0
SUBPROCESS_EXECUTION_COUNT = 0
NETWORK_IMPLEMENTATION_COUNT = 0
PROVIDER_CLIENT_IMPLEMENTATION_COUNT = 0
MODEL_CALL_IMPLEMENTATION_COUNT = 0
MODEL_ROUTING_IMPLEMENTATION_COUNT = 0
AUTH_IMPLEMENTATION_COUNT = 0
HUMAN_APPROVAL_EXECUTION_COUNT = 0
STATE_TRANSITION_EXECUTION_COUNT = 0
AUTO_RETRY_IMPLEMENTATION_COUNT = 0
AUTO_FALLBACK_IMPLEMENTATION_COUNT = 0


class VerifierValidationError(ValueError):
    """A verifier input or output violates a frozen MR-05 contract."""

    def __init__(
        self,
        message: str,
        code: FailureCode | str = FailureCode.INVALID_SCHEMA,
    ) -> None:
        super().__init__(message)
        self.code = code.value if isinstance(code, FailureCode) else code
        self.failure_code = self.code
        self.retry_allowed = False


VerifierContractValidationError = VerifierValidationError
VerificationValidationError = VerifierValidationError
VerifierError = VerifierValidationError


def _fail(
    message: str,
    code: FailureCode | str = FailureCode.INVALID_SCHEMA,
) -> NoReturn:
    raise VerifierValidationError(message, code)


def _mapping(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _fail(f"{context} must be a mapping", FailureCode.INVALID_SCHEMA)
    if any(not isinstance(key, str) for key in value):
        _fail(f"{context} contains a non-string field name", FailureCode.INVALID_SCHEMA)
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
        _fail(
            f"{context} fields are not exact",
            FailureCode.INVALID_SCHEMA,
        )


def _sequence(value: object, context: str) -> tuple[object, ...]:
    if not isinstance(value, (list, tuple)):
        _fail(f"{context} must be an array", FailureCode.INVALID_SCHEMA)
    return tuple(value)


def _text(value: object, context: str, *, maximum: int = 256) -> str:
    if type(value) is not str or not 1 <= len(value) <= maximum:
        _fail(f"{context} must be a non-empty string", FailureCode.INVALID_SCHEMA)
    if "\x00" in value or "\n" in value or "\r" in value:
        _fail(f"{context} contains an unsafe character", FailureCode.INVALID_SCHEMA)
    return value


def _sha(value: object, context: str) -> str:
    try:
        return require_sha256(value, field=context)
    except (TypeError, ValueError) as exc:
        _fail(str(exc), FailureCode.HASH_MISMATCH)
    raise AssertionError("unreachable")


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


def _enum_value(value: object) -> object:
    # Existing MR-05 enums inherit str.  Converting only those explicit enum
    # values keeps callers from accidentally relying on arbitrary coercion.
    if isinstance(value, (FailureCode, FailureOwner, FailureSeverity)):
        return value.value
    return value


def _ascii_key(value: str) -> bytes:
    try:
        return value.encode("ascii")
    except UnicodeEncodeError:
        _fail("identity ordering value must be ASCII", FailureCode.INVALID_SCHEMA)
    raise AssertionError("unreachable")


def _utf8_key(value: str) -> bytes:
    return value.encode("utf-8")


@dataclass(frozen=True, slots=True)
class VerifierRule:
    """A frozen rule descriptor whose identity is independently recomputable."""

    rule_id: str
    rule_version: str
    rule_owner: str
    rule_severity: str
    expected_contract_identity: str | None

    def __post_init__(self) -> None:
        rule_id = _text(self.rule_id, "rule_id")
        rule_version = _text(self.rule_version, "rule_version")
        owner = _enum_value(self.rule_owner)
        severity = _enum_value(self.rule_severity)
        if owner not in RULE_OWNER_VALUES:
            _fail("unknown rule owner", FailureCode.INVALID_SCHEMA)
        if severity not in RULE_SEVERITY_VALUES:
            _fail("unknown rule severity", FailureCode.INVALID_SCHEMA)
        expected = self.expected_contract_identity
        if expected is not None:
            expected = _sha(expected, "expected_contract_identity")
        object.__setattr__(self, "rule_id", rule_id)
        object.__setattr__(self, "rule_version", rule_version)
        object.__setattr__(self, "rule_owner", owner)
        object.__setattr__(self, "rule_severity", severity)
        object.__setattr__(self, "expected_contract_identity", expected)

    @property
    def rule_identity(self) -> str:
        return sha256_bytes(
            canonical_identity_bytes(
                {
                    "rule_schema_id": VERIFIER_RULE_SCHEMA_ID,
                    "schema_version": VERIFIER_SCHEMA_VERSION,
                    "rule_id": self.rule_id,
                    "rule_version": self.rule_version,
                    "rule_owner": self.rule_owner,
                    "rule_severity": self.rule_severity,
                    "expected_contract_identity": self.expected_contract_identity,
                }
            )
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_id": VERIFIER_RULE_SCHEMA_ID,
            "schema_version": VERIFIER_SCHEMA_VERSION,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "rule_owner": self.rule_owner,
            "rule_severity": self.rule_severity,
            "expected_contract_identity": self.expected_contract_identity,
            "rule_identity": self.rule_identity,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "VerifierRule":
        mapping = _mapping(value, "verifier rule")
        required = frozenset(
            {
                "schema_id",
                "schema_version",
                "rule_id",
                "rule_version",
                "rule_owner",
                "rule_severity",
                "expected_contract_identity",
                "rule_identity",
            }
        )
        _exact_fields(mapping, required, "verifier rule")
        if mapping["schema_id"] != VERIFIER_RULE_SCHEMA_ID:
            _fail("unknown verifier rule schema", FailureCode.MR05_UNKNOWN_SCHEMA_MAJOR)
        if mapping["schema_version"] != VERIFIER_SCHEMA_VERSION:
            _fail("unsupported verifier rule schema version", FailureCode.MR05_UNKNOWN_SCHEMA_MAJOR)
        result = cls(
            rule_id=mapping["rule_id"],
            rule_version=mapping["rule_version"],
            rule_owner=mapping["rule_owner"],
            rule_severity=mapping["rule_severity"],
            expected_contract_identity=mapping["expected_contract_identity"],
        )
        declared = _sha(mapping["rule_identity"], "rule_identity")
        if declared != result.rule_identity:
            _fail("rule identity mismatch", FailureCode.HASH_MISMATCH)
        return result


_FROZEN_CONTRACT_IDENTITY_VALUES = {
    "MR05A_CONTRACT_SHA256": MR05A_CONTRACT_SHA256,
    "MR05B_MASTER_CONTRACT_SHA256": MR05B_MASTER_CONTRACT_SHA256,
    "MR05B_CONTRACT_SET_SHA256": MR05B_CONTRACT_SET_SHA256,
    "HAI_MR_05L_BOUNDED_CONTEXT_PLANNING_CONTRACT_SHA256": "27ee969481fdba4d5ed773a3a67533940dd34160c1c1cb345c9483aff1541c54",
}
FROZEN_CONTRACT_IDENTITIES = tuple(
    MappingProxyType({"contract_name": name, "contract_identity": value})
    for name, value in sorted(
        _FROZEN_CONTRACT_IDENTITY_VALUES.items(),
        key=lambda pair: pair[0].encode("utf-8"),
    )
)


def _contract_identity_for(name: str | None) -> str | None:
    if name is None:
        return None
    try:
        return _FROZEN_CONTRACT_IDENTITY_VALUES[name]
    except KeyError:
        _fail("unknown frozen contract name", FailureCode.UNSUPPORTED_INPUT)
    raise AssertionError("unreachable")


# The rule catalog follows the exact frozen check order from MR-05A.  The
# result itself uses canonical identity ordering, not caller/input ordering.
RULE_CATALOG = (
    VerifierRule("SCHEMA_EXACT", "1.0.0", FailureOwner.PROPOSAL_SCHEMA.value, FailureSeverity.HIGH.value, _contract_identity_for("MR05B_CONTRACT_SET_SHA256")),
    VerifierRule("IDENTITY_RECOMPUTATION", "1.0.0", FailureOwner.VERIFICATION.value, FailureSeverity.CRITICAL.value, _contract_identity_for("MR05B_MASTER_CONTRACT_SHA256")),
    VerifierRule("INPUT_BINDING_EXACT", "1.0.0", FailureOwner.VERIFICATION.value, FailureSeverity.CRITICAL.value, _contract_identity_for("HAI_MR_05L_BOUNDED_CONTEXT_PLANNING_CONTRACT_SHA256")),
    VerifierRule("SOURCE_REF_MEMBERSHIP", "1.0.0", FailureOwner.VERIFICATION.value, FailureSeverity.CRITICAL.value, _contract_identity_for("MR05B_MASTER_CONTRACT_SHA256")),
    VerifierRule("REQUIRED_EVIDENCE", "1.0.0", FailureOwner.VERIFICATION.value, FailureSeverity.HIGH.value, _contract_identity_for("MR05B_MASTER_CONTRACT_SHA256")),
    VerifierRule("DISCLOSURE_POLICY", "1.0.0", FailureOwner.DISCLOSURE.value, FailureSeverity.CRITICAL.value, _contract_identity_for("MR05A_CONTRACT_SHA256")),
    VerifierRule("CLAIM_SUPPORT", "1.0.0", FailureOwner.PROPOSAL_BINDING.value, FailureSeverity.HIGH.value, _contract_identity_for("MR05B_MASTER_CONTRACT_SHA256")),
    VerifierRule("CONTRADICTION_PRECEDENCE", "1.0.0", FailureOwner.VERIFICATION.value, FailureSeverity.HIGH.value, _contract_identity_for("MR05A_CONTRACT_SHA256")),
    VerifierRule("FROZEN_MR04_RESULT", "1.0.0", FailureOwner.MR04.value, FailureSeverity.CRITICAL.value, None),
    VerifierRule("ESCALATION_FLAGS", "1.0.0", FailureOwner.VERIFICATION.value, FailureSeverity.HIGH.value, _contract_identity_for("MR05A_CONTRACT_SHA256")),
    VerifierRule("DETERMINISTIC_OUTPUT", "1.0.0", FailureOwner.INTERNAL_INVARIANT.value, FailureSeverity.CRITICAL.value, _contract_identity_for("MR05B_MASTER_CONTRACT_SHA256")),
)
_RULE_BY_ID = MappingProxyType({rule.rule_id: rule for rule in RULE_CATALOG})
RULE_IDS = tuple(rule.rule_id for rule in RULE_CATALOG)
_RULE_SEVERITY_RANK = MappingProxyType(
    {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
)


@dataclass(frozen=True, slots=True)
class VerifierCheckRecord:
    """One exact rule/check outcome."""

    rule_id: str
    rule_version: str
    rule_owner: str
    rule_severity: str
    input_identity: str
    expected_contract_identity: str | None
    check_result: str
    failure_identity: str | None = None
    decision: str | None = None
    decision_reason_code: str | None = None
    schema_id: str = VERIFIER_CHECK_SCHEMA_ID
    schema_version: str = VERIFIER_SCHEMA_VERSION
    rule_identity: str | None = None

    def __post_init__(self) -> None:
        if self.schema_id != VERIFIER_CHECK_SCHEMA_ID:
            _fail("unknown verifier check schema", FailureCode.MR05_UNKNOWN_SCHEMA_MAJOR)
        if self.schema_version != VERIFIER_SCHEMA_VERSION:
            _fail("unsupported verifier check schema version", FailureCode.MR05_UNKNOWN_SCHEMA_MAJOR)
        try:
            spec = _RULE_BY_ID[self.rule_id]
        except (KeyError, TypeError):
            _fail("unknown verifier rule", FailureCode.UNSUPPORTED_INPUT)
        if self.rule_version != spec.rule_version:
            _fail("unknown verifier rule version", FailureCode.UNSUPPORTED_INPUT)
        if _enum_value(self.rule_owner) != spec.rule_owner:
            _fail("rule owner does not match frozen catalog", FailureCode.INVALID_SCHEMA)
        if _enum_value(self.rule_severity) != spec.rule_severity:
            _fail("rule severity does not match frozen catalog", FailureCode.INVALID_SCHEMA)
        if self.expected_contract_identity != spec.expected_contract_identity:
            _fail("expected contract identity does not match rule", FailureCode.HASH_MISMATCH)
        input_identity = _sha(self.input_identity, "input_identity")
        check_result = _enum_value(self.check_result)
        if check_result not in CHECK_RESULT_VALUES:
            _fail("unknown check result", FailureCode.INVALID_SCHEMA)
        declared_rule_identity = self.rule_identity
        computed_rule_identity = spec.rule_identity
        if declared_rule_identity is not None:
            if _sha(declared_rule_identity, "rule_identity") != computed_rule_identity:
                _fail("rule identity mismatch", FailureCode.HASH_MISMATCH)
        failure_identity = self.failure_identity
        if failure_identity is not None:
            failure_identity = _sha(failure_identity, "failure_identity")
        reason = self.decision_reason_code
        if reason is None:
            if check_result == "PASS":
                reason = CHECK_PASS_REASON
            else:
                _fail("non-PASS check requires a failure reason", FailureCode.INVALID_SCHEMA)
        reason = _enum_value(reason)
        if reason == CHECK_PASS_REASON:
            if check_result != "PASS" or failure_identity is not None:
                _fail("CHECK_PASS is valid only for PASS", FailureCode.INVALID_SCHEMA)
        else:
            try:
                FailureCode(reason)
            except (TypeError, ValueError):
                _fail("unknown decision reason code", FailureCode.UNSUPPORTED_INPUT)
            if check_result == "PASS" or failure_identity is None:
                _fail("non-PASS check requires a failure identity", FailureCode.INVALID_SCHEMA)
        expected_decision = _expected_check_decision(check_result, reason)
        decision = self.decision
        if decision is None:
            decision = expected_decision
        decision = _enum_value(decision)
        if decision not in VERIFIER_DECISION_VALUES:
            _fail("unknown verifier decision", FailureCode.INVALID_SCHEMA)
        if decision != expected_decision:
            _fail("check result and decision are inconsistent", FailureCode.INVALID_SCHEMA)
        object.__setattr__(self, "rule_owner", spec.rule_owner)
        object.__setattr__(self, "rule_severity", spec.rule_severity)
        object.__setattr__(self, "expected_contract_identity", spec.expected_contract_identity)
        object.__setattr__(self, "input_identity", input_identity)
        object.__setattr__(self, "check_result", check_result)
        object.__setattr__(self, "failure_identity", failure_identity)
        object.__setattr__(self, "decision_reason_code", reason)
        object.__setattr__(self, "decision", decision)
        object.__setattr__(self, "rule_identity", computed_rule_identity)

    @classmethod
    def create(
        cls,
        *,
        rule_id: str,
        input_identity: str,
        check_result: str,
        failure_identity: str | None = None,
        decision: str | None = None,
        decision_reason_code: str | None = None,
    ) -> "VerifierCheckRecord":
        try:
            spec = _RULE_BY_ID[rule_id]
        except (KeyError, TypeError):
            _fail("unknown verifier rule", FailureCode.UNSUPPORTED_INPUT)
        return cls(
            rule_id=spec.rule_id,
            rule_version=spec.rule_version,
            rule_owner=spec.rule_owner,
            rule_severity=spec.rule_severity,
            input_identity=input_identity,
            expected_contract_identity=spec.expected_contract_identity,
            check_result=check_result,
            failure_identity=failure_identity,
            decision=decision,
            decision_reason_code=decision_reason_code,
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "VerifierCheckRecord":
        mapping = _mapping(value, "verifier check")
        required = frozenset(
            {
                "schema_id",
                "schema_version",
                "rule_id",
                "rule_version",
                "rule_owner",
                "rule_severity",
                "rule_identity",
                "input_identity",
                "expected_contract_identity",
                "check_result",
                "failure_identity",
                "decision",
                "decision_reason_code",
            }
        )
        _exact_fields(mapping, required, "verifier check")
        return cls(
            schema_id=mapping["schema_id"],
            schema_version=mapping["schema_version"],
            rule_id=mapping["rule_id"],
            rule_version=mapping["rule_version"],
            rule_owner=mapping["rule_owner"],
            rule_severity=mapping["rule_severity"],
            rule_identity=mapping["rule_identity"],
            input_identity=mapping["input_identity"],
            expected_contract_identity=mapping["expected_contract_identity"],
            check_result=mapping["check_result"],
            failure_identity=mapping["failure_identity"],
            decision=mapping["decision"],
            decision_reason_code=mapping["decision_reason_code"],
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_id": self.schema_id,
            "schema_version": self.schema_version,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "rule_owner": self.rule_owner,
            "rule_severity": self.rule_severity,
            "rule_identity": self.rule_identity,
            "input_identity": self.input_identity,
            "expected_contract_identity": self.expected_contract_identity,
            "check_result": self.check_result,
            "failure_identity": self.failure_identity,
            "decision": self.decision,
            "decision_reason_code": self.decision_reason_code,
        }


def build_verifier_check(
    *,
    rule_id: str,
    input_identity: str,
    check_result: str,
    failure_identity: str | None = None,
    decision: str | None = None,
    decision_reason_code: str | None = None,
) -> VerifierCheckRecord:
    """Construct one check from the frozen rule catalog."""

    return VerifierCheckRecord.create(
        rule_id=rule_id,
        input_identity=input_identity,
        check_result=check_result,
        failure_identity=failure_identity,
        decision=decision,
        decision_reason_code=decision_reason_code,
    )


make_verifier_check = build_verifier_check


def _expected_check_decision(check_result: str, reason: str) -> str:
    if check_result == "PASS":
        return "PASS_FOR_REVIEW"
    if reason == FailureCode.AMBIGUOUS_PRECEDENCE.value:
        return "ESCALATE"
    return "DENY"


def _normalize_contract_identities(value: object) -> tuple[Mapping[str, str], ...]:
    raw_value = value
    if isinstance(value, Mapping):
        outer = _mapping(value, "frozen_contract_identity_set")
        required = frozenset({"schema_id", "schema_version", "contract_identities"})
        _exact_fields(outer, required, "frozen_contract_identity_set")
        if outer["schema_id"] != "mr05.frozen_contract_identity_set":
            _fail("unknown frozen contract identity schema", FailureCode.MR05_UNKNOWN_SCHEMA_MAJOR)
        if outer["schema_version"] != VERIFIER_SCHEMA_VERSION:
            _fail("unsupported frozen contract identity version", FailureCode.MR05_UNKNOWN_SCHEMA_MAJOR)
        raw_value = outer["contract_identities"]
    records = _sequence(raw_value, "contract_identities")
    normalized: list[Mapping[str, str]] = []
    seen: set[str] = set()
    for index, item in enumerate(records):
        mapping = _mapping(item, f"contract_identities[{index}]")
        _exact_fields(
            mapping,
            frozenset({"contract_name", "contract_identity"}),
            f"contract_identities[{index}]",
        )
        name = _text(mapping["contract_name"], "contract_name")
        if name in seen:
            _fail("duplicate contract identity name", FailureCode.DUPLICATE_CONFLICT)
        seen.add(name)
        expected = _contract_identity_for(name)
        actual = _sha(mapping["contract_identity"], "contract_identity")
        if expected != actual:
            _fail("forged or mismatched contract identity", FailureCode.HASH_MISMATCH)
        normalized.append(
            MappingProxyType({"contract_name": name, "contract_identity": actual})
        )
    normalized.sort(key=lambda record: _utf8_key(record["contract_name"]))
    expected_names = set(_FROZEN_CONTRACT_IDENTITY_VALUES)
    if seen != expected_names:
        _fail("frozen contract identity set is incomplete", FailureCode.PROVENANCE_GAP)
    return tuple(normalized)


def _normalize_input_identities(value: object) -> Mapping[str, str]:
    mapping = _mapping(value, "input_identities")
    _exact_fields(mapping, frozenset(INPUT_IDENTITY_FIELDS), "input_identities")
    normalized = {
        field: _sha(mapping[field], f"input_identities.{field}")
        for field in INPUT_IDENTITY_FIELDS
    }
    return MappingProxyType(normalized)


def _normalize_dependency_identities(value: object) -> tuple[str, ...]:
    values = tuple(_sha(item, "dependency_binding_identity") for item in _sequence(value, "dependency_binding_identities"))
    if len(values) != 2:
        _fail("exactly two dependency identities are required", FailureCode.PROVENANCE_GAP)
    if len(set(values)) != len(values):
        _fail("dependency identities are duplicated", FailureCode.DUPLICATE_CONFLICT)
    return tuple(sorted(values, key=_ascii_key))


def _normalize_failure_records(value: object) -> Mapping[str, Failure]:
    records = _sequence(value, "failure_records")
    result: dict[str, Failure] = {}
    for index, item in enumerate(records):
        try:
            failure = item if isinstance(item, Failure) else Failure.from_mapping(_mapping(item, f"failure_records[{index}]"))
        except VerifierValidationError:
            raise
        except Exception as exc:
            _fail(f"failure record is invalid at index {index}", FailureCode.INVALID_SCHEMA)
        identity = _sha(failure.failure_identity, "failure_identity")
        if identity in result:
            _fail("duplicate failure identity", FailureCode.DUPLICATE_CONFLICT)
        result[identity] = failure
    return MappingProxyType(result)


def _normalize_checks(value: object) -> tuple[VerifierCheckRecord, ...]:
    records = _sequence(value, "verification_evidence")
    checks: list[VerifierCheckRecord] = []
    seen_rules: set[str] = set()
    for index, item in enumerate(records):
        try:
            check = item if isinstance(item, VerifierCheckRecord) else VerifierCheckRecord.from_mapping(_mapping(item, f"verification_evidence[{index}]"))
        except VerifierValidationError:
            raise
        except Exception as exc:
            _fail(f"verifier check is invalid at index {index}", FailureCode.INVALID_SCHEMA)
        if check.rule_id in seen_rules:
            _fail("duplicate verifier rule check", FailureCode.DUPLICATE_CONFLICT)
        seen_rules.add(check.rule_id)
        checks.append(check)
    checks.sort(key=lambda check: _ascii_key(check.rule_identity))
    return tuple(checks)


def _validate_check_bindings(
    checks: tuple[VerifierCheckRecord, ...],
    input_identities: Mapping[str, str],
    dependency_identities: tuple[str, ...],
    provenance_identity: str,
    metrics_identity: str,
    contract_identities: tuple[Mapping[str, str], ...],
    failure_records: Mapping[str, Failure],
) -> None:
    available_inputs = set(input_identities.values()) | set(dependency_identities)
    available_inputs.update({provenance_identity, metrics_identity})
    available_contracts = {record["contract_identity"] for record in contract_identities}
    for check in checks:
        if check.input_identity not in available_inputs:
            _fail("check input identity is not bound to supplied inputs", FailureCode.HASH_MISMATCH)
        if check.expected_contract_identity is not None and check.expected_contract_identity not in available_contracts:
            _fail("check expected contract is not supplied", FailureCode.HASH_MISMATCH)
        if check.check_result == "PASS":
            if check.failure_identity is not None:
                _fail("PASS check carries a failure identity", FailureCode.INVALID_SCHEMA)
            continue
        if check.failure_identity is None or check.failure_identity not in failure_records:
            _fail("check failure identity is not supplied", FailureCode.HASH_MISMATCH)
        failure = failure_records[check.failure_identity]
        if failure.failure_code.value != check.decision_reason_code:
            _fail("check reason does not match failure record", FailureCode.HASH_MISMATCH)


def _missing_rule_ids(checks: tuple[VerifierCheckRecord, ...]) -> tuple[str, ...]:
    present = {check.rule_id for check in checks}
    return tuple(sorted(set(RULE_IDS) - present, key=_utf8_key))


def _derive_decision(
    checks: tuple[VerifierCheckRecord, ...],
    missing_rule_ids: tuple[str, ...],
) -> str:
    if missing_rule_ids:
        return "DENY"
    if any(check.decision == "DENY" for check in checks):
        return "DENY"
    if any(check.decision == "ESCALATE" for check in checks):
        return "ESCALATE"
    if checks and all(check.check_result == "PASS" for check in checks):
        return "PASS_FOR_REVIEW"
    return "DENY"


def _winning_reason(
    checks: tuple[VerifierCheckRecord, ...],
    decision: str,
    missing_rule_ids: tuple[str, ...],
) -> str:
    if missing_rule_ids:
        return FailureCode.MISSING_REQUIRED_ARTIFACT.value
    candidates = [check for check in checks if check.decision == decision]
    if not candidates:
        return CHECK_PASS_REASON
    candidates.sort(
        key=lambda check: (
            -_RULE_SEVERITY_RANK[check.rule_severity],
            _ascii_key(check.rule_identity),
        )
    )
    return candidates[0].decision_reason_code


def _result_identity_payload(
    *,
    schema_id: str,
    schema_version: str,
    verification_policy_version: str,
    input_identities: Mapping[str, str],
    dependency_binding_identities: tuple[str, ...],
    provenance_identity: str,
    metrics_identity: str,
    contract_identities: tuple[Mapping[str, str], ...],
    rule_identities: tuple[str, ...],
    checks: tuple[VerifierCheckRecord, ...],
    missing_rule_ids: tuple[str, ...],
    failure_identities: tuple[str, ...],
    decision: str,
    decision_reason_code: str,
) -> dict[str, object]:
    return {
        "schema_id": schema_id,
        "schema_version": schema_version,
        "verification_policy_version": verification_policy_version,
        "input_identities": _plain(input_identities),
        "dependency_binding_identities": list(dependency_binding_identities),
        "provenance_identity": provenance_identity,
        "metrics_identity": metrics_identity,
        "contract_identities": [_plain(item) for item in contract_identities],
        "rule_identities": list(rule_identities),
        "checks": [check.to_dict() for check in checks],
        "missing_rule_ids": list(missing_rule_ids),
        "failure_identities": list(failure_identities),
        "decision": decision,
        "decision_reason_code": decision_reason_code,
    }


@dataclass(frozen=True, slots=True)
class VerifierResult:
    """Immutable deterministic verifier result."""

    schema_id: str
    schema_version: str
    verification_policy_version: str
    input_identities: Mapping[str, object]
    dependency_binding_identities: tuple[str, ...]
    provenance_identity: str
    metrics_identity: str
    contract_identities: tuple[Mapping[str, object], ...]
    rule_identities: tuple[str, ...]
    checks: tuple[VerifierCheckRecord, ...]
    missing_rule_ids: tuple[str, ...]
    failure_identities: tuple[str, ...]
    decision: str
    decision_reason_code: str
    verifier_identity: str | None = None

    def __post_init__(self) -> None:
        if self.schema_id != VERIFIER_RESULT_SCHEMA_ID:
            _fail("unknown verifier result schema", FailureCode.MR05_UNKNOWN_SCHEMA_MAJOR)
        if self.schema_version != VERIFIER_SCHEMA_VERSION:
            _fail("unsupported verifier result schema version", FailureCode.MR05_UNKNOWN_SCHEMA_MAJOR)
        if self.verification_policy_version != VERIFICATION_POLICY_VERSION:
            _fail("unsupported verifier policy version", FailureCode.INVALID_SCHEMA)
        inputs = _normalize_input_identities(self.input_identities)
        dependencies = _normalize_dependency_identities(self.dependency_binding_identities)
        provenance_identity = _sha(self.provenance_identity, "provenance_identity")
        metrics_identity = _sha(self.metrics_identity, "metrics_identity")
        contracts = _normalize_contract_identities(self.contract_identities)
        checks = _normalize_checks(self.checks)
        if len({check.rule_id for check in checks}) != len(checks):
            _fail("duplicate verifier rule check", FailureCode.DUPLICATE_CONFLICT)
        missing = _missing_rule_ids(checks)
        declared_missing = tuple(_text(item, "missing_rule_id") for item in _sequence(self.missing_rule_ids, "missing_rule_ids"))
        declared_missing = tuple(sorted(declared_missing, key=_utf8_key))
        if declared_missing != missing:
            _fail("missing rule ids do not match checks", FailureCode.HASH_MISMATCH)
        rule_ids = tuple(sorted((check.rule_identity for check in checks), key=_ascii_key))
        declared_rule_ids = tuple(_sha(item, "rule_identity") for item in _sequence(self.rule_identities, "rule_identities"))
        declared_rule_ids = tuple(sorted(declared_rule_ids, key=_ascii_key))
        if declared_rule_ids != rule_ids:
            _fail("rule identities do not match checks", FailureCode.HASH_MISMATCH)
        failure_ids = tuple(
            sorted(
                {
                    check.failure_identity
                    for check in checks
                    if check.failure_identity is not None
                },
                key=_ascii_key,
            )
        )
        declared_failure_ids = tuple(_sha(item, "failure_identity") for item in _sequence(self.failure_identities, "failure_identities"))
        declared_failure_ids = tuple(sorted(set(declared_failure_ids), key=_ascii_key))
        if declared_failure_ids != failure_ids:
            _fail("failure identities do not match checks", FailureCode.HASH_MISMATCH)
        decision = _enum_value(self.decision)
        if decision not in VERIFIER_DECISION_VALUES:
            _fail("unknown verifier decision", FailureCode.INVALID_SCHEMA)
        derived_decision = _derive_decision(checks, missing)
        if decision != derived_decision:
            _fail("verifier decision violates frozen precedence", FailureCode.INVALID_SCHEMA)
        reason = _enum_value(self.decision_reason_code)
        if reason != _winning_reason(checks, decision, missing):
            _fail("verifier decision reason is not deterministic", FailureCode.INVALID_SCHEMA)
        if reason != CHECK_PASS_REASON:
            try:
                FailureCode(reason)
            except (TypeError, ValueError):
                _fail("unknown verifier decision reason", FailureCode.UNSUPPORTED_INPUT)
        elif decision != "PASS_FOR_REVIEW":
            _fail("CHECK_PASS is valid only for PASS_FOR_REVIEW", FailureCode.INVALID_SCHEMA)
        identity_payload = _result_identity_payload(
            schema_id=VERIFIER_RESULT_SCHEMA_ID,
            schema_version=VERIFIER_SCHEMA_VERSION,
            verification_policy_version=VERIFICATION_POLICY_VERSION,
            input_identities=inputs,
            dependency_binding_identities=dependencies,
            provenance_identity=provenance_identity,
            metrics_identity=metrics_identity,
            contract_identities=contracts,
            rule_identities=rule_ids,
            checks=checks,
            missing_rule_ids=missing,
            failure_identities=failure_ids,
            decision=decision,
            decision_reason_code=reason,
        )
        computed_identity = sha256_canonical(identity_payload)
        declared_identity = self.verifier_identity
        if declared_identity is not None and _sha(declared_identity, "verifier_identity") != computed_identity:
            _fail("verifier identity mismatch", FailureCode.HASH_MISMATCH)
        object.__setattr__(self, "schema_id", VERIFIER_RESULT_SCHEMA_ID)
        object.__setattr__(self, "schema_version", VERIFIER_SCHEMA_VERSION)
        object.__setattr__(self, "verification_policy_version", VERIFICATION_POLICY_VERSION)
        object.__setattr__(self, "input_identities", inputs)
        object.__setattr__(self, "dependency_binding_identities", dependencies)
        object.__setattr__(self, "provenance_identity", provenance_identity)
        object.__setattr__(self, "metrics_identity", metrics_identity)
        object.__setattr__(self, "contract_identities", tuple(_freeze(item) for item in contracts))
        object.__setattr__(self, "rule_identities", rule_ids)
        object.__setattr__(self, "checks", checks)
        object.__setattr__(self, "missing_rule_ids", missing)
        object.__setattr__(self, "failure_identities", failure_ids)
        object.__setattr__(self, "decision", decision)
        object.__setattr__(self, "decision_reason_code", reason)
        object.__setattr__(self, "verifier_identity", computed_identity)

    @property
    def identity_payload(self) -> dict[str, object]:
        return _result_identity_payload(
            schema_id=self.schema_id,
            schema_version=self.schema_version,
            verification_policy_version=self.verification_policy_version,
            input_identities=self.input_identities,
            dependency_binding_identities=self.dependency_binding_identities,
            provenance_identity=self.provenance_identity,
            metrics_identity=self.metrics_identity,
            contract_identities=self.contract_identities,
            rule_identities=self.rule_identities,
            checks=self.checks,
            missing_rule_ids=self.missing_rule_ids,
            failure_identities=self.failure_identities,
            decision=self.decision,
            decision_reason_code=self.decision_reason_code,
        )

    def canonical_identity_bytes(self) -> bytes:
        return canonical_identity_bytes(self.identity_payload)

    def to_dict(self) -> dict[str, object]:
        result = self.identity_payload
        result["verifier_identity"] = self.verifier_identity
        return result

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, object],
        *,
        failure_records: object = (),
    ) -> "VerifierResult":
        mapping = _mapping(value, "verifier result")
        required = frozenset(
            {
                "schema_id",
                "schema_version",
                "verification_policy_version",
                "input_identities",
                "dependency_binding_identities",
                "provenance_identity",
                "metrics_identity",
                "contract_identities",
                "rule_identities",
                "checks",
                "missing_rule_ids",
                "failure_identities",
                "decision",
                "decision_reason_code",
                "verifier_identity",
            }
        )
        _exact_fields(mapping, required, "verifier result")
        result = cls(
            schema_id=mapping["schema_id"],
            schema_version=mapping["schema_version"],
            verification_policy_version=mapping["verification_policy_version"],
            input_identities=mapping["input_identities"],
            dependency_binding_identities=tuple(_sequence(mapping["dependency_binding_identities"], "dependency_binding_identities")),
            provenance_identity=mapping["provenance_identity"],
            metrics_identity=mapping["metrics_identity"],
            contract_identities=tuple(_sequence(mapping["contract_identities"], "contract_identities")),
            rule_identities=tuple(_sequence(mapping["rule_identities"], "rule_identities")),
            checks=tuple(_sequence(mapping["checks"], "checks")),
            missing_rule_ids=tuple(_sequence(mapping["missing_rule_ids"], "missing_rule_ids")),
            failure_identities=tuple(_sequence(mapping["failure_identities"], "failure_identities")),
            decision=mapping["decision"],
            decision_reason_code=mapping["decision_reason_code"],
            verifier_identity=mapping["verifier_identity"],
        )
        if failure_records:
            records = _normalize_failure_records(failure_records)
            _validate_check_bindings(
                result.checks,
                result.input_identities,
                result.dependency_binding_identities,
                result.provenance_identity,
                result.metrics_identity,
                result.contract_identities,
                records,
            )
        return result


VerificationResult = VerifierResult
VerifierOutput = VerifierResult


def _build_verifier_result(
    *,
    input_identities: object,
    dependency_binding_identities: object,
    provenance_identity: object,
    metrics_identity: object,
    contract_identities: object,
    checks: object,
    failure_records: object,
) -> VerifierResult:
    inputs = _normalize_input_identities(input_identities)
    dependencies = _normalize_dependency_identities(dependency_binding_identities)
    provenance = _sha(provenance_identity, "provenance_identity")
    metrics = _sha(metrics_identity, "metrics_identity")
    contracts = _normalize_contract_identities(contract_identities)
    normalized_checks = _normalize_checks(checks)
    failures = _normalize_failure_records(failure_records)
    _validate_check_bindings(
        normalized_checks,
        inputs,
        dependencies,
        provenance,
        metrics,
        contracts,
        failures,
    )
    missing = _missing_rule_ids(normalized_checks)
    decision = _derive_decision(normalized_checks, missing)
    reason = _winning_reason(normalized_checks, decision, missing)
    return VerifierResult(
        schema_id=VERIFIER_RESULT_SCHEMA_ID,
        schema_version=VERIFIER_SCHEMA_VERSION,
        verification_policy_version=VERIFICATION_POLICY_VERSION,
        input_identities=inputs,
        dependency_binding_identities=dependencies,
        provenance_identity=provenance,
        metrics_identity=metrics,
        contract_identities=contracts,
        rule_identities=tuple(check.rule_identity for check in normalized_checks),
        checks=normalized_checks,
        missing_rule_ids=missing,
        failure_identities=tuple(
            check.failure_identity
            for check in normalized_checks
            if check.failure_identity is not None
        ),
        decision=decision,
        decision_reason_code=reason,
    )


def build_verifier_result(
    input_identities: object,
    dependency_binding_identities: object,
    provenance_identity: object,
    metrics_identity: object,
    contract_identities: object,
    checks: object,
    failure_records: object = (),
) -> VerifierResult:
    """Build a result from supplied pure data and fail closed on any error."""

    try:
        return _build_verifier_result(
            input_identities=input_identities,
            dependency_binding_identities=dependency_binding_identities,
            provenance_identity=provenance_identity,
            metrics_identity=metrics_identity,
            contract_identities=contract_identities,
            checks=checks,
            failure_records=failure_records,
        )
    except VerifierValidationError:
        raise
    except Exception as exc:
        raise VerifierValidationError(
            "unrecognized verifier exception",
            FailureCode.MR05_VERIFIER_EXCEPTION,
        ) from exc


construct_verifier_result = build_verifier_result
build_verification_result = build_verifier_result
evaluate_verification = build_verifier_result
verify = build_verifier_result


def derive_final_decision(
    checks: object,
    missing_rule_ids: object = (),
) -> str:
    """Derive only the frozen final decision from validated check records."""

    normalized = _normalize_checks(checks)
    computed_missing = _missing_rule_ids(normalized)
    declared_missing = tuple(
        sorted(
            (_text(item, "missing_rule_id") for item in _sequence(missing_rule_ids, "missing_rule_ids")),
            key=_utf8_key,
        )
    )
    if declared_missing and declared_missing != computed_missing:
        _fail("missing rule ids do not match checks", FailureCode.HASH_MISMATCH)
    return _derive_decision(normalized, computed_missing)


derive_decision = derive_final_decision


def compute_rule_identity(
    rule: VerifierRule | Mapping[str, object] | None = None,
    *,
    rule_id: str | None = None,
    rule_version: str | None = None,
    rule_owner: str | None = None,
    rule_severity: str | None = None,
    expected_contract_identity: str | None = None,
) -> str:
    """Recompute a frozen rule identity without trusting a declared identity."""

    if rule is not None:
        if any(item is not None for item in (rule_id, rule_version, rule_owner, rule_severity, expected_contract_identity)):
            _fail("rule object and rule fields cannot be mixed", FailureCode.INVALID_SCHEMA)
        if isinstance(rule, VerifierRule):
            return rule.rule_identity
        mapping = _mapping(rule, "verifier rule")
        rule_id = mapping.get("rule_id")
        rule_version = mapping.get("rule_version")
        rule_owner = mapping.get("rule_owner")
        rule_severity = mapping.get("rule_severity")
        expected_contract_identity = mapping.get("expected_contract_identity")
    if None in (rule_id, rule_version, rule_owner, rule_severity):
        _fail("complete rule fields are required", FailureCode.INVALID_SCHEMA)
    candidate = VerifierRule(
        rule_id=rule_id,
        rule_version=rule_version,
        rule_owner=rule_owner,
        rule_severity=rule_severity,
        expected_contract_identity=expected_contract_identity,
    )
    try:
        frozen = _RULE_BY_ID[candidate.rule_id]
    except KeyError:
        _fail("unknown verifier rule", FailureCode.UNSUPPORTED_INPUT)
    if candidate != frozen:
        _fail("rule fields do not match frozen catalog", FailureCode.INVALID_SCHEMA)
    return candidate.rule_identity


def compute_verifier_identity(value: VerifierResult | Mapping[str, object]) -> str:
    """Recompute a verifier result identity from its exact identity preimage."""

    if isinstance(value, VerifierResult):
        return sha256_canonical(value.identity_payload)
    mapping = _mapping(value, "verifier identity input")
    if set(mapping) == set(VERIFIER_IDENTITY_PREIMAGE):
        return verifier_identity_from_preimage(mapping)
    return VerifierResult.from_mapping(mapping).verifier_identity


def verifier_identity_from_preimage(value: Mapping[str, object]) -> str:
    """Hash exactly the frozen verifier identity preimage fields."""

    mapping = _mapping(value, "verifier identity preimage")
    _exact_fields(mapping, frozenset(VERIFIER_IDENTITY_PREIMAGE), "verifier identity preimage")
    if mapping["schema_id"] != VERIFIER_RESULT_SCHEMA_ID:
        _fail("unknown verifier result schema", FailureCode.MR05_UNKNOWN_SCHEMA_MAJOR)
    if mapping["schema_version"] != VERIFIER_SCHEMA_VERSION:
        _fail("unsupported verifier result schema version", FailureCode.MR05_UNKNOWN_SCHEMA_MAJOR)
    if mapping["verification_policy_version"] != VERIFICATION_POLICY_VERSION:
        _fail("unsupported verifier policy version", FailureCode.INVALID_SCHEMA)
    # Parsing through the exact result fields validates all nested identities,
    # ordering, decisions, and rule/check records before hashing.
    inputs = _normalize_input_identities(mapping["input_identities"])
    dependencies = _normalize_dependency_identities(mapping["dependency_binding_identities"])
    provenance = _sha(mapping["provenance_identity"], "provenance_identity")
    metrics = _sha(mapping["metrics_identity"], "metrics_identity")
    contracts = _normalize_contract_identities(mapping["contract_identities"])
    checks = _normalize_checks(mapping["checks"])
    missing = tuple(sorted((_text(item, "missing_rule_id") for item in _sequence(mapping["missing_rule_ids"], "missing_rule_ids")), key=_utf8_key))
    rule_ids = tuple(sorted((_sha(item, "rule_identity") for item in _sequence(mapping["rule_identities"], "rule_identities")), key=_ascii_key))
    failure_ids = tuple(sorted((_sha(item, "failure_identity") for item in _sequence(mapping["failure_identities"], "failure_identities")), key=_ascii_key))
    decision = _enum_value(mapping["decision"])
    reason = _enum_value(mapping["decision_reason_code"])
    if decision not in VERIFIER_DECISION_VALUES:
        _fail("unknown verifier decision", FailureCode.INVALID_SCHEMA)
    derived = _derive_decision(checks, missing)
    if decision != derived or rule_ids != tuple(sorted((check.rule_identity for check in checks), key=_ascii_key)):
        _fail("verifier identity preimage is inconsistent", FailureCode.HASH_MISMATCH)
    if missing != _missing_rule_ids(checks):
        _fail("verifier identity missing rules are inconsistent", FailureCode.HASH_MISMATCH)
    expected_failures = tuple(sorted({check.failure_identity for check in checks if check.failure_identity is not None}, key=_ascii_key))
    if failure_ids != expected_failures or reason != _winning_reason(checks, decision, missing):
        _fail("verifier identity findings are inconsistent", FailureCode.HASH_MISMATCH)
    canonical_preimage = _result_identity_payload(
        schema_id=VERIFIER_RESULT_SCHEMA_ID,
        schema_version=VERIFIER_SCHEMA_VERSION,
        verification_policy_version=VERIFICATION_POLICY_VERSION,
        input_identities=inputs,
        dependency_binding_identities=dependencies,
        provenance_identity=provenance,
        metrics_identity=metrics,
        contract_identities=contracts,
        rule_identities=rule_ids,
        checks=checks,
        missing_rule_ids=missing,
        failure_identities=failure_ids,
        decision=decision,
        decision_reason_code=reason,
    )
    return sha256_canonical(canonical_preimage)


def canonical_verifier_bytes(value: VerifierResult | Mapping[str, object]) -> bytes:
    """Return canonical serialized verifier output after exact validation."""

    result = value if isinstance(value, VerifierResult) else VerifierResult.from_mapping(value)
    return result.canonical_bytes()


def _record_value(value: object, field: str) -> object:
    if isinstance(value, Mapping):
        try:
            return value[field]
        except KeyError:
            _fail(f"record field is missing: {field}", FailureCode.PROVENANCE_GAP)
    try:
        return getattr(value, field)
    except AttributeError:
        _fail(f"record field is missing: {field}", FailureCode.PROVENANCE_GAP)
    raise AssertionError("unreachable")


def verify_supplied_records(
    discovery_result: object,
    normalization_result: object,
    dependency_bindings: object,
    bounded_context_package: object,
    provenance_chain: object,
    metrics: object,
    frozen_contract_identity_set: object,
    verification_evidence: object,
    failure_records: object = (),
) -> VerifierResult:
    """Bind already-supplied validated MR-05 records without executing them."""

    package_inputs = _normalize_input_identities(_record_value(bounded_context_package, "input_identities"))
    package_context_identity = _sha(_record_value(bounded_context_package, "context_identity"), "context_identity")
    input_values = dict(package_inputs)
    input_values["context_identity"] = package_context_identity
    expected_upstream = {
        "task_identity": _sha(_record_value(discovery_result, "task_identity"), "task_identity"),
        "source_set_identity": _sha(_record_value(discovery_result, "source_set_identity"), "source_set_identity"),
        "discovery_identity": _sha(_record_value(discovery_result, "discovery_identity"), "discovery_identity"),
        "normalization_identity": _sha(_record_value(normalization_result, "normalization_identity"), "normalization_identity"),
    }
    for field, expected in expected_upstream.items():
        if input_values[field] != expected:
            _fail("bounded context is not bound to upstream input", FailureCode.HASH_MISMATCH)
    dependency_values = _record_value(bounded_context_package, "dependency_binding_identities")
    provenance = _sha(_record_value(provenance_chain, "provenance_identity"), "provenance_identity")
    metrics_identity = _sha(_record_value(metrics, "metrics_identity"), "metrics_identity")
    if provenance != _sha(_record_value(bounded_context_package, "provenance_identity"), "provenance_identity"):
        _fail("provenance identity is not bound to context", FailureCode.HASH_MISMATCH)
    if metrics_identity != _sha(_record_value(bounded_context_package, "metrics_identity"), "metrics_identity"):
        _fail("metrics identity is not bound to context", FailureCode.HASH_MISMATCH)
    return build_verifier_result(
        input_values,
        dependency_values,
        provenance,
        metrics_identity,
        frozen_contract_identity_set,
        verification_evidence,
        failure_records,
    )


verify_records = verify_supplied_records


def not_implemented(*args: object, **kwargs: object) -> None:
    """Retain the legacy operational-boundary marker for direct callers."""

    del args, kwargs
    phase_not_implemented("verifier")


__all__ = (
    "VERIFIER_RESULT_SCHEMA_ID",
    "VERIFIER_RULE_SCHEMA_ID",
    "VERIFIER_CHECK_SCHEMA_ID",
    "VERIFIER_SCHEMA_ID",
    "VERIFIER_SCHEMA_VERSION",
    "VERIFICATION_POLICY_VERSION",
    "VERIFIER_POLICY_VERSION",
    "VERIFIER_DECISION_VALUES",
    "VERIFIER_DECISION_PRECEDENCE",
    "VERIFIER_DECISION_PRECEDENCE_EXPRESSION",
    "CHECK_RESULT_VALUES",
    "CHECK_PASS_REASON",
    "MISSING_REQUIRED_EVIDENCE_BEHAVIOR",
    "PASS_FOR_REVIEW_IS_APPROVAL",
    "VERIFIER_IDENTITY_PREIMAGE",
    "INPUT_IDENTITY_FIELDS",
    "RULE_OWNER_VALUES",
    "RULE_SEVERITY_VALUES",
    "VERIFIER_IMPLEMENTATION_COUNT",
    "LIVE_VERIFICATION_EXECUTION_COUNT",
    "CONTROLLER_IMPLEMENTATION_COUNT",
    "OPERATIONAL_ORCHESTRATION_IMPLEMENTATION_COUNT",
    "MR03_EXECUTION_IMPLEMENTATION_COUNT",
    "MR04_EXECUTION_IMPLEMENTATION_COUNT",
    "FILESYSTEM_SOURCE_READ_COUNT",
    "SUBPROCESS_EXECUTION_COUNT",
    "NETWORK_IMPLEMENTATION_COUNT",
    "PROVIDER_CLIENT_IMPLEMENTATION_COUNT",
    "MODEL_CALL_IMPLEMENTATION_COUNT",
    "MODEL_ROUTING_IMPLEMENTATION_COUNT",
    "AUTH_IMPLEMENTATION_COUNT",
    "HUMAN_APPROVAL_EXECUTION_COUNT",
    "STATE_TRANSITION_EXECUTION_COUNT",
    "AUTO_RETRY_IMPLEMENTATION_COUNT",
    "AUTO_FALLBACK_IMPLEMENTATION_COUNT",
    "FROZEN_CONTRACT_IDENTITIES",
    "RULE_CATALOG",
    "RULE_IDS",
    "VerifierValidationError",
    "VerifierContractValidationError",
    "VerificationValidationError",
    "VerifierError",
    "VerifierRule",
    "VerifierCheckRecord",
    "VerifierCheck",
    "build_verifier_check",
    "make_verifier_check",
    "VerifierResult",
    "VerificationResult",
    "VerifierOutput",
    "build_verifier_result",
    "construct_verifier_result",
    "build_verification_result",
    "evaluate_verification",
    "verify",
    "derive_final_decision",
    "derive_decision",
    "compute_rule_identity",
    "compute_verifier_identity",
    "verifier_identity_from_preimage",
    "canonical_verifier_bytes",
    "verify_supplied_records",
    "verify_records",
    "not_implemented",
)

# Descriptive compatibility alias used by callers that call the record a
# check rather than a check record.
VerifierCheck = VerifierCheckRecord
