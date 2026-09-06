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

from .canonical import (
    CanonicalizationError,
    canonical_identity_bytes,
    canonical_json_bytes,
    parse_json_no_duplicates,
)
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
    FAILURE_CODE_OWNERS,
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


# ---------------------------------------------------------------------------
# Frozen public mr05.verification / 1.0.0 record and validation adapter.
#
# This additive layer intentionally does not change the legacy
# mr05.verifier_result / verifier_rule / verifier_check contract above.
# It validates already-supplied structured findings and cross-checks their
# bindings against the legacy deterministic decision engine. It never
# discovers evidence or generates semantic findings.
# ---------------------------------------------------------------------------

PUBLIC_VERIFICATION_SCHEMA_ID = "mr05.verification"
PUBLIC_VERIFICATION_SCHEMA_VERSION = SCHEMA_VERSION
PUBLIC_VERIFICATION_POLICY_VERSION = SCHEMA_VERSION

VERIFICATION_RECORD_IDENTITY_PREIMAGE = (
    "schema_version",
    "proposal_identity",
    "verification_result",
    "reason_codes",
    "reason_details",
    "verified_source_refs",
    "unsupported_claims",
    "missing_refs",
    "protected_content_findings",
    "identity_findings",
    "verification_policy_version",
)

VERIFICATION_RECORD_PARSE_IMPLEMENTATION_COUNT = 1
VERIFICATION_IDENTITY_VALIDATION_IMPLEMENTATION_COUNT = 1
VERIFICATION_ADAPTER_VALIDATION_IMPLEMENTATION_COUNT = 1
MR04_VERIFIER_EXECUTION_IMPLEMENTATION_COUNT = 0
SOURCE_DISCOVERY_IMPLEMENTATION_COUNT = 0
FILESYSTEM_WRITE_IMPLEMENTATION_COUNT = 0
HUMAN_DECISION_EXECUTION_COUNT = 0
GIT_OPERATION_COUNT = 0

_PUBLIC_VERIFICATION_REQUIRED_FIELDS = frozenset(
    set(VERIFICATION_RECORD_IDENTITY_PREIMAGE) | {"verification_identity"}
)
_PUBLIC_VERIFICATION_OPTIONAL_FIELDS = frozenset({"observational_metadata"})
_PUBLIC_SEVERITY_RANK = MappingProxyType(
    {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
)
_PUBLIC_PROTECTED_CLASSIFICATIONS = frozenset({"PROTECTED", "SECRET_LIKE", "UNKNOWN"})
_PUBLIC_PROTECTED_ACTIONS = frozenset({"DENY", "REDACT", "ESCALATE"})


def _verification_exact_fields(
    value: Mapping[str, object],
    required: frozenset[str],
    optional: frozenset[str],
    context: str,
) -> None:
    actual = set(value)
    missing = required - actual
    unknown = actual - required - optional
    if missing or unknown:
        _fail(f"{context} fields are not exact", FailureCode.INVALID_SCHEMA)


def _verification_string(
    value: object,
    context: str,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> str:
    if type(value) is not str or len(value) < minimum:
        _fail(f"{context} has invalid string type or length", FailureCode.INVALID_SCHEMA)
    if maximum is not None and len(value) > maximum:
        _fail(f"{context} exceeds the frozen maximum length", FailureCode.INVALID_SCHEMA)
    if "\x00" in value or any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        _fail(f"{context} contains invalid Unicode", FailureCode.INVALID_SCHEMA)
    return value


def _verification_integer(value: object, context: str) -> int:
    if type(value) is not int or not 0 <= value <= 9223372036854775807:
        _fail(f"{context} must be an integer in the frozen range", FailureCode.INVALID_SCHEMA)
    return value


def _verification_metadata(value: object) -> Mapping[str, object]:
    row = _mapping(value, "observational_metadata")
    try:
        canonical_json_bytes(row, identity_critical=False)
    except (CanonicalizationError, TypeError, ValueError) as exc:
        _fail(f"observational_metadata is invalid: {exc}", FailureCode.INVALID_SCHEMA)
    frozen = _freeze(row)
    if not isinstance(frozen, Mapping):
        raise AssertionError("metadata freezing changed type")
    return frozen


@dataclass(frozen=True, slots=True)
class VerificationReasonDetail:
    code: str
    owner: str
    severity: str
    explanation: str
    related_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        code = _verification_string(self.code, "reason_detail.code", minimum=1, maximum=256)
        try:
            failure_code = FailureCode(code)
        except (TypeError, ValueError):
            _fail("reason_detail.code is outside the frozen failure namespace", FailureCode.UNSUPPORTED_INPUT)
        owner = _verification_string(self.owner, "reason_detail.owner", minimum=1, maximum=128)
        try:
            owner_enum = FailureOwner(owner)
        except (TypeError, ValueError):
            _fail("reason_detail.owner is outside the frozen failure-owner namespace", FailureCode.INVALID_SCHEMA)
        if FAILURE_CODE_OWNERS[failure_code] is not owner_enum:
            _fail("reason_detail.owner does not match failure code", FailureCode.INVALID_SCHEMA)
        severity = _verification_string(self.severity, "reason_detail.severity", minimum=1, maximum=16)
        try:
            severity = FailureSeverity(severity).value
        except (TypeError, ValueError):
            _fail("reason_detail.severity is outside the frozen enum", FailureCode.INVALID_SCHEMA)
        explanation = _verification_string(
            self.explanation, "reason_detail.explanation", minimum=1, maximum=2048
        )
        related_refs = tuple(
            _verification_string(item, f"reason_detail.related_refs[{index}]", minimum=1, maximum=2048)
            for index, item in enumerate(_sequence(self.related_refs, "reason_detail.related_refs"))
        )
        object.__setattr__(self, "code", failure_code.value)
        object.__setattr__(self, "owner", owner_enum.value)
        object.__setattr__(self, "severity", severity)
        object.__setattr__(self, "explanation", explanation)
        object.__setattr__(self, "related_refs", related_refs)

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "owner": self.owner,
            "severity": self.severity,
            "explanation": self.explanation,
            "related_refs": list(self.related_refs),
        }

    @classmethod
    def from_mapping(cls, value: object) -> "VerificationReasonDetail":
        row = _mapping(value, "reason_detail")
        required = frozenset({"code", "owner", "severity", "explanation", "related_refs"})
        _exact_fields(row, required, "reason_detail")
        return cls(
            code=row["code"],
            owner=row["owner"],
            severity=row["severity"],
            explanation=row["explanation"],
            related_refs=tuple(_sequence(row["related_refs"], "reason_detail.related_refs")),
        )


@dataclass(frozen=True, slots=True)
class VerificationSourceRef:
    source_id: str
    canonical_locator: str
    content_sha256: str
    content_size_bytes: int
    source_set_identity: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_id", _sha(self.source_id, "verified_source_ref.source_id"))
        object.__setattr__(
            self,
            "canonical_locator",
            _verification_string(
                self.canonical_locator,
                "verified_source_ref.canonical_locator",
                minimum=1,
                maximum=2048,
            ),
        )
        object.__setattr__(
            self,
            "content_sha256",
            _sha(self.content_sha256, "verified_source_ref.content_sha256"),
        )
        object.__setattr__(
            self,
            "content_size_bytes",
            _verification_integer(
                self.content_size_bytes, "verified_source_ref.content_size_bytes"
            ),
        )
        object.__setattr__(
            self,
            "source_set_identity",
            _sha(self.source_set_identity, "verified_source_ref.source_set_identity"),
        )

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
    def from_mapping(cls, value: object) -> "VerificationSourceRef":
        row = _mapping(value, "verified_source_ref")
        required = frozenset(
            {
                "source_id",
                "canonical_locator",
                "content_sha256",
                "content_size_bytes",
                "source_set_identity",
            }
        )
        _exact_fields(row, required, "verified_source_ref")
        return cls(**row)


@dataclass(frozen=True, slots=True)
class VerificationProtectedContentFinding:
    classification: str
    action: str
    source_id: str | None

    def __post_init__(self) -> None:
        classification = _verification_string(
            self.classification, "protected_content_finding.classification", minimum=1, maximum=32
        )
        if classification not in _PUBLIC_PROTECTED_CLASSIFICATIONS:
            _fail("protected_content_finding.classification is outside the frozen enum")
        action = _verification_string(
            self.action, "protected_content_finding.action", minimum=1, maximum=16
        )
        if action not in _PUBLIC_PROTECTED_ACTIONS:
            _fail("protected_content_finding.action is outside the frozen enum")
        source_id = self.source_id
        if source_id is not None:
            source_id = _verification_string(
                source_id, "protected_content_finding.source_id", minimum=0
            )
        object.__setattr__(self, "classification", classification)
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "source_id", source_id)

    def to_dict(self) -> dict[str, object]:
        return {
            "classification": self.classification,
            "action": self.action,
            "source_id": self.source_id,
        }

    @classmethod
    def from_mapping(cls, value: object) -> "VerificationProtectedContentFinding":
        row = _mapping(value, "protected_content_finding")
        required = frozenset({"classification", "action", "source_id"})
        _exact_fields(row, required, "protected_content_finding")
        return cls(**row)


@dataclass(frozen=True, slots=True)
class VerificationIdentityFinding:
    identity_name: str
    expected: str
    observed: str | None
    action: str

    def __post_init__(self) -> None:
        identity_name = _verification_string(
            self.identity_name, "identity_finding.identity_name", minimum=1, maximum=128
        )
        expected = _sha(self.expected, "identity_finding.expected")
        observed = self.observed
        if observed is not None:
            observed = _verification_string(observed, "identity_finding.observed", minimum=0)
        if self.action != "BLOCK":
            _fail("identity_finding.action must be BLOCK", FailureCode.INVALID_SCHEMA)
        object.__setattr__(self, "identity_name", identity_name)
        object.__setattr__(self, "expected", expected)
        object.__setattr__(self, "observed", observed)
        object.__setattr__(self, "action", "BLOCK")

    def to_dict(self) -> dict[str, object]:
        return {
            "identity_name": self.identity_name,
            "expected": self.expected,
            "observed": self.observed,
            "action": self.action,
        }

    @classmethod
    def from_mapping(cls, value: object) -> "VerificationIdentityFinding":
        row = _mapping(value, "identity_finding")
        required = frozenset({"identity_name", "expected", "observed", "action"})
        _exact_fields(row, required, "identity_finding")
        return cls(**row)


def _verification_reason_details(value: object) -> tuple[VerificationReasonDetail, ...]:
    return tuple(
        item if isinstance(item, VerificationReasonDetail) else VerificationReasonDetail.from_mapping(item)
        for item in _sequence(value, "reason_details")
    )


def _verification_reason_codes(
    value: object,
    details: tuple[VerificationReasonDetail, ...],
) -> tuple[str, ...]:
    codes = tuple(
        _verification_string(item, f"reason_codes[{index}]", minimum=1, maximum=256)
        for index, item in enumerate(_sequence(value, "reason_codes"))
    )
    if len(set(codes)) != len(codes):
        _fail("reason_codes contains duplicates", FailureCode.DUPLICATE_CONFLICT)
    by_code: dict[str, str] = {}
    for detail in details:
        previous = by_code.setdefault(detail.code, detail.severity)
        if previous != detail.severity:
            _fail("one reason code has conflicting severities", FailureCode.DUPLICATE_CONFLICT)
    if set(codes) != set(by_code):
        _fail("reason_codes and reason_details codes are inconsistent", FailureCode.INVALID_SCHEMA)
    expected = tuple(
        sorted(
            by_code,
            key=lambda code: (-_PUBLIC_SEVERITY_RANK[by_code[code]], code.encode("utf-8")),
        )
    )
    if codes != expected:
        _fail(
            "reason_codes are not in frozen severity-then-lexical order",
            FailureCode.NONDETERMINISTIC_OUTPUT,
        )
    return codes


def _verification_source_refs(value: object) -> tuple[VerificationSourceRef, ...]:
    refs = tuple(
        item if isinstance(item, VerificationSourceRef) else VerificationSourceRef.from_mapping(item)
        for item in _sequence(value, "verified_source_refs")
    )
    keys = tuple(ref.order_key for ref in refs)
    if len(set(keys)) != len(keys):
        _fail("verified_source_refs contains duplicates", FailureCode.DUPLICATE_CONFLICT)
    if keys != tuple(sorted(keys)):
        _fail(
            "verified_source_refs are not in frozen source_id-then-locator order",
            FailureCode.NONDETERMINISTIC_OUTPUT,
        )
    return refs


def _verification_string_array(
    value: object,
    field: str,
    *,
    maximum: int,
) -> tuple[str, ...]:
    return tuple(
        _verification_string(item, f"{field}[{index}]", minimum=1, maximum=maximum)
        for index, item in enumerate(_sequence(value, field))
    )


def _verification_protected_findings(
    value: object,
) -> tuple[VerificationProtectedContentFinding, ...]:
    return tuple(
        item
        if isinstance(item, VerificationProtectedContentFinding)
        else VerificationProtectedContentFinding.from_mapping(item)
        for item in _sequence(value, "protected_content_findings")
    )


def _verification_identity_findings(
    value: object,
) -> tuple[VerificationIdentityFinding, ...]:
    return tuple(
        item
        if isinstance(item, VerificationIdentityFinding)
        else VerificationIdentityFinding.from_mapping(item)
        for item in _sequence(value, "identity_findings")
    )


def _normalize_public_verification_semantics(value: Mapping[str, object]) -> dict[str, object]:
    schema_version = value["schema_version"]
    if schema_version != PUBLIC_VERIFICATION_SCHEMA_VERSION:
        code = FailureCode.INVALID_SCHEMA
        if isinstance(schema_version, str) and schema_version.split(".", 1)[0] != "1":
            code = FailureCode.MR05_UNKNOWN_SCHEMA_MAJOR
        _fail("unsupported public verification schema version", code)
    proposal_identity = _sha(value["proposal_identity"], "verification.proposal_identity")
    verification_result = value["verification_result"]
    if verification_result not in VERIFIER_DECISION_VALUES:
        _fail("verification_result is outside the frozen enum", FailureCode.INVALID_SCHEMA)
    details = _verification_reason_details(value["reason_details"])
    reason_codes = _verification_reason_codes(value["reason_codes"], details)
    verified_refs = _verification_source_refs(value["verified_source_refs"])
    unsupported_claims = _verification_string_array(
        value["unsupported_claims"], "unsupported_claims", maximum=256
    )
    missing_refs = _verification_string_array(value["missing_refs"], "missing_refs", maximum=2048)
    protected_findings = _verification_protected_findings(value["protected_content_findings"])
    identity_findings = _verification_identity_findings(value["identity_findings"])
    verification_policy_version = value["verification_policy_version"]
    if verification_policy_version != PUBLIC_VERIFICATION_POLICY_VERSION:
        _fail("public verification policy version is not frozen", FailureCode.INVALID_SCHEMA)
    return {
        "schema_version": PUBLIC_VERIFICATION_SCHEMA_VERSION,
        "proposal_identity": proposal_identity,
        "verification_result": verification_result,
        "reason_codes": reason_codes,
        "reason_details": details,
        "verified_source_refs": verified_refs,
        "unsupported_claims": unsupported_claims,
        "missing_refs": missing_refs,
        "protected_content_findings": protected_findings,
        "identity_findings": identity_findings,
        "verification_policy_version": PUBLIC_VERIFICATION_POLICY_VERSION,
    }


def _public_verification_payload(normalized: Mapping[str, object]) -> dict[str, object]:
    return {
        "schema_version": normalized["schema_version"],
        "proposal_identity": normalized["proposal_identity"],
        "verification_result": normalized["verification_result"],
        "reason_codes": list(normalized["reason_codes"]),
        "reason_details": [item.to_dict() for item in normalized["reason_details"]],
        "verified_source_refs": [item.to_dict() for item in normalized["verified_source_refs"]],
        "unsupported_claims": list(normalized["unsupported_claims"]),
        "missing_refs": list(normalized["missing_refs"]),
        "protected_content_findings": [
            item.to_dict() for item in normalized["protected_content_findings"]
        ],
        "identity_findings": [item.to_dict() for item in normalized["identity_findings"]],
        "verification_policy_version": normalized["verification_policy_version"],
    }


@dataclass(frozen=True, slots=True)
class VerificationRecord:
    schema_version: str
    proposal_identity: str
    verification_result: str
    reason_codes: tuple[str, ...]
    reason_details: tuple[VerificationReasonDetail, ...]
    verified_source_refs: tuple[VerificationSourceRef, ...]
    unsupported_claims: tuple[str, ...]
    missing_refs: tuple[str, ...]
    protected_content_findings: tuple[VerificationProtectedContentFinding, ...]
    identity_findings: tuple[VerificationIdentityFinding, ...]
    verification_policy_version: str
    verification_identity: str
    observational_metadata: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        normalized = _normalize_public_verification_semantics(
            {
                "schema_version": self.schema_version,
                "proposal_identity": self.proposal_identity,
                "verification_result": self.verification_result,
                "reason_codes": self.reason_codes,
                "reason_details": self.reason_details,
                "verified_source_refs": self.verified_source_refs,
                "unsupported_claims": self.unsupported_claims,
                "missing_refs": self.missing_refs,
                "protected_content_findings": self.protected_content_findings,
                "identity_findings": self.identity_findings,
                "verification_policy_version": self.verification_policy_version,
            }
        )
        declared_identity = _sha(self.verification_identity, "verification_identity")
        computed_identity = sha256_canonical(_public_verification_payload(normalized))
        if declared_identity != computed_identity:
            _fail(
                "verification_identity does not match authoritative semantic preimage",
                FailureCode.HASH_MISMATCH,
            )
        metadata = (
            None
            if self.observational_metadata is None
            else _verification_metadata(self.observational_metadata)
        )
        for field, child in normalized.items():
            object.__setattr__(self, field, child)
        object.__setattr__(self, "verification_identity", declared_identity)
        object.__setattr__(self, "observational_metadata", metadata)

    @property
    def identity_payload(self) -> dict[str, object]:
        return _public_verification_payload(
            {
                "schema_version": self.schema_version,
                "proposal_identity": self.proposal_identity,
                "verification_result": self.verification_result,
                "reason_codes": self.reason_codes,
                "reason_details": self.reason_details,
                "verified_source_refs": self.verified_source_refs,
                "unsupported_claims": self.unsupported_claims,
                "missing_refs": self.missing_refs,
                "protected_content_findings": self.protected_content_findings,
                "identity_findings": self.identity_findings,
                "verification_policy_version": self.verification_policy_version,
            }
        )

    def to_dict(self) -> dict[str, object]:
        result = self.identity_payload
        result["verification_identity"] = self.verification_identity
        if self.observational_metadata is not None:
            result["observational_metadata"] = _plain(self.observational_metadata)
        return result

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict(), identity_critical=False)

    @classmethod
    def from_mapping(cls, value: object) -> "VerificationRecord":
        row = _mapping(value, "public verification record")
        _verification_exact_fields(
            row,
            _PUBLIC_VERIFICATION_REQUIRED_FIELDS,
            _PUBLIC_VERIFICATION_OPTIONAL_FIELDS,
            "public verification record",
        )
        if "observational_metadata" in row and row["observational_metadata"] is None:
            _fail("observational_metadata must not be null when present")
        return cls(
            schema_version=row["schema_version"],
            proposal_identity=row["proposal_identity"],
            verification_result=row["verification_result"],
            reason_codes=tuple(_sequence(row["reason_codes"], "reason_codes")),
            reason_details=tuple(_sequence(row["reason_details"], "reason_details")),
            verified_source_refs=tuple(
                _sequence(row["verified_source_refs"], "verified_source_refs")
            ),
            unsupported_claims=tuple(
                _sequence(row["unsupported_claims"], "unsupported_claims")
            ),
            missing_refs=tuple(_sequence(row["missing_refs"], "missing_refs")),
            protected_content_findings=tuple(
                _sequence(row["protected_content_findings"], "protected_content_findings")
            ),
            identity_findings=tuple(
                _sequence(row["identity_findings"], "identity_findings")
            ),
            verification_policy_version=row["verification_policy_version"],
            verification_identity=row["verification_identity"],
            observational_metadata=row.get("observational_metadata"),
        )


def parse_verification_record(value: VerificationRecord | Mapping[str, object]) -> VerificationRecord:
    if isinstance(value, VerificationRecord):
        return value
    return VerificationRecord.from_mapping(value)


def parse_verification_json(data: str | bytes) -> VerificationRecord:
    try:
        parsed = parse_json_no_duplicates(data, identity_critical=False)
    except CanonicalizationError as exc:
        _fail(f"malformed verification JSON: {exc}", FailureCode.INVALID_SCHEMA)
    return VerificationRecord.from_mapping(parsed)


def verification_identity_from_preimage(value: Mapping[str, object]) -> str:
    row = _mapping(value, "verification identity preimage")
    _exact_fields(
        row,
        frozenset(VERIFICATION_RECORD_IDENTITY_PREIMAGE),
        "verification identity preimage",
    )
    normalized = _normalize_public_verification_semantics(row)
    return sha256_canonical(_public_verification_payload(normalized))


def compute_verification_identity(
    value: VerificationRecord | Mapping[str, object],
) -> str:
    if isinstance(value, VerificationRecord):
        return sha256_canonical(value.identity_payload)
    row = _mapping(value, "verification identity input")
    if set(row) == set(VERIFICATION_RECORD_IDENTITY_PREIMAGE):
        return verification_identity_from_preimage(row)
    return VerificationRecord.from_mapping(row).verification_identity


def canonical_verification_bytes(
    value: VerificationRecord | Mapping[str, object],
) -> bytes:
    return parse_verification_record(value).canonical_bytes()


def _verification_source_ref_from_supplied(value: object, context: str) -> VerificationSourceRef:
    if isinstance(value, VerificationSourceRef):
        return value
    if isinstance(value, Mapping):
        return VerificationSourceRef.from_mapping(value)
    try:
        mapping = value.to_dict()
    except AttributeError:
        _fail(f"{context} source reference is not a record", FailureCode.INVALID_SCHEMA)
    return VerificationSourceRef.from_mapping(mapping)


def _verification_supplied_refs(value: object, context: str) -> tuple[VerificationSourceRef, ...]:
    return tuple(
        _verification_source_ref_from_supplied(item, context)
        for item in _sequence(value, context)
    )


def _verification_ref_bytes(ref: VerificationSourceRef) -> bytes:
    return canonical_json_bytes(ref.to_dict())


def _failure_reason_detail(failure: Failure) -> VerificationReasonDetail:
    related_refs = () if failure.related_identity is None else (failure.related_identity,)
    return VerificationReasonDetail(
        code=failure.failure_code.value,
        owner=failure.failure_owner.value,
        severity=failure.severity.value,
        explanation=failure.message,
        related_refs=related_refs,
    )


def _reason_codes_from_details(
    details: tuple[VerificationReasonDetail, ...],
) -> tuple[str, ...]:
    by_code: dict[str, str] = {}
    for detail in details:
        previous = by_code.setdefault(detail.code, detail.severity)
        if previous != detail.severity:
            _fail(
                "failure evidence has conflicting severities for one code",
                FailureCode.DUPLICATE_CONFLICT,
            )
    return tuple(
        sorted(
            by_code,
            key=lambda code: (-_PUBLIC_SEVERITY_RANK[by_code[code]], code.encode("utf-8")),
        )
    )


def validate_verification_adapter(
    verification: VerificationRecord | Mapping[str, object],
    *,
    proposal: object,
    context: object,
    legacy_result: VerifierResult | Mapping[str, object],
    failure_records: object = (),
) -> VerificationRecord:
    """Cross-check supplied public findings without generating semantic evidence."""

    record = parse_verification_record(verification)
    failures = _normalize_failure_records(failure_records)
    if isinstance(legacy_result, VerifierResult):
        legacy = VerifierResult.from_mapping(
            legacy_result.to_dict(), failure_records=tuple(failures.values())
        )
    else:
        legacy = VerifierResult.from_mapping(
            _mapping(legacy_result, "legacy verifier result"),
            failure_records=tuple(failures.values()),
        )
    if legacy.verification_policy_version != VERIFICATION_POLICY_VERSION:
        _fail("legacy verifier policy compatibility precondition failed")
    if record.verification_result != legacy.decision:
        _fail(
            "public verification result does not match legacy decision",
            FailureCode.HASH_MISMATCH,
        )

    proposal_identity = _sha(_record_value(proposal, "proposal_identity"), "proposal_identity")
    if record.proposal_identity != proposal_identity:
        _fail("public verification is bound to a different proposal", FailureCode.HASH_MISMATCH)

    context_identity = _sha(_record_value(context, "context_identity"), "context_identity")
    task_identity = _sha(_record_value(context, "task_identity"), "context.task_identity")
    run_identity = _sha(_record_value(context, "run_identity"), "context.run_identity")
    source_set_identity = _sha(
        _record_value(context, "source_set_identity"), "context.source_set_identity"
    )
    mr03_identity = _sha(
        _record_value(context, "mr03_package_identity"), "context.mr03_package_identity"
    )
    mr04_identity = _sha(
        _record_value(context, "mr04_result_identity"), "context.mr04_result_identity"
    )
    expected_bindings = (
        ("bound_context_identity", context_identity),
        ("task_identity", task_identity),
        ("run_identity", run_identity),
        ("bound_mr03_package_identity", mr03_identity),
        ("bound_mr04_result_identity", mr04_identity),
    )
    for field, expected in expected_bindings:
        observed = _sha(_record_value(proposal, field), f"proposal.{field}")
        if observed != expected:
            _fail(f"proposal {field} does not match context", FailureCode.HASH_MISMATCH)

    for field, expected in (
        ("context_identity", context_identity),
        ("task_identity", task_identity),
        ("source_set_identity", source_set_identity),
    ):
        if legacy.input_identities[field] != expected:
            _fail(f"legacy verifier {field} does not match context", FailureCode.HASH_MISMATCH)

    proposal_refs = _verification_supplied_refs(
        _record_value(proposal, "source_refs"), "proposal.source_refs"
    )
    context_refs = _verification_supplied_refs(
        _record_value(context, "source_refs"), "context.source_refs"
    )
    proposal_ref_set = {_verification_ref_bytes(ref) for ref in proposal_refs}
    context_ref_set = {_verification_ref_bytes(ref) for ref in context_refs}
    if not proposal_ref_set.issubset(context_ref_set):
        _fail(
            "proposal source reference is outside bounded context",
            FailureCode.PROPOSAL_SOURCE_REF_INVALID,
        )
    verified_ref_set = {_verification_ref_bytes(ref) for ref in record.verified_source_refs}
    if not verified_ref_set.issubset(proposal_ref_set) or not verified_ref_set.issubset(
        context_ref_set
    ):
        _fail(
            "verified source reference is not bound to proposal/context",
            FailureCode.PROPOSAL_SOURCE_REF_INVALID,
        )
    if record.verification_result == "PASS_FOR_REVIEW" and verified_ref_set != proposal_ref_set:
        _fail(
            "PASS_FOR_REVIEW requires all proposal source refs to be verified",
            FailureCode.PROPOSAL_SOURCE_REF_INVALID,
        )

    claims = _sequence(_record_value(proposal, "claims"), "proposal.claims")
    claim_ids: set[str] = set()
    for index, claim in enumerate(claims):
        claim_id = _record_value(claim, "claim_id")
        claim_id = _verification_string(
            claim_id, f"proposal.claims[{index}].claim_id", minimum=1, maximum=256
        )
        if claim_id in claim_ids:
            _fail("proposal claim ids are duplicated", FailureCode.DUPLICATE_CONFLICT)
        claim_ids.add(claim_id)
    if any(claim_id not in claim_ids for claim_id in record.unsupported_claims):
        _fail("unsupported_claims contains a fabricated claim id", FailureCode.INVALID_SCHEMA)

    if legacy.missing_rule_ids:
        _fail(
            "legacy verifier missing-rule denial lacks supplied structured failure evidence",
            FailureCode.MISSING_REQUIRED_ARTIFACT,
        )
    required_failure_ids = {
        check.failure_identity
        for check in legacy.checks
        if check.check_result != "PASS" and check.failure_identity is not None
    }
    if any(identity not in failures for identity in required_failure_ids):
        _fail("legacy non-PASS check lacks supplied failure record", FailureCode.HASH_MISMATCH)
    expected_details = tuple(
        _failure_reason_detail(failures[identity]) for identity in sorted(required_failure_ids)
    )
    actual_detail_bytes = sorted(
        canonical_json_bytes(detail.to_dict()) for detail in record.reason_details
    )
    expected_detail_bytes = sorted(
        canonical_json_bytes(detail.to_dict()) for detail in expected_details
    )
    if actual_detail_bytes != expected_detail_bytes:
        _fail(
            "public reason_details are not exact supplied failure evidence",
            FailureCode.HASH_MISMATCH,
        )
    if record.reason_codes != _reason_codes_from_details(expected_details):
        _fail(
            "public reason_codes do not match supplied failure evidence",
            FailureCode.HASH_MISMATCH,
        )

    if record.verification_result == "PASS_FOR_REVIEW":
        if (
            record.reason_codes
            or record.reason_details
            or record.unsupported_claims
            or record.missing_refs
            or record.protected_content_findings
            or record.identity_findings
        ):
            _fail("PASS_FOR_REVIEW cannot carry unresolved findings", FailureCode.INVALID_SCHEMA)
    return record


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
    "PUBLIC_VERIFICATION_SCHEMA_ID",
    "PUBLIC_VERIFICATION_SCHEMA_VERSION",
    "PUBLIC_VERIFICATION_POLICY_VERSION",
    "VERIFICATION_RECORD_IDENTITY_PREIMAGE",
    "VERIFICATION_RECORD_PARSE_IMPLEMENTATION_COUNT",
    "VERIFICATION_IDENTITY_VALIDATION_IMPLEMENTATION_COUNT",
    "VERIFICATION_ADAPTER_VALIDATION_IMPLEMENTATION_COUNT",
    "MR04_VERIFIER_EXECUTION_IMPLEMENTATION_COUNT",
    "SOURCE_DISCOVERY_IMPLEMENTATION_COUNT",
    "FILESYSTEM_WRITE_IMPLEMENTATION_COUNT",
    "HUMAN_DECISION_EXECUTION_COUNT",
    "GIT_OPERATION_COUNT",
    "VerificationReasonDetail",
    "VerificationSourceRef",
    "VerificationProtectedContentFinding",
    "VerificationIdentityFinding",
    "VerificationRecord",
    "parse_verification_record",
    "parse_verification_json",
    "verification_identity_from_preimage",
    "compute_verification_identity",
    "canonical_verification_bytes",
    "validate_verification_adapter",
    "not_implemented",
)

# Descriptive compatibility alias used by callers that call the record a
# check rather than a check record.
VerifierCheck = VerifierCheckRecord
