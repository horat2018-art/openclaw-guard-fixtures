"""Deterministic local admission of the frozen MR-05 cloud-context envelope.

This module projects an already validated bounded context into the exact
mr05.cloud_context / 1.0.0 semantic envelope and deterministically builds the
mr05.cloud_request / 1.0.0 request envelope.  It performs no source
acquisition, dependency execution, provider/model call, authentication,
evidence persistence, state transition, retry, fallback, or Git mutation.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import NoReturn

from .canonical import CanonicalizationError, canonical_json_bytes
from .context_builder import BoundedContextPackage, ContextBuildValidationError
from .contracts import (
    MR03_EXPECTED_COMMIT,
    MR04_EXPECTED_COMMIT,
    SCHEMA_VERSION,
    SCHEMA_VERSIONS,
    UnknownSchemaMajorVersionError,
    UnsupportedSchemaVersionError,
    validate_schema_version,
)
from .disclosure import DisclosureRecord, DisclosureValidationError
from .failures import FailureCode, phase_not_implemented
from .identity import require_sha256, sha256_canonical


CLOUD_CONTEXT_SCHEMA_ID = "mr05.cloud_context"
CLOUD_CONTEXT_SCHEMA_VERSION = SCHEMA_VERSION
CLOUD_CONTEXT_BYTE_AUTHORITY = "CANONICAL_CLOUD_CONTEXT.complete_record_bytes"
CLOUD_REQUEST_SCHEMA_ID = "mr05.cloud_request"
CLOUD_REQUEST_SCHEMA_VERSION = SCHEMA_VERSION
CLOUD_REQUEST_POLICY_VERSION = SCHEMA_VERSION
CLOUD_REQUEST_REQUIRED_RESPONSE_SCHEMA = "mr05-cloud-proposal:1.0.0"
CLOUD_REQUEST_REASONING_METADATA = MappingProxyType(
    {"OPENCLAW_REASONING": "ON", "PROJECT_REASONING_PROFILE": "MAX"}
)
NO_REPACK_POLICY = "EXACT_BOUNDED_CONTEXT_PROJECTION_ONLY"
PARTIAL_CONTEXT_TRUNCATION = "NOT_ALLOWED"

CLOUD_CONTEXT_ADMISSION_IMPLEMENTATION_COUNT = 1
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
SOURCE_ACQUISITION_IMPLEMENTATION_COUNT = 0
DEPENDENCY_EXECUTION_IMPLEMENTATION_COUNT = 0
EVIDENCE_PERSISTENCE_COUNT = 0
CLOUD_REQUEST_BUILD_COUNT = 1
LIVE_CLOUD_EXECUTION_COUNT = 0
CONTEXT_REPACK_IMPLEMENTATION_COUNT = 0
PARTIAL_CONTEXT_TRUNCATION_IMPLEMENTATION_COUNT = 0

_REQUIRED_FIELDS = frozenset(
    {
        "schema_version",
        "run_identity",
        "task_identity",
        "source_set_identity",
        "mr03_package_identity",
        "mr04_result_identity",
        "context_items",
        "source_refs",
        "byte_budget",
        "estimated_token_metadata",
        "provenance_summary",
        "prohibited_assumptions",
        "proposal_schema_version",
        "disclosure_result",
        "context_identity",
    }
)
_OPTIONAL_FIELDS = frozenset({"observational_metadata"})

CLOUD_CONTEXT_IDENTITY_PREIMAGE = (
    "schema_version",
    "run_identity",
    "task_identity",
    "source_set_identity",
    "mr03_package_identity",
    "mr04_result_identity",
    "context_items",
    "source_refs",
    "byte_budget",
    "estimated_token_metadata",
    "provenance_summary",
    "prohibited_assumptions",
    "proposal_schema_version",
    "disclosure_result",
)

_CLOUD_REQUEST_REQUIRED_FIELDS = frozenset(
    {
        "schema_version",
        "run_identity",
        "context_identity",
        "request_identity",
        "model_identifier",
        "reasoning_metadata",
        "attempt_number",
        "max_attempts",
        "required_response_schema",
        "request_policy_version",
        "human_authorization_reference",
    }
)
_CLOUD_REQUEST_OPTIONAL_FIELDS = frozenset({"observational_metadata"})
_CLOUD_REQUEST_REASONING_FIELDS = frozenset(
    {"OPENCLAW_REASONING", "PROJECT_REASONING_PROFILE"}
)

CLOUD_REQUEST_IDENTITY_PREIMAGE = (
    "schema_version",
    "run_identity",
    "context_identity",
    "model_identifier",
    "reasoning_metadata",
    "attempt_number",
    "max_attempts",
    "required_response_schema",
    "request_policy_version",
)

_SOURCE_REF_FIELDS = frozenset(
    {
        "source_id",
        "canonical_locator",
        "content_sha256",
        "content_size_bytes",
        "source_set_identity",
    }
)
_CONTEXT_ITEM_FIELDS = frozenset(
    {"item_id", "item_type", "content", "source_refs", "required"}
)
_BYTE_BUDGET_FIELDS = frozenset(
    {"budget_identity", "max_cloud_context_bytes", "overflow_policy", "silent_truncation"}
)
_TOKEN_METADATA_FIELDS = frozenset(
    {
        "estimator_name",
        "estimator_version",
        "input_bytes",
        "estimated_tokens",
        "confidence",
        "authority",
    }
)
_PROVENANCE_FIELDS = frozenset(
    {"coverage_percent", "chain_identity", "source_count", "dependency_commits"}
)
_DEPENDENCY_COMMIT_FIELDS = frozenset({"MR03", "MR04"})


class CloudContextAdmissionValidationError(ValueError):
    """A cloud-context record violates the frozen deterministic contract."""

    def __init__(
        self,
        message: str,
        code: FailureCode | str = FailureCode.INVALID_SCHEMA,
    ) -> None:
        super().__init__(message)
        self.code = code.value if isinstance(code, FailureCode) else code
        self.failure_code = self.code
        self.retry_allowed = False


CloudContextValidationError = CloudContextAdmissionValidationError


def _fail(
    message: str,
    code: FailureCode | str = FailureCode.INVALID_SCHEMA,
) -> NoReturn:
    raise CloudContextAdmissionValidationError(message, code)


def _failure_code(exc: BaseException) -> str:
    value = getattr(exc, "code", getattr(exc, "failure_code", FailureCode.INVALID_SCHEMA))
    if isinstance(value, FailureCode):
        return value.value
    if type(value) is str and value:
        return value
    return FailureCode.INVALID_SCHEMA.value


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        _fail(f"{field} must be a string-keyed mapping")
    return value


def _exact_fields(
    value: Mapping[str, object],
    required: frozenset[str],
    field: str,
    optional: frozenset[str] = frozenset(),
) -> None:
    actual = set(value)
    if required - actual or actual - required - optional:
        _fail(f"{field} fields are not exact")


def _sequence(value: object, field: str) -> tuple[object, ...]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        _fail(f"{field} must be an array")
    return tuple(value)


def _integer(value: object, field: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum or value > 9223372036854775807:
        _fail(f"{field} must be an integer in the frozen range")
    return value


def _text(value: object, field: str, *, minimum: int = 1, maximum: int) -> str:
    if type(value) is not str or not minimum <= len(value) <= maximum:
        _fail(f"{field} must contain {minimum}..{maximum} characters")
    if "\x00" in value:
        _fail(f"{field} contains NUL")
    for character in value:
        if 0xD800 <= ord(character) <= 0xDFFF:
            _fail(f"{field} contains an unpaired surrogate")
    return value


def _boolean(value: object, field: str) -> bool:
    if type(value) is not bool:
        _fail(f"{field} must be boolean")
    return value


def _sha(value: object, field: str) -> str:
    try:
        return require_sha256(value, field=field)
    except (TypeError, ValueError) as exc:
        _fail(str(exc))
    raise AssertionError("unreachable")


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            _fail("cloud context must use string keys")
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


def _coerce_context(value: object) -> BoundedContextPackage:
    if isinstance(value, BoundedContextPackage):
        return value
    if not isinstance(value, Mapping):
        _fail("bounded context must be a validated package", FailureCode.UNSUPPORTED_INPUT)
    try:
        return BoundedContextPackage.from_mapping(value)
    except ContextBuildValidationError as exc:
        _fail(str(exc), _failure_code(exc))
    except (TypeError, ValueError) as exc:
        _fail(str(exc))
    raise AssertionError("unreachable")


def _coerce_disclosure(value: object) -> DisclosureRecord:
    if isinstance(value, DisclosureRecord):
        return value
    if not isinstance(value, Mapping):
        _fail("disclosure must be a validated record", FailureCode.UNSUPPORTED_INPUT)
    try:
        return DisclosureRecord.from_mapping(value)
    except DisclosureValidationError as exc:
        _fail(str(exc), _failure_code(exc))
    except (TypeError, ValueError) as exc:
        _fail(str(exc))
    raise AssertionError("unreachable")


def _source_reference(value: object, *, source_set_identity: str) -> dict[str, object]:
    row = _mapping(value, "source_ref")
    _exact_fields(row, _SOURCE_REF_FIELDS, "source_ref")
    result = {
        "source_id": _sha(row["source_id"], "source_ref.source_id"),
        "canonical_locator": _text(
            row["canonical_locator"], "source_ref.canonical_locator", maximum=2048
        ),
        "content_sha256": _sha(row["content_sha256"], "source_ref.content_sha256"),
        "content_size_bytes": _integer(
            row["content_size_bytes"], "source_ref.content_size_bytes"
        ),
        "source_set_identity": _sha(
            row["source_set_identity"], "source_ref.source_set_identity"
        ),
    }
    if result["source_set_identity"] != source_set_identity:
        _fail("source_ref is outside the bound source set", FailureCode.HASH_MISMATCH)
    return result


def _source_refs(
    value: object,
    *,
    source_set_identity: str,
    require_nonempty: bool,
    require_canonical_order: bool,
) -> tuple[dict[str, object], ...]:
    rows = tuple(
        _source_reference(item, source_set_identity=source_set_identity)
        for item in _sequence(value, "source_refs")
    )
    if require_nonempty and not rows:
        _fail("source_refs must contain at least one source", FailureCode.PROVENANCE_GAP)
    keys = tuple(
        (
            row["source_id"],
            row["canonical_locator"],
            row["content_sha256"],
            row["content_size_bytes"],
            row["source_set_identity"],
        )
        for row in rows
    )
    if len(set(keys)) != len(keys):
        _fail("source_refs contain duplicates", FailureCode.DUPLICATE_CONFLICT)
    if require_canonical_order:
        expected = tuple(
            sorted(rows, key=lambda row: (row["source_id"], row["canonical_locator"]))
        )
        if rows != expected:
            _fail("source_refs are not canonically ordered", FailureCode.NONDETERMINISTIC_OUTPUT)
    return rows


def _context_content(value: object) -> object:
    if type(value) is str:
        return _text(value, "context item content", minimum=0, maximum=16384)
    if isinstance(value, Mapping):
        mapped = _mapping(value, "context item content")
        try:
            canonical_json_bytes(mapped)
        except CanonicalizationError as exc:
            _fail(str(exc))
        return _plain(mapped)
    _fail("context item content must be a string or object")


def _context_items(
    value: object,
    *,
    source_set_identity: str,
    top_level_refs: tuple[dict[str, object], ...],
) -> tuple[dict[str, object], ...]:
    raw_items = _sequence(value, "context_items")
    if not raw_items:
        _fail("context_items must contain at least one item", FailureCode.PROVENANCE_GAP)
    allowed_refs = {canonical_json_bytes(ref) for ref in top_level_refs}
    items: list[dict[str, object]] = []
    for raw in raw_items:
        row = _mapping(raw, "context item")
        _exact_fields(row, _CONTEXT_ITEM_FIELDS, "context item")
        refs = _source_refs(
            row["source_refs"],
            source_set_identity=source_set_identity,
            require_nonempty=False,
            require_canonical_order=True,
        )
        if any(canonical_json_bytes(ref) not in allowed_refs for ref in refs):
            _fail("context item contains a source_ref outside top-level source_refs", FailureCode.HASH_MISMATCH)
        items.append(
            {
                "item_id": _text(row["item_id"], "context item item_id", maximum=256),
                "item_type": _text(row["item_type"], "context item item_type", maximum=128),
                "content": _context_content(row["content"]),
                "source_refs": list(refs),
                "required": _boolean(row["required"], "context item required"),
            }
        )
    item_ids = tuple(item["item_id"] for item in items)
    if len(set(item_ids)) != len(item_ids):
        _fail("context_items contain duplicate item_id values", FailureCode.DUPLICATE_CONFLICT)
    expected_ids = tuple(sorted(item_ids))
    if item_ids != expected_ids:
        _fail("context_items are not in contract-defined canonical order", FailureCode.NONDETERMINISTIC_OUTPUT)
    return tuple(items)


def _byte_budget(value: object) -> dict[str, object]:
    row = _mapping(value, "byte_budget")
    _exact_fields(row, _BYTE_BUDGET_FIELDS, "byte_budget")
    result = {
        "budget_identity": _sha(row["budget_identity"], "byte_budget.budget_identity"),
        "max_cloud_context_bytes": _integer(
            row["max_cloud_context_bytes"], "byte_budget.max_cloud_context_bytes", minimum=1
        ),
        "overflow_policy": row["overflow_policy"],
        "silent_truncation": _boolean(row["silent_truncation"], "byte_budget.silent_truncation"),
    }
    if result["overflow_policy"] != "BLOCK_OR_DETERMINISTIC_REPACK":
        _fail("byte_budget.overflow_policy is not frozen")
    if result["silent_truncation"] is not False:
        _fail("byte_budget.silent_truncation must be false")
    return result


def _estimated_token_metadata(value: object) -> dict[str, object]:
    row = _mapping(value, "estimated_token_metadata")
    _exact_fields(row, _TOKEN_METADATA_FIELDS, "estimated_token_metadata")
    result = {
        "estimator_name": row["estimator_name"],
        "estimator_version": row["estimator_version"],
        "input_bytes": _integer(row["input_bytes"], "estimated_token_metadata.input_bytes"),
        "estimated_tokens": _integer(
            row["estimated_tokens"], "estimated_token_metadata.estimated_tokens"
        ),
        "confidence": row["confidence"],
        "authority": row["authority"],
    }
    if result["estimator_name"] != "non_whitespace_groups_div4":
        _fail("estimated_token_metadata.estimator_name is not frozen")
    if result["estimator_version"] != SCHEMA_VERSION:
        _fail("estimated_token_metadata.estimator_version is not frozen")
    if result["authority"] != "ADVISORY_ONLY":
        _fail("estimated_token_metadata.authority is not frozen")
    if result["confidence"] not in {"ADVISORY", "UNKNOWN"}:
        _fail("estimated_token_metadata.confidence is outside the frozen enum")
    return result


def _provenance_summary(
    value: object,
    *,
    source_ref_count: int,
) -> dict[str, object]:
    row = _mapping(value, "provenance_summary")
    _exact_fields(row, _PROVENANCE_FIELDS, "provenance_summary")
    commits = _mapping(row["dependency_commits"], "provenance_summary.dependency_commits")
    _exact_fields(commits, _DEPENDENCY_COMMIT_FIELDS, "provenance_summary.dependency_commits")
    result = {
        "coverage_percent": _integer(row["coverage_percent"], "provenance_summary.coverage_percent"),
        "chain_identity": _sha(row["chain_identity"], "provenance_summary.chain_identity"),
        "source_count": _integer(row["source_count"], "provenance_summary.source_count", minimum=1),
        "dependency_commits": {"MR03": commits["MR03"], "MR04": commits["MR04"]},
    }
    if result["coverage_percent"] != 100:
        _fail("provenance_summary.coverage_percent must be 100", FailureCode.PROVENANCE_GAP)
    if result["source_count"] != source_ref_count:
        _fail("provenance_summary.source_count does not match source_refs", FailureCode.PROVENANCE_GAP)
    if result["dependency_commits"] != {
        "MR03": MR03_EXPECTED_COMMIT,
        "MR04": MR04_EXPECTED_COMMIT,
    }:
        _fail("provenance dependency commits do not match frozen dependencies", FailureCode.HASH_MISMATCH)
    return result


def _prohibited_assumptions(value: object) -> tuple[str, ...]:
    values = tuple(
        _text(item, "prohibited_assumption", maximum=2048)
        for item in _sequence(value, "prohibited_assumptions")
    )
    if len(set(values)) != len(values):
        _fail("prohibited_assumptions contains duplicates", FailureCode.DUPLICATE_CONFLICT)
    if values != tuple(sorted(values)):
        _fail("prohibited_assumptions are not lexically ordered", FailureCode.NONDETERMINISTIC_OUTPUT)
    return values


def _observational_metadata(value: object | None) -> Mapping[str, object] | None:
    if value is None:
        return None
    row = _mapping(value, "observational_metadata")
    try:
        canonical_json_bytes(row, identity_critical=False)
    except CanonicalizationError as exc:
        _fail(str(exc))
    return _freeze(_plain(row))


def _request_reasoning_metadata(value: object) -> dict[str, str]:
    row = _mapping(value, "reasoning_metadata")
    _exact_fields(row, _CLOUD_REQUEST_REASONING_FIELDS, "reasoning_metadata")
    result = {
        "OPENCLAW_REASONING": row["OPENCLAW_REASONING"],
        "PROJECT_REASONING_PROFILE": row["PROJECT_REASONING_PROFILE"],
    }
    if result != dict(CLOUD_REQUEST_REASONING_METADATA):
        _fail("reasoning_metadata does not match the frozen request profile")
    return result


def _human_authorization_reference(value: object) -> str:
    if type(value) is not str or not 1 <= len(value) <= 2048:
        _fail(
            "human_authorization_reference is required for cloud request construction",
            FailureCode.MR05_MODEL_UNAUTHORIZED,
        )
    try:
        return _text(value, "human_authorization_reference", maximum=2048)
    except CloudContextAdmissionValidationError:
        _fail(
            "human_authorization_reference is invalid",
            FailureCode.MR05_MODEL_UNAUTHORIZED,
        )
    raise AssertionError("unreachable")


def _project_package(
    package: BoundedContextPackage,
) -> tuple[tuple[dict[str, object], ...], tuple[dict[str, object], ...]]:
    projected_items: list[dict[str, object]] = []
    unique_refs: dict[tuple[object, ...], dict[str, object]] = {}
    source_set_identity = package.input_identities["source_set_identity"]
    for item in package.context_items:
        refs: list[dict[str, object]] = []
        for raw_ref in item.source_refs:
            ref = _source_reference(raw_ref, source_set_identity=source_set_identity)
            key = (
                ref["source_id"],
                ref["canonical_locator"],
                ref["content_sha256"],
                ref["content_size_bytes"],
                ref["source_set_identity"],
            )
            unique_refs[key] = ref
            refs.append(ref)
        refs.sort(key=lambda row: (row["source_id"], row["canonical_locator"]))
        projected_items.append(
            {
                "item_id": item.item_identity,
                "item_type": item.item_type,
                "content": _plain(item.content),
                "source_refs": refs,
                "required": item.required,
            }
        )
    projected_items.sort(key=lambda item: item["item_id"])
    refs = tuple(
        sorted(unique_refs.values(), key=lambda row: (row["source_id"], row["canonical_locator"]))
    )
    if not refs:
        _fail("validated bounded context produced no cloud source references", FailureCode.PROVENANCE_GAP)
    return tuple(projected_items), refs


@dataclass(frozen=True, slots=True)
class CloudContext:
    """Exact mr05.cloud_context / 1.0.0 record."""

    schema_version: str
    run_identity: str
    task_identity: str
    source_set_identity: str
    mr03_package_identity: str
    mr04_result_identity: str
    context_items: tuple[Mapping[str, object], ...]
    source_refs: tuple[Mapping[str, object], ...]
    byte_budget: Mapping[str, object]
    estimated_token_metadata: Mapping[str, object]
    provenance_summary: Mapping[str, object]
    prohibited_assumptions: tuple[str, ...]
    proposal_schema_version: str
    disclosure_result: str
    context_identity: str
    observational_metadata: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        try:
            validate_schema_version(CLOUD_CONTEXT_SCHEMA_ID, self.schema_version)
        except UnknownSchemaMajorVersionError as exc:
            _fail(str(exc), FailureCode.MR05_UNKNOWN_SCHEMA_MAJOR)
        except (UnsupportedSchemaVersionError, TypeError, ValueError) as exc:
            _fail(str(exc))

        run_identity = _sha(self.run_identity, "run_identity")
        task_identity = _sha(self.task_identity, "task_identity")
        source_set_identity = _sha(self.source_set_identity, "source_set_identity")
        mr03_package_identity = _sha(self.mr03_package_identity, "mr03_package_identity")
        mr04_result_identity = _sha(self.mr04_result_identity, "mr04_result_identity")
        source_refs = _source_refs(
            self.source_refs,
            source_set_identity=source_set_identity,
            require_nonempty=True,
            require_canonical_order=True,
        )
        context_items = _context_items(
            self.context_items,
            source_set_identity=source_set_identity,
            top_level_refs=source_refs,
        )
        byte_budget = _byte_budget(self.byte_budget)
        estimated_token_metadata = _estimated_token_metadata(self.estimated_token_metadata)
        provenance_summary = _provenance_summary(
            self.provenance_summary,
            source_ref_count=len(source_refs),
        )
        prohibited_assumptions = _prohibited_assumptions(self.prohibited_assumptions)
        if self.proposal_schema_version != SCHEMA_VERSIONS["mr05.cloud_proposal"]:
            _fail("proposal_schema_version is not frozen")
        if self.disclosure_result != "ALLOW":
            _fail("cloud context requires disclosure_result ALLOW", FailureCode.MR05_DISCLOSURE_DENIED)
        observational_metadata = _observational_metadata(self.observational_metadata)

        object.__setattr__(self, "schema_version", CLOUD_CONTEXT_SCHEMA_VERSION)
        object.__setattr__(self, "run_identity", run_identity)
        object.__setattr__(self, "task_identity", task_identity)
        object.__setattr__(self, "source_set_identity", source_set_identity)
        object.__setattr__(self, "mr03_package_identity", mr03_package_identity)
        object.__setattr__(self, "mr04_result_identity", mr04_result_identity)
        object.__setattr__(self, "context_items", tuple(_freeze(item) for item in context_items))
        object.__setattr__(self, "source_refs", tuple(_freeze(ref) for ref in source_refs))
        object.__setattr__(self, "byte_budget", _freeze(byte_budget))
        object.__setattr__(self, "estimated_token_metadata", _freeze(estimated_token_metadata))
        object.__setattr__(self, "provenance_summary", _freeze(provenance_summary))
        object.__setattr__(self, "prohibited_assumptions", prohibited_assumptions)
        object.__setattr__(self, "proposal_schema_version", SCHEMA_VERSIONS["mr05.cloud_proposal"])
        object.__setattr__(self, "disclosure_result", "ALLOW")
        object.__setattr__(self, "observational_metadata", observational_metadata)

        declared_identity = _sha(self.context_identity, "context_identity")
        try:
            computed_identity = sha256_canonical(self.identity_payload)
        except (CanonicalizationError, TypeError, ValueError) as exc:
            _fail(str(exc))
        if declared_identity != computed_identity:
            _fail("context_identity does not match frozen cloud-context semantics", FailureCode.HASH_MISMATCH)
        object.__setattr__(self, "context_identity", declared_identity)

        if self.canonical_byte_count > byte_budget["max_cloud_context_bytes"]:
            _fail(
                "canonical cloud context exceeds max_cloud_context_bytes",
                FailureCode.MR05_CONTEXT_OVER_BYTE_BUDGET,
            )

    @property
    def identity_payload(self) -> dict[str, object]:
        """Return the exact frozen CLOUD_CONTEXT_IDENTITY_SHA256 preimage."""

        return {
            "schema_version": self.schema_version,
            "run_identity": self.run_identity,
            "task_identity": self.task_identity,
            "source_set_identity": self.source_set_identity,
            "mr03_package_identity": self.mr03_package_identity,
            "mr04_result_identity": self.mr04_result_identity,
            "context_items": [_plain(item) for item in self.context_items],
            "source_refs": [_plain(ref) for ref in self.source_refs],
            "byte_budget": _plain(self.byte_budget),
            "estimated_token_metadata": _plain(self.estimated_token_metadata),
            "provenance_summary": _plain(self.provenance_summary),
            "prohibited_assumptions": list(self.prohibited_assumptions),
            "proposal_schema_version": self.proposal_schema_version,
            "disclosure_result": self.disclosure_result,
        }

    def to_dict(self) -> dict[str, object]:
        out = dict(self.identity_payload)
        out["context_identity"] = self.context_identity
        if self.observational_metadata is not None:
            out["observational_metadata"] = _plain(self.observational_metadata)
        return out

    def canonical_bytes(self) -> bytes:
        """Return the complete canonical cloud-context bytes."""

        return canonical_json_bytes(self.to_dict(), identity_critical=False)

    @property
    def canonical_byte_count(self) -> int:
        """Return the authoritative byte count used by the cloud-context budget."""

        return len(self.canonical_bytes())

    @classmethod
    def from_mapping(cls, value: object) -> "CloudContext":
        row = _mapping(value, "cloud context")
        _exact_fields(row, _REQUIRED_FIELDS, "cloud context", _OPTIONAL_FIELDS)
        return cls(
            schema_version=row["schema_version"],
            run_identity=row["run_identity"],
            task_identity=row["task_identity"],
            source_set_identity=row["source_set_identity"],
            mr03_package_identity=row["mr03_package_identity"],
            mr04_result_identity=row["mr04_result_identity"],
            context_items=tuple(_sequence(row["context_items"], "context_items")),
            source_refs=tuple(_sequence(row["source_refs"], "source_refs")),
            byte_budget=row["byte_budget"],
            estimated_token_metadata=row["estimated_token_metadata"],
            provenance_summary=row["provenance_summary"],
            prohibited_assumptions=tuple(
                _sequence(row["prohibited_assumptions"], "prohibited_assumptions")
            ),
            proposal_schema_version=row["proposal_schema_version"],
            disclosure_result=row["disclosure_result"],
            context_identity=row["context_identity"],
            observational_metadata=row.get("observational_metadata"),
        )


CloudContextAdmission = CloudContext


@dataclass(frozen=True, slots=True)
class CloudRequest:
    """Exact mr05.cloud_request / 1.0.0 deterministic envelope."""

    schema_version: str
    run_identity: str
    context_identity: str
    request_identity: str
    model_identifier: str
    reasoning_metadata: Mapping[str, object]
    attempt_number: int
    max_attempts: int
    required_response_schema: str
    request_policy_version: str
    human_authorization_reference: str
    observational_metadata: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        try:
            validate_schema_version(CLOUD_REQUEST_SCHEMA_ID, self.schema_version)
        except UnknownSchemaMajorVersionError as exc:
            _fail(str(exc), FailureCode.MR05_UNKNOWN_SCHEMA_MAJOR)
        except (UnsupportedSchemaVersionError, TypeError, ValueError) as exc:
            _fail(str(exc))

        run_identity = _sha(self.run_identity, "run_identity")
        context_identity = _sha(self.context_identity, "context_identity")
        model_identifier = _text(
            self.model_identifier, "model_identifier", maximum=256
        )
        reasoning_metadata = _request_reasoning_metadata(self.reasoning_metadata)
        attempt_number = _integer(self.attempt_number, "attempt_number", minimum=1)
        max_attempts = _integer(self.max_attempts, "max_attempts", minimum=1)
        if attempt_number != 1:
            _fail("attempt_number must equal frozen value 1")
        if max_attempts != 1:
            _fail("max_attempts must equal frozen value 1")
        if self.required_response_schema != CLOUD_REQUEST_REQUIRED_RESPONSE_SCHEMA:
            _fail("required_response_schema is not frozen")
        if self.request_policy_version != CLOUD_REQUEST_POLICY_VERSION:
            _fail("request_policy_version is not frozen")
        human_authorization_reference = _human_authorization_reference(
            self.human_authorization_reference
        )
        observational_metadata = _observational_metadata(self.observational_metadata)

        object.__setattr__(self, "schema_version", CLOUD_REQUEST_SCHEMA_VERSION)
        object.__setattr__(self, "run_identity", run_identity)
        object.__setattr__(self, "context_identity", context_identity)
        object.__setattr__(self, "model_identifier", model_identifier)
        object.__setattr__(self, "reasoning_metadata", _freeze(reasoning_metadata))
        object.__setattr__(self, "attempt_number", 1)
        object.__setattr__(self, "max_attempts", 1)
        object.__setattr__(
            self, "required_response_schema", CLOUD_REQUEST_REQUIRED_RESPONSE_SCHEMA
        )
        object.__setattr__(self, "request_policy_version", CLOUD_REQUEST_POLICY_VERSION)
        object.__setattr__(
            self, "human_authorization_reference", human_authorization_reference
        )
        object.__setattr__(self, "observational_metadata", observational_metadata)

        declared_identity = _sha(self.request_identity, "request_identity")
        try:
            computed_identity = sha256_canonical(self.identity_payload)
        except (CanonicalizationError, TypeError, ValueError) as exc:
            _fail(str(exc))
        if declared_identity != computed_identity:
            _fail(
                "request_identity does not match frozen cloud-request semantics",
                FailureCode.HASH_MISMATCH,
            )
        object.__setattr__(self, "request_identity", declared_identity)

    @property
    def identity_payload(self) -> dict[str, object]:
        """Return the exact frozen CLOUD_REQUEST_IDENTITY_SHA256 preimage."""

        return {
            "schema_version": self.schema_version,
            "run_identity": self.run_identity,
            "context_identity": self.context_identity,
            "model_identifier": self.model_identifier,
            "reasoning_metadata": _plain(self.reasoning_metadata),
            "attempt_number": self.attempt_number,
            "max_attempts": self.max_attempts,
            "required_response_schema": self.required_response_schema,
            "request_policy_version": self.request_policy_version,
        }

    def to_dict(self) -> dict[str, object]:
        out = dict(self.identity_payload)
        out["request_identity"] = self.request_identity
        out["human_authorization_reference"] = self.human_authorization_reference
        if self.observational_metadata is not None:
            out["observational_metadata"] = _plain(self.observational_metadata)
        return out

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict(), identity_critical=False)

    @classmethod
    def from_mapping(cls, value: object) -> "CloudRequest":
        row = _mapping(value, "cloud request")
        _exact_fields(
            row,
            _CLOUD_REQUEST_REQUIRED_FIELDS,
            "cloud request",
            _CLOUD_REQUEST_OPTIONAL_FIELDS,
        )
        return cls(
            schema_version=row["schema_version"],
            run_identity=row["run_identity"],
            context_identity=row["context_identity"],
            request_identity=row["request_identity"],
            model_identifier=row["model_identifier"],
            reasoning_metadata=row["reasoning_metadata"],
            attempt_number=row["attempt_number"],
            max_attempts=row["max_attempts"],
            required_response_schema=row["required_response_schema"],
            request_policy_version=row["request_policy_version"],
            human_authorization_reference=row["human_authorization_reference"],
            observational_metadata=row.get("observational_metadata"),
        )


CloudRequestValidationError = CloudContextAdmissionValidationError


def admit_cloud_context(
    bounded_context: BoundedContextPackage | Mapping[str, object],
    disclosure_record: DisclosureRecord | Mapping[str, object],
    *,
    run_identity: object,
    mr03_package_identity: object,
    mr04_result_identity: object,
    byte_budget: Mapping[str, object],
    estimated_token_metadata: Mapping[str, object],
    prohibited_assumptions: object = (),
    observational_metadata: Mapping[str, object] | None = None,
) -> CloudContext:
    """Project exact bounded content into the frozen local cloud-context record."""

    package = _coerce_context(bounded_context)
    disclosure = _coerce_disclosure(disclosure_record)
    if disclosure.disclosure_result != "ALLOW" or not disclosure.cloud_eligible:
        _fail(
            "disclosure policy does not allow cloud-context admission",
            FailureCode.MR05_DISCLOSURE_DENIED,
        )

    task_identity = _sha(package.input_identities["task_identity"], "task_identity")
    source_set_identity = _sha(
        package.input_identities["source_set_identity"], "source_set_identity"
    )
    context_items, source_refs = _project_package(package)
    budget = _byte_budget(byte_budget)
    token_metadata = _estimated_token_metadata(estimated_token_metadata)
    assumptions = tuple(sorted(_prohibited_assumptions(prohibited_assumptions)))
    provenance_summary = {
        "coverage_percent": 100,
        "chain_identity": package.provenance_identity,
        "source_count": len(source_refs),
        "dependency_commits": {
            "MR03": MR03_EXPECTED_COMMIT,
            "MR04": MR04_EXPECTED_COMMIT,
        },
    }

    semantic = {
        "schema_version": CLOUD_CONTEXT_SCHEMA_VERSION,
        "run_identity": _sha(run_identity, "run_identity"),
        "task_identity": task_identity,
        "source_set_identity": source_set_identity,
        "mr03_package_identity": _sha(mr03_package_identity, "mr03_package_identity"),
        "mr04_result_identity": _sha(mr04_result_identity, "mr04_result_identity"),
        "context_items": list(context_items),
        "source_refs": list(source_refs),
        "byte_budget": budget,
        "estimated_token_metadata": token_metadata,
        "provenance_summary": provenance_summary,
        "prohibited_assumptions": list(assumptions),
        "proposal_schema_version": SCHEMA_VERSIONS["mr05.cloud_proposal"],
        "disclosure_result": "ALLOW",
    }
    try:
        context_identity = sha256_canonical(semantic)
    except (CanonicalizationError, TypeError, ValueError) as exc:
        _fail(str(exc))
    return CloudContext(
        **semantic,
        context_identity=context_identity,
        observational_metadata=observational_metadata,
    )


def build_cloud_context(
    bounded_context: BoundedContextPackage | Mapping[str, object],
    disclosure_record: DisclosureRecord | Mapping[str, object],
    **kwargs: object,
) -> CloudContext:
    """Descriptive alias for deterministic cloud-context admission."""

    return admit_cloud_context(bounded_context, disclosure_record, **kwargs)


def compute_cloud_context_identity(value: CloudContext | Mapping[str, object]) -> str:
    """Recompute the frozen context_identity after exact validation."""

    record = value if isinstance(value, CloudContext) else CloudContext.from_mapping(value)
    return sha256_canonical(record.identity_payload)


def canonical_cloud_context_bytes(value: CloudContext | Mapping[str, object]) -> bytes:
    """Return complete canonical cloud-context bytes after exact validation."""

    record = value if isinstance(value, CloudContext) else CloudContext.from_mapping(value)
    return record.canonical_bytes()


def build_cloud_request(
    cloud_context: CloudContext | Mapping[str, object],
    *,
    model_identifier: object,
    human_authorization_reference: object,
    observational_metadata: Mapping[str, object] | None = None,
) -> CloudRequest:
    """Build one deterministic request envelope without executing a provider call."""

    context = (
        cloud_context
        if isinstance(cloud_context, CloudContext)
        else CloudContext.from_mapping(cloud_context)
    )
    model = _text(model_identifier, "model_identifier", maximum=256)
    authorization = _human_authorization_reference(human_authorization_reference)
    semantic = {
        "schema_version": CLOUD_REQUEST_SCHEMA_VERSION,
        "run_identity": context.run_identity,
        "context_identity": context.context_identity,
        "model_identifier": model,
        "reasoning_metadata": dict(CLOUD_REQUEST_REASONING_METADATA),
        "attempt_number": 1,
        "max_attempts": 1,
        "required_response_schema": CLOUD_REQUEST_REQUIRED_RESPONSE_SCHEMA,
        "request_policy_version": CLOUD_REQUEST_POLICY_VERSION,
    }
    try:
        request_identity = sha256_canonical(semantic)
    except (CanonicalizationError, TypeError, ValueError) as exc:
        _fail(str(exc))
    return CloudRequest(
        **semantic,
        request_identity=request_identity,
        human_authorization_reference=authorization,
        observational_metadata=observational_metadata,
    )


def compute_cloud_request_identity(value: CloudRequest | Mapping[str, object]) -> str:
    """Recompute the frozen request_identity after exact validation."""

    record = value if isinstance(value, CloudRequest) else CloudRequest.from_mapping(value)
    return sha256_canonical(record.identity_payload)


def canonical_cloud_request_bytes(value: CloudRequest | Mapping[str, object]) -> bytes:
    """Return complete canonical cloud-request bytes after exact validation."""

    record = value if isinstance(value, CloudRequest) else CloudRequest.from_mapping(value)
    return record.canonical_bytes()


def not_implemented(*args: object, **kwargs: object) -> None:
    """Retain the legacy non-operational marker for direct callers."""

    del args, kwargs
    phase_not_implemented("cloud_boundary")


__all__ = (
    "CLOUD_CONTEXT_SCHEMA_ID",
    "CLOUD_CONTEXT_SCHEMA_VERSION",
    "CLOUD_CONTEXT_BYTE_AUTHORITY",
    "CLOUD_REQUEST_SCHEMA_ID",
    "CLOUD_REQUEST_SCHEMA_VERSION",
    "CLOUD_REQUEST_POLICY_VERSION",
    "CLOUD_REQUEST_REQUIRED_RESPONSE_SCHEMA",
    "CLOUD_REQUEST_REASONING_METADATA",
    "NO_REPACK_POLICY",
    "PARTIAL_CONTEXT_TRUNCATION",
    "CLOUD_CONTEXT_ADMISSION_IMPLEMENTATION_COUNT",
    "FILESYSTEM_SOURCE_READ_COUNT",
    "FILESYSTEM_WRITE_IMPLEMENTATION_COUNT",
    "SUBPROCESS_EXECUTION_COUNT",
    "NETWORK_IMPLEMENTATION_COUNT",
    "PROVIDER_CLIENT_IMPLEMENTATION_COUNT",
    "MODEL_CALL_IMPLEMENTATION_COUNT",
    "MODEL_ROUTING_IMPLEMENTATION_COUNT",
    "AUTH_IMPLEMENTATION_COUNT",
    "AUTO_RETRY_IMPLEMENTATION_COUNT",
    "AUTO_FALLBACK_IMPLEMENTATION_COUNT",
    "STATE_TRANSITION_EXECUTION_COUNT",
    "GIT_OPERATION_COUNT",
    "SOURCE_ACQUISITION_IMPLEMENTATION_COUNT",
    "DEPENDENCY_EXECUTION_IMPLEMENTATION_COUNT",
    "EVIDENCE_PERSISTENCE_COUNT",
    "CLOUD_REQUEST_BUILD_COUNT",
    "LIVE_CLOUD_EXECUTION_COUNT",
    "CONTEXT_REPACK_IMPLEMENTATION_COUNT",
    "PARTIAL_CONTEXT_TRUNCATION_IMPLEMENTATION_COUNT",
    "CLOUD_CONTEXT_IDENTITY_PREIMAGE",
    "CLOUD_REQUEST_IDENTITY_PREIMAGE",
    "CloudContextAdmissionValidationError",
    "CloudContextValidationError",
    "CloudContext",
    "CloudContextAdmission",
    "CloudRequestValidationError",
    "CloudRequest",
    "admit_cloud_context",
    "build_cloud_context",
    "compute_cloud_context_identity",
    "canonical_cloud_context_bytes",
    "build_cloud_request",
    "compute_cloud_request_identity",
    "canonical_cloud_request_bytes",
    "not_implemented",
)
