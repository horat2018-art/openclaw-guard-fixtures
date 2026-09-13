"""Bounded offline pre-live command-line entrypoint.

Explicit bounded commands accept strict JSON requests on stdin. ``local-prepare``
delegates one approved-root local file read to the qualified source-acquisition
boundary and deterministically stops at the zero-send handoff. ``materialize``
requalifies already-produced local deterministic records, constructs exact
prepare inputs, and delegates to the same zero-send prepare workflow. ``offline``
admits an already-obtained provider response as exact base64 bytes, while
``prepare``/``resume`` expose the two-step zero-send discontinuity. None performs
network/provider/model/auth operation, retry, fallback, Human approval execution,
autonomous state transition, Git mutation, dependency execution, or direct
source/evidence filesystem access from the CLI module. Final evidence publication
remains owned by the existing qualified workflow/evidence boundary.

Calling ``main()`` without one of the explicit bounded commands preserves the
historical fail-closed CLI compatibility behavior.
"""

from __future__ import annotations

import base64
import binascii
import inspect
import sys
from collections.abc import Mapping, Sequence
from typing import TextIO

from . import canonical, local_orchestration, materialization, workflow
from .failures import phase_not_implemented

OFFLINE_CLI_SCHEMA_VERSION = "1.0.0"
OFFLINE_CLI_OPERATION = "OFFLINE_COMPOSE_PREOBTAINED_RESPONSE"
OFFLINE_CLI_COMMAND = "offline"
PREPARE_CLI_OPERATION = "PREPARE_PRE_SEND_HANDOFF"
PREPARE_CLI_COMMAND = "prepare"
RESUME_CLI_OPERATION = "RESUME_PREOBTAINED_RESPONSE"
RESUME_CLI_COMMAND = "resume"
MATERIALIZE_CLI_OPERATION = "MATERIALIZE_LOCAL_PREPARE_INPUTS"
MATERIALIZE_CLI_COMMAND = "materialize"
LOCAL_PREPARE_CLI_OPERATION = "LOCAL_PREPARE_FROM_APPROVED_SOURCE"
LOCAL_PREPARE_CLI_COMMAND = "local-prepare"
OFFLINE_CLI_IMPLEMENTATION_COUNT = 1
TWO_STEP_CLI_IMPLEMENTATION_COUNT = 1
MATERIALIZATION_CLI_IMPLEMENTATION_COUNT = 1
LOCAL_PREPARE_CLI_IMPLEMENTATION_COUNT = 1
LOCAL_SOURCE_READ_DELEGATION_COUNT = 1
OFFLINE_CLI_INPUT_TRANSPORT = "STDIN_JSON_ONLY"
OFFLINE_CLI_RAW_RESPONSE_ENCODING = "BASE64_EXACT_BYTES"
OFFLINE_CLI_MAX_INPUT_BYTES = 8 * 1024 * 1024
OFFLINE_CLI_MAX_RAW_RESPONSE_BYTES = 4 * 1024 * 1024

NETWORK_IMPLEMENTATION_COUNT = 0
PROVIDER_CLIENT_IMPLEMENTATION_COUNT = 0
MODEL_CALL_IMPLEMENTATION_COUNT = 0
MODEL_ROUTING_IMPLEMENTATION_COUNT = 0
AUTH_IMPLEMENTATION_COUNT = 0
AUTO_RETRY_IMPLEMENTATION_COUNT = 0
AUTO_FALLBACK_IMPLEMENTATION_COUNT = 0
HUMAN_APPROVAL_EXECUTION_COUNT = 0
HUMAN_DECISION_SIDE_EFFECT_COUNT = 0
STATE_TRANSITION_EXECUTION_COUNT = 0
GIT_OPERATION_COUNT = 0
DIRECT_FILESYSTEM_READ_COUNT = 0
DIRECT_FILESYSTEM_WRITE_COUNT = 0

_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "operation",
        "workflow_arguments",
        "raw_provider_response_base64",
    }
)
_WORKFLOW_REQUIRED_FIELDS = frozenset(
    {
        "run_record",
        "bounded_context_record",
        "disclosure_classification",
        "disclosure_findings",
        "disclosure_observational_metadata",
        "metrics_raw_source_bytes",
        "metrics_normalized_bytes",
        "metrics_package_bytes",
        "metrics_cloud_context_bytes",
        "metrics_raw_estimated_tokens",
        "metrics_cloud_estimated_tokens",
        "metrics_model_call_count",
        "metrics_model_retry_count",
        "metrics_failure_count",
        "metrics_source_ref_count",
        "metrics_missing_source_ref_count",
        "metrics_identity_mismatch_count",
        "metrics_observational_metadata",
        "model_identifier",
        "human_authorization_reference",
        "estimated_token_metadata",
        "authorized_provider_identifier",
        "authorized_account_boundary_reference",
        "authorization_observational_metadata",
        "provider_identifier",
        "actual_model_identifier",
        "provider_request_id",
        "account_boundary_reference",
        "provider_usage_if_available",
        "error_metadata",
        "legacy_verifier_checks",
        "verification_result",
        "verification_reason_codes",
        "verification_reason_details",
        "verification_verified_source_refs",
        "verification_unsupported_claims",
        "verification_missing_refs",
        "verification_protected_content_findings",
        "verification_identity_findings",
        "verification_observational_metadata",
        "approved_root",
        "manifest_relative_path",
        "final_result_relative_path",
    }
)
_WORKFLOW_OPTIONAL_FIELDS = frozenset(
    {
        "verifier_failure_records",
        "human_gate_task_summary",
        "human_gate_proposal_summary",
        "human_gate_uncertainties",
        "human_gate_evidence_pointers",
        "human_gate_observational_metadata",
        "human_decision",
        "human_decision_reason",
        "human_decision_scope",
        "human_decision_authority_reference",
        "human_decision_observational_metadata",
        "failure_record",
        "prohibited_assumptions",
        "context_observational_metadata",
        "request_observational_metadata",
        "manifest_observational_metadata",
        "final_observational_metadata",
    }
)
_WORKFLOW_FIELDS = _WORKFLOW_REQUIRED_FIELDS | _WORKFLOW_OPTIONAL_FIELDS

_PREPARE_TOP_LEVEL_FIELDS = frozenset(
    {"schema_version", "operation", "prepare_arguments"}
)
_PREPARE_REQUIRED_FIELDS = frozenset(
    {
        "run_record",
        "bounded_context_record",
        "disclosure_classification",
        "disclosure_findings",
        "disclosure_observational_metadata",
        "metrics_raw_source_bytes",
        "metrics_normalized_bytes",
        "metrics_package_bytes",
        "metrics_cloud_context_bytes",
        "metrics_raw_estimated_tokens",
        "metrics_cloud_estimated_tokens",
        "metrics_model_call_count",
        "metrics_model_retry_count",
        "metrics_failure_count",
        "metrics_source_ref_count",
        "metrics_missing_source_ref_count",
        "metrics_identity_mismatch_count",
        "metrics_observational_metadata",
        "model_identifier",
        "human_authorization_reference",
        "estimated_token_metadata",
        "authorized_provider_identifier",
        "authorized_account_boundary_reference",
        "authorization_observational_metadata",
        "legacy_verifier_checks",
    }
)
_PREPARE_OPTIONAL_FIELDS = frozenset(
    {
        "verifier_failure_records",
        "prohibited_assumptions",
        "context_observational_metadata",
        "request_observational_metadata",
    }
)
_PREPARE_FIELDS = _PREPARE_REQUIRED_FIELDS | _PREPARE_OPTIONAL_FIELDS

_RESUME_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "operation",
        "prepared_workflow",
        "resume_arguments",
        "raw_provider_response_base64",
    }
)
_RESUME_REQUIRED_FIELDS = frozenset(
    {
        "provider_identifier",
        "actual_model_identifier",
        "provider_request_id",
        "account_boundary_reference",
        "provider_usage_if_available",
        "error_metadata",
        "verification_result",
        "verification_reason_codes",
        "verification_reason_details",
        "verification_verified_source_refs",
        "verification_unsupported_claims",
        "verification_missing_refs",
        "verification_protected_content_findings",
        "verification_identity_findings",
        "verification_observational_metadata",
        "approved_root",
        "manifest_relative_path",
        "final_result_relative_path",
    }
)
_RESUME_OPTIONAL_FIELDS = frozenset(
    {
        "human_gate_task_summary",
        "human_gate_proposal_summary",
        "human_gate_uncertainties",
        "human_gate_evidence_pointers",
        "human_gate_observational_metadata",
        "human_decision",
        "human_decision_reason",
        "human_decision_scope",
        "human_decision_authority_reference",
        "human_decision_observational_metadata",
        "failure_record",
        "manifest_observational_metadata",
        "final_observational_metadata",
    }
)
_RESUME_FIELDS = _RESUME_REQUIRED_FIELDS | _RESUME_OPTIONAL_FIELDS

_MATERIALIZE_TOP_LEVEL_FIELDS = frozenset(
    {"schema_version", "operation", "materialization_arguments"}
)
_MATERIALIZE_REQUIRED_FIELDS = frozenset(
    {
        "discovery_result",
        "normalization_result",
        "dependency_bindings",
        "provenance_chain",
        "metrics_raw_source_bytes",
        "metrics_normalized_bytes",
        "metrics_package_bytes",
        "metrics_cloud_context_bytes",
        "metrics_raw_estimated_tokens",
        "metrics_cloud_estimated_tokens",
        "metrics_model_call_count",
        "metrics_model_retry_count",
        "metrics_failure_count",
        "metrics_source_ref_count",
        "metrics_missing_source_ref_count",
        "metrics_identity_mismatch_count",
        "metrics_observational_metadata",
        "max_context_bytes",
        "mr03_result_identity",
        "mr04_result_identity",
        "frozen_run_byte_budget",
        "frozen_run_state",
        "frozen_run_observational_metadata",
        "disclosure_classification",
        "disclosure_findings",
        "disclosure_observational_metadata",
        "model_identifier",
        "human_authorization_reference",
        "estimated_token_metadata",
        "authorized_provider_identifier",
        "authorized_account_boundary_reference",
        "authorization_observational_metadata",
        "legacy_verifier_checks",
    }
)
_MATERIALIZE_OPTIONAL_FIELDS = frozenset(
    {
        "verifier_failure_records",
        "prohibited_assumptions",
        "context_observational_metadata",
        "request_observational_metadata",
    }
)
_MATERIALIZE_FIELDS = _MATERIALIZE_REQUIRED_FIELDS | _MATERIALIZE_OPTIONAL_FIELDS

_LOCAL_PREPARE_TOP_LEVEL_FIELDS = frozenset(
    {"schema_version", "operation", "local_prepare_arguments"}
)
_LOCAL_PREPARE_REQUIRED_FIELDS = frozenset(
    {
        "approved_source_root",
        "source_relative_path",
        "source_alias",
        "provenance_owner",
        "task",
        "classification",
        "content_kind",
        "source_observational_metadata",
        "discovery_max_bytes",
        "phase_id",
        "artifact_type",
        "current_validity",
        "supersession",
        "mandatory",
        "metrics_raw_estimated_tokens",
        "metrics_cloud_estimated_tokens",
        "mr03_result_identity",
        "mr04_result_identity",
        "frozen_run_byte_budget",
        "frozen_run_state",
        "frozen_run_observational_metadata",
        "disclosure_classification",
        "disclosure_findings",
        "disclosure_observational_metadata",
        "model_identifier",
        "human_authorization_reference",
        "estimated_token_metadata",
        "authorized_provider_identifier",
        "authorized_account_boundary_reference",
        "authorization_observational_metadata",
        "legacy_verifier_pass_rule_ids",
    }
)
_LOCAL_PREPARE_OPTIONAL_FIELDS = frozenset(
    {
        "prohibited_assumptions",
        "context_observational_metadata",
        "request_observational_metadata",
    }
)
_LOCAL_PREPARE_FIELDS = _LOCAL_PREPARE_REQUIRED_FIELDS | _LOCAL_PREPARE_OPTIONAL_FIELDS


class OfflineCLIValidationError(ValueError):
    """The bounded offline CLI request is malformed or outside its contract."""


def _read_bounded_text(stream: TextIO) -> str:
    text = stream.read(OFFLINE_CLI_MAX_INPUT_BYTES + 1)
    if not isinstance(text, str):
        raise OfflineCLIValidationError("stdin must provide text")
    try:
        encoded = text.encode("utf-8")
    except UnicodeError as exc:
        raise OfflineCLIValidationError("stdin is not valid UTF-8 text") from exc
    if len(encoded) > OFFLINE_CLI_MAX_INPUT_BYTES:
        raise OfflineCLIValidationError("offline request exceeds bounded input size")
    return text


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        raise OfflineCLIValidationError(f"{field} must be a string-keyed object")
    return value


def _decode_raw_response(value: object) -> bytes:
    if type(value) is not str or not value:
        raise OfflineCLIValidationError("raw_provider_response_base64 must be a non-empty string")
    if any(ord(ch) > 127 for ch in value):
        raise OfflineCLIValidationError("raw_provider_response_base64 must be ASCII")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise OfflineCLIValidationError("raw_provider_response_base64 is invalid") from exc
    if base64.b64encode(raw).decode("ascii") != value:
        raise OfflineCLIValidationError("raw_provider_response_base64 is not canonical")
    if len(raw) > OFFLINE_CLI_MAX_RAW_RESPONSE_BYTES:
        raise OfflineCLIValidationError("raw provider response exceeds bounded size")
    return raw


def _workflow_signature_contract() -> tuple[frozenset[str], frozenset[str]]:
    signature = inspect.signature(workflow.compose_top_level_workflow)
    observed_fields: set[str] = set()
    observed_required: set[str] = set()
    for name, parameter in signature.parameters.items():
        if parameter.kind not in {
            inspect.Parameter.KEYWORD_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        }:
            raise OfflineCLIValidationError("workflow signature contains unsupported parameter kind")
        if name == "raw_provider_response":
            if parameter.default is not inspect.Parameter.empty:
                raise OfflineCLIValidationError("raw provider response workflow contract drifted")
            continue
        observed_fields.add(name)
        if parameter.default is inspect.Parameter.empty:
            observed_required.add(name)
    if observed_fields != _WORKFLOW_FIELDS or observed_required != _WORKFLOW_REQUIRED_FIELDS:
        raise OfflineCLIValidationError("workflow signature drifted from frozen offline CLI contract")
    return _WORKFLOW_FIELDS, _WORKFLOW_REQUIRED_FIELDS


def _prepare_signature_contract() -> tuple[frozenset[str], frozenset[str]]:
    signature = inspect.signature(workflow.prepare_top_level_workflow)
    observed_fields: set[str] = set()
    observed_required: set[str] = set()
    for name, parameter in signature.parameters.items():
        if parameter.kind not in {
            inspect.Parameter.KEYWORD_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        }:
            raise OfflineCLIValidationError("prepare workflow signature contains unsupported parameter kind")
        observed_fields.add(name)
        if parameter.default is inspect.Parameter.empty:
            observed_required.add(name)
    if observed_fields != _PREPARE_FIELDS or observed_required != _PREPARE_REQUIRED_FIELDS:
        raise OfflineCLIValidationError("prepare workflow signature drifted from frozen CLI contract")
    return _PREPARE_FIELDS, _PREPARE_REQUIRED_FIELDS


def _resume_signature_contract() -> tuple[frozenset[str], frozenset[str]]:
    signature = inspect.signature(workflow.resume_top_level_workflow)
    observed_fields: set[str] = set()
    observed_required: set[str] = set()
    excluded = {"prepared_package", "raw_provider_response"}
    for name, parameter in signature.parameters.items():
        if parameter.kind not in {
            inspect.Parameter.KEYWORD_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        }:
            raise OfflineCLIValidationError("resume workflow signature contains unsupported parameter kind")
        if name in excluded:
            if parameter.default is not inspect.Parameter.empty:
                raise OfflineCLIValidationError("resume discontinuity contract drifted")
            continue
        observed_fields.add(name)
        if parameter.default is inspect.Parameter.empty:
            observed_required.add(name)
    if observed_fields != _RESUME_FIELDS or observed_required != _RESUME_REQUIRED_FIELDS:
        raise OfflineCLIValidationError("resume workflow signature drifted from frozen CLI contract")
    return _RESUME_FIELDS, _RESUME_REQUIRED_FIELDS


def _materialize_signature_contract() -> tuple[frozenset[str], frozenset[str]]:
    signature = inspect.signature(materialization.materialize_prepare_inputs)
    observed_fields: set[str] = set()
    observed_required: set[str] = set()
    for name, parameter in signature.parameters.items():
        if parameter.kind not in {
            inspect.Parameter.KEYWORD_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        }:
            raise OfflineCLIValidationError("materialization signature contains unsupported parameter kind")
        observed_fields.add(name)
        if parameter.default is inspect.Parameter.empty:
            observed_required.add(name)
    if observed_fields != _MATERIALIZE_FIELDS or observed_required != _MATERIALIZE_REQUIRED_FIELDS:
        raise OfflineCLIValidationError("materialization signature drifted from frozen CLI contract")
    return _MATERIALIZE_FIELDS, _MATERIALIZE_REQUIRED_FIELDS


def _local_prepare_signature_contract() -> tuple[frozenset[str], frozenset[str]]:
    signature = inspect.signature(local_orchestration.orchestrate_local_prepare)
    observed_fields: set[str] = set()
    observed_required: set[str] = set()
    for name, parameter in signature.parameters.items():
        if parameter.kind not in {
            inspect.Parameter.KEYWORD_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        }:
            raise OfflineCLIValidationError("local prepare signature contains unsupported parameter kind")
        observed_fields.add(name)
        if parameter.default is inspect.Parameter.empty:
            observed_required.add(name)
    if observed_fields != _LOCAL_PREPARE_FIELDS or observed_required != _LOCAL_PREPARE_REQUIRED_FIELDS:
        raise OfflineCLIValidationError("local prepare signature drifted from frozen CLI contract")
    return _LOCAL_PREPARE_FIELDS, _LOCAL_PREPARE_REQUIRED_FIELDS


def _parse_request(text: str) -> tuple[dict[str, object], bytes]:
    try:
        value = canonical.parse_json_no_duplicates(text)
    except (TypeError, ValueError, canonical.CanonicalizationError) as exc:
        raise OfflineCLIValidationError("offline request is not strict duplicate-free JSON") from exc
    request = _mapping(value, "request")
    if set(request) != _TOP_LEVEL_FIELDS:
        raise OfflineCLIValidationError("offline request fields are not exact")
    if request["schema_version"] != OFFLINE_CLI_SCHEMA_VERSION:
        raise OfflineCLIValidationError("offline request schema_version is unsupported")
    if request["operation"] != OFFLINE_CLI_OPERATION:
        raise OfflineCLIValidationError("offline request operation is unsupported")

    arguments = dict(_mapping(request["workflow_arguments"], "workflow_arguments"))
    if "raw_provider_response" in arguments:
        raise OfflineCLIValidationError("raw_provider_response must use the bounded base64 field")
    allowed, required = _workflow_signature_contract()
    unknown = set(arguments) - allowed
    missing = required - set(arguments)
    if unknown:
        raise OfflineCLIValidationError("workflow_arguments contain unsupported fields")
    if missing:
        raise OfflineCLIValidationError("workflow_arguments are missing required fields")
    return arguments, _decode_raw_response(request["raw_provider_response_base64"])


def _parse_prepare_request(text: str) -> dict[str, object]:
    try:
        value = canonical.parse_json_no_duplicates(text)
    except (TypeError, ValueError, canonical.CanonicalizationError) as exc:
        raise OfflineCLIValidationError("prepare request is not strict duplicate-free JSON") from exc
    request = _mapping(value, "prepare request")
    if set(request) != _PREPARE_TOP_LEVEL_FIELDS:
        raise OfflineCLIValidationError("prepare request fields are not exact")
    if request["schema_version"] != OFFLINE_CLI_SCHEMA_VERSION:
        raise OfflineCLIValidationError("prepare request schema_version is unsupported")
    if request["operation"] != PREPARE_CLI_OPERATION:
        raise OfflineCLIValidationError("prepare request operation is unsupported")
    arguments = dict(_mapping(request["prepare_arguments"], "prepare_arguments"))
    allowed, required = _prepare_signature_contract()
    if set(arguments) - allowed:
        raise OfflineCLIValidationError("prepare_arguments contain unsupported fields")
    if required - set(arguments):
        raise OfflineCLIValidationError("prepare_arguments are missing required fields")
    return arguments


def _parse_resume_request(
    text: str,
) -> tuple[workflow.PreSendWorkflowPackage, dict[str, object], bytes]:
    try:
        value = canonical.parse_json_no_duplicates(text, identity_critical=False)
    except (TypeError, ValueError, canonical.CanonicalizationError) as exc:
        raise OfflineCLIValidationError("resume request is not strict duplicate-free JSON") from exc
    request = _mapping(value, "resume request")
    if set(request) != _RESUME_TOP_LEVEL_FIELDS:
        raise OfflineCLIValidationError("resume request fields are not exact")
    if request["schema_version"] != OFFLINE_CLI_SCHEMA_VERSION:
        raise OfflineCLIValidationError("resume request schema_version is unsupported")
    if request["operation"] != RESUME_CLI_OPERATION:
        raise OfflineCLIValidationError("resume request operation is unsupported")
    prepared = workflow.validate_pre_send_workflow_package(
        workflow.PreSendWorkflowPackage.from_mapping(
            _mapping(request["prepared_workflow"], "prepared_workflow")
        )
    )
    arguments = dict(_mapping(request["resume_arguments"], "resume_arguments"))
    if "prepared_package" in arguments or "raw_provider_response" in arguments:
        raise OfflineCLIValidationError("resume discontinuities must use bounded top-level fields")
    allowed, required = _resume_signature_contract()
    if set(arguments) - allowed:
        raise OfflineCLIValidationError("resume_arguments contain unsupported fields")
    if required - set(arguments):
        raise OfflineCLIValidationError("resume_arguments are missing required fields")
    raw = _decode_raw_response(request["raw_provider_response_base64"])
    return prepared, arguments, raw


def _parse_materialize_request(text: str) -> dict[str, object]:
    try:
        value = canonical.parse_json_no_duplicates(text, identity_critical=False)
    except (TypeError, ValueError, canonical.CanonicalizationError) as exc:
        raise OfflineCLIValidationError("materialize request is not strict duplicate-free JSON") from exc
    request = _mapping(value, "materialize request")
    if set(request) != _MATERIALIZE_TOP_LEVEL_FIELDS:
        raise OfflineCLIValidationError("materialize request fields are not exact")
    if request["schema_version"] != OFFLINE_CLI_SCHEMA_VERSION:
        raise OfflineCLIValidationError("materialize request schema_version is unsupported")
    if request["operation"] != MATERIALIZE_CLI_OPERATION:
        raise OfflineCLIValidationError("materialize request operation is unsupported")
    arguments = dict(_mapping(request["materialization_arguments"], "materialization_arguments"))
    allowed, required = _materialize_signature_contract()
    if set(arguments) - allowed:
        raise OfflineCLIValidationError("materialization_arguments contain unsupported fields")
    if required - set(arguments):
        raise OfflineCLIValidationError("materialization_arguments are missing required fields")
    return arguments


def _parse_local_prepare_request(text: str) -> dict[str, object]:
    try:
        value = canonical.parse_json_no_duplicates(text, identity_critical=False)
    except (TypeError, ValueError, canonical.CanonicalizationError) as exc:
        raise OfflineCLIValidationError("local prepare request is not strict duplicate-free JSON") from exc
    request = _mapping(value, "local prepare request")
    if set(request) != _LOCAL_PREPARE_TOP_LEVEL_FIELDS:
        raise OfflineCLIValidationError("local prepare request fields are not exact")
    if request["schema_version"] != OFFLINE_CLI_SCHEMA_VERSION:
        raise OfflineCLIValidationError("local prepare request schema_version is unsupported")
    if request["operation"] != LOCAL_PREPARE_CLI_OPERATION:
        raise OfflineCLIValidationError("local prepare request operation is unsupported")
    arguments = dict(_mapping(request["local_prepare_arguments"], "local_prepare_arguments"))
    allowed, required = _local_prepare_signature_contract()
    if set(arguments) - allowed:
        raise OfflineCLIValidationError("local_prepare_arguments contain unsupported fields")
    if required - set(arguments):
        raise OfflineCLIValidationError("local_prepare_arguments are missing required fields")
    return arguments


def _result_summary(
    result: workflow.WorkflowCompositionResult,
    *,
    operation: str = OFFLINE_CLI_OPERATION,
) -> dict[str, object]:
    persistence = result.final_evidence_persistence_result
    return {
        "schema_version": OFFLINE_CLI_SCHEMA_VERSION,
        "operation": operation,
        "status": "PASS",
        "run_identity": result.run_record.run_identity,
        "request_identity": result.cloud_request_record.request_identity,
        "authorization_identity": result.cloud_execution_authorization_record.authorization_identity,
        "handoff_identity": result.cloud_execution_handoff_record.handoff_identity,
        "response_identity": result.cloud_response_record.response_identity,
        "proposal_identity": result.proposal_record.proposal_identity,
        "verification_identity": result.verification_record.verification_identity,
        "manifest_identity": result.evidence_manifest.manifest_identity,
        "final_result_identity": result.final_result.final_result_identity,
        "manifest_relative_path": persistence.manifest_relative_path,
        "manifest_content_sha256": persistence.manifest_content_sha256,
        "final_result_relative_path": persistence.final_result_relative_path,
        "final_result_content_sha256": persistence.final_result_content_sha256,
        "execution_authority": "NONE",
        "network_authority": False,
        "model_provider_authority": False,
        "human_approval_execution_authority": False,
        "state_transition_execution_authority": False,
    }


def _write_json(stream: TextIO, value: Mapping[str, object]) -> None:
    stream.write(canonical.canonical_json_bytes(value, identity_critical=False).decode("utf-8"))
    stream.flush()


def run_offline(*, stdin: TextIO, stdout: TextIO) -> workflow.WorkflowCompositionResult:
    """Execute one bounded one-shot offline composition from strict stdin JSON."""

    arguments, raw_response = _parse_request(_read_bounded_text(stdin))
    result = workflow.compose_top_level_workflow(
        **arguments,
        raw_provider_response=raw_response,
    )
    _write_json(stdout, _result_summary(result))
    return result


def run_prepare(*, stdin: TextIO, stdout: TextIO) -> workflow.PreSendWorkflowPackage:
    """Build and emit one exact pre-send package without executing transport."""

    arguments = _parse_prepare_request(_read_bounded_text(stdin))
    prepared = workflow.prepare_top_level_workflow(**arguments)
    _write_json(
        stdout,
        {
            "schema_version": OFFLINE_CLI_SCHEMA_VERSION,
            "operation": PREPARE_CLI_OPERATION,
            "status": "PASS",
            "prepared_workflow": prepared.to_dict(),
            "pre_send_identity": prepared.pre_send_identity,
            "request_identity": prepared.cloud_request_record.request_identity,
            "authorization_identity": prepared.cloud_execution_authorization_record.authorization_identity,
            "handoff_identity": prepared.cloud_execution_handoff_record.handoff_identity,
            "execution_authority": prepared.execution_authority,
            "network_authority": False,
            "model_provider_authority": False,
            "state_transition_execution_authority": False,
        },
    )
    return prepared


def run_resume(*, stdin: TextIO, stdout: TextIO) -> workflow.WorkflowCompositionResult:
    """Resume one exact pre-send package with already-obtained response bytes."""

    prepared, arguments, raw_response = _parse_resume_request(_read_bounded_text(stdin))
    result = workflow.resume_top_level_workflow(
        prepared_package=prepared,
        raw_provider_response=raw_response,
        **arguments,
    )
    _write_json(stdout, _result_summary(result, operation=RESUME_CLI_OPERATION))
    return result


def run_materialize(
    *, stdin: TextIO, stdout: TextIO
) -> tuple[materialization.PrepareInputMaterialization, workflow.PreSendWorkflowPackage]:
    """Materialize local deterministic inputs and immediately build the zero-send handoff."""

    arguments = _parse_materialize_request(_read_bounded_text(stdin))
    materialized = materialization.materialize_prepare_inputs(**arguments)
    prepared = workflow.prepare_top_level_workflow(**dict(materialized.prepare_arguments))
    _write_json(
        stdout,
        {
            "schema_version": OFFLINE_CLI_SCHEMA_VERSION,
            "operation": MATERIALIZE_CLI_OPERATION,
            "status": "PASS",
            "materialization": materialized.to_dict(),
            "materialization_identity": materialized.materialization_identity,
            "prepared_workflow": prepared.to_dict(),
            "pre_send_identity": prepared.pre_send_identity,
            "request_identity": prepared.cloud_request_record.request_identity,
            "authorization_identity": prepared.cloud_execution_authorization_record.authorization_identity,
            "handoff_identity": prepared.cloud_execution_handoff_record.handoff_identity,
            "execution_authority": prepared.execution_authority,
            "network_authority": False,
            "model_provider_authority": False,
            "state_transition_execution_authority": False,
        },
    )
    return materialized, prepared


def run_local_prepare(
    *, stdin: TextIO, stdout: TextIO
) -> local_orchestration.LocalPrepareOrchestrationResult:
    """Read one approved local source and stop at the exact zero-send handoff."""

    arguments = _parse_local_prepare_request(_read_bounded_text(stdin))
    result = local_orchestration.orchestrate_local_prepare(**arguments)
    _write_json(
        stdout,
        {
            "schema_version": OFFLINE_CLI_SCHEMA_VERSION,
            "operation": LOCAL_PREPARE_CLI_OPERATION,
            "status": "PASS",
            "orchestration": result.to_dict(),
            "orchestration_identity": result.orchestration_identity,
            "capture_identity": result.capture_identity,
            "materialization_identity": result.materialization_identity,
            "pre_send_identity": result.pre_send_identity,
            "request_identity": result.request_identity,
            "authorization_identity": result.authorization_identity,
            "handoff_identity": result.handoff_identity,
            "execution_authority": "NONE",
            "filesystem_source_read_authority": "APPROVED_ROOT_SINGLE_FILE_ONLY",
            "network_authority": False,
            "model_provider_authority": False,
            "dependency_execution_authority": False,
            "state_transition_execution_authority": False,
        },
    )
    return result


def main(
    argv: Sequence[str] | None = None,
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Run only explicit bounded offline commands; all other CLI use fails closed."""

    args = tuple(sys.argv[1:] if argv is None else argv)
    operations = {
        (OFFLINE_CLI_COMMAND,): (OFFLINE_CLI_OPERATION, run_offline),
        (PREPARE_CLI_COMMAND,): (PREPARE_CLI_OPERATION, run_prepare),
        (RESUME_CLI_COMMAND,): (RESUME_CLI_OPERATION, run_resume),
        (MATERIALIZE_CLI_COMMAND,): (MATERIALIZE_CLI_OPERATION, run_materialize),
        (LOCAL_PREPARE_CLI_COMMAND,): (LOCAL_PREPARE_CLI_OPERATION, run_local_prepare),
    }
    selected = operations.get(args)
    if selected is None:
        phase_not_implemented("cli")
    operation, runner = selected

    input_stream = sys.stdin if stdin is None else stdin
    output_stream = sys.stdout if stdout is None else stdout
    error_stream = sys.stderr if stderr is None else stderr
    try:
        runner(stdin=input_stream, stdout=output_stream)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        _write_json(
            error_stream,
            {
                "schema_version": OFFLINE_CLI_SCHEMA_VERSION,
                "operation": operation,
                "status": "FAIL_CLOSED",
                "error_type": type(exc).__name__,
            },
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "OfflineCLIValidationError",
    "run_offline",
    "run_prepare",
    "run_resume",
    "run_materialize",
    "run_local_prepare",
    "main",
    "OFFLINE_CLI_SCHEMA_VERSION",
    "OFFLINE_CLI_OPERATION",
    "OFFLINE_CLI_COMMAND",
    "PREPARE_CLI_OPERATION",
    "PREPARE_CLI_COMMAND",
    "RESUME_CLI_OPERATION",
    "RESUME_CLI_COMMAND",
    "MATERIALIZE_CLI_OPERATION",
    "MATERIALIZE_CLI_COMMAND",
    "LOCAL_PREPARE_CLI_OPERATION",
    "LOCAL_PREPARE_CLI_COMMAND",
    "OFFLINE_CLI_IMPLEMENTATION_COUNT",
    "TWO_STEP_CLI_IMPLEMENTATION_COUNT",
    "MATERIALIZATION_CLI_IMPLEMENTATION_COUNT",
    "LOCAL_PREPARE_CLI_IMPLEMENTATION_COUNT",
    "LOCAL_SOURCE_READ_DELEGATION_COUNT",
    "OFFLINE_CLI_INPUT_TRANSPORT",
    "OFFLINE_CLI_RAW_RESPONSE_ENCODING",
    "OFFLINE_CLI_MAX_INPUT_BYTES",
    "OFFLINE_CLI_MAX_RAW_RESPONSE_BYTES",
    "NETWORK_IMPLEMENTATION_COUNT",
    "PROVIDER_CLIENT_IMPLEMENTATION_COUNT",
    "MODEL_CALL_IMPLEMENTATION_COUNT",
    "MODEL_ROUTING_IMPLEMENTATION_COUNT",
    "AUTH_IMPLEMENTATION_COUNT",
    "AUTO_RETRY_IMPLEMENTATION_COUNT",
    "AUTO_FALLBACK_IMPLEMENTATION_COUNT",
    "HUMAN_APPROVAL_EXECUTION_COUNT",
    "HUMAN_DECISION_SIDE_EFFECT_COUNT",
    "STATE_TRANSITION_EXECUTION_COUNT",
    "GIT_OPERATION_COUNT",
    "DIRECT_FILESYSTEM_READ_COUNT",
    "DIRECT_FILESYSTEM_WRITE_COUNT",
]
