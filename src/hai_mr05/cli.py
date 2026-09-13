"""Bounded offline pre-live command-line entrypoint.

The explicit ``offline`` command accepts one JSON request on stdin, admits an
already-obtained provider response as exact base64 bytes, and delegates exactly
once to the qualified deterministic top-level workflow.  It performs no
network/provider/model/auth operation, retry, fallback, Human approval
execution, autonomous state transition, Git mutation, or direct source/evidence
filesystem access.  Final evidence publication remains owned by the existing
qualified workflow/evidence boundary.

Calling ``main()`` without the explicit ``offline`` command preserves the
historical fail-closed CLI compatibility behavior.
"""

from __future__ import annotations

import base64
import binascii
import inspect
import sys
from collections.abc import Mapping, Sequence
from typing import TextIO

from . import canonical, workflow
from .failures import phase_not_implemented

OFFLINE_CLI_SCHEMA_VERSION = "1.0.0"
OFFLINE_CLI_OPERATION = "OFFLINE_COMPOSE_PREOBTAINED_RESPONSE"
OFFLINE_CLI_COMMAND = "offline"
OFFLINE_CLI_IMPLEMENTATION_COUNT = 1
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


def _result_summary(result: workflow.WorkflowCompositionResult) -> dict[str, object]:
    persistence = result.final_evidence_persistence_result
    return {
        "schema_version": OFFLINE_CLI_SCHEMA_VERSION,
        "operation": OFFLINE_CLI_OPERATION,
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
    """Execute one bounded offline composition from strict stdin JSON."""

    arguments, raw_response = _parse_request(_read_bounded_text(stdin))
    result = workflow.compose_top_level_workflow(
        **arguments,
        raw_provider_response=raw_response,
    )
    _write_json(stdout, _result_summary(result))
    return result


def main(
    argv: Sequence[str] | None = None,
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Run only the explicit bounded offline command; all other CLI use fails closed."""

    args = tuple(sys.argv[1:] if argv is None else argv)
    if args != (OFFLINE_CLI_COMMAND,):
        phase_not_implemented("cli")

    input_stream = sys.stdin if stdin is None else stdin
    output_stream = sys.stdout if stdout is None else stdout
    error_stream = sys.stderr if stderr is None else stderr
    try:
        run_offline(stdin=input_stream, stdout=output_stream)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        _write_json(
            error_stream,
            {
                "schema_version": OFFLINE_CLI_SCHEMA_VERSION,
                "operation": OFFLINE_CLI_OPERATION,
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
    "main",
    "OFFLINE_CLI_SCHEMA_VERSION",
    "OFFLINE_CLI_OPERATION",
    "OFFLINE_CLI_COMMAND",
    "OFFLINE_CLI_IMPLEMENTATION_COUNT",
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
