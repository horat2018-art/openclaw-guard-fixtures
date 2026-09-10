"""Pure-data composition of the qualified deterministic HAI MR-05 workflow.

This module binds already-qualified local records and delegates final-evidence
publication to the qualified evidence boundary. It does not execute a provider,
model, Human decision, state transition, retry, fallback, or other external action.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from . import cloud_boundary, evidence, human_gate, proposal, verifier
from .identity import sha256_bytes


WORKFLOW_COMPOSITION_IMPLEMENTATION_COUNT = 1
WORKFLOW_EXECUTION_COUNT = 0
LIVE_CLOUD_EXECUTION_COUNT = 0
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
FILESYSTEM_SOURCE_READ_COUNT = 0
FILESYSTEM_WRITE_IMPLEMENTATION_COUNT = 0
SUBPROCESS_EXECUTION_COUNT = 0
GIT_OPERATION_COUNT = 0

_HUMAN_TERMINAL_STATES = {
    "HUMAN_APPROVED",
    "HUMAN_REJECTED",
    "HUMAN_REWORK",
    "HUMAN_MORE_EVIDENCE",
}
_VERIFIED_TERMINAL_STATES = {
    "VERIFIED_DENY",
    "VERIFIED_ESCALATE",
    "VERIFIED_PASS_FOR_REVIEW",
}


class WorkflowCompositionError(ValueError):
    """Fail-closed error for composition-only invariants."""


@dataclass(frozen=True, slots=True)
class WorkflowCompositionResult:
    """Deterministic aggregate of the qualified records produced by composition."""

    run_record: evidence.FrozenRunRecord
    cloud_context_record: cloud_boundary.CloudContext
    cloud_request_record: cloud_boundary.CloudRequest
    cloud_execution_authorization_record: cloud_boundary.CloudExecutionAuthorization
    cloud_response_record: cloud_boundary.CloudResponse
    proposal_record: proposal.CloudProposal
    verification_record: verifier.VerificationRecord
    human_gate_record: human_gate.HumanGateRecord | None
    human_decision_record: human_gate.HumanDecisionRecord | None
    evidence_manifest: evidence.FrozenEvidenceManifest
    final_result: evidence.FinalResultRecord
    final_evidence_persistence_result: evidence.FinalEvidencePersistenceResult


def _qualified_frozen_run(value: object) -> evidence.FrozenRunRecord:
    if isinstance(value, evidence.RunRecord):
        raise WorkflowCompositionError(
            "legacy controller RunRecord is not an authoritative FrozenRunRecord"
        )
    try:
        if isinstance(value, evidence.FrozenRunRecord):
            return evidence.FrozenRunRecord.from_mapping(value.to_dict())
        if isinstance(value, Mapping):
            return evidence.FrozenRunRecord.from_mapping(value)
    except evidence.EvidenceValidationError as exc:
        raise WorkflowCompositionError(
            "run_record is not an exact qualified FrozenRunRecord"
        ) from exc
    raise WorkflowCompositionError(
        "run_record must be an exact qualified FrozenRunRecord"
    )


def _cloud_budget(run: evidence.FrozenRunRecord) -> dict[str, object]:
    return {
        "budget_identity": run.byte_budget["budget_identity"],
        "max_cloud_context_bytes": run.byte_budget["max_cloud_context_bytes"],
        "overflow_policy": run.byte_budget["overflow_policy"],
        "silent_truncation": run.byte_budget["silent_truncation"],
    }


def _qualified_gate(value: object | None) -> human_gate.HumanGateRecord | None:
    if value is None:
        return None
    if isinstance(value, human_gate.HumanGateRecord):
        return human_gate.HumanGateRecord.from_mapping(value.to_dict())
    return human_gate.HumanGateRecord.from_mapping(value)


def _qualified_decision(
    value: object | None,
    gate: human_gate.HumanGateRecord | None,
) -> human_gate.HumanDecisionRecord | None:
    if value is None:
        return None
    if gate is None:
        raise WorkflowCompositionError(
            "human_decision_record requires an explicit qualified Human Gate"
        )
    payload = value.to_dict() if isinstance(value, human_gate.HumanDecisionRecord) else value
    return human_gate.HumanDecisionRecord.from_mapping(payload, human_gate=gate)


def _validate_remaining_proposal_bindings(
    record: proposal.CloudProposal,
    *,
    run: evidence.FrozenRunRecord,
) -> None:
    expected = {
        "task_identity": run.task_identity,
        "bound_mr03_package_identity": run.mr03_result_identity,
        "bound_mr04_result_identity": run.mr04_result_identity,
    }
    for field, expected_value in expected.items():
        if getattr(record, field) != expected_value:
            raise WorkflowCompositionError(
                f"proposal {field} is not bound to the composed deterministic chain"
            )


def _transport_evidence_artifacts(
    authorization: cloud_boundary.CloudExecutionAuthorization,
    response: cloud_boundary.CloudResponse,
    admitted_proposal: proposal.CloudProposal,
    raw_provider_response: bytes,
) -> tuple[evidence.FrozenEvidenceArtifact, ...]:
    authorization_bytes = authorization.canonical_bytes()
    response_bytes = response.canonical_bytes()
    return (
        evidence.FrozenEvidenceArtifact(
            relative_path="cloud/execution_authorization.json",
            byte_size=len(authorization_bytes),
            sha256=sha256_bytes(authorization_bytes),
            artifact_type=cloud_boundary.CLOUD_EXECUTION_AUTHORIZATION_SCHEMA_ID,
            schema_version=authorization.schema_version,
        ),
        evidence.FrozenEvidenceArtifact(
            relative_path="cloud/response.json",
            byte_size=len(response_bytes),
            sha256=sha256_bytes(response_bytes),
            artifact_type=cloud_boundary.CLOUD_RESPONSE_SCHEMA_ID,
            schema_version=response.schema_version,
        ),
        evidence.FrozenEvidenceArtifact(
            relative_path="cloud/response.raw.json",
            byte_size=len(raw_provider_response),
            sha256=response.raw_response_sha256,
            artifact_type=proposal.PROPOSAL_SCHEMA_ID,
            schema_version=admitted_proposal.schema_version,
        ),
    )


def _validate_human_bindings(
    *,
    run: evidence.FrozenRunRecord,
    proposal_record: proposal.CloudProposal,
    verification_record: verifier.VerificationRecord,
    gate: human_gate.HumanGateRecord | None,
    decision: human_gate.HumanDecisionRecord | None,
) -> None:
    if run.state in _HUMAN_TERMINAL_STATES and (gate is None or decision is None):
        raise WorkflowCompositionError(
            "human terminal state requires explicit Human Gate and Human Decision records"
        )
    if run.state in _VERIFIED_TERMINAL_STATES and (gate is not None or decision is not None):
        raise WorkflowCompositionError(
            "verified terminal state cannot silently consume Human Gate or Human Decision records"
        )
    if gate is None:
        return
    expected = {
        "run_identity": run.run_identity,
        "task_identity": proposal_record.task_identity,
        "proposal_identity": proposal_record.proposal_identity,
        "verification_identity": verification_record.verification_identity,
        "package_identity": proposal_record.bound_package_identity,
        "context_identity": proposal_record.bound_context_identity,
        "verification_result": verification_record.verification_result,
    }
    for field, expected_value in expected.items():
        if getattr(gate, field) != expected_value:
            raise WorkflowCompositionError(
                f"Human Gate {field} is not bound to the composed deterministic chain"
            )


def compose_top_level_workflow(
    *,
    run_record: object,
    bounded_context_record: object,
    disclosure_record: object,
    metrics_record: object,
    model_identifier: object,
    human_authorization_reference: object,
    estimated_token_metadata: Mapping[str, object],
    cloud_execution_authorization_record: object,
    cloud_response_record: object,
    raw_provider_response: bytes,
    legacy_verifier_result: object,
    verification_record: object,
    approved_root: object,
    manifest_relative_path: object,
    final_result_relative_path: object,
    verifier_failure_records: object = (),
    human_gate_record: object | None = None,
    human_decision_record: object | None = None,
    failure_record: object | None = None,
    prohibited_assumptions: object = (),
    context_observational_metadata: Mapping[str, object] | None = None,
    request_observational_metadata: Mapping[str, object] | None = None,
    manifest_observational_metadata: Mapping[str, object] | None = None,
    final_observational_metadata: Mapping[str, object] | None = None,
) -> WorkflowCompositionResult:
    """Compose supplied deterministic records without executing external authority.

    Cloud execution authorization, provider response data, raw provider-response
    bytes, Human Decision data, and final-evidence destination data are explicit
    discontinuity inputs. The function never executes a model/provider call and never
    makes a Human decision. Final-evidence publication is delegated exactly once to the
    qualified evidence persistence boundary. A supplied
    run must be the authoritative FrozenRunRecord shape; the
    legacy controller RunRecord is intentionally not bridged or coerced.
    """

    run = _qualified_frozen_run(run_record)
    context = cloud_boundary.admit_cloud_context(
        bounded_context_record,
        disclosure_record,
        run_identity=run.run_identity,
        mr03_package_identity=run.mr03_result_identity,
        mr04_result_identity=run.mr04_result_identity,
        byte_budget=_cloud_budget(run),
        estimated_token_metadata=estimated_token_metadata,
        prohibited_assumptions=prohibited_assumptions,
        observational_metadata=context_observational_metadata,
    )
    request = cloud_boundary.build_cloud_request(
        context,
        model_identifier=model_identifier,
        human_authorization_reference=human_authorization_reference,
        observational_metadata=request_observational_metadata,
    )

    authorization = cloud_boundary.validate_cloud_execution_authorization(
        cloud_execution_authorization_record, request
    )
    response = cloud_boundary.validate_cloud_response_binding(
        cloud_response_record, request, authorization
    )
    admitted_proposal = proposal.admit_cloud_response_proposal(
        raw_provider_response, response, request, authorization
    )
    _validate_remaining_proposal_bindings(admitted_proposal, run=run)
    supplied_verification = verifier.validate_verification_adapter(
        verification_record,
        proposal=admitted_proposal,
        context=context,
        legacy_result=legacy_verifier_result,
        failure_records=verifier_failure_records,
    )
    gate = _qualified_gate(human_gate_record)
    decision = _qualified_decision(human_decision_record, gate)
    _validate_human_bindings(
        run=run,
        proposal_record=admitted_proposal,
        verification_record=supplied_verification,
        gate=gate,
        decision=decision,
    )

    evidence_args = {
        "run_record": run,
        "bounded_context_record": bounded_context_record,
        "disclosure_record": disclosure_record,
        "cloud_context_record": context,
        "cloud_request_record": request,
        "proposal_record": admitted_proposal,
        "verification_record": supplied_verification,
        "metrics_record": metrics_record,
        "legacy_verifier_result": legacy_verifier_result,
        "verifier_failure_records": verifier_failure_records,
        "human_gate_record": gate,
        "human_decision_record": decision,
        "failure_record": failure_record,
    }
    transport_artifacts = _transport_evidence_artifacts(
        authorization, response, admitted_proposal, raw_provider_response
    )
    manifest = evidence.build_pre_final_evidence_manifest(
        **evidence_args,
        additional_artifacts=transport_artifacts,
        observational_metadata=manifest_observational_metadata,
    )
    final_result = evidence.build_final_result(
        terminal_state=run.state,
        manifest=manifest,
        **evidence_args,
        observational_metadata=final_observational_metadata,
    )
    persistence_result = evidence.persist_final_evidence_records(
        approved_root=approved_root,
        manifest_relative_path=manifest_relative_path,
        final_result_relative_path=final_result_relative_path,
        manifest=manifest,
        final_result=final_result,
        **evidence_args,
    )
    return WorkflowCompositionResult(
        run_record=run,
        cloud_context_record=context,
        cloud_request_record=request,
        cloud_execution_authorization_record=authorization,
        cloud_response_record=response,
        proposal_record=admitted_proposal,
        verification_record=supplied_verification,
        human_gate_record=gate,
        human_decision_record=decision,
        evidence_manifest=manifest,
        final_result=final_result,
        final_evidence_persistence_result=persistence_result,
    )


__all__ = [
    "WorkflowCompositionError",
    "WorkflowCompositionResult",
    "compose_top_level_workflow",
    "WORKFLOW_COMPOSITION_IMPLEMENTATION_COUNT",
    "WORKFLOW_EXECUTION_COUNT",
    "LIVE_CLOUD_EXECUTION_COUNT",
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
]