"""Pure-data composition of the qualified deterministic HAI MR-05 workflow.

This module binds already-qualified local records and delegates final-evidence
publication to the qualified evidence boundary. It does not execute a provider,
model, Human decision, state transition, retry, fallback, or other external action.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from . import cloud_boundary, context_builder, disclosure, evidence, human_gate, metrics, proposal, verifier
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
    cloud_execution_handoff_record: cloud_boundary.CloudExecutionHandoff
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


def _qualified_bounded_context(value: object) -> context_builder.BoundedContextPackage:
    try:
        if isinstance(value, context_builder.BoundedContextPackage):
            return context_builder.BoundedContextPackage.from_mapping(value.to_dict())
        if isinstance(value, Mapping):
            return context_builder.BoundedContextPackage.from_mapping(value)
    except context_builder.ContextBuildValidationError as exc:
        raise WorkflowCompositionError(
            "bounded_context_record is not an exact qualified BoundedContextPackage"
        ) from exc
    raise WorkflowCompositionError(
        "bounded_context_record must be an exact qualified BoundedContextPackage"
    )


def _cloud_budget(run: evidence.FrozenRunRecord) -> dict[str, object]:
    return {
        "budget_identity": run.byte_budget["budget_identity"],
        "max_cloud_context_bytes": run.byte_budget["max_cloud_context_bytes"],
        "overflow_policy": run.byte_budget["overflow_policy"],
        "silent_truncation": run.byte_budget["silent_truncation"],
    }


def _construct_human_gate(
    *,
    run: evidence.FrozenRunRecord,
    context: cloud_boundary.CloudContext,
    proposal_record: proposal.CloudProposal,
    verification_record: verifier.VerificationRecord,
    task_summary: object | None,
    proposal_summary: object | None,
    uncertainties: object | None,
    evidence_pointers: object | None,
    observational_metadata: Mapping[str, object] | None,
) -> human_gate.HumanGateRecord | None:
    construction_material = (
        task_summary,
        proposal_summary,
        uncertainties,
        evidence_pointers,
    )
    any_material = any(value is not None for value in construction_material)
    any_material = any_material or observational_metadata is not None

    if run.state in _VERIFIED_TERMINAL_STATES:
        if any_material:
            raise WorkflowCompositionError(
                "verified terminal state cannot consume Human Gate construction material"
            )
        return None
    if run.state not in _HUMAN_TERMINAL_STATES:
        if any_material:
            raise WorkflowCompositionError(
                "non-human terminal state cannot consume Human Gate construction material"
            )
        return None
    if any(value is None for value in construction_material):
        raise WorkflowCompositionError(
            "human terminal state requires complete Human Gate construction material"
        )

    fields: dict[str, object] = {
        "run_identity": run.run_identity,
        "task_identity": proposal_record.task_identity,
        "proposal_identity": proposal_record.proposal_identity,
        "verification_identity": verification_record.verification_identity,
        "package_identity": proposal_record.bound_package_identity,
        "context_identity": context.context_identity,
        "task_summary": task_summary,
        "proposal_summary": proposal_summary,
        "verification_result": verification_record.verification_result,
        "reason_codes": verification_record.reason_codes,
        "source_refs": tuple(
            ref.to_dict() for ref in verification_record.verified_source_refs
        ),
        "uncertainties": uncertainties,
        "evidence_pointers": evidence_pointers,
    }
    if observational_metadata is not None:
        fields["observational_metadata"] = observational_metadata
    try:
        return human_gate.build_human_gate(**fields)
    except human_gate.HumanGateValidationError as exc:
        raise WorkflowCompositionError(
            "Human Gate construction failed closed"
        ) from exc


def _construct_human_decision(
    *,
    run: evidence.FrozenRunRecord,
    gate: human_gate.HumanGateRecord | None,
    decision: object | None,
    decision_reason: object | None,
    decision_scope: object | None,
    human_authority_reference: object | None,
    observational_metadata: Mapping[str, object] | None,
) -> human_gate.HumanDecisionRecord | None:
    construction_material = (
        decision,
        decision_reason,
        decision_scope,
        human_authority_reference,
    )
    any_material = any(value is not None for value in construction_material)
    any_material = any_material or observational_metadata is not None

    if run.state in _VERIFIED_TERMINAL_STATES:
        if any_material:
            raise WorkflowCompositionError(
                "verified terminal state cannot consume Human Decision construction material"
            )
        return None
    if run.state not in _HUMAN_TERMINAL_STATES:
        if any_material:
            raise WorkflowCompositionError(
                "non-human terminal state cannot consume Human Decision construction material"
            )
        return None
    if gate is None:
        raise WorkflowCompositionError(
            "human terminal state requires a qualified Human Gate before Human Decision construction"
        )
    if any(value is None for value in construction_material):
        raise WorkflowCompositionError(
            "human terminal state requires complete Human Decision construction material"
        )

    fields: dict[str, object] = {
        "decision": decision,
        "decision_reason": decision_reason,
        "decision_scope": decision_scope,
        "human_authority_reference": human_authority_reference,
    }
    if observational_metadata is not None:
        fields["observational_metadata"] = observational_metadata
    try:
        return human_gate.build_human_decision(
            human_gate=gate,
            **fields,
        )
    except human_gate.HumanGateValidationError as exc:
        raise WorkflowCompositionError(
            "Human Decision construction failed closed"
        ) from exc


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
    handoff: cloud_boundary.CloudExecutionHandoff,
    response: cloud_boundary.CloudResponse,
    admitted_proposal: proposal.CloudProposal,
    raw_provider_response: bytes,
) -> tuple[evidence.FrozenEvidenceArtifact, ...]:
    authorization_bytes = authorization.canonical_bytes()
    handoff_bytes = handoff.canonical_bytes()
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
            relative_path="cloud/execution_handoff.json",
            byte_size=len(handoff_bytes),
            sha256=sha256_bytes(handoff_bytes),
            artifact_type=cloud_boundary.CLOUD_EXECUTION_HANDOFF_SCHEMA_ID,
            schema_version=handoff.schema_version,
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
            "human terminal state requires constructed Human Gate and Human Decision records"
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
    disclosure_classification: object,
    disclosure_findings: object,
    disclosure_observational_metadata: object | None,
    metrics_raw_source_bytes: object,
    metrics_normalized_bytes: object,
    metrics_package_bytes: object,
    metrics_cloud_context_bytes: object,
    metrics_raw_estimated_tokens: object,
    metrics_cloud_estimated_tokens: object,
    metrics_model_call_count: object,
    metrics_model_retry_count: object,
    metrics_failure_count: object,
    metrics_source_ref_count: object,
    metrics_missing_source_ref_count: object,
    metrics_identity_mismatch_count: object,
    metrics_observational_metadata: Mapping[str, object] | None,
    model_identifier: object,
    human_authorization_reference: object,
    estimated_token_metadata: Mapping[str, object],
    authorized_provider_identifier: object,
    authorized_account_boundary_reference: object,
    authorization_observational_metadata: Mapping[str, object] | None,
    raw_provider_response: bytes,
    provider_identifier: object,
    actual_model_identifier: object,
    provider_request_id: object,
    account_boundary_reference: object,
    provider_usage_if_available: Mapping[str, object] | None,
    error_metadata: Mapping[str, object] | None,
    legacy_verifier_checks: object,
    verification_result: object,
    verification_reason_codes: object,
    verification_reason_details: object,
    verification_verified_source_refs: object,
    verification_unsupported_claims: object,
    verification_missing_refs: object,
    verification_protected_content_findings: object,
    verification_identity_findings: object,
    verification_observational_metadata: Mapping[str, object] | None,
    approved_root: object,
    manifest_relative_path: object,
    final_result_relative_path: object,
    verifier_failure_records: object = (),
    human_gate_task_summary: object | None = None,
    human_gate_proposal_summary: object | None = None,
    human_gate_uncertainties: object | None = None,
    human_gate_evidence_pointers: object | None = None,
    human_gate_observational_metadata: Mapping[str, object] | None = None,
    human_decision: object | None = None,
    human_decision_reason: object | None = None,
    human_decision_scope: object | None = None,
    human_decision_authority_reference: object | None = None,
    human_decision_observational_metadata: Mapping[str, object] | None = None,
    failure_record: object | None = None,
    prohibited_assumptions: object = (),
    context_observational_metadata: Mapping[str, object] | None = None,
    request_observational_metadata: Mapping[str, object] | None = None,
    manifest_observational_metadata: Mapping[str, object] | None = None,
    final_observational_metadata: Mapping[str, object] | None = None,
) -> WorkflowCompositionResult:
    """Compose supplied deterministic records without executing external authority.

    Authorized provider/account intent, already-obtained raw provider-response bytes,
    non-secret actual transport metadata, explicit disclosure metadata, explicit metric
    counters, explicit legacy-verifier checks, explicit public-verification semantic material,
    Human Gate presentation/evidence material, Human Decision material, and final-evidence
    destination data are explicit discontinuity inputs. Disclosure, Metrics, legacy
    VerifierResult, Public Verification, Human Gate, and Human Decision record construction is
    deterministic; legacy checks and public-verification semantics remain caller-supplied and
    are qualified against the authoritative chain. The function
    never executes a model/provider call or external transport, never generates verification
    findings, never chooses a Human decision, and never performs a state transition.
    Final-evidence publication is delegated exactly once to the
    qualified evidence persistence boundary. A supplied
    run must be the authoritative FrozenRunRecord shape; the
    legacy controller RunRecord is intentionally not bridged or coerced.
    """

    run = _qualified_frozen_run(run_record)
    bounded_context = _qualified_bounded_context(bounded_context_record)
    constructed_metrics = metrics.build_metrics(
        raw_source_bytes=metrics_raw_source_bytes,
        normalized_bytes=metrics_normalized_bytes,
        package_bytes=metrics_package_bytes,
        cloud_context_bytes=metrics_cloud_context_bytes,
        raw_estimated_tokens=metrics_raw_estimated_tokens,
        cloud_estimated_tokens=metrics_cloud_estimated_tokens,
        model_call_count=metrics_model_call_count,
        model_retry_count=metrics_model_retry_count,
        failure_count=metrics_failure_count,
        source_ref_count=metrics_source_ref_count,
        missing_source_ref_count=metrics_missing_source_ref_count,
        identity_mismatch_count=metrics_identity_mismatch_count,
        observational_metadata=metrics_observational_metadata,
    )
    if constructed_metrics.metrics_identity != bounded_context.metrics_identity:
        raise WorkflowCompositionError(
            "constructed Metrics are not bound to the qualified BoundedContextPackage"
        )
    constructed_disclosure = disclosure.build_disclosure(
        classification=disclosure_classification,
        findings=disclosure_findings,
        observational_metadata=disclosure_observational_metadata,
    )
    context = cloud_boundary.admit_cloud_context(
        bounded_context,
        constructed_disclosure,
        run_identity=run.run_identity,
        mr03_package_identity=run.mr03_result_identity,
        mr04_result_identity=run.mr04_result_identity,
        byte_budget=_cloud_budget(run),
        estimated_token_metadata=estimated_token_metadata,
        prohibited_assumptions=prohibited_assumptions,
        observational_metadata=context_observational_metadata,
    )
    legacy_input_identities = dict(bounded_context.input_identities)
    legacy_input_identities["context_identity"] = context.context_identity
    constructed_legacy_verifier = verifier.build_verifier_result(
        input_identities=legacy_input_identities,
        dependency_binding_identities=bounded_context.dependency_binding_identities,
        provenance_identity=bounded_context.provenance_identity,
        metrics_identity=constructed_metrics.metrics_identity,
        contract_identities=verifier.FROZEN_CONTRACT_IDENTITIES,
        checks=legacy_verifier_checks,
        failure_records=verifier_failure_records,
    )
    request = cloud_boundary.build_cloud_request(
        context,
        model_identifier=model_identifier,
        human_authorization_reference=human_authorization_reference,
        observational_metadata=request_observational_metadata,
    )

    authorization = cloud_boundary.build_cloud_execution_authorization(
        request,
        provider_identifier=authorized_provider_identifier,
        account_boundary_reference=authorized_account_boundary_reference,
        observational_metadata=authorization_observational_metadata,
    )
    handoff = cloud_boundary.build_cloud_execution_handoff(request, authorization)
    response = cloud_boundary.adapt_governed_external_transport_response(
        request,
        authorization,
        raw_provider_response=raw_provider_response,
        provider_identifier=provider_identifier,
        actual_model_identifier=actual_model_identifier,
        provider_request_id=provider_request_id,
        account_boundary_reference=account_boundary_reference,
        provider_usage_if_available=provider_usage_if_available,
        error_metadata=error_metadata,
    )
    admitted_proposal = proposal.admit_cloud_response_proposal(
        raw_provider_response, response, request, authorization
    )
    _validate_remaining_proposal_bindings(admitted_proposal, run=run)
    constructed_verification = verifier.build_verification_record(
        proposal=admitted_proposal,
        verification_result=verification_result,
        reason_codes=verification_reason_codes,
        reason_details=verification_reason_details,
        verified_source_refs=verification_verified_source_refs,
        unsupported_claims=verification_unsupported_claims,
        missing_refs=verification_missing_refs,
        protected_content_findings=verification_protected_content_findings,
        identity_findings=verification_identity_findings,
        observational_metadata=verification_observational_metadata,
    )
    supplied_verification = verifier.validate_verification_adapter(
        constructed_verification,
        proposal=admitted_proposal,
        context=context,
        legacy_result=constructed_legacy_verifier,
        failure_records=verifier_failure_records,
    )
    gate = _construct_human_gate(
        run=run,
        context=context,
        proposal_record=admitted_proposal,
        verification_record=supplied_verification,
        task_summary=human_gate_task_summary,
        proposal_summary=human_gate_proposal_summary,
        uncertainties=human_gate_uncertainties,
        evidence_pointers=human_gate_evidence_pointers,
        observational_metadata=human_gate_observational_metadata,
    )
    decision = _construct_human_decision(
        run=run,
        gate=gate,
        decision=human_decision,
        decision_reason=human_decision_reason,
        decision_scope=human_decision_scope,
        human_authority_reference=human_decision_authority_reference,
        observational_metadata=human_decision_observational_metadata,
    )
    _validate_human_bindings(
        run=run,
        proposal_record=admitted_proposal,
        verification_record=supplied_verification,
        gate=gate,
        decision=decision,
    )

    evidence_args = {
        "run_record": run,
        "bounded_context_record": bounded_context,
        "disclosure_record": constructed_disclosure,
        "cloud_context_record": context,
        "cloud_request_record": request,
        "proposal_record": admitted_proposal,
        "verification_record": supplied_verification,
        "metrics_record": constructed_metrics,
        "legacy_verifier_result": constructed_legacy_verifier,
        "verifier_failure_records": verifier_failure_records,
        "human_gate_record": gate,
        "human_decision_record": decision,
        "failure_record": failure_record,
    }
    transport_artifacts = _transport_evidence_artifacts(
        authorization, handoff, response, admitted_proposal, raw_provider_response
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
        cloud_execution_handoff_record=handoff,
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