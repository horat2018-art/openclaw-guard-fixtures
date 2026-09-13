"""Pure-data composition of the qualified deterministic HAI MR-05 workflow.

This module binds already-qualified local records and delegates final-evidence
publication to the qualified evidence boundary. It does not execute a provider,
model, Human decision, state transition, retry, fallback, or other external action.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from . import cloud_boundary, context_builder, disclosure, evidence, failures, human_gate, metrics, proposal, verifier
from .canonical import canonical_json_bytes
from .identity import sha256_bytes


WORKFLOW_COMPOSITION_IMPLEMENTATION_COUNT = 1
WORKFLOW_COMPOSITION_VALIDATION_IMPLEMENTATION_COUNT = 1
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
PRE_SEND_PREPARATION_IMPLEMENTATION_COUNT = 1
TWO_STEP_RESUME_IMPLEMENTATION_COUNT = 1
PRE_SEND_WORKFLOW_SCHEMA_VERSION = "1.0.0"
PRE_SEND_EXECUTION_AUTHORITY = "NONE"

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
    bounded_context_record: context_builder.BoundedContextPackage
    disclosure_record: disclosure.DisclosureRecord
    metrics_record: metrics.Metrics
    legacy_verifier_result: verifier.VerifierResult
    verifier_failure_records: tuple[object, ...]
    failure_record: object | None
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


@dataclass(frozen=True, slots=True)
class PreSendWorkflowPackage:
    """Serializable zero-send package that binds the exact pre-transport chain."""

    schema_version: str
    run_record: evidence.FrozenRunRecord
    bounded_context_record: context_builder.BoundedContextPackage
    disclosure_record: disclosure.DisclosureRecord
    metrics_record: metrics.Metrics
    legacy_verifier_result: verifier.VerifierResult
    verifier_failure_records: tuple[failures.Failure, ...]
    cloud_context_record: cloud_boundary.CloudContext
    cloud_request_record: cloud_boundary.CloudRequest
    cloud_execution_authorization_record: cloud_boundary.CloudExecutionAuthorization
    cloud_execution_handoff_record: cloud_boundary.CloudExecutionHandoff
    execution_authority: str
    pre_send_identity: str

    def __post_init__(self) -> None:
        if self.schema_version != PRE_SEND_WORKFLOW_SCHEMA_VERSION:
            raise WorkflowCompositionError("pre-send workflow schema_version is unsupported")
        if self.execution_authority != PRE_SEND_EXECUTION_AUTHORITY:
            raise WorkflowCompositionError("pre-send workflow execution authority must remain NONE")
        computed = sha256_bytes(
            canonical_json_bytes(self.identity_payload(), identity_critical=False)
        )
        if self.pre_send_identity != computed:
            raise WorkflowCompositionError("pre-send workflow identity does not match exact package bytes")

    def identity_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "run_record": self.run_record.to_dict(),
            "bounded_context_record": self.bounded_context_record.to_dict(),
            "disclosure_record": self.disclosure_record.to_dict(),
            "metrics_record": self.metrics_record.to_dict(),
            "legacy_verifier_result": self.legacy_verifier_result.to_dict(),
            "verifier_failure_records": [item.to_dict() for item in self.verifier_failure_records],
            "cloud_context_record": self.cloud_context_record.to_dict(),
            "cloud_request_record": self.cloud_request_record.to_dict(),
            "cloud_execution_authorization_record": self.cloud_execution_authorization_record.to_dict(),
            "cloud_execution_handoff_record": self.cloud_execution_handoff_record.to_dict(),
            "execution_authority": self.execution_authority,
        }

    def to_dict(self) -> dict[str, object]:
        result = self.identity_payload()
        result["pre_send_identity"] = self.pre_send_identity
        return result

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict(), identity_critical=False)

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "PreSendWorkflowPackage":
        required = {
            "schema_version",
            "run_record",
            "bounded_context_record",
            "disclosure_record",
            "metrics_record",
            "legacy_verifier_result",
            "verifier_failure_records",
            "cloud_context_record",
            "cloud_request_record",
            "cloud_execution_authorization_record",
            "cloud_execution_handoff_record",
            "execution_authority",
            "pre_send_identity",
        }
        if not isinstance(value, Mapping) or set(value) != required:
            raise WorkflowCompositionError("pre-send workflow fields are not exact")
        raw_failures = value["verifier_failure_records"]
        if isinstance(raw_failures, (str, bytes)) or not isinstance(raw_failures, (list, tuple)):
            raise WorkflowCompositionError("pre-send verifier failure records must be an array")
        try:
            failure_records = tuple(
                item if isinstance(item, failures.Failure) else failures.Failure.from_mapping(item)
                for item in raw_failures
            )
            legacy = verifier.VerifierResult.from_mapping(
                value["legacy_verifier_result"], failure_records=failure_records
            )
            return cls(
                schema_version=value["schema_version"],
                run_record=evidence.FrozenRunRecord.from_mapping(value["run_record"]),
                bounded_context_record=context_builder.BoundedContextPackage.from_mapping(
                    value["bounded_context_record"]
                ),
                disclosure_record=disclosure.DisclosureRecord.from_mapping(value["disclosure_record"]),
                metrics_record=metrics.Metrics.from_mapping(value["metrics_record"]),
                legacy_verifier_result=legacy,
                verifier_failure_records=failure_records,
                cloud_context_record=cloud_boundary.CloudContext.from_mapping(value["cloud_context_record"]),
                cloud_request_record=cloud_boundary.CloudRequest.from_mapping(value["cloud_request_record"]),
                cloud_execution_authorization_record=cloud_boundary.CloudExecutionAuthorization.from_mapping(
                    value["cloud_execution_authorization_record"]
                ),
                cloud_execution_handoff_record=cloud_boundary.CloudExecutionHandoff.from_mapping(
                    value["cloud_execution_handoff_record"]
                ),
                execution_authority=value["execution_authority"],
                pre_send_identity=value["pre_send_identity"],
            )
        except WorkflowCompositionError:
            raise
        except (TypeError, ValueError, AttributeError, KeyError) as exc:
            raise WorkflowCompositionError("pre-send workflow contains an invalid qualified record") from exc


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
            byte_size=response.raw_response_size_bytes,
            sha256=response.raw_response_sha256,
            artifact_type=proposal.PROPOSAL_SCHEMA_ID,
            schema_version=admitted_proposal.schema_version,
        ),
    )


def _exposed_result_evidence_artifacts(
    run: evidence.FrozenRunRecord,
    context: cloud_boundary.CloudContext,
    request: cloud_boundary.CloudRequest,
    proposal_record: proposal.CloudProposal,
    verification_record: verifier.VerificationRecord,
    gate: human_gate.HumanGateRecord | None,
    decision: human_gate.HumanDecisionRecord | None,
) -> tuple[evidence.FrozenEvidenceArtifact, ...]:
    def artifact(relative_path: str, artifact_type: str, schema_version: str, content: bytes) -> evidence.FrozenEvidenceArtifact:
        return evidence.FrozenEvidenceArtifact(
            relative_path=relative_path,
            byte_size=len(content),
            sha256=sha256_bytes(content),
            artifact_type=artifact_type,
            schema_version=schema_version,
        )

    artifacts = [
        artifact(
            "run/run.json",
            evidence.FROZEN_RUN_SCHEMA_ID,
            run.schema_version,
            run.canonical_bytes(),
        ),
        artifact(
            "cloud/context.json",
            cloud_boundary.CLOUD_CONTEXT_SCHEMA_ID,
            context.schema_version,
            context.canonical_bytes(),
        ),
        artifact(
            "cloud/request.json",
            cloud_boundary.CLOUD_REQUEST_SCHEMA_ID,
            request.schema_version,
            request.canonical_bytes(),
        ),
        artifact(
            "proposal/proposal.json",
            proposal.PROPOSAL_SCHEMA_ID,
            proposal_record.schema_version,
            proposal.canonical_cloud_proposal_bytes(proposal_record),
        ),
        artifact(
            "verification/verification.json",
            verifier.PUBLIC_VERIFICATION_SCHEMA_ID,
            verification_record.schema_version,
            verifier.canonical_verification_bytes(verification_record),
        ),
    ]
    if gate is not None:
        artifacts.append(artifact(
            "human_gate/human_gate.json",
            human_gate.HUMAN_GATE_SCHEMA_ID,
            gate.schema_version,
            human_gate.canonical_human_gate_bytes(gate),
        ))
    if decision is not None:
        artifacts.append(artifact(
            "human_gate/human_decision.json",
            human_gate.HUMAN_DECISION_SCHEMA_ID,
            decision.schema_version,
            human_gate.canonical_human_decision_bytes(decision),
        ))
    return tuple(artifacts)


def _qualified_verifier_failure_records(values: object) -> tuple[failures.Failure, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, (list, tuple)):
        raise WorkflowCompositionError("verifier_failure_records must be an array")
    try:
        return tuple(
            item if isinstance(item, failures.Failure) else failures.Failure.from_mapping(item)
            for item in values
        )
    except (TypeError, ValueError, AttributeError, KeyError) as exc:
        raise WorkflowCompositionError("verifier_failure_records are not exact qualified failures") from exc


def _build_pre_send_package(
    *,
    run: evidence.FrozenRunRecord,
    bounded_context: context_builder.BoundedContextPackage,
    disclosure_record: disclosure.DisclosureRecord,
    metrics_record: metrics.Metrics,
    legacy_verifier_result: verifier.VerifierResult,
    verifier_failure_records: tuple[failures.Failure, ...],
    context: cloud_boundary.CloudContext,
    request: cloud_boundary.CloudRequest,
    authorization: cloud_boundary.CloudExecutionAuthorization,
    handoff: cloud_boundary.CloudExecutionHandoff,
) -> PreSendWorkflowPackage:
    payload = {
        "schema_version": PRE_SEND_WORKFLOW_SCHEMA_VERSION,
        "run_record": run.to_dict(),
        "bounded_context_record": bounded_context.to_dict(),
        "disclosure_record": disclosure_record.to_dict(),
        "metrics_record": metrics_record.to_dict(),
        "legacy_verifier_result": legacy_verifier_result.to_dict(),
        "verifier_failure_records": [item.to_dict() for item in verifier_failure_records],
        "cloud_context_record": context.to_dict(),
        "cloud_request_record": request.to_dict(),
        "cloud_execution_authorization_record": authorization.to_dict(),
        "cloud_execution_handoff_record": handoff.to_dict(),
        "execution_authority": PRE_SEND_EXECUTION_AUTHORITY,
    }
    pre_send_identity = sha256_bytes(
        canonical_json_bytes(payload, identity_critical=False)
    )
    return PreSendWorkflowPackage(
        schema_version=PRE_SEND_WORKFLOW_SCHEMA_VERSION,
        run_record=run,
        bounded_context_record=bounded_context,
        disclosure_record=disclosure_record,
        metrics_record=metrics_record,
        legacy_verifier_result=legacy_verifier_result,
        verifier_failure_records=verifier_failure_records,
        cloud_context_record=context,
        cloud_request_record=request,
        cloud_execution_authorization_record=authorization,
        cloud_execution_handoff_record=handoff,
        execution_authority=PRE_SEND_EXECUTION_AUTHORITY,
        pre_send_identity=pre_send_identity,
    )


def validate_pre_send_workflow_package(
    value: PreSendWorkflowPackage | Mapping[str, object],
) -> PreSendWorkflowPackage:
    """Requalify zero-send identities and cross-bindings without invoking builders."""

    package = (
        value
        if isinstance(value, PreSendWorkflowPackage)
        else PreSendWorkflowPackage.from_mapping(value)
    )
    try:
        run = _qualified_frozen_run(package.run_record)
        bounded_context = _qualified_bounded_context(package.bounded_context_record)
        disclosure_record = disclosure.DisclosureRecord.from_mapping(
            package.disclosure_record.to_dict()
        )
        metric_record = metrics.Metrics.from_mapping(package.metrics_record.to_dict())
        failure_records = _qualified_verifier_failure_records(package.verifier_failure_records)
        legacy = verifier.VerifierResult.from_mapping(
            package.legacy_verifier_result.to_dict(), failure_records=failure_records
        )
        context = cloud_boundary.CloudContext.from_mapping(package.cloud_context_record.to_dict())
        request = cloud_boundary.CloudRequest.from_mapping(package.cloud_request_record.to_dict())
        authorization = cloud_boundary.CloudExecutionAuthorization.from_mapping(
            package.cloud_execution_authorization_record.to_dict()
        )
        handoff = cloud_boundary.CloudExecutionHandoff.from_mapping(
            package.cloud_execution_handoff_record.to_dict()
        )
    except WorkflowCompositionError:
        raise
    except (TypeError, ValueError, AttributeError, KeyError) as exc:
        raise WorkflowCompositionError("pre-send workflow package requalification failed closed") from exc

    expected_inputs = {
        "task_identity": run.task_identity,
        "source_set_identity": run.source_set_identity,
        "discovery_identity": run.discovery_identity,
        "normalization_identity": run.normalization_identity,
    }
    if dict(bounded_context.input_identities) != expected_inputs:
        raise WorkflowCompositionError("pre-send bounded context is not bound to the frozen run inputs")
    if metric_record.metrics_identity != bounded_context.metrics_identity:
        raise WorkflowCompositionError(
            "pre-send Metrics are not bound to the qualified BoundedContextPackage"
        )

    projected_items: list[dict[str, object]] = []
    unique_refs: dict[tuple[object, ...], dict[str, object]] = {}
    for item in bounded_context.context_items:
        refs: list[dict[str, object]] = []
        for raw_ref in item.source_refs:
            ref = dict(raw_ref)
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
                "content": dict(item.content),
                "source_refs": refs,
                "required": item.required,
            }
        )
    projected_items.sort(key=lambda item: item["item_id"])
    projected_refs = tuple(
        sorted(unique_refs.values(), key=lambda row: (row["source_id"], row["canonical_locator"]))
    )
    if canonical_json_bytes(
        list(context.context_items), identity_critical=False
    ) != canonical_json_bytes(projected_items, identity_critical=False):
        raise WorkflowCompositionError("pre-send cloud context items do not project the bounded context")
    if canonical_json_bytes(
        list(context.source_refs), identity_critical=False
    ) != canonical_json_bytes(list(projected_refs), identity_critical=False):
        raise WorkflowCompositionError("pre-send cloud source refs do not project the bounded context")
    expected_context_bindings = {
        "run_identity": run.run_identity,
        "task_identity": run.task_identity,
        "source_set_identity": run.source_set_identity,
        "mr03_package_identity": run.mr03_result_identity,
        "mr04_result_identity": run.mr04_result_identity,
        "disclosure_result": disclosure_record.disclosure_result,
    }
    for field, expected in expected_context_bindings.items():
        if getattr(context, field) != expected:
            raise WorkflowCompositionError(f"pre-send cloud context {field} is not exactly bound")
    if dict(context.byte_budget) != _cloud_budget(run):
        raise WorkflowCompositionError("pre-send cloud context byte budget is not bound to the frozen run")
    if context.provenance_summary["chain_identity"] != bounded_context.provenance_identity:
        raise WorkflowCompositionError("pre-send cloud provenance is not bound to the bounded context")
    if context.provenance_summary["source_count"] != len(projected_refs):
        raise WorkflowCompositionError("pre-send cloud provenance source count is not exact")

    expected_legacy_inputs = dict(bounded_context.input_identities)
    expected_legacy_inputs["context_identity"] = context.context_identity
    if dict(legacy.input_identities) != expected_legacy_inputs:
        raise WorkflowCompositionError("pre-send legacy verifier inputs are not exactly bound")
    if tuple(legacy.dependency_binding_identities) != tuple(
        sorted(bounded_context.dependency_binding_identities)
    ):
        raise WorkflowCompositionError("pre-send legacy verifier dependencies are not exactly bound")
    if legacy.provenance_identity != bounded_context.provenance_identity:
        raise WorkflowCompositionError("pre-send legacy verifier provenance is not exactly bound")
    if legacy.metrics_identity != metric_record.metrics_identity:
        raise WorkflowCompositionError("pre-send legacy verifier Metrics are not exactly bound")
    if tuple(legacy.contract_identities) != tuple(verifier.FROZEN_CONTRACT_IDENTITIES):
        raise WorkflowCompositionError("pre-send legacy verifier contracts are not frozen")

    if request.run_identity != run.run_identity or request.context_identity != context.context_identity:
        raise WorkflowCompositionError("pre-send cloud request is not bound to the run/context chain")
    authorization_expected = {
        "run_identity": request.run_identity,
        "context_identity": request.context_identity,
        "request_identity": request.request_identity,
        "model_identifier": request.model_identifier,
        "human_authorization_reference": request.human_authorization_reference,
    }
    for field, expected in authorization_expected.items():
        if getattr(authorization, field) != expected:
            raise WorkflowCompositionError(f"pre-send authorization {field} is not bound to the exact request")
    handoff_expected = {
        "run_identity": request.run_identity,
        "context_identity": request.context_identity,
        "request_identity": request.request_identity,
        "authorization_identity": authorization.authorization_identity,
        "model_identifier": request.model_identifier,
        "provider_identifier": authorization.provider_identifier,
        "account_boundary_reference": authorization.account_boundary_reference,
        "human_authorization_reference": authorization.human_authorization_reference,
    }
    for field, expected in handoff_expected.items():
        if getattr(handoff, field) != expected:
            raise WorkflowCompositionError(f"pre-send handoff {field} is not bound to the exact request/authorization")
    if handoff.execution_authority != PRE_SEND_EXECUTION_AUTHORITY:
        raise WorkflowCompositionError("pre-send handoff grants forbidden execution authority")

    reconstructed_package = _build_pre_send_package(
        run=run,
        bounded_context=bounded_context,
        disclosure_record=disclosure_record,
        metrics_record=metric_record,
        legacy_verifier_result=legacy,
        verifier_failure_records=failure_records,
        context=context,
        request=request,
        authorization=authorization,
        handoff=handoff,
    )
    if reconstructed_package != package:
        raise WorkflowCompositionError("pre-send workflow package does not equal exact normalized bytes")
    return package


def prepare_top_level_workflow(
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
    legacy_verifier_checks: object,
    verifier_failure_records: object = (),
    prohibited_assumptions: object = (),
    context_observational_metadata: Mapping[str, object] | None = None,
    request_observational_metadata: Mapping[str, object] | None = None,
) -> PreSendWorkflowPackage:
    """Build an exact zero-send request/authorization/handoff package."""

    run = _qualified_frozen_run(run_record)
    bounded_context = _qualified_bounded_context(bounded_context_record)
    qualified_failures = _qualified_verifier_failure_records(verifier_failure_records)
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
        failure_records=qualified_failures,
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
    return validate_pre_send_workflow_package(
        _build_pre_send_package(
            run=run,
            bounded_context=bounded_context,
            disclosure_record=constructed_disclosure,
            metrics_record=constructed_metrics,
            legacy_verifier_result=constructed_legacy_verifier,
            verifier_failure_records=qualified_failures,
            context=context,
            request=request,
            authorization=authorization,
            handoff=handoff,
        )
    )


def validate_workflow_composition_result(
    value: WorkflowCompositionResult,
) -> WorkflowCompositionResult:
    # Pure in-memory post-admission continuity validation; grants no authority.
    if not isinstance(value, WorkflowCompositionResult):
        raise WorkflowCompositionError(
            "workflow composition result must be an exact WorkflowCompositionResult"
        )
    try:
        run = _qualified_frozen_run(value.run_record)
        context = cloud_boundary.CloudContext.from_mapping(value.cloud_context_record.to_dict())
        request = cloud_boundary.CloudRequest.from_mapping(value.cloud_request_record.to_dict())
        authorization = cloud_boundary.validate_cloud_execution_authorization(
            value.cloud_execution_authorization_record, request
        )
        handoff = cloud_boundary.validate_cloud_execution_handoff(
            value.cloud_execution_handoff_record, request, authorization
        )
        response = cloud_boundary.validate_cloud_response_binding(
            value.cloud_response_record, request, authorization
        )
        proposal_record = proposal.CloudProposal.from_mapping(value.proposal_record.to_dict())
        verification_record = verifier.VerificationRecord.from_mapping(value.verification_record.to_dict())
        manifest = evidence.FrozenEvidenceManifest.from_mapping(value.evidence_manifest.to_dict())
        final_result = evidence.FinalResultRecord.from_mapping(value.final_result.to_dict())
        gate = None if value.human_gate_record is None else human_gate.HumanGateRecord.from_mapping(value.human_gate_record.to_dict())
        decision = None if value.human_decision_record is None else human_gate.HumanDecisionRecord.from_mapping(value.human_decision_record.to_dict(), human_gate=gate)
    except (TypeError, ValueError, AttributeError, KeyError) as exc:
        raise WorkflowCompositionError(
            "workflow composition result contains an invalid qualified record"
        ) from exc
    if context.run_identity != run.run_identity:
        raise WorkflowCompositionError("workflow cloud context is not bound to the frozen run")
    if request.run_identity != run.run_identity or request.context_identity != context.context_identity:
        raise WorkflowCompositionError("workflow cloud request is not bound to the run/context chain")
    _validate_remaining_proposal_bindings(proposal_record, run=run)
    if (proposal_record.request_identity != request.request_identity or
        proposal_record.run_identity != run.run_identity or
        proposal_record.bound_context_identity != context.context_identity):
        raise WorkflowCompositionError("workflow proposal is not bound to the exact request/run/context chain")
    metadata = proposal_record.proposer_metadata
    if (metadata.model_identifier != response.actual_model_identifier or
        metadata.provider_request_id != response.provider_request_id or
        metadata.attempt_number != response.attempt_number or
        metadata.usage_if_available != response.provider_usage_if_available):
        raise WorkflowCompositionError("workflow proposal transport metadata is not bound to the response")
    if verification_record.proposal_identity != proposal_record.proposal_identity:
        raise WorkflowCompositionError("workflow verification is not bound to the exact proposal")
    _validate_human_bindings(run=run, proposal_record=proposal_record, verification_record=verification_record, gate=gate, decision=decision)
    if manifest.run_identity != run.run_identity:
        raise WorkflowCompositionError("workflow evidence manifest is not bound to the frozen run")
    by_path={artifact.relative_path: artifact for artifact in manifest.artifacts}
    expected_manifest_artifacts = (
        _transport_evidence_artifacts(authorization, handoff, response, proposal_record)
        + _exposed_result_evidence_artifacts(
            run, context, request, proposal_record, verification_record, gate, decision
        )
    )
    for expected in expected_manifest_artifacts:
        if by_path.get(expected.relative_path) != expected:
            raise WorkflowCompositionError(
                f"workflow manifest does not bind exact composed artifact {expected.relative_path}"
            )
    evidence_args = {
        "run_record": run,
        "bounded_context_record": value.bounded_context_record,
        "disclosure_record": value.disclosure_record,
        "cloud_context_record": context,
        "cloud_request_record": request,
        "proposal_record": proposal_record,
        "verification_record": verification_record,
        "metrics_record": value.metrics_record,
        "legacy_verifier_result": value.legacy_verifier_result,
        "verifier_failure_records": value.verifier_failure_records,
        "human_gate_record": gate,
        "human_decision_record": decision,
        "failure_record": value.failure_record,
    }
    try:
        reconstructed_manifest = evidence.build_pre_final_evidence_manifest(
            **evidence_args,
            additional_artifacts=_transport_evidence_artifacts(
                authorization, handoff, response, proposal_record
            ),
            observational_metadata=dict(manifest.observational_metadata),
        )
        reconstructed_final_result = evidence.build_final_result(
            terminal_state=run.state,
            manifest=manifest,
            **evidence_args,
            observational_metadata=dict(final_result.observational_metadata),
        )
    except (TypeError, ValueError, AttributeError, KeyError) as exc:
        raise WorkflowCompositionError(
            "workflow authoritative evidence chain cannot be requalified"
        ) from exc
    if reconstructed_manifest != manifest:
        raise WorkflowCompositionError(
            "workflow manifest does not equal exact reconstruction from exposed evidence inputs"
        )
    if reconstructed_final_result != final_result:
        raise WorkflowCompositionError(
            "workflow Final Result does not equal exact authoritative reconstruction"
        )

    expected_decision=None if decision is None else decision.decision
    if (final_result.run_identity != run.run_identity or
        final_result.proposal_identity_if_any != proposal_record.proposal_identity or
        final_result.verification_result != verification_record.verification_result or
        final_result.human_decision_if_any != expected_decision or
        final_result.evidence_manifest_identity != manifest.manifest_identity):
        raise WorkflowCompositionError("workflow Final Result is not bound to the composed qualified chain")
    persistence=value.final_evidence_persistence_result
    if not isinstance(persistence, evidence.FinalEvidencePersistenceResult):
        raise WorkflowCompositionError("workflow persistence result is not an exact FinalEvidencePersistenceResult")
    manifest_bytes=manifest.canonical_bytes()
    final_bytes=canonical_json_bytes(final_result.to_dict(), identity_critical=False)
    if (persistence.run_identity != run.run_identity or
        persistence.manifest_identity != manifest.manifest_identity or
        persistence.final_result_identity != final_result.final_result_identity or
        persistence.manifest_content_sha256 != sha256_bytes(manifest_bytes) or
        persistence.manifest_byte_count != len(manifest_bytes) or
        persistence.final_result_content_sha256 != sha256_bytes(final_bytes) or
        persistence.final_result_byte_count != len(final_bytes) or
        persistence.human_approval or persistence.state_transition_authority or
        persistence.source_write_authority or persistence.git_authority or
        persistence.model_provider_authority):
        raise WorkflowCompositionError("workflow persistence result is not bound to exact manifest/final bytes")
    return value


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


def resume_top_level_workflow(
    *,
    prepared_package: PreSendWorkflowPackage | Mapping[str, object],
    raw_provider_response: bytes,
    provider_identifier: object,
    actual_model_identifier: object,
    provider_request_id: object,
    account_boundary_reference: object,
    provider_usage_if_available: Mapping[str, object] | None,
    error_metadata: Mapping[str, object] | None,
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
    manifest_observational_metadata: Mapping[str, object] | None = None,
    final_observational_metadata: Mapping[str, object] | None = None,
) -> WorkflowCompositionResult:
    """Resume one validated zero-send handoff using an already-obtained response."""

    prepared = validate_pre_send_workflow_package(prepared_package)
    run = prepared.run_record
    bounded_context = prepared.bounded_context_record
    constructed_disclosure = prepared.disclosure_record
    constructed_metrics = prepared.metrics_record
    constructed_legacy_verifier = prepared.legacy_verifier_result
    verifier_failure_records = prepared.verifier_failure_records
    context = prepared.cloud_context_record
    request = prepared.cloud_request_record
    authorization = prepared.cloud_execution_authorization_record
    handoff = prepared.cloud_execution_handoff_record

    response = cloud_boundary.adapt_governed_external_transport_response(
        request,
        authorization,
        handoff,
        raw_provider_response=raw_provider_response,
        provider_identifier=provider_identifier,
        actual_model_identifier=actual_model_identifier,
        provider_request_id=provider_request_id,
        account_boundary_reference=account_boundary_reference,
        provider_usage_if_available=provider_usage_if_available,
        error_metadata=error_metadata,
    )
    admitted_proposal = proposal.admit_cloud_response_proposal(
        raw_provider_response, response, request, authorization, handoff
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
        authorization, handoff, response, admitted_proposal
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
    result = WorkflowCompositionResult(
        run_record=run,
        bounded_context_record=bounded_context,
        disclosure_record=constructed_disclosure,
        metrics_record=constructed_metrics,
        legacy_verifier_result=constructed_legacy_verifier,
        verifier_failure_records=verifier_failure_records,
        failure_record=failure_record,
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
    return validate_workflow_composition_result(result)


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
    """Compose the existing one-shot offline flow through the same two-step boundary."""

    prepared = prepare_top_level_workflow(
        run_record=run_record,
        bounded_context_record=bounded_context_record,
        disclosure_classification=disclosure_classification,
        disclosure_findings=disclosure_findings,
        disclosure_observational_metadata=disclosure_observational_metadata,
        metrics_raw_source_bytes=metrics_raw_source_bytes,
        metrics_normalized_bytes=metrics_normalized_bytes,
        metrics_package_bytes=metrics_package_bytes,
        metrics_cloud_context_bytes=metrics_cloud_context_bytes,
        metrics_raw_estimated_tokens=metrics_raw_estimated_tokens,
        metrics_cloud_estimated_tokens=metrics_cloud_estimated_tokens,
        metrics_model_call_count=metrics_model_call_count,
        metrics_model_retry_count=metrics_model_retry_count,
        metrics_failure_count=metrics_failure_count,
        metrics_source_ref_count=metrics_source_ref_count,
        metrics_missing_source_ref_count=metrics_missing_source_ref_count,
        metrics_identity_mismatch_count=metrics_identity_mismatch_count,
        metrics_observational_metadata=metrics_observational_metadata,
        model_identifier=model_identifier,
        human_authorization_reference=human_authorization_reference,
        estimated_token_metadata=estimated_token_metadata,
        authorized_provider_identifier=authorized_provider_identifier,
        authorized_account_boundary_reference=authorized_account_boundary_reference,
        authorization_observational_metadata=authorization_observational_metadata,
        legacy_verifier_checks=legacy_verifier_checks,
        verifier_failure_records=verifier_failure_records,
        prohibited_assumptions=prohibited_assumptions,
        context_observational_metadata=context_observational_metadata,
        request_observational_metadata=request_observational_metadata,
    )
    return resume_top_level_workflow(
        prepared_package=prepared,
        raw_provider_response=raw_provider_response,
        provider_identifier=provider_identifier,
        actual_model_identifier=actual_model_identifier,
        provider_request_id=provider_request_id,
        account_boundary_reference=account_boundary_reference,
        provider_usage_if_available=provider_usage_if_available,
        error_metadata=error_metadata,
        verification_result=verification_result,
        verification_reason_codes=verification_reason_codes,
        verification_reason_details=verification_reason_details,
        verification_verified_source_refs=verification_verified_source_refs,
        verification_unsupported_claims=verification_unsupported_claims,
        verification_missing_refs=verification_missing_refs,
        verification_protected_content_findings=verification_protected_content_findings,
        verification_identity_findings=verification_identity_findings,
        verification_observational_metadata=verification_observational_metadata,
        approved_root=approved_root,
        manifest_relative_path=manifest_relative_path,
        final_result_relative_path=final_result_relative_path,
        human_gate_task_summary=human_gate_task_summary,
        human_gate_proposal_summary=human_gate_proposal_summary,
        human_gate_uncertainties=human_gate_uncertainties,
        human_gate_evidence_pointers=human_gate_evidence_pointers,
        human_gate_observational_metadata=human_gate_observational_metadata,
        human_decision=human_decision,
        human_decision_reason=human_decision_reason,
        human_decision_scope=human_decision_scope,
        human_decision_authority_reference=human_decision_authority_reference,
        human_decision_observational_metadata=human_decision_observational_metadata,
        failure_record=failure_record,
        manifest_observational_metadata=manifest_observational_metadata,
        final_observational_metadata=final_observational_metadata,
    )


__all__ = [
    "WorkflowCompositionError",
    "WorkflowCompositionResult",
    "PreSendWorkflowPackage",
    "validate_pre_send_workflow_package",
    "prepare_top_level_workflow",
    "resume_top_level_workflow",
    "validate_workflow_composition_result",
    "compose_top_level_workflow",
    "PRE_SEND_PREPARATION_IMPLEMENTATION_COUNT",
    "TWO_STEP_RESUME_IMPLEMENTATION_COUNT",
    "PRE_SEND_WORKFLOW_SCHEMA_VERSION",
    "PRE_SEND_EXECUTION_AUTHORITY",
    "WORKFLOW_COMPOSITION_IMPLEMENTATION_COUNT",
    "WORKFLOW_COMPOSITION_VALIDATION_IMPLEMENTATION_COUNT",
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