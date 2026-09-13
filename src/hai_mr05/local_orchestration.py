"""Bounded local-source orchestration into the qualified zero-send prepare boundary.

This MR22D surface reads exactly one caller-selected file through the qualified
approved-root source-acquisition boundary, then performs only deterministic
in-process record construction.  It does not execute MR03/MR04, spawn a
subprocess, perform network/provider/model/auth operations, choose verifier
semantics, execute Human approval/state transitions, write evidence, mutate Git,
or perform live transport.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

from . import (
    cloud_boundary,
    context_builder,
    disclosure,
    discovery,
    evidence,
    materialization,
    metrics,
    mr03_adapter,
    mr04_adapter,
    normalization,
    provenance,
    source_acquisition,
    verifier,
    workflow,
)
from .canonical import canonical_json_bytes
from .contracts import SCHEMA_VERSION
from .identity import sha256_bytes

LOCAL_ORCHESTRATION_SCHEMA_VERSION = "1.0.0"
LOCAL_SOURCE_ORCHESTRATION_IMPLEMENTATION_COUNT = 1
FILESYSTEM_SOURCE_READ_COUNT = 1
FILESYSTEM_WRITE_COUNT = 0
DEPENDENCY_EXECUTION_COUNT = 0
SUBPROCESS_EXECUTION_COUNT = 0
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
LIVE_CLOUD_EXECUTION_COUNT = 0


class LocalPrepareOrchestrationError(ValueError):
    """The bounded local source cannot form one qualified pre-send package."""


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        raise LocalPrepareOrchestrationError(f"{field} must be a string-keyed mapping")
    return value


def _sequence(value: object, field: str) -> tuple[object, ...]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise LocalPrepareOrchestrationError(f"{field} must be an array")
    return tuple(value)


def _text(value: object, field: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise LocalPrepareOrchestrationError(f"{field} must be a non-empty string")
    return value


def _int(value: object, field: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise LocalPrepareOrchestrationError(f"{field} must be an integer >= {minimum}")
    return value


def _dependency_record(
    *,
    role: str,
    discovered: discovery.DiscoveryResult,
    normalized: normalization.NormalizationResult,
    source_ref: discovery.SourceReference,
    upstream_dependency_identity: str | None,
) -> dict[str, object]:
    if role == "MR03_PACKAGER":
        frozen = {
            "dependency_role": "MR03_PACKAGER",
            "dependency_logical_id": "MR03",
            "expected_dependency_class": "FROZEN_MR03_EVIDENCE_PACKAGER",
            "dependency_contract_identity": None,
            "dependency_version_identity": mr03_adapter.MR03_INTERFACE_IDENTITY,
            "dependency_content_identity": {
                "kind": "COMMITTED_FILESET",
                "sha256": mr03_adapter.MR03_COMMITTED_FILESET_SHA256,
            },
            "dependency_snapshot": {
                "commit": mr03_adapter.MR03_EXPECTED_COMMIT,
                "parent": mr03_adapter.MR03_EXPECTED_PARENT,
                "tree": mr03_adapter.MR03_EXPECTED_TREE,
                "pathset_sha256": None,
            },
        }
    elif role == "MR04_GUARD":
        frozen = {
            "dependency_role": "MR04_GUARD",
            "dependency_logical_id": "MR04",
            "expected_dependency_class": "FROZEN_MR04_LOWER_LEVEL_COMPOSITION",
            "dependency_contract_identity": mr03_adapter.MR04_IMPLEMENTATION_CONTRACT_SHA256,
            "dependency_version_identity": None,
            "dependency_content_identity": {
                "kind": "CONTENTSET",
                "sha256": mr03_adapter.MR04_CONTENTSET_SHA256,
            },
            "dependency_snapshot": {
                "commit": mr03_adapter.MR04_EXPECTED_COMMIT,
                "parent": mr03_adapter.MR04_EXPECTED_PARENT,
                "tree": mr03_adapter.MR04_EXPECTED_TREE,
                "pathset_sha256": mr03_adapter.MR04_PATHSET_SHA256,
            },
        }
    else:
        raise LocalPrepareOrchestrationError("unsupported frozen dependency role")
    return {
        "schema_version": SCHEMA_VERSION,
        **frozen,
        "source_ref": {"schema_version": SCHEMA_VERSION, **source_ref.to_dict()},
        "input_binding": {
            "task_identity": discovered.task_identity,
            "source_set_identity": discovered.source_set_identity,
            "discovery_identity": discovered.discovery_identity,
            "normalization_identity": normalized.normalization_identity,
            "upstream_dependency_identity": upstream_dependency_identity,
        },
    }


def _build_bindings(
    discovered: discovery.DiscoveryResult,
    normalized: normalization.NormalizationResult,
) -> tuple[mr03_adapter.DependencyBinding, mr03_adapter.DependencyBinding]:
    if len(discovered.selected_sources) != 1:
        raise LocalPrepareOrchestrationError("local orchestration requires exactly one selected source")
    source_ref = discovered.selected_sources[0]
    mr03 = mr03_adapter.bind_mr03_dependency(
        _dependency_record(
            role="MR03_PACKAGER",
            discovered=discovered,
            normalized=normalized,
            source_ref=source_ref,
            upstream_dependency_identity=None,
        ),
        discovered,
        normalized,
        source_ref,
    )
    mr04 = mr04_adapter.bind_mr04_dependency(
        _dependency_record(
            role="MR04_GUARD",
            discovered=discovered,
            normalized=normalized,
            source_ref=source_ref,
            upstream_dependency_identity=mr03.binding_identity,
        ),
        discovered,
        normalized,
        mr03.binding_identity,
        source_ref,
    )
    return mr03, mr04


def _provenance_chain(
    discovered: discovery.DiscoveryResult,
    normalized: normalization.NormalizationResult,
    bindings: tuple[mr03_adapter.DependencyBinding, mr03_adapter.DependencyBinding],
    metric: metrics.Metrics,
) -> provenance.ProvenanceChain:
    identities = (
        ("TASK_IDENTITY", discovered.task_identity),
        ("SOURCE_SET_IDENTITY", discovered.source_set_identity),
        ("DISCOVERY_IDENTITY", discovered.discovery_identity),
        ("NORMALIZATION_IDENTITY", normalized.normalization_identity),
        ("MR03_BINDING_IDENTITY", bindings[0].binding_identity),
        ("MR04_BINDING_IDENTITY", bindings[1].binding_identity),
        ("METRICS_IDENTITY", metric.metrics_identity),
    )
    if any(value is None for _, value in identities):
        raise LocalPrepareOrchestrationError("required orchestration identity is missing")
    return provenance.ProvenanceChain(
        nodes=tuple(
            provenance.ProvenanceNode(name, value, f"mr22d/{name.lower()}")  # type: ignore[arg-type]
            for name, value in identities
        ),
        edges=(),
    )


def _pass_checks(context_identity: str, asserted_rule_ids: object) -> tuple[verifier.VerifierCheckRecord, ...]:
    asserted = tuple(_text(item, "legacy_verifier_pass_rule_id") for item in _sequence(asserted_rule_ids, "legacy_verifier_pass_rule_ids"))
    if len(asserted) != len(set(asserted)) or asserted != tuple(sorted(asserted)):
        raise LocalPrepareOrchestrationError("legacy verifier pass rule ids must be unique and lexically ordered")
    expected = tuple(sorted(rule.rule_id for rule in verifier.RULE_CATALOG))
    if asserted != expected:
        raise LocalPrepareOrchestrationError("legacy verifier pass assertions must cover the exact frozen rule catalog")
    return tuple(
        verifier.build_verifier_check(
            rule_id=rule_id,
            input_identity=context_identity,
            check_result="PASS",
        )
        for rule_id in asserted
    )


@dataclass(frozen=True, slots=True)
class LocalPrepareOrchestrationResult:
    schema_version: str
    capture_identity: str
    source_id: str
    discovery_identity: str
    normalization_identity: str
    mr03_binding_identity: str
    mr04_binding_identity: str
    provenance_identity: str
    materialization_identity: str
    pre_send_identity: str
    request_identity: str
    authorization_identity: str
    handoff_identity: str
    orchestration_identity: str
    materialization_result: materialization.PrepareInputMaterialization
    prepared_workflow: workflow.PreSendWorkflowPackage

    def __post_init__(self) -> None:
        if self.schema_version != LOCAL_ORCHESTRATION_SCHEMA_VERSION:
            raise LocalPrepareOrchestrationError("unsupported local orchestration schema version")
        for field in (
            "capture_identity", "source_id", "discovery_identity", "normalization_identity",
            "mr03_binding_identity", "mr04_binding_identity", "provenance_identity",
            "materialization_identity", "pre_send_identity", "request_identity",
            "authorization_identity", "handoff_identity", "orchestration_identity",
        ):
            value = getattr(self, field)
            if type(value) is not str or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
                raise LocalPrepareOrchestrationError(f"{field} must be a lowercase SHA-256 identity")
        if self.materialization_result.materialization_identity != self.materialization_identity:
            raise LocalPrepareOrchestrationError("materialization identity is not bound to result")
        if self.prepared_workflow.pre_send_identity != self.pre_send_identity:
            raise LocalPrepareOrchestrationError("pre-send identity is not bound to result")
        if self.prepared_workflow.cloud_request_record.request_identity != self.request_identity:
            raise LocalPrepareOrchestrationError("request identity is not bound to result")
        if self.prepared_workflow.cloud_execution_authorization_record.authorization_identity != self.authorization_identity:
            raise LocalPrepareOrchestrationError("authorization identity is not bound to result")
        if self.prepared_workflow.cloud_execution_handoff_record.handoff_identity != self.handoff_identity:
            raise LocalPrepareOrchestrationError("handoff identity is not bound to result")
        if self.prepared_workflow.execution_authority != "NONE":
            raise LocalPrepareOrchestrationError("local orchestration must stop with execution authority NONE")
        payload = self.identity_payload
        computed = sha256_bytes(canonical_json_bytes(payload, identity_critical=False))
        if computed != self.orchestration_identity:
            raise LocalPrepareOrchestrationError("orchestration identity does not match canonical result")

    @property
    def identity_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "capture_identity": self.capture_identity,
            "source_id": self.source_id,
            "discovery_identity": self.discovery_identity,
            "normalization_identity": self.normalization_identity,
            "mr03_binding_identity": self.mr03_binding_identity,
            "mr04_binding_identity": self.mr04_binding_identity,
            "provenance_identity": self.provenance_identity,
            "materialization_identity": self.materialization_identity,
            "pre_send_identity": self.pre_send_identity,
            "request_identity": self.request_identity,
            "authorization_identity": self.authorization_identity,
            "handoff_identity": self.handoff_identity,
            "execution_authority": "NONE",
        }

    def to_dict(self) -> dict[str, object]:
        return {
            **self.identity_payload,
            "orchestration_identity": self.orchestration_identity,
            "materialization_result": self.materialization_result.to_dict(),
            "prepared_workflow": self.prepared_workflow.to_dict(),
        }


def orchestrate_local_prepare(
    *,
    approved_source_root: object,
    source_relative_path: object,
    source_alias: object,
    provenance_owner: object,
    task: object,
    classification: object,
    content_kind: object | None,
    source_observational_metadata: object | None,
    discovery_max_bytes: object,
    phase_id: object,
    artifact_type: object,
    current_validity: object,
    supersession: object,
    mandatory: object,
    metrics_raw_estimated_tokens: object,
    metrics_cloud_estimated_tokens: object,
    mr03_result_identity: object,
    mr04_result_identity: object,
    frozen_run_byte_budget: object,
    frozen_run_state: object,
    frozen_run_observational_metadata: Mapping[str, object] | None,
    disclosure_classification: object,
    disclosure_findings: object,
    disclosure_observational_metadata: object | None,
    model_identifier: object,
    human_authorization_reference: object,
    estimated_token_metadata: Mapping[str, object],
    authorized_provider_identifier: object,
    authorized_account_boundary_reference: object,
    authorization_observational_metadata: Mapping[str, object] | None,
    legacy_verifier_pass_rule_ids: object,
    prohibited_assumptions: object = (),
    context_observational_metadata: Mapping[str, object] | None = None,
    request_observational_metadata: Mapping[str, object] | None = None,
) -> LocalPrepareOrchestrationResult:
    """Compose one approved local source into the existing zero-send prepare boundary."""

    if classification != "PUBLIC" or disclosure_classification != "PUBLIC":
        raise LocalPrepareOrchestrationError("MR22D local prepare is bounded to explicitly PUBLIC material")
    if type(mandatory) is not bool:
        raise LocalPrepareOrchestrationError("mandatory must be a boolean")
    max_bytes = _int(discovery_max_bytes, "discovery_max_bytes", minimum=1)
    task_record = _mapping(task, "task")
    budget = _mapping(frozen_run_byte_budget, "frozen_run_byte_budget")
    max_context_bytes = _int(budget.get("max_cloud_context_bytes"), "frozen_run_byte_budget.max_cloud_context_bytes", minimum=1)

    acquisition = source_acquisition.capture_source(
        approved_root=approved_source_root,
        relative_path=source_relative_path,
        source_alias=source_alias,
        provenance_owner=provenance_owner,
        source_type="LOCAL_FILE",
        classification="PUBLIC",
        content_kind=content_kind,
        observational_metadata={} if source_observational_metadata is None else source_observational_metadata,
    )
    descriptor = acquisition.captured_source.descriptor
    discovered = discovery.discover(
        task_record,
        (descriptor,),
        max_item_count=1,
        max_bytes=max_bytes,
    )
    if len(discovered.selected_sources) != 1:
        raise LocalPrepareOrchestrationError("exactly one approved local source must be selected")
    normalized_item = normalization.NormalizedItem.from_source(
        discovered.selected_sources[0],
        phase_id=_text(phase_id, "phase_id"),
        artifact_type=_text(artifact_type, "artifact_type"),
        current_validity=_text(current_validity, "current_validity"),
        supersession=_text(supersession, "supersession"),
        classification="PUBLIC",
        mandatory=mandatory,
    )
    normalized = normalization.normalize(discovered, (normalized_item,))
    bindings = _build_bindings(discovered, normalized)

    metric = metrics.build_metrics(
        raw_source_bytes=discovered.total_selected_bytes,
        normalized_bytes=normalized.output_bytes,
        package_bytes=normalized.output_bytes,
        cloud_context_bytes=0,
        raw_estimated_tokens=_int(metrics_raw_estimated_tokens, "metrics_raw_estimated_tokens"),
        cloud_estimated_tokens=_int(metrics_cloud_estimated_tokens, "metrics_cloud_estimated_tokens"),
        model_call_count=0,
        model_retry_count=0,
        failure_count=0,
        source_ref_count=1,
        missing_source_ref_count=0,
        identity_mismatch_count=0,
        observational_metadata=None,
    )
    chain = _provenance_chain(discovered, normalized, bindings, metric)
    preview_context = context_builder.build_context(
        discovered,
        normalized,
        bindings,
        chain,
        metric,
        max_context_bytes=max_context_bytes,
    )
    preview_run = evidence.build_frozen_run_record(
        task_identity=discovered.task_identity,
        source_set_identity=discovered.source_set_identity,
        discovery_identity=discovered.discovery_identity,
        normalization_identity=normalized.normalization_identity,
        mr03_result_identity=mr03_result_identity,
        mr04_result_identity=mr04_result_identity,
        byte_budget=budget,
        state=frozen_run_state,
        observational_metadata=frozen_run_observational_metadata,
    )
    preview_disclosure = disclosure.build_disclosure(
        classification=disclosure_classification,
        findings=disclosure_findings,
        observational_metadata=disclosure_observational_metadata,
    )
    preview_cloud_context = cloud_boundary.admit_cloud_context(
        preview_context,
        preview_disclosure,
        run_identity=preview_run.run_identity,
        mr03_package_identity=preview_run.mr03_result_identity,
        mr04_result_identity=preview_run.mr04_result_identity,
        byte_budget={
            "budget_identity": preview_run.byte_budget["budget_identity"],
            "max_cloud_context_bytes": preview_run.byte_budget["max_cloud_context_bytes"],
            "overflow_policy": preview_run.byte_budget["overflow_policy"],
            "silent_truncation": preview_run.byte_budget["silent_truncation"],
        },
        estimated_token_metadata=estimated_token_metadata,
        prohibited_assumptions=prohibited_assumptions,
        observational_metadata=context_observational_metadata,
    )
    checks = _pass_checks(preview_cloud_context.context_identity, legacy_verifier_pass_rule_ids)

    materialized = materialization.materialize_prepare_inputs(
        discovery_result=discovered,
        normalization_result=normalized,
        dependency_bindings=bindings,
        provenance_chain=chain,
        metrics_raw_source_bytes=discovered.total_selected_bytes,
        metrics_normalized_bytes=normalized.output_bytes,
        metrics_package_bytes=normalized.output_bytes,
        metrics_cloud_context_bytes=0,
        metrics_raw_estimated_tokens=metrics_raw_estimated_tokens,
        metrics_cloud_estimated_tokens=metrics_cloud_estimated_tokens,
        metrics_model_call_count=0,
        metrics_model_retry_count=0,
        metrics_failure_count=0,
        metrics_source_ref_count=1,
        metrics_missing_source_ref_count=0,
        metrics_identity_mismatch_count=0,
        metrics_observational_metadata=None,
        max_context_bytes=max_context_bytes,
        mr03_result_identity=mr03_result_identity,
        mr04_result_identity=mr04_result_identity,
        frozen_run_byte_budget=budget,
        frozen_run_state=frozen_run_state,
        frozen_run_observational_metadata=frozen_run_observational_metadata,
        disclosure_classification=disclosure_classification,
        disclosure_findings=disclosure_findings,
        disclosure_observational_metadata=disclosure_observational_metadata,
        model_identifier=model_identifier,
        human_authorization_reference=human_authorization_reference,
        estimated_token_metadata=estimated_token_metadata,
        authorized_provider_identifier=authorized_provider_identifier,
        authorized_account_boundary_reference=authorized_account_boundary_reference,
        authorization_observational_metadata=authorization_observational_metadata,
        legacy_verifier_checks=checks,
        verifier_failure_records=(),
        prohibited_assumptions=prohibited_assumptions,
        context_observational_metadata=context_observational_metadata,
        request_observational_metadata=request_observational_metadata,
    )
    if materialized.bounded_context_identity != preview_context.context_identity:
        raise LocalPrepareOrchestrationError("MR22C materialization changed the preview context identity")
    if materialized.frozen_run_identity != preview_run.run_identity:
        raise LocalPrepareOrchestrationError("MR22C materialization changed the preview frozen-run identity")
    prepared = workflow.prepare_top_level_workflow(**dict(materialized.prepare_arguments))
    if prepared.cloud_context_record.context_identity != preview_cloud_context.context_identity:
        raise LocalPrepareOrchestrationError("MR22B prepare changed the preview cloud-context identity")
    identity_payload = {
        "schema_version": LOCAL_ORCHESTRATION_SCHEMA_VERSION,
        "capture_identity": acquisition.capture_identity,
        "source_id": descriptor.source_id,
        "discovery_identity": discovered.discovery_identity,
        "normalization_identity": normalized.normalization_identity,
        "mr03_binding_identity": bindings[0].binding_identity,
        "mr04_binding_identity": bindings[1].binding_identity,
        "provenance_identity": chain.provenance_identity,
        "materialization_identity": materialized.materialization_identity,
        "pre_send_identity": prepared.pre_send_identity,
        "request_identity": prepared.cloud_request_record.request_identity,
        "authorization_identity": prepared.cloud_execution_authorization_record.authorization_identity,
        "handoff_identity": prepared.cloud_execution_handoff_record.handoff_identity,
        "execution_authority": "NONE",
    }
    orchestration_identity = sha256_bytes(canonical_json_bytes(identity_payload, identity_critical=False))
    return LocalPrepareOrchestrationResult(
        schema_version=LOCAL_ORCHESTRATION_SCHEMA_VERSION,
        capture_identity=acquisition.capture_identity,
        source_id=descriptor.source_id,
        discovery_identity=discovered.discovery_identity,
        normalization_identity=normalized.normalization_identity,
        mr03_binding_identity=bindings[0].binding_identity,  # type: ignore[arg-type]
        mr04_binding_identity=bindings[1].binding_identity,  # type: ignore[arg-type]
        provenance_identity=chain.provenance_identity,  # type: ignore[arg-type]
        materialization_identity=materialized.materialization_identity,
        pre_send_identity=prepared.pre_send_identity,
        request_identity=prepared.cloud_request_record.request_identity,
        authorization_identity=prepared.cloud_execution_authorization_record.authorization_identity,
        handoff_identity=prepared.cloud_execution_handoff_record.handoff_identity,
        orchestration_identity=orchestration_identity,
        materialization_result=materialized,
        prepared_workflow=prepared,
    )


__all__ = [
    "LocalPrepareOrchestrationError",
    "LocalPrepareOrchestrationResult",
    "orchestrate_local_prepare",
    "LOCAL_ORCHESTRATION_SCHEMA_VERSION",
    "LOCAL_SOURCE_ORCHESTRATION_IMPLEMENTATION_COUNT",
    "FILESYSTEM_SOURCE_READ_COUNT",
    "FILESYSTEM_WRITE_COUNT",
    "DEPENDENCY_EXECUTION_COUNT",
    "SUBPROCESS_EXECUTION_COUNT",
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
    "LIVE_CLOUD_EXECUTION_COUNT",
]
