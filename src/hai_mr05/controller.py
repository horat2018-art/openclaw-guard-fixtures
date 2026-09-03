"""Deterministic MR-05 controller orchestration primitives.

This module composes already-qualified local, deterministic runtime primitives.
It never executes Human Gate approval, workflow progression, dependency Git
verification, network/provider/model/auth operations, retry, fallback, or Git
mutation. Optional evidence persistence is delegated exclusively to the existing
bounded evidence runtime and grants no workflow or execution authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Sequence

from . import dependency_runtime, evidence
from .evidence import EvidenceManifest, RunRecord, build_evidence_manifest, build_run_record
from .failures import phase_not_implemented
from .source_acquisition import AcquisitionResult, capture_source

FAIL_CLOSED_OVERRIDE = "ENABLED"
HUMAN_GATE_REQUIRED_TO_LEAVE_SEMANTICS = "PROGRESS_TRANSITIONS_ONLY"
HOLD_TRANSITION_SEMANTICS = "QUALIFIED / PASS"
READY_FOR_HUMAN_REVIEW_GATE_SEMANTICS = "QUALIFIED / PASS"
PASS_FOR_REVIEW_IS_IMPLEMENTATION_AUTHORITY = "NO"
TRANSITION_FAIL_CLOSED = "FAIL_CLOSED"
TRANSITION_PROGRESS = "PROGRESS"
TRANSITION_HOLD = "HOLD"
TRANSITION_READY_FOR_HUMAN_REVIEW_GATE = "READY_FOR_HUMAN_REVIEW_GATE"
TRANSITION_KINDS = (TRANSITION_FAIL_CLOSED, TRANSITION_PROGRESS, TRANSITION_HOLD, TRANSITION_READY_FOR_HUMAN_REVIEW_GATE)
QUALIFIED_PASS = "QUALIFIED / PASS"
HUMAN_GATE_REQUIRED = "HUMAN_GATE_REQUIRED"
NO_IMPLEMENTATION_AUTHORITY = "NONE"
CONTROLLER_IMPLEMENTATION_COUNT = 1
OPERATIONAL_ORCHESTRATION_IMPLEMENTATION_COUNT = 1
STATE_TRANSITION_EXECUTION_COUNT = 0
HUMAN_APPROVAL_EXECUTION_COUNT = 0
HUMAN_GATE_EXECUTION_COUNT = 0
MR03_EXECUTION_IMPLEMENTATION_COUNT = 1
MR04_EXECUTION_IMPLEMENTATION_COUNT = 1
FILESYSTEM_WRITE_IMPLEMENTATION_COUNT = 0
SUBPROCESS_EXECUTION_COUNT = 0
NETWORK_IMPLEMENTATION_COUNT = 0
PROVIDER_CLIENT_IMPLEMENTATION_COUNT = 0
MODEL_CALL_IMPLEMENTATION_COUNT = 0
MODEL_ROUTING_IMPLEMENTATION_COUNT = 0
AUTH_IMPLEMENTATION_COUNT = 0
AUTO_RETRY_IMPLEMENTATION_COUNT = 0
AUTO_FALLBACK_IMPLEMENTATION_COUNT = 0
EVIDENCE_PERSISTENCE_COUNT = 1

class ControllerPolicyError(ValueError):
    """A controller request is outside the frozen deterministic semantics."""

@dataclass(frozen=True)
class TransitionQualification:
    transition_kind: str
    semantic_status: str
    human_gate_required: bool
    fail_closed_override_applied: bool
    implementation_authority: str = NO_IMPLEMENTATION_AUTHORITY

@dataclass(frozen=True, slots=True)
class ControllerOrchestrationResult:
    transition: TransitionQualification
    acquisition: AcquisitionResult
    run_record: RunRecord
    evidence_manifest: EvidenceManifest
    mr03_result: Mapping[str, object] | None = None
    mr04_result: Mapping[str, object] | None = None
    persistence_result: evidence.PersistenceResult | None = None
    controller_progress_authority: bool = False
    human_approval: bool = False
    evidence_write_authority: bool = False
    git_authority: bool = False
    model_provider_authority: bool = False

_TRANSITION_POLICY = MappingProxyType({
    TRANSITION_FAIL_CLOSED: TransitionQualification(TRANSITION_FAIL_CLOSED, QUALIFIED_PASS, False, True),
    TRANSITION_PROGRESS: TransitionQualification(TRANSITION_PROGRESS, HUMAN_GATE_REQUIRED, True, False),
    TRANSITION_HOLD: TransitionQualification(TRANSITION_HOLD, HOLD_TRANSITION_SEMANTICS, False, False),
    TRANSITION_READY_FOR_HUMAN_REVIEW_GATE: TransitionQualification(TRANSITION_READY_FOR_HUMAN_REVIEW_GATE, READY_FOR_HUMAN_REVIEW_GATE_SEMANTICS, False, False),
})

def qualify_transition(transition_kind: object) -> TransitionQualification:
    if type(transition_kind) is not str:
        raise ControllerPolicyError("transition_kind must be an exact string")
    try:
        return _TRANSITION_POLICY[transition_kind]
    except KeyError as exc:
        raise ControllerPolicyError(f"unknown controller transition kind: {transition_kind!r}") from exc

def human_gate_required_for_transition(transition_kind: object) -> bool:
    return qualify_transition(transition_kind).human_gate_required

def _identity_sequence(value: object, field: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ControllerPolicyError(f"{field} must be a sequence")
    items = tuple(value)
    if not allow_empty and not items:
        raise ControllerPolicyError(f"{field} must not be empty")
    for item in items:
        if type(item) is not str or len(item) != 64 or any(ch not in "0123456789abcdef" for ch in item):
            raise ControllerPolicyError(f"{field} must contain lowercase SHA-256 identities")
    if len(set(items)) != len(items):
        raise ControllerPolicyError(f"{field} must not contain duplicates")
    return items

def _counters(value: object) -> Mapping[str, int]:
    if not isinstance(value, Mapping) or not value:
        raise ControllerPolicyError("operational_counters must be a non-empty mapping")
    out: dict[str, int] = {}
    for key, counter in value.items():
        if type(key) is not str or not key or type(counter) is not int or counter < 0:
            raise ControllerPolicyError("operational_counters are malformed")
        out[key] = counter
    forbidden = {"network", "provider_client", "model_call", "model_routing", "auth", "human_approval", "human_gate", "auto_retry", "auto_fallback", "controller_progress", "git_operation", "mr03_execution", "mr04_execution", "subprocess", "filesystem_dependency", "evidence_persistence", "filesystem_evidence_write"}
    if any(out.get(name, 0) != 0 for name in forbidden):
        raise ControllerPolicyError("forbidden operational counter is non-zero")
    return MappingProxyType(dict(sorted(out.items())))

def _sha256_identity(value: object, field: str) -> str:
    if type(value) is not str or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise ControllerPolicyError(f"{field} must be a lowercase SHA-256 identity")
    return value

def orchestrate_deterministic_run(*, transition_kind: object, approved_source_root: object, source_relative_path: object, source_alias: object, provenance_owner: object, repository_commit: object, task_identity: object, contract_identities: object, dependency_identities: object, provenance_identity: object, metrics_identity: object, operational_counters: object, artifact_identities: object = (), source_type: object = "LOCAL_FILE", classification: object = "INTERNAL", content_kind: object = None, dependency_task: object = None, normalization_identity: object = None, source_set_identity: object = None, byte_budget: object = None, token_estimate_metadata: object = None, approved_evidence_root: object = None, evidence_relative_path: object = None) -> ControllerOrchestrationResult:
    """Compose one deterministic local run without progressing workflow state."""
    transition = qualify_transition(transition_kind)
    if transition.transition_kind == TRANSITION_FAIL_CLOSED:
        raise ControllerPolicyError("FAIL_CLOSED is terminal and executes no orchestration")
    if transition.human_gate_required:
        raise ControllerPolicyError("PROGRESS requires Human Gate; execution authority is absent")
    persistence_requested = any(value is not None for value in (approved_evidence_root, evidence_relative_path))
    if persistence_requested and (approved_evidence_root is None or evidence_relative_path is None):
        raise ControllerPolicyError("approved_evidence_root and evidence_relative_path must be supplied together")
    contracts = _identity_sequence(contract_identities, "contract_identities")
    dependencies = _identity_sequence(dependency_identities, "dependency_identities")
    artifacts = _identity_sequence(artifact_identities, "artifact_identities", allow_empty=True)
    counters = _counters(operational_counters)
    if type(repository_commit) is not str or len(repository_commit) != 40 or any(ch not in "0123456789abcdef" for ch in repository_commit):
        raise ControllerPolicyError("repository_commit must be an exact lowercase Git commit identity")
    task = _sha256_identity(task_identity, "task_identity")
    provenance = _sha256_identity(provenance_identity, "provenance_identity")
    metrics = _sha256_identity(metrics_identity, "metrics_identity")
    acquisition = capture_source(approved_root=approved_source_root, relative_path=source_relative_path, source_alias=source_alias, provenance_owner=provenance_owner, source_type=source_type, classification=classification, content_kind=content_kind, observational_metadata={})
    dependency_requested = any(value is not None for value in (dependency_task, normalization_identity, source_set_identity, byte_budget, token_estimate_metadata))
    mr03_result: Mapping[str, object] | None = None
    mr04_result: Mapping[str, object] | None = None
    bound_dependencies = dependencies
    effective_counters = dict(counters)
    if dependency_requested:
        if not isinstance(dependency_task, Mapping):
            raise ControllerPolicyError("dependency_task must be a mapping when frozen dependency execution is requested")
        normalization = _sha256_identity(normalization_identity, "normalization_identity")
        source_set = _sha256_identity(source_set_identity, "source_set_identity")
        if not isinstance(byte_budget, Mapping) or not isinstance(token_estimate_metadata, Mapping):
            raise ControllerPolicyError("byte_budget and token_estimate_metadata must be mappings")
        if type(approved_source_root) is not str:
            raise ControllerPolicyError("approved_source_root must be an exact string for dependency execution")
        mr03_result = dependency_runtime.invoke_mr03(
            approved_source_root, dict(dependency_task), task_identity=task,
            normalization_identity=normalization, source_set_identity=source_set,
            capture_identity=acquisition.capture_identity,
        )
        mr04_result = dependency_runtime.invoke_mr04(
            approved_source_root, dict(dependency_task), mr03_result, task_identity=task,
            source_set_identity=source_set, normalization_identity=normalization,
            byte_budget=dict(byte_budget), token_estimate_metadata=dict(token_estimate_metadata),
        )
        mr03_identity = _sha256_identity(mr03_result.get("result_identity"), "mr03_result_identity")
        mr04_identity = _sha256_identity(mr04_result.get("result_identity"), "mr04_result_identity")
        bound_dependencies = tuple(sorted(set(dependencies + (mr03_identity, mr04_identity))))
        effective_counters.update({"mr03_execution": 1, "mr04_execution": 1, "subprocess": 1, "filesystem_dependency": 1})
    if persistence_requested:
        effective_counters.update({"evidence_persistence": 1, "filesystem_evidence_write": 1})
    run = build_run_record(repository_commit=repository_commit, task_identity=task, contract_identities=contracts, dependency_identities=bound_dependencies, input_identities=(acquisition.capture_identity,))
    manifest_artifacts = tuple(sorted(set(artifacts + (acquisition.captured_source.descriptor.source_id,))))
    manifest = build_evidence_manifest(run_identity=run.run_identity, artifact_identities=manifest_artifacts, provenance_identity=provenance, metrics_identity=metrics, operational_counters=effective_counters)
    persistence_result: evidence.PersistenceResult | None = None
    if persistence_requested:
        persistence_result = evidence.persist_evidence(
            approved_root=approved_evidence_root,
            relative_path=evidence_relative_path,
            manifest=manifest,
        )
    return ControllerOrchestrationResult(transition=transition, acquisition=acquisition, run_record=run, evidence_manifest=manifest, mr03_result=mr03_result, mr04_result=mr04_result, persistence_result=persistence_result)

def not_implemented(*args: object, **kwargs: object) -> None:
    del args, kwargs
    phase_not_implemented("controller")

__all__ = ("FAIL_CLOSED_OVERRIDE", "HUMAN_GATE_REQUIRED_TO_LEAVE_SEMANTICS", "HOLD_TRANSITION_SEMANTICS", "READY_FOR_HUMAN_REVIEW_GATE_SEMANTICS", "PASS_FOR_REVIEW_IS_IMPLEMENTATION_AUTHORITY", "TRANSITION_FAIL_CLOSED", "TRANSITION_PROGRESS", "TRANSITION_HOLD", "TRANSITION_READY_FOR_HUMAN_REVIEW_GATE", "CONTROLLER_IMPLEMENTATION_COUNT", "OPERATIONAL_ORCHESTRATION_IMPLEMENTATION_COUNT", "STATE_TRANSITION_EXECUTION_COUNT", "HUMAN_APPROVAL_EXECUTION_COUNT", "HUMAN_GATE_EXECUTION_COUNT", "MR03_EXECUTION_IMPLEMENTATION_COUNT", "MR04_EXECUTION_IMPLEMENTATION_COUNT", "FILESYSTEM_WRITE_IMPLEMENTATION_COUNT", "SUBPROCESS_EXECUTION_COUNT", "NETWORK_IMPLEMENTATION_COUNT", "PROVIDER_CLIENT_IMPLEMENTATION_COUNT", "MODEL_CALL_IMPLEMENTATION_COUNT", "MODEL_ROUTING_IMPLEMENTATION_COUNT", "AUTH_IMPLEMENTATION_COUNT", "AUTO_RETRY_IMPLEMENTATION_COUNT", "AUTO_FALLBACK_IMPLEMENTATION_COUNT", "EVIDENCE_PERSISTENCE_COUNT", "ControllerPolicyError", "TransitionQualification", "ControllerOrchestrationResult", "qualify_transition", "human_gate_required_for_transition", "orchestrate_deterministic_run", "not_implemented")
