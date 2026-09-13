"""Deterministic local materialization of prepare-ready workflow inputs.

This boundary consumes already-produced, explicitly supplied deterministic records.
It performs no discovery, source read, dependency execution, network/provider/model/auth
operation, Human approval, state transition, retry/fallback, Git mutation, or filesystem I/O.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

from . import context_builder, discovery, evidence, metrics, normalization, provenance, verifier
from .canonical import canonical_json_bytes
from .failures import Failure
from .identity import sha256_bytes
from .mr03_adapter import DependencyBinding

MATERIALIZATION_SCHEMA_VERSION = "1.0.0"
MATERIALIZATION_IMPLEMENTATION_COUNT = 1
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
FILESYSTEM_READ_COUNT = 0
FILESYSTEM_WRITE_COUNT = 0
DEPENDENCY_EXECUTION_COUNT = 0
GIT_OPERATION_COUNT = 0


class PrepareInputMaterializationError(ValueError):
    """Supplied local material cannot form one exact prepare-ready package."""


def _plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _plain(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(child) for child in value]
    return value


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        raise PrepareInputMaterializationError(f"{field} must be a string-keyed mapping")
    return value


def _sequence(value: object, field: str) -> tuple[object, ...]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise PrepareInputMaterializationError(f"{field} must be an array")
    return tuple(value)


def _failure_records(value: object) -> tuple[Failure, ...]:
    records: list[Failure] = []
    for item in _sequence(value, "verifier_failure_records"):
        if isinstance(item, Failure):
            records.append(Failure.from_mapping(item.to_dict()))
        else:
            records.append(Failure.from_mapping(_mapping(item, "verifier_failure_record")))
    return tuple(records)


def _checks(value: object) -> tuple[verifier.VerifierCheckRecord, ...]:
    return tuple(
        item
        if isinstance(item, verifier.VerifierCheckRecord)
        else verifier.VerifierCheckRecord.from_mapping(_mapping(item, "legacy_verifier_check"))
        for item in _sequence(value, "legacy_verifier_checks")
    )


def _materialization_identity(payload: Mapping[str, object]) -> str:
    return sha256_bytes(canonical_json_bytes(payload, identity_critical=False))


@dataclass(frozen=True, slots=True)
class PrepareInputMaterialization:
    schema_version: str
    discovery_identity: str
    normalization_identity: str
    dependency_binding_identities: tuple[str, str]
    provenance_identity: str
    metrics_identity: str
    bounded_context_identity: str
    frozen_run_identity: str
    prepare_arguments: Mapping[str, object]
    materialization_identity: str

    @property
    def identity_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "discovery_identity": self.discovery_identity,
            "normalization_identity": self.normalization_identity,
            "dependency_binding_identities": list(self.dependency_binding_identities),
            "provenance_identity": self.provenance_identity,
            "metrics_identity": self.metrics_identity,
            "bounded_context_identity": self.bounded_context_identity,
            "frozen_run_identity": self.frozen_run_identity,
            "prepare_arguments": _plain(self.prepare_arguments),
        }

    def __post_init__(self) -> None:
        if self.schema_version != MATERIALIZATION_SCHEMA_VERSION:
            raise PrepareInputMaterializationError("unsupported materialization schema version")
        if len(self.dependency_binding_identities) != 2:
            raise PrepareInputMaterializationError("exactly two dependency binding identities are required")
        for field in (
            "discovery_identity",
            "normalization_identity",
            "provenance_identity",
            "metrics_identity",
            "bounded_context_identity",
            "frozen_run_identity",
            "materialization_identity",
        ):
            value = getattr(self, field)
            if type(value) is not str or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
                raise PrepareInputMaterializationError(f"{field} must be a lowercase SHA-256 identity")
        dependencies = tuple(self.dependency_binding_identities)
        if dependencies != tuple(sorted(dependencies)) or len(set(dependencies)) != 2:
            raise PrepareInputMaterializationError("dependency binding identities are not exact/canonical")
        arguments = _mapping(self.prepare_arguments, "prepare_arguments")
        try:
            run = evidence.FrozenRunRecord.from_mapping(_mapping(arguments["run_record"], "run_record"))
            bounded = context_builder.BoundedContextPackage.from_mapping(
                _mapping(arguments["bounded_context_record"], "bounded_context_record")
            )
            metric = metrics.build_metrics(
                raw_source_bytes=arguments["metrics_raw_source_bytes"],
                normalized_bytes=arguments["metrics_normalized_bytes"],
                package_bytes=arguments["metrics_package_bytes"],
                cloud_context_bytes=arguments["metrics_cloud_context_bytes"],
                raw_estimated_tokens=arguments["metrics_raw_estimated_tokens"],
                cloud_estimated_tokens=arguments["metrics_cloud_estimated_tokens"],
                model_call_count=arguments["metrics_model_call_count"],
                model_retry_count=arguments["metrics_model_retry_count"],
                failure_count=arguments["metrics_failure_count"],
                source_ref_count=arguments["metrics_source_ref_count"],
                missing_source_ref_count=arguments["metrics_missing_source_ref_count"],
                identity_mismatch_count=arguments["metrics_identity_mismatch_count"],
                observational_metadata=arguments["metrics_observational_metadata"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise PrepareInputMaterializationError("prepare arguments fail deterministic requalification") from exc
        if run.run_identity != self.frozen_run_identity:
            raise PrepareInputMaterializationError("frozen run identity is not bound to prepare arguments")
        if bounded.context_identity != self.bounded_context_identity:
            raise PrepareInputMaterializationError("bounded context identity is not bound to prepare arguments")
        if metric.metrics_identity != self.metrics_identity or bounded.metrics_identity != self.metrics_identity:
            raise PrepareInputMaterializationError("metrics identity is not bound to bounded context")
        inputs = bounded.input_identities
        if inputs["discovery_identity"] != self.discovery_identity:
            raise PrepareInputMaterializationError("discovery identity is not bound to bounded context")
        if inputs["normalization_identity"] != self.normalization_identity:
            raise PrepareInputMaterializationError("normalization identity is not bound to bounded context")
        if tuple(bounded.dependency_binding_identities) != dependencies:
            raise PrepareInputMaterializationError("dependency identities are not bound to bounded context")
        if bounded.provenance_identity != self.provenance_identity:
            raise PrepareInputMaterializationError("provenance identity is not bound to bounded context")
        computed = _materialization_identity(self.identity_payload)
        if computed != self.materialization_identity:
            raise PrepareInputMaterializationError("materialization_identity does not match canonical output")
        object.__setattr__(self, "dependency_binding_identities", dependencies)
        object.__setattr__(self, "prepare_arguments", MappingProxyType(dict(_plain(arguments))))

    def to_dict(self) -> dict[str, object]:
        out = self.identity_payload
        out["materialization_identity"] = self.materialization_identity
        return out

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "PrepareInputMaterialization":
        mapping = _mapping(value, "prepare input materialization")
        required = {
            "schema_version",
            "discovery_identity",
            "normalization_identity",
            "dependency_binding_identities",
            "provenance_identity",
            "metrics_identity",
            "bounded_context_identity",
            "frozen_run_identity",
            "prepare_arguments",
            "materialization_identity",
        }
        if set(mapping) != required:
            raise PrepareInputMaterializationError("materialization fields are not exact")
        dependencies = _sequence(mapping["dependency_binding_identities"], "dependency_binding_identities")
        return cls(
            schema_version=mapping["schema_version"],
            discovery_identity=mapping["discovery_identity"],
            normalization_identity=mapping["normalization_identity"],
            dependency_binding_identities=dependencies,  # type: ignore[arg-type]
            provenance_identity=mapping["provenance_identity"],
            metrics_identity=mapping["metrics_identity"],
            bounded_context_identity=mapping["bounded_context_identity"],
            frozen_run_identity=mapping["frozen_run_identity"],
            prepare_arguments=mapping["prepare_arguments"],
            materialization_identity=mapping["materialization_identity"],
        )


def materialize_prepare_inputs(
    *,
    discovery_result: object,
    normalization_result: object,
    dependency_bindings: object,
    provenance_chain: object,
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
    max_context_bytes: object,
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
    legacy_verifier_checks: object,
    verifier_failure_records: object = (),
    prohibited_assumptions: object = (),
    context_observational_metadata: Mapping[str, object] | None = None,
    request_observational_metadata: Mapping[str, object] | None = None,
) -> PrepareInputMaterialization:
    """Build one identity-bound prepare input from already-supplied local records only."""

    try:
        discovered = (
            discovery_result
            if isinstance(discovery_result, discovery.DiscoveryResult)
            else discovery.DiscoveryResult.from_mapping(_mapping(discovery_result, "discovery_result"))
        )
        normalized = (
            normalization_result
            if isinstance(normalization_result, normalization.NormalizationResult)
            else normalization.NormalizationResult.from_mapping(
                _mapping(normalization_result, "normalization_result")
            )
        )
        raw_bindings = _sequence(dependency_bindings, "dependency_bindings")
        if len(raw_bindings) != 2:
            raise PrepareInputMaterializationError("exactly two dependency bindings are required")
        bindings = tuple(
            item
            if isinstance(item, DependencyBinding)
            else DependencyBinding.from_mapping(_mapping(item, "dependency_binding"))
            for item in raw_bindings
        )
        chain = (
            provenance_chain
            if isinstance(provenance_chain, provenance.ProvenanceChain)
            else provenance.ProvenanceChain.from_mapping(_mapping(provenance_chain, "provenance_chain"))
        )
        metric = metrics.build_metrics(
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
        bounded = context_builder.build_bounded_context(
            discovered,
            normalized,
            bindings,
            chain,
            metric,
            max_context_bytes=max_context_bytes,
        )
        inputs = bounded.input_identities
        run = evidence.build_frozen_run_record(
            task_identity=inputs["task_identity"],
            source_set_identity=inputs["source_set_identity"],
            discovery_identity=inputs["discovery_identity"],
            normalization_identity=inputs["normalization_identity"],
            mr03_result_identity=mr03_result_identity,
            mr04_result_identity=mr04_result_identity,
            byte_budget=_mapping(frozen_run_byte_budget, "frozen_run_byte_budget"),
            state=frozen_run_state,
            observational_metadata=frozen_run_observational_metadata,
        )
        checks = _checks(legacy_verifier_checks)
        failure_records = _failure_records(verifier_failure_records)
    except PrepareInputMaterializationError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise PrepareInputMaterializationError("local prepare-input materialization failed closed") from exc

    prepare_arguments: dict[str, object] = {
        "run_record": run.to_dict(),
        "bounded_context_record": bounded.to_dict(),
        "disclosure_classification": disclosure_classification,
        "disclosure_findings": _plain(disclosure_findings),
        "disclosure_observational_metadata": _plain(disclosure_observational_metadata),
        "metrics_raw_source_bytes": metric.raw_source_bytes,
        "metrics_normalized_bytes": metric.normalized_bytes,
        "metrics_package_bytes": metric.package_bytes,
        "metrics_cloud_context_bytes": metric.cloud_context_bytes,
        "metrics_raw_estimated_tokens": metric.raw_estimated_tokens,
        "metrics_cloud_estimated_tokens": metric.cloud_estimated_tokens,
        "metrics_model_call_count": metric.model_call_count,
        "metrics_model_retry_count": metric.model_retry_count,
        "metrics_failure_count": metric.failure_count,
        "metrics_source_ref_count": metric.source_ref_count,
        "metrics_missing_source_ref_count": metric.missing_source_ref_count,
        "metrics_identity_mismatch_count": metric.identity_mismatch_count,
        "metrics_observational_metadata": dict(metric.observational_metadata),
        "model_identifier": model_identifier,
        "human_authorization_reference": human_authorization_reference,
        "estimated_token_metadata": _plain(estimated_token_metadata),
        "authorized_provider_identifier": authorized_provider_identifier,
        "authorized_account_boundary_reference": authorized_account_boundary_reference,
        "authorization_observational_metadata": _plain(authorization_observational_metadata),
        "legacy_verifier_checks": [item.to_dict() for item in checks],
        "verifier_failure_records": [item.to_dict() for item in failure_records],
        "prohibited_assumptions": list(_sequence(prohibited_assumptions, "prohibited_assumptions")),
        "context_observational_metadata": _plain(context_observational_metadata),
        "request_observational_metadata": _plain(request_observational_metadata),
    }
    dependency_ids = tuple(bounded.dependency_binding_identities)
    identity_payload = {
        "schema_version": MATERIALIZATION_SCHEMA_VERSION,
        "discovery_identity": discovered.discovery_identity,
        "normalization_identity": normalized.normalization_identity,
        "dependency_binding_identities": list(dependency_ids),
        "provenance_identity": chain.provenance_identity,
        "metrics_identity": metric.metrics_identity,
        "bounded_context_identity": bounded.context_identity,
        "frozen_run_identity": run.run_identity,
        "prepare_arguments": prepare_arguments,
    }
    result = PrepareInputMaterialization(
        schema_version=MATERIALIZATION_SCHEMA_VERSION,
        discovery_identity=discovered.discovery_identity,
        normalization_identity=normalized.normalization_identity,
        dependency_binding_identities=dependency_ids,  # type: ignore[arg-type]
        provenance_identity=chain.provenance_identity,
        metrics_identity=metric.metrics_identity,
        bounded_context_identity=bounded.context_identity,
        frozen_run_identity=run.run_identity,
        prepare_arguments=prepare_arguments,
        materialization_identity=_materialization_identity(identity_payload),
    )
    return PrepareInputMaterialization.from_mapping(result.to_dict())


__all__ = [
    "PrepareInputMaterializationError",
    "PrepareInputMaterialization",
    "materialize_prepare_inputs",
    "MATERIALIZATION_SCHEMA_VERSION",
    "MATERIALIZATION_IMPLEMENTATION_COUNT",
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
    "FILESYSTEM_READ_COUNT",
    "FILESYSTEM_WRITE_COUNT",
    "DEPENDENCY_EXECUTION_COUNT",
    "GIT_OPERATION_COUNT",
]
