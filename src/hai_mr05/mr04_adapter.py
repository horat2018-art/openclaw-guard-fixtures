"""Pure-data binding primitives for the frozen MR-04 dependency."""

from __future__ import annotations

from collections.abc import Mapping

from .discovery import DiscoveryResult, SourceReference
from .failures import phase_not_implemented
from .mr03_adapter import (
    AUTH_IMPLEMENTATION_COUNT,
    AUTO_FALLBACK_IMPLEMENTATION_COUNT,
    AUTO_RETRY_IMPLEMENTATION_COUNT,
    BINDING_SCHEMA_ID,
    BOUNDED_CONTEXT_IMPLEMENTATION_COUNT,
    CONTROLLER_IMPLEMENTATION_COUNT,
    DEPENDENCY_BINDING_SCHEMA_ID,
    DEPENDENCY_BINDING_SCHEMA_VERSION,
    FILESYSTEM_DEPENDENCY_EXECUTION_COUNT,
    MODEL_CALL_IMPLEMENTATION_COUNT,
    SUBPROCESS_EXECUTION_COUNT,
    NETWORK_IMPLEMENTATION_COUNT,
    VERIFIER_IMPLEMENTATION_COUNT,
    MR03DependencyBinding,
    MR03_EXECUTION_IMPLEMENTATION_COUNT,
    MR03_EXPECTED_COMMIT,
    MR03_EXPECTED_PARENT,
    MR03_EXPECTED_TREE,
    MR04_EXECUTION_IMPLEMENTATION_COUNT,
    MR04_EXPECTED_COMMIT,
    MR04_EXPECTED_PARENT,
    MR04_EXPECTED_TREE,
    MR04_CONTENTSET_SHA256,
    MR04_IMPLEMENTATION_CONTRACT_SHA256,
    MR04_PATHSET_SHA256,
    AdapterValidationError,
    DependencyBinding,
    DependencyBindingError,
    DependencyBindingValidationError,
    _bind_dependency,
    binding_identity_for,
    canonical_dependency_binding_bytes,
    compute_binding_identity,
    dependency_binding_identity,
)
from .normalization import NormalizationResult


MR04_GUARD = "MR04_GUARD"
MR04_ADAPTER_ROLE = MR04_GUARD
MR04DependencyBinding = DependencyBinding


def bind_mr04_dependency(
    record: Mapping[str, object] | DependencyBinding,
    discovery_result: DiscoveryResult | Mapping[str, object],
    normalization_result: NormalizationResult | Mapping[str, object],
    mr03_result_identity: object,
    source_ref: SourceReference | Mapping[str, object],
) -> DependencyBinding:
    """Bind supplied MR-05 identities to the frozen MR-04 declaration."""

    return _bind_dependency(
        record,
        expected_role=MR04_GUARD,
        discovery_result=discovery_result,
        normalization_result=normalization_result,
        source_ref=source_ref,
        upstream_dependency_identity=mr03_result_identity,
    )


def not_implemented(*args: object, **kwargs: object) -> None:
    """Retain the explicit fail-closed marker for operational composition."""

    del args, kwargs
    phase_not_implemented("mr04_adapter")


__all__ = (
    "BINDING_SCHEMA_ID",
    "DEPENDENCY_BINDING_SCHEMA_ID",
    "DEPENDENCY_BINDING_SCHEMA_VERSION",
    "MR03_EXPECTED_COMMIT",
    "MR03_EXPECTED_PARENT",
    "MR03_EXPECTED_TREE",
    "MR04_EXPECTED_COMMIT",
    "MR04_EXPECTED_PARENT",
    "MR04_EXPECTED_TREE",
    "MR04_CONTENTSET_SHA256",
    "MR04_PATHSET_SHA256",
    "MR04_IMPLEMENTATION_CONTRACT_SHA256",
    "MR03_EXECUTION_IMPLEMENTATION_COUNT",
    "MR04_EXECUTION_IMPLEMENTATION_COUNT",
    "AUTH_IMPLEMENTATION_COUNT",
    "AUTO_FALLBACK_IMPLEMENTATION_COUNT",
    "AUTO_RETRY_IMPLEMENTATION_COUNT",
    "BOUNDED_CONTEXT_IMPLEMENTATION_COUNT",
    "CONTROLLER_IMPLEMENTATION_COUNT",
    "FILESYSTEM_DEPENDENCY_EXECUTION_COUNT",
    "MODEL_CALL_IMPLEMENTATION_COUNT",
    "SUBPROCESS_EXECUTION_COUNT",
    "NETWORK_IMPLEMENTATION_COUNT",
    "VERIFIER_IMPLEMENTATION_COUNT",
    "DependencyBindingValidationError",
    "DependencyBindingError",
    "AdapterValidationError",
    "DependencyBinding",
    "MR03DependencyBinding",
    "MR04DependencyBinding",
    "MR04_GUARD",
    "MR04_ADAPTER_ROLE",
    "bind_mr04_dependency",
    "compute_binding_identity",
    "dependency_binding_identity",
    "binding_identity_for",
    "canonical_dependency_binding_bytes",
    "not_implemented",
)
