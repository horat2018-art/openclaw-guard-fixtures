"""Deterministic in-memory byte and advisory token metric primitives."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from types import MappingProxyType

from .canonical import canonical_json_bytes
from .failures import phase_not_implemented
from .contracts import SCHEMA_VERSION, TOKEN_ESTIMATE_AUTHORITY
from .identity import require_sha256, sha256_canonical


MAX_METRIC_VALUE = 9223372036854775807
METRICS_SCHEMA_ID = "mr05.metrics"
METRIC_FORMULA_VERSION = "MR05-METRICS-FORMULAS-1.0.0"
BYTE_REDUCTION_FORMULA_VERSION = "MR05-BYTE-REDUCTION-1.0.0"
TOKEN_REDUCTION_FORMULA_VERSION = "MR05-TOKEN-REDUCTION-1.0.0"


class MetricsValidationError(ValueError):
    """Metric input violates the frozen bounded integer or retry policy."""


def _counter(value: object, *, name: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_METRIC_VALUE:
        raise MetricsValidationError(f"{name} must be a non-negative bounded integer")
    return value


def _decimal_percent(source: int, reduced: int) -> Decimal:
    if source == 0:
        return Decimal(0)
    return (Decimal(source - reduced) * Decimal(100)) / Decimal(source)


def _percent_value(source: int, reduced: int) -> float:
    return float(_decimal_percent(source, reduced))


def _provided_percent(value: object, *, expected: float, name: str) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MetricsValidationError(f"{name} must be a finite number")
    if not math.isfinite(float(value)) or float(value) != expected:
        raise MetricsValidationError(f"{name} does not match the frozen formula")


@dataclass(frozen=True, slots=True)
class Metrics:
    """Immutable deterministic metrics; token fields remain advisory metadata."""

    raw_source_bytes: int
    normalized_bytes: int = 0
    package_bytes: int = 0
    cloud_context_bytes: int = 0
    raw_estimated_tokens: int = 0
    cloud_estimated_tokens: int = 0
    model_call_count: int = 0
    model_retry_count: int = 0
    failure_count: int = 0
    source_ref_count: int = 0
    missing_source_ref_count: int = 0
    identity_mismatch_count: int = 0
    schema_version: str = SCHEMA_VERSION
    byte_reduction_percent: float | None = None
    estimated_token_reduction_percent: float | None = None
    metrics_identity: str | None = None
    observational_metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise MetricsValidationError("unsupported metrics schema version")
        for name in (
            "raw_source_bytes", "normalized_bytes", "package_bytes", "cloud_context_bytes",
            "raw_estimated_tokens", "cloud_estimated_tokens", "model_call_count",
            "model_retry_count", "failure_count", "source_ref_count",
            "missing_source_ref_count", "identity_mismatch_count",
        ):
            _counter(getattr(self, name), name=name)
        if self.model_retry_count != 0:
            raise MetricsValidationError("model_retry_count is frozen to zero")
        expected_bytes = _percent_value(self.raw_source_bytes, self.cloud_context_bytes)
        expected_tokens = _percent_value(self.raw_estimated_tokens, self.cloud_estimated_tokens)
        _provided_percent(self.byte_reduction_percent, expected=expected_bytes, name="byte_reduction_percent")
        _provided_percent(
            self.estimated_token_reduction_percent,
            expected=expected_tokens,
            name="estimated_token_reduction_percent",
        )
        if not isinstance(self.observational_metadata, Mapping):
            raise MetricsValidationError("observational_metadata must be a mapping")
        object.__setattr__(self, "byte_reduction_percent", expected_bytes)
        object.__setattr__(self, "estimated_token_reduction_percent", expected_tokens)
        object.__setattr__(self, "observational_metadata", MappingProxyType(dict(self.observational_metadata)))
        computed = sha256_canonical(self.identity_payload())
        if self.metrics_identity is None:
            object.__setattr__(self, "metrics_identity", computed)
        else:
            try:
                actual = require_sha256(self.metrics_identity, field="metrics_identity")
            except ValueError as exc:
                raise MetricsValidationError(str(exc)) from exc
            if actual != computed:
                raise MetricsValidationError("metrics_identity does not match canonical metrics")
            object.__setattr__(self, "metrics_identity", actual)

    @property
    def zero_denominator(self) -> bool:
        """Whether the explicit zero-source-byte rule was applied."""

        return self.raw_source_bytes == 0

    def identity_payload(self) -> dict[str, object]:
        """Return governed identity inputs without percentage presentation values."""

        return {
            "schema_version": self.schema_version,
            "raw_source_bytes": self.raw_source_bytes,
            "normalized_bytes": self.normalized_bytes,
            "package_bytes": self.package_bytes,
            "cloud_context_bytes": self.cloud_context_bytes,
            "metric_formula_version": METRIC_FORMULA_VERSION,
            "raw_estimated_tokens": self.raw_estimated_tokens,
            "cloud_estimated_tokens": self.cloud_estimated_tokens,
            "model_call_count": self.model_call_count,
            "model_retry_count": self.model_retry_count,
            "failure_count": self.failure_count,
            "source_ref_count": self.source_ref_count,
            "missing_source_ref_count": self.missing_source_ref_count,
            "identity_mismatch_count": self.identity_mismatch_count,
        }

    def to_dict(self) -> dict[str, object]:
        """Return the frozen metrics envelope; token fields are advisory only."""

        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "raw_source_bytes": self.raw_source_bytes,
            "normalized_bytes": self.normalized_bytes,
            "package_bytes": self.package_bytes,
            "cloud_context_bytes": self.cloud_context_bytes,
            "byte_reduction_percent": self.byte_reduction_percent,
            "raw_estimated_tokens": self.raw_estimated_tokens,
            "cloud_estimated_tokens": self.cloud_estimated_tokens,
            "estimated_token_reduction_percent": self.estimated_token_reduction_percent,
            "model_call_count": self.model_call_count,
            "model_retry_count": self.model_retry_count,
            "failure_count": self.failure_count,
            "source_ref_count": self.source_ref_count,
            "missing_source_ref_count": self.missing_source_ref_count,
            "identity_mismatch_count": self.identity_mismatch_count,
            "metrics_identity": self.metrics_identity,
        }
        if self.observational_metadata:
            result["observational_metadata"] = dict(self.observational_metadata)
        return result

    def canonical_bytes(self) -> bytes:
        """Return stable metric bytes without treating percentages as identities."""

        return canonical_json_bytes(self.to_dict(), identity_critical=False)

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "Metrics":
        """Construct metrics while rejecting missing or unknown critical fields."""

        required = {
            "schema_version", "raw_source_bytes", "normalized_bytes", "package_bytes",
            "cloud_context_bytes", "byte_reduction_percent", "raw_estimated_tokens",
            "cloud_estimated_tokens", "estimated_token_reduction_percent", "model_call_count",
            "model_retry_count", "failure_count", "source_ref_count", "missing_source_ref_count",
            "identity_mismatch_count", "metrics_identity",
        }
        allowed = required | {"observational_metadata"}
        if not isinstance(value, Mapping):
            raise MetricsValidationError("metrics must be a mapping")
        if required - set(value) or set(value) - allowed:
            raise MetricsValidationError("metrics fields are not exact")
        return cls(
            raw_source_bytes=value["raw_source_bytes"],
            normalized_bytes=value["normalized_bytes"],
            package_bytes=value["package_bytes"],
            cloud_context_bytes=value["cloud_context_bytes"],
            raw_estimated_tokens=value["raw_estimated_tokens"],
            cloud_estimated_tokens=value["cloud_estimated_tokens"],
            model_call_count=value["model_call_count"],
            model_retry_count=value["model_retry_count"],
            failure_count=value["failure_count"],
            source_ref_count=value["source_ref_count"],
            missing_source_ref_count=value["missing_source_ref_count"],
            identity_mismatch_count=value["identity_mismatch_count"],
            schema_version=value["schema_version"],
            byte_reduction_percent=value["byte_reduction_percent"],
            estimated_token_reduction_percent=value["estimated_token_reduction_percent"],
            metrics_identity=value["metrics_identity"],
            observational_metadata=value.get("observational_metadata", {}),
        )


def byte_reduction_percent(raw_source_bytes: int, cloud_context_bytes: int) -> float:
    """Apply the frozen byte reduction formula with explicit zero behavior."""

    raw = _counter(raw_source_bytes, name="raw_source_bytes")
    context = _counter(cloud_context_bytes, name="cloud_context_bytes")
    return _percent_value(raw, context)


def token_reduction_percent(raw_estimated_tokens: int, cloud_estimated_tokens: int) -> float:
    """Return an advisory deterministic estimate; it is not provider usage."""

    raw = _counter(raw_estimated_tokens, name="raw_estimated_tokens")
    cloud = _counter(cloud_estimated_tokens, name="cloud_estimated_tokens")
    return _percent_value(raw, cloud)


# Descriptive alias for callers that use the schema title.
RunMetrics = Metrics


def not_implemented(*args: object, **kwargs: object) -> None:
    """Retain the non-operational boundary for future metric phases."""

    del args, kwargs
    phase_not_implemented("metrics")


__all__ = (
    "MAX_METRIC_VALUE", "METRICS_SCHEMA_ID", "METRIC_FORMULA_VERSION",
    "BYTE_REDUCTION_FORMULA_VERSION", "TOKEN_REDUCTION_FORMULA_VERSION",
    "TOKEN_ESTIMATE_AUTHORITY", "MetricsValidationError",
    "Metrics", "RunMetrics", "byte_reduction_percent", "token_reduction_percent", "not_implemented",
)
