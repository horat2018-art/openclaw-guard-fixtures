"""Deterministic, immutable MR-05 provenance structures."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType

from .canonical import canonical_identity_bytes, canonical_json_bytes
from .failures import phase_not_implemented
from .identity import require_sha256, sha256_bytes
from .contracts import SCHEMA_VERSION


class ProvenanceValidationError(ValueError):
    """A provenance node, edge, or chain is malformed."""


class RelationType(str, Enum):
    DERIVED_FROM = "DERIVED_FROM"
    BINDS = "BINDS"
    VERIFIED_BY = "VERIFIED_BY"
    REVIEWED_BY = "REVIEWED_BY"
    CAPTURES = "CAPTURES"


def _required_text(value: object, *, field_name: str, maximum: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        raise ProvenanceValidationError(f"{field_name} must contain 1..{maximum} characters")
    if "\x00" in value:
        raise ProvenanceValidationError(f"{field_name} must not contain NUL")
    return value


def _required_identity(value: object, *, field_name: str) -> str:
    try:
        return require_sha256(value, field=field_name)
    except ValueError as exc:
        raise ProvenanceValidationError(str(exc)) from exc


@dataclass(frozen=True, slots=True)
class ProvenanceNode:
    """An immutable named identity and its bounded artifact reference."""

    identity_name: str
    identity_value: str
    artifact_reference: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "identity_name", _required_text(self.identity_name, field_name="identity_name", maximum=128))
        object.__setattr__(self, "identity_value", _required_identity(self.identity_value, field_name="identity_value"))
        object.__setattr__(self, "artifact_reference", _required_text(self.artifact_reference, field_name="artifact_reference", maximum=4096))

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "ProvenanceNode":
        required = {"identity_name", "identity_value", "artifact_reference"}
        if not isinstance(value, Mapping) or set(value) != required:
            raise ProvenanceValidationError("provenance node fields are not exact")
        return cls(
            identity_name=value["identity_name"],
            identity_value=value["identity_value"],
            artifact_reference=value["artifact_reference"],
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "identity_name": self.identity_name,
            "identity_value": self.identity_value,
            "artifact_reference": self.artifact_reference,
        }


@dataclass(frozen=True, slots=True)
class ProvenanceEdge:
    """An immutable, schema-bound relation between two identities."""

    from_identity: str
    to_identity: str
    relation_type: RelationType | str
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "from_identity", _required_identity(self.from_identity, field_name="from_identity"))
        object.__setattr__(self, "to_identity", _required_identity(self.to_identity, field_name="to_identity"))
        try:
            relation = self.relation_type if isinstance(self.relation_type, RelationType) else RelationType(self.relation_type)
        except (TypeError, ValueError) as exc:
            raise ProvenanceValidationError("relation_type is outside the frozen enum") from exc
        object.__setattr__(self, "relation_type", relation)
        if self.schema_version != SCHEMA_VERSION:
            raise ProvenanceValidationError("unsupported provenance schema version")

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "ProvenanceEdge":
        required = {"from_identity", "to_identity", "relation_type", "schema_version"}
        if not isinstance(value, Mapping) or set(value) != required:
            raise ProvenanceValidationError("provenance edge fields are not exact")
        return cls(
            from_identity=value["from_identity"],
            to_identity=value["to_identity"],
            relation_type=value["relation_type"],
            schema_version=value["schema_version"],
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "from_identity": self.from_identity,
            "to_identity": self.to_identity,
            "relation_type": self.relation_type.value,
            "schema_version": self.schema_version,
        }


@dataclass(frozen=True, slots=True)
class ProvenanceChain:
    """A complete deterministic provenance chain with 100% coverage target."""

    nodes: tuple[ProvenanceNode, ...]
    edges: tuple[ProvenanceEdge, ...]
    coverage_percent: int = 100
    observational_metadata: Mapping[str, object] = field(default_factory=dict)
    provenance_identity: str | None = None

    def __post_init__(self) -> None:
        nodes = tuple(self.nodes)
        edges = tuple(self.edges)
        if not nodes or any(not isinstance(node, ProvenanceNode) for node in nodes):
            raise ProvenanceValidationError("provenance requires at least one valid node")
        if any(not isinstance(edge, ProvenanceEdge) for edge in edges):
            raise ProvenanceValidationError("provenance edges must use ProvenanceEdge")
        if len({(node.identity_name, node.identity_value) for node in nodes}) != len(nodes):
            raise ProvenanceValidationError("provenance nodes contain duplicate identities")
        if type(self.coverage_percent) is not int or self.coverage_percent != 100:
            raise ProvenanceValidationError("provenance coverage_percent is frozen to 100")
        if not isinstance(self.observational_metadata, Mapping):
            raise ProvenanceValidationError("observational_metadata must be a mapping")
        edges = tuple(sorted(edges, key=lambda edge: (edge.from_identity, edge.to_identity, edge.relation_type.value, edge.schema_version)))
        metadata = MappingProxyType(dict(self.observational_metadata))
        object.__setattr__(self, "nodes", nodes)
        object.__setattr__(self, "edges", edges)
        object.__setattr__(self, "observational_metadata", metadata)
        computed = sha256_bytes(canonical_identity_bytes(self._identity_payload(nodes, edges)))
        if self.provenance_identity is None:
            object.__setattr__(self, "provenance_identity", computed)
        else:
            actual = _required_identity(self.provenance_identity, field_name="provenance_identity")
            if actual != computed:
                raise ProvenanceValidationError("provenance_identity does not match canonical content")
            object.__setattr__(self, "provenance_identity", actual)

    @staticmethod
    def _identity_payload(nodes: tuple[ProvenanceNode, ...], edges: tuple[ProvenanceEdge, ...]) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION,
            "nodes": [node.to_dict() for node in nodes],
            "edges": [edge.to_dict() for edge in edges],
            "coverage_percent": 100,
        }

    def identity_payload(self) -> dict[str, object]:
        """Return identity-bearing fields, excluding identity and observations."""

        return self._identity_payload(self.nodes, self.edges)

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
            "coverage_percent": self.coverage_percent,
            "provenance_identity": self.provenance_identity,
        }
        if self.observational_metadata:
            result["observational_metadata"] = dict(self.observational_metadata)
        return result

    def canonical_bytes(self) -> bytes:
        """Return stable serialized chain bytes without identity-critical float rules."""

        return canonical_json_bytes(self.to_dict(), identity_critical=False)

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "ProvenanceChain":
        required = {"schema_version", "nodes", "edges", "coverage_percent", "provenance_identity"}
        allowed = required | {"observational_metadata"}
        if not isinstance(value, Mapping) or not required.issubset(value) or set(value) - allowed:
            raise ProvenanceValidationError("provenance chain fields are not exact")
        if value["schema_version"] != SCHEMA_VERSION:
            raise ProvenanceValidationError("unsupported provenance schema version")
        raw_nodes = value["nodes"]
        raw_edges = value["edges"]
        if not isinstance(raw_nodes, (list, tuple)) or not isinstance(raw_edges, (list, tuple)):
            raise ProvenanceValidationError("nodes and edges must be arrays")
        return cls(
            nodes=tuple(ProvenanceNode.from_mapping(node) for node in raw_nodes),
            edges=tuple(ProvenanceEdge.from_mapping(edge) for edge in raw_edges),
            coverage_percent=value["coverage_percent"],
            observational_metadata=value.get("observational_metadata", {}),
            provenance_identity=value["provenance_identity"],
        )


def not_implemented(*args: object, **kwargs: object) -> None:
    """Retain the non-operational boundary for future provenance phases."""

    del args, kwargs
    phase_not_implemented("provenance")


__all__ = (
    "ProvenanceValidationError", "RelationType", "ProvenanceNode", "ProvenanceEdge",
    "ProvenanceChain", "not_implemented",
)
