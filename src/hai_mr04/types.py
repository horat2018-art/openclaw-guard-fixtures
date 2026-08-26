from dataclasses import dataclass
from typing import Any

@dataclass(frozen=True)
class Artifact:
    reference: str
    sha256: str
    artifact_type: str
    phase_id: str
    current_validity: str
    mandatory: bool
    security: str
    protected: bool
    provenance: dict[str, Any]

@dataclass(frozen=True)
class ProposalBinding:
    schema_version: str
    package_identity: str
    package_sha256: str
    package_schema_version: str
