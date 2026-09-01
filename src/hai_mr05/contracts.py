"""Frozen MR-05 contract, dependency, and schema-version primitives."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType


SCHEMA_VERSION = "1.0.0"
SUPPORTED_SCHEMA_MAJOR = 1
TOKEN_ESTIMATE_AUTHORITY = "ADVISORY_ONLY"
MODEL_RETRY_POLICY = "ZERO_BY_DEFAULT"

MR05A_CONTRACT_SHA256 = "99a52798cafc038bf3c9db20eacc7f5fa3cadc16468afdb39697d9c9b7d06811"
MR05B_MASTER_CONTRACT_SHA256 = "20462c72898252b9a31670c08a7c253e9a1a65d42363bc25151a2bebbff7c6bd"
MR05B_CONTRACT_SET_SHA256 = "a78c2574bc15692e1e8e56b4ff1a91b19b11a4b0e4fc808db3577a158ef45cc9"
MR05C_PD_CONTRACT_SHA256 = "7ed85094454da0362ab47d66e59b81a6e42283685809573a60cffe93df9549df"
MR05C_R2_CONTRACT_SHA256 = "c7e561000b43677b65ffe8ce46ba44d679de9c75c1febe2471114bccd7072cf9"
MR05D_R2_CONTRACT_SHA256 = "44fac0d7abe60487202b7937ebe1055a347c1ab30dd0ef90e0e4fcccd1826000"
MR05C_FROZEN_SKELETON_PATHSET_SHA256 = "3b3cef0d17cc3c039a372c81c2e59b32642b7546145474314348aa6b8af0be3b"
MR05C_MATERIALIZATION_IDENTITY_SHA256 = "0a81c369cc795d10fee261d570e3e3c2e5b4885d24473be3f989c45ada9a68a0"
MR03_EXPECTED_COMMIT = "945559bf0f1811cb2f88e827ff1412081f1fbd75"
MR04_EXPECTED_COMMIT = "8ce9eb8a542799e00088a6654e1061405fde7d33"
MR03_CONTROLLED_WORKTREE = "/home/hor99/openclaw-guard-fixtures/HAI-MR-03-tool-worktrees/mr03b"
MR04_CONTROLLED_WORKTREE = "/home/hor99/openclaw-guard-fixtures/HAI-MR-04-tool-worktrees/mr04b"
MR05_REPOSITORY_ROOT = "/home/hor99/openclaw-guard-fixtures/HAI-MR-05-repository"
MR05_CONTROLLED_WORKTREE_ROOT = "/home/hor99/openclaw-guard-fixtures/HAI-MR-05-worktrees/main"
MR05_BRANCH_NAME = "hai/mr05-deterministic-workflow-integration"
MR05_PACKAGE_NAME = "hai_mr05"
MR05_PACKAGE_ROOT_RELATIVE = "src/hai_mr05/"
MR05_TEST_ROOT_RELATIVE = "tests/"
MR05_BASELINE_BRANCH_NAME = "mr05-empty-baseline"
MR05_BASELINE_COMMIT_SUBJECT = "chore: initialize mr05 empty baseline"
MR05_PACKAGE_PATH_LAYOUT = "src/hai_mr05/ with tests/ at repository root"

SCHEMA_VERSIONS: Mapping[str, str] = MappingProxyType(
    {
        "mr05.byte_budget": "1.0.0",
        "mr05.claim": "1.0.0",
        "mr05.cloud_context": "1.0.0",
        "mr05.cloud_proposal": "1.0.0",
        "mr05.cloud_request": "1.0.0",
        "mr05.disclosure": "1.0.0",
        "mr05.discovery": "1.0.0",
        "mr05.evidence_manifest": "1.0.0",
        "mr05.failure": "1.0.0",
        "mr05.final_result": "1.0.0",
        "mr05.human_decision": "1.0.0",
        "mr05.human_gate": "1.0.0",
        "mr05.metrics": "1.0.0",
        "mr05.mr03_invocation": "1.0.0",
        "mr05.mr03_result": "1.0.0",
        "mr05.mr04_invocation": "1.0.0",
        "mr05.mr04_result": "1.0.0",
        "mr05.normalization": "1.0.0",
        "mr05.provenance": "1.0.0",
        "mr05.run": "1.0.0",
        "mr05.source": "1.0.0",
        "mr05.source_ref": "1.0.0",
        "mr05.source_set": "1.0.0",
        "mr05.task": "1.0.0",
        "mr05.token_estimate": "1.0.0",
        "mr05.verification": "1.0.0",
    }
)

FROZEN_CONTRACT_REFERENCES: Mapping[str, str] = MappingProxyType(
    {
        "MR05A_CONTRACT_SHA256": MR05A_CONTRACT_SHA256,
        "MR05B_MASTER_CONTRACT_SHA256": MR05B_MASTER_CONTRACT_SHA256,
        "MR05B_CONTRACT_SET_SHA256": MR05B_CONTRACT_SET_SHA256,
        "MR05C_PD_CONTRACT_SHA256": MR05C_PD_CONTRACT_SHA256,
        "MR05C_R2_CONTRACT_SHA256": MR05C_R2_CONTRACT_SHA256,
        "MR05D_R2_CONTRACT_SHA256": MR05D_R2_CONTRACT_SHA256,
    }
)
FROZEN_DEPENDENCY_COMMITS: Mapping[str, str] = MappingProxyType(
    {"MR03": MR03_EXPECTED_COMMIT, "MR04": MR04_EXPECTED_COMMIT}
)


class ContractValidationError(ValueError):
    """A contract or schema-version binding is invalid."""


class UnknownSchemaMajorVersionError(ContractValidationError):
    """The schema is unknown or has an incompatible major version."""


class UnsupportedSchemaVersionError(ContractValidationError):
    """The schema is known but its exact frozen version is not supported."""


def is_known_schema(schema_id: object) -> bool:
    """Return whether *schema_id* is in the frozen MR-05 schema set."""

    return isinstance(schema_id, str) and schema_id in SCHEMA_VERSIONS


def schema_version_for(schema_id: str) -> str:
    """Return the exact frozen version for a known schema identifier."""

    if not is_known_schema(schema_id):
        raise UnknownSchemaMajorVersionError(f"unknown schema: {schema_id!r}")
    return SCHEMA_VERSIONS[schema_id]


def validate_schema_version(schema_id: str, version: str) -> str:
    """Validate an exact frozen schema/version binding and return its version."""

    expected = schema_version_for(schema_id)
    if not isinstance(version, str) or not version:
        raise UnsupportedSchemaVersionError("schema version must be a non-empty string")
    expected_major = expected.split(".", 1)[0]
    actual_major = version.split(".", 1)[0]
    if actual_major != expected_major:
        raise UnknownSchemaMajorVersionError(
            f"incompatible schema major for {schema_id}: {version!r}"
        )
    if version != expected:
        raise UnsupportedSchemaVersionError(
            f"unsupported frozen version for {schema_id}: {version!r}"
        )
    return expected


def require_frozen_contract_reference(name: str, actual: str) -> str:
    """Require an exact named frozen contract identity."""

    try:
        expected = FROZEN_CONTRACT_REFERENCES[name]
    except (KeyError, TypeError) as exc:
        raise ContractValidationError(f"unknown contract reference: {name!r}") from exc
    if actual != expected:
        raise ContractValidationError(f"contract reference mismatch: {name}")
    return expected


__all__ = tuple(name for name in globals() if name.isupper()) + (
    "ContractValidationError",
    "UnknownSchemaMajorVersionError",
    "UnsupportedSchemaVersionError",
    "is_known_schema",
    "schema_version_for",
    "validate_schema_version",
    "require_frozen_contract_reference",
)
