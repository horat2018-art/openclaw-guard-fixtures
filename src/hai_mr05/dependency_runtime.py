"""Controlled operational boundary for exact frozen MR-03 / MR-04 dependencies.

This module is intentionally the only MR-06C dependency-execution surface.
The existing :mod:`mr03_adapter` and :mod:`mr04_adapter` modules remain pure
binding logic.  No network, provider, model, auth, controller, human-gate, or
evidence-persistence behavior is implemented here.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import importlib
import json
import os
import subprocess
import sys
from typing import NoReturn

from .canonical import canonical_json_bytes
from .contracts import (
    MR03_CONTROLLED_WORKTREE,
    MR03_EXPECTED_COMMIT,
    MR04_CONTROLLED_WORKTREE,
    MR04_EXPECTED_COMMIT,
    SCHEMA_VERSION,
)
from .failures import FailureCode
from .identity import require_sha256, sha256_canonical
from .mr03_adapter import (
    MR03_INTERFACE_IDENTITY,
    MR04_CONTENTSET_SHA256,
    MR04_EXPECTED_TREE,
    MR04_IMPLEMENTATION_CONTRACT_SHA256,
    MR04_PATHSET_SHA256,
)


MR03_CALL_MODE = "FROZEN_MR04_MR03_ADAPTER_SUBPROCESS"
MR03_TIMEOUT_SECONDS = 10
MR03_RETRY_POLICY = "ZERO_BY_DEFAULT"
MR04_CALL_MODE = "FROZEN_MR04_LOWER_LEVEL_COMPOSITION"
MR04_INTERFACE_IDENTITY = MR04_IMPLEMENTATION_CONTRACT_SHA256

MR03_EXECUTION_IMPLEMENTATION_COUNT = 1
MR04_EXECUTION_IMPLEMENTATION_COUNT = 1
SUBPROCESS_EXECUTION_COUNT = 1
FILESYSTEM_DEPENDENCY_EXECUTION_COUNT = 1
NETWORK_IMPLEMENTATION_COUNT = 0
MODEL_CALL_IMPLEMENTATION_COUNT = 0
AUTH_IMPLEMENTATION_COUNT = 0
AUTO_RETRY_IMPLEMENTATION_COUNT = 0
AUTO_FALLBACK_IMPLEMENTATION_COUNT = 0
PROVIDER_CLIENT_IMPLEMENTATION_COUNT = 0
CONTROLLER_IMPLEMENTATION_COUNT = 0
HUMAN_GATE_EXECUTION_COUNT = 0
EVIDENCE_PERSISTENCE_COUNT = 0

_MR03_TOP_LEVEL = frozenset(
    {
        "L0_IDENTITY_HEADER",
        "L1_CURRENT_STATE",
        "L2_REQUIRED_EVIDENCE",
        "L3_RELEVANT_HISTORICAL_DELTA",
        "L4_PROVENANCE_REFERENCES",
        "L5_EXCLUDED_EVIDENCE_INDEX",
        "L6_VALIDATION_REPORT",
    }
)
_MR04_MODULES = (
    "hai_mr04.mr03_adapter",
    "hai_mr04.discovery",
    "hai_mr04.normalization",
    "hai_mr04.provenance",
    "hai_mr04.bounded_context",
)
_PRESERVED_CODES = frozenset(
    {
        FailureCode.MR03_IDENTITY_MISMATCH.value,
        FailureCode.SOURCE_PATH_ESCAPE.value,
        FailureCode.PROTECTED_CONTENT_SELECTED.value,
        FailureCode.SECRET_RISK.value,
        FailureCode.HASH_MISMATCH.value,
        FailureCode.MISSING_REQUIRED_ARTIFACT.value,
        FailureCode.AMBIGUOUS_PRECEDENCE.value,
        FailureCode.UNKNOWN_VALIDITY.value,
        FailureCode.INVALID_SCHEMA.value,
        FailureCode.PROVENANCE_GAP.value,
        FailureCode.DUPLICATE_CONFLICT.value,
        FailureCode.UNSUPPORTED_INPUT.value,
    }
)


class DependencyRuntimeError(RuntimeError):
    """Fail-closed operational dependency error with a frozen MR-05 code."""

    def __init__(self, code: FailureCode | str, message: str) -> None:
        normalized = code.value if isinstance(code, FailureCode) else str(code)
        super().__init__(message)
        self.code = normalized
        self.failure_code = normalized
        self.retry_allowed = False


def _fail(code: FailureCode | str, message: str) -> NoReturn:
    raise DependencyRuntimeError(code, message)


def _sha(value: object, field: str) -> str:
    try:
        return require_sha256(value, field=field)
    except ValueError as exc:
        _fail(FailureCode.INVALID_SCHEMA, str(exc))


def _mapping(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        _fail(FailureCode.INVALID_SCHEMA, f"{context} must be an object with string keys")
    return value


def _schema_fail(message: str, *, mr03: bool = False) -> NoReturn:
    code = FailureCode.MR05_MR03_OUTPUT_INVALID_SCHEMA if mr03 else FailureCode.INVALID_SCHEMA
    _fail(code, message)


def _exact_keys(value: Mapping[str, object], required: set[str], context: str, *, mr03: bool = False) -> None:
    actual = set(value)
    if actual != required:
        missing = sorted(required - actual)
        unknown = sorted(actual - required)
        _schema_fail(f"{context} field set mismatch; missing={missing}; unknown={unknown}", mr03=mr03)


def _bounded_string(value: object, context: str, minimum: int, maximum: int, *, mr03: bool = False) -> str:
    if type(value) is not str or not minimum <= len(value) <= maximum:
        _schema_fail(f"{context} must be a string with length {minimum}..{maximum}", mr03=mr03)
    return value


def _bounded_integer(value: object, context: str, minimum: int, maximum: int, *, mr03: bool = False) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _schema_fail(f"{context} must be an integer in range {minimum}..{maximum}", mr03=mr03)
    return value


def _sha_schema(value: object, context: str, *, mr03: bool = False) -> str:
    if type(value) is not str or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        _schema_fail(f"{context} must be a lowercase SHA-256 hex string", mr03=mr03)
    return value


def _validate_mr03_evidence_item(value: object) -> None:
    item = _mapping(value, "MR03 evidence item")
    required = {"phase_id", "result", "current_validity", "important_hashes", "provenance"}
    _exact_keys(item, required, "MR03 evidence item", mr03=True)
    _bounded_string(item["phase_id"], "MR03 evidence phase_id", 1, 256, mr03=True)
    _bounded_string(item["result"], "MR03 evidence result", 1, 1024, mr03=True)
    _bounded_string(item["current_validity"], "MR03 evidence current_validity", 1, 128, mr03=True)
    hashes = item["important_hashes"]
    if type(hashes) is not list:
        _schema_fail("MR03 evidence important_hashes must be an array", mr03=True)
    for index, digest in enumerate(hashes):
        _sha_schema(digest, f"MR03 evidence important_hashes[{index}]", mr03=True)
    _bounded_string(item["provenance"], "MR03 evidence provenance", 1, 2048, mr03=True)


def _validate_mr03_reference(value: object) -> None:
    item = _mapping(value, "MR03 provenance reference")
    required = {"sha256", "source_path", "phase_id", "artifact_type", "relative_path"}
    _exact_keys(item, required, "MR03 provenance reference", mr03=True)
    _sha_schema(item["sha256"], "MR03 provenance sha256", mr03=True)
    _bounded_string(item["source_path"], "MR03 provenance source_path", 1, 4096, mr03=True)
    _bounded_string(item["phase_id"], "MR03 provenance phase_id", 1, 256, mr03=True)
    _bounded_string(item["artifact_type"], "MR03 provenance artifact_type", 1, 256, mr03=True)
    _bounded_string(item["relative_path"], "MR03 provenance relative_path", 1, 4096, mr03=True)


def _validate_mr03_excluded_item(value: object) -> None:
    item = _mapping(value, "MR03 excluded evidence item")
    required = {"path", "reason"}
    _exact_keys(item, required, "MR03 excluded evidence item", mr03=True)
    _bounded_string(item["path"], "MR03 excluded path", 1, 4096, mr03=True)
    _bounded_string(item["reason"], "MR03 excluded reason", 1, 256, mr03=True)


def _validate_byte_budget(value: object) -> dict[str, object]:
    budget = _mapping(value, "byte_budget")
    required = {
        "budget_identity",
        "max_raw_bytes",
        "max_normalized_bytes",
        "max_package_bytes",
        "max_cloud_context_bytes",
    }
    _exact_keys(budget, required, "byte_budget")
    _sha_schema(budget["budget_identity"], "byte_budget.budget_identity")
    for field in (
        "max_raw_bytes",
        "max_normalized_bytes",
        "max_package_bytes",
        "max_cloud_context_bytes",
    ):
        _bounded_integer(budget[field], f"byte_budget.{field}", 1, 9223372036854775807)
    return dict(budget)


def _validate_token_estimate_metadata(value: object) -> dict[str, object]:
    metadata = _mapping(value, "token_estimate_metadata")
    required = {
        "estimator_name",
        "estimator_version",
        "authority",
        "input_bytes",
        "estimated_tokens",
        "confidence",
    }
    _exact_keys(metadata, required, "token_estimate_metadata")
    if metadata["estimator_name"] != "non_whitespace_groups_div4":
        _schema_fail("token_estimate_metadata.estimator_name is not frozen")
    if metadata["estimator_version"] != "1.0.0":
        _schema_fail("token_estimate_metadata.estimator_version is not frozen")
    if metadata["authority"] != "ADVISORY_ONLY":
        _schema_fail("token_estimate_metadata.authority is not frozen")
    _bounded_integer(metadata["input_bytes"], "token_estimate_metadata.input_bytes", 0, 9223372036854775807)
    _bounded_integer(metadata["estimated_tokens"], "token_estimate_metadata.estimated_tokens", 0, 9223372036854775807)
    if type(metadata["confidence"]) is not str or metadata["confidence"] not in {"ADVISORY", "UNKNOWN"}:
        _schema_fail("token_estimate_metadata.confidence is invalid")
    return dict(metadata)


def _exact_root(path: str, expected: str, owner_code: FailureCode) -> str:
    if type(path) is not str or path != expected:
        _fail(FailureCode.SOURCE_PATH_ESCAPE, "dependency root is outside the frozen path")
    if not os.path.isdir(path) or os.path.islink(path) or os.path.realpath(path) != path:
        _fail(FailureCode.SOURCE_PATH_ESCAPE, "dependency root is missing, linked, or substituted")
    try:
        head = subprocess.check_output(
            ["git", "-C", path, "rev-parse", "HEAD"],
            text=True,
            timeout=5,
        ).strip()
    except Exception as exc:
        _fail(owner_code, f"dependency identity check failed: {exc}")
    return head


def _mr04_fileset(root: str) -> tuple[str, str]:
    paths: list[str] = []
    records: list[dict[str, object]] = []
    for base, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name != ".git")
        for name in sorted(files):
            absolute = os.path.join(base, name)
            relative = os.path.relpath(absolute, root).replace(os.sep, "/")
            if relative == ".git" or relative.startswith(".git/"):
                continue
            if os.path.islink(absolute):
                _fail(FailureCode.MR05_MR04_DEPENDENCY_IDENTITY_MISMATCH, "MR04 fileset contains a symlink")
            try:
                with open(absolute, "rb") as stream:
                    raw = stream.read()
            except OSError as exc:
                _fail(FailureCode.MR05_MR04_DEPENDENCY_IDENTITY_MISMATCH, f"MR04 fileset read failed: {exc}")
            paths.append(relative)
            records.append(
                {
                    "relative_path": relative,
                    "size": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
    paths.sort(key=lambda value: value.encode("utf-8"))
    records.sort(key=lambda item: str(item["relative_path"]).encode("utf-8"))
    pathset = hashlib.sha256(("\n".join(paths) + "\n").encode("utf-8")).hexdigest()
    content_bytes = (
        json.dumps(records, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return pathset, hashlib.sha256(content_bytes).hexdigest()


def verify_mr03_dependency(root: str = MR03_CONTROLLED_WORKTREE) -> dict[str, object]:
    """Verify the exact frozen MR-03 root and commit without mutation."""

    head = _exact_root(root, MR03_CONTROLLED_WORKTREE, FailureCode.MR03_IDENTITY_MISMATCH)
    if head != MR03_EXPECTED_COMMIT:
        _fail(FailureCode.MR03_IDENTITY_MISMATCH, "frozen MR03 commit mismatch")
    return {
        "commit": MR03_EXPECTED_COMMIT,
        "root_policy": "EXACT_FROZEN_MR03_ROOT",
        "resolve_once": True,
        "checked_path_equals_execution_path": True,
    }


def verify_mr04_dependency(root: str = MR04_CONTROLLED_WORKTREE) -> dict[str, object]:
    """Verify exact MR-04 commit/tree/pathset/contentset before execution."""

    head = _exact_root(
        root,
        MR04_CONTROLLED_WORKTREE,
        FailureCode.MR05_MR04_DEPENDENCY_IDENTITY_MISMATCH,
    )
    if head != MR04_EXPECTED_COMMIT:
        _fail(FailureCode.MR05_MR04_DEPENDENCY_IDENTITY_MISMATCH, "frozen MR04 commit mismatch")
    try:
        tree = subprocess.check_output(
            ["git", "-C", root, "rev-parse", "HEAD^{tree}"],
            text=True,
            timeout=5,
        ).strip()
    except Exception as exc:
        _fail(FailureCode.MR05_MR04_DEPENDENCY_IDENTITY_MISMATCH, f"MR04 tree check failed: {exc}")
    pathset, contentset = _mr04_fileset(root)
    if (
        tree != MR04_EXPECTED_TREE
        or pathset != MR04_PATHSET_SHA256
        or contentset != MR04_CONTENTSET_SHA256
    ):
        _fail(FailureCode.MR05_MR04_DEPENDENCY_IDENTITY_MISMATCH, "frozen MR04 identity mismatch")
    return {
        "commit": MR04_EXPECTED_COMMIT,
        "tree": MR04_EXPECTED_TREE,
        "pathset_sha256": MR04_PATHSET_SHA256,
        "contentset_sha256": MR04_CONTENTSET_SHA256,
        "resolve_once": True,
        "checked_path_equals_executed_path": True,
    }


def _load_mr04_module(name: str):
    if name not in _MR04_MODULES:
        _fail(FailureCode.MR05_INTERNAL_INVARIANT, "MR04 module is outside the qualified callable set")
    source_root = os.path.join(MR04_CONTROLLED_WORKTREE, "src")
    inserted = False
    if source_root not in sys.path:
        sys.path.insert(0, source_root)
        inserted = True
    try:
        module = importlib.import_module(name)
    except Exception as exc:
        _fail(FailureCode.MR05_MR04_DEPENDENCY_IDENTITY_MISMATCH, f"MR04 import failed: {exc}")
    finally:
        if inserted and sys.path and sys.path[0] == source_root:
            sys.path.pop(0)
    module_path = os.path.realpath(getattr(module, "__file__", ""))
    expected_prefix = os.path.realpath(source_root) + os.sep
    if not module_path.startswith(expected_prefix):
        _fail(FailureCode.MR05_MR04_DEPENDENCY_IDENTITY_MISMATCH, "MR04 module path substitution")
    return module


def _identity_record(fields: Mapping[str, object], identity_field: str) -> dict[str, object]:
    result = dict(fields)
    result[identity_field] = sha256_canonical(fields)
    return result


def build_mr03_invocation(
    *,
    task_identity: str,
    normalization_identity: str,
    source_set_identity: str,
    capture_identity: str,
) -> dict[str, object]:
    """Build the exact frozen MR-03 invocation identity record."""

    semantic = {
        "schema_version": SCHEMA_VERSION,
        "mr03_dependency_identity": verify_mr03_dependency(),
        "task_identity": _sha(task_identity, "task_identity"),
        "input_normalization_identity": _sha(normalization_identity, "normalization_identity"),
        "input_source_set_identity": _sha(source_set_identity, "source_set_identity"),
        "expected_schema_version": MR03_INTERFACE_IDENTITY,
        "capture_identity": _sha(capture_identity, "capture_identity"),
        "call_policy": {
            "call_mode": MR03_CALL_MODE,
            "shell": False,
            "retry": MR03_RETRY_POLICY,
            "timeout_seconds": MR03_TIMEOUT_SECONDS,
            "alternate_clone": False,
            "latest_resolution": False,
        },
    }
    return _identity_record(semantic, "invocation_identity")


def _validate_mr03_payload(value: object) -> dict[str, object]:
    payload = _mapping(value, "MR03 payload")
    _exact_keys(payload, set(_MR03_TOP_LEVEL), "MR03 payload", mr03=True)

    header = _mapping(payload["L0_IDENTITY_HEADER"], "MR03 identity header")
    _exact_keys(header, {"policy_version", "task_id", "qualification_exposure"}, "MR03 identity header", mr03=True)
    _bounded_string(header["policy_version"], "MR03 policy_version", 1, 256, mr03=True)
    _bounded_string(header["task_id"], "MR03 task_id", 1, 256, mr03=True)
    if type(header["qualification_exposure"]) is not int or header["qualification_exposure"] != 0:
        _schema_fail("MR03 qualification_exposure must equal 0", mr03=True)

    current = _mapping(payload["L1_CURRENT_STATE"], "MR03 current state")
    _exact_keys(current, {"task_class"}, "MR03 current state", mr03=True)
    _bounded_string(current["task_class"], "MR03 task_class", 1, 256, mr03=True)

    evidence = payload["L2_REQUIRED_EVIDENCE"]
    if type(evidence) is not list:
        _schema_fail("MR03 required evidence must be an array", mr03=True)
    for item in evidence:
        _validate_mr03_evidence_item(item)

    historical = payload["L3_RELEVANT_HISTORICAL_DELTA"]
    if type(historical) is not list:
        _schema_fail("MR03 historical delta must be an array", mr03=True)

    references = payload["L4_PROVENANCE_REFERENCES"]
    if type(references) is not list:
        _schema_fail("MR03 provenance references must be an array", mr03=True)
    for item in references:
        _validate_mr03_reference(item)

    excluded = payload["L5_EXCLUDED_EVIDENCE_INDEX"]
    if type(excluded) is not list:
        _schema_fail("MR03 excluded evidence index must be an array", mr03=True)
    for item in excluded:
        _validate_mr03_excluded_item(item)

    report = _mapping(payload["L6_VALIDATION_REPORT"], "MR03 validation report")
    _exact_keys(
        report,
        {"mandatory_field_retention", "provenance_reference_retention", "known_fact_regression_count"},
        "MR03 validation report",
        mr03=True,
    )
    _bounded_string(report["mandatory_field_retention"], "MR03 mandatory_field_retention", 1, 64, mr03=True)
    _bounded_string(report["provenance_reference_retention"], "MR03 provenance_reference_retention", 1, 64, mr03=True)
    _bounded_integer(
        report["known_fact_regression_count"],
        "MR03 known_fact_regression_count",
        0,
        9223372036854775807,
        mr03=True,
    )
    return dict(payload)


def _map_mr03_exception(exc: BaseException) -> NoReturn:
    if isinstance(exc, subprocess.TimeoutExpired):
        _fail(FailureCode.MR05_MR03_CALL_TIMEOUT, "frozen MR03 adapter timed out")
    code = getattr(exc, "code", getattr(exc, "failure_code", None))
    if isinstance(code, str) and code in _PRESERVED_CODES:
        _fail(code, str(exc))
    if isinstance(code, str) and code == FailureCode.MR05_MR03_OUTPUT_INVALID_SCHEMA.value:
        _fail(code, str(exc))
    _fail(FailureCode.MR05_MR03_CALL_FAILURE, f"unrecognized MR03 invocation failure: {exc}")


def invoke_mr03(
    source: str,
    task: Mapping[str, object],
    *,
    task_identity: str,
    normalization_identity: str,
    source_set_identity: str,
    capture_identity: str,
) -> dict[str, object]:
    """Invoke MR-03 exactly once through the frozen MR-04 read-only adapter."""

    invocation = build_mr03_invocation(
        task_identity=task_identity,
        normalization_identity=normalization_identity,
        source_set_identity=source_set_identity,
        capture_identity=capture_identity,
    )
    verify_mr04_dependency()
    adapter = _load_mr04_module("hai_mr04.mr03_adapter")
    try:
        payload = _validate_mr03_payload(adapter.invoke_read_only(source, dict(task)))
    except DependencyRuntimeError:
        raise
    except BaseException as exc:
        _map_mr03_exception(exc)
    references = sorted(
        payload["L4_PROVENANCE_REFERENCES"],
        key=lambda item: canonical_json_bytes(item),
    )
    header = dict(payload["L0_IDENTITY_HEADER"])
    provenance = {
        "policy_version": str(header.get("policy_version", header.get("policy", "UNKNOWN"))),
        "task_id": str(header.get("task_id", "UNKNOWN")),
        "qualification_exposure": 0,
        "reference_count": len(references),
    }
    semantic = {
        "schema_version": SCHEMA_VERSION,
        "invocation_identity": invocation["invocation_identity"],
        "mr03_package_identity": sha256_canonical(payload),
        "mr03_payload": payload,
        "mr03_provenance": provenance,
        "mr03_source_references": references,
        "mr03_failure_status": {
            "status": "PASS",
            "failure_code": None,
            "failure_owner": None,
            "stderr_code_reference": None,
        },
    }
    return _identity_record(semantic, "result_identity")


def build_mr04_invocation(
    *,
    task_identity: str,
    source_set_identity: str,
    normalization_identity: str,
    mr03_result_identity: str,
    byte_budget: Mapping[str, object],
    token_estimate_metadata: Mapping[str, object],
) -> dict[str, object]:
    """Build the frozen MR-04 lower-level composition invocation record."""

    semantic = {
        "schema_version": SCHEMA_VERSION,
        "mr04_dependency_identity": verify_mr04_dependency(),
        "task_identity": _sha(task_identity, "task_identity"),
        "source_set_identity": _sha(source_set_identity, "source_set_identity"),
        "normalization_identity": _sha(normalization_identity, "normalization_identity"),
        "mr03_result_identity": _sha(mr03_result_identity, "mr03_result_identity"),
        "byte_budget": _validate_byte_budget(byte_budget),
        "token_estimate_metadata": _validate_token_estimate_metadata(token_estimate_metadata),
        "expected_interface_identity": MR04_INTERFACE_IDENTITY,
        "call_mode": MR04_CALL_MODE,
    }
    return _identity_record(semantic, "invocation_identity")


def invoke_mr04(
    source_root: str,
    task: Mapping[str, object],
    mr03_result: Mapping[str, object],
    *,
    task_identity: str,
    source_set_identity: str,
    normalization_identity: str,
    byte_budget: Mapping[str, object],
    token_estimate_metadata: Mapping[str, object],
) -> dict[str, object]:
    """Run only the qualified frozen MR-04 lower-level composition callables."""

    mr03_record = _mapping(mr03_result, "mr03_result")
    mr03_result_identity = _sha(mr03_record.get("result_identity"), "mr03_result_identity")
    mr03_payload = _validate_mr03_payload(mr03_record.get("mr03_payload"))
    invocation = build_mr04_invocation(
        task_identity=task_identity,
        source_set_identity=source_set_identity,
        normalization_identity=normalization_identity,
        mr03_result_identity=mr03_result_identity,
        byte_budget=byte_budget,
        token_estimate_metadata=token_estimate_metadata,
    )
    discovery_module = _load_mr04_module("hai_mr04.discovery")
    normalization_module = _load_mr04_module("hai_mr04.normalization")
    provenance_module = _load_mr04_module("hai_mr04.provenance")
    context_module = _load_mr04_module("hai_mr04.bounded_context")
    try:
        discovered = discovery_module.discover(source_root)
        rows = normalization_module.normalize(discovered)
        provenance_module.validate(rows)
        package = context_module.build(rows, task=dict(task), mr03_output=mr03_payload)
        package_identity = context_module.package_identity_from_semantics(package)
        package_sha256 = context_module.package_sha256_from_content(package)
    except DependencyRuntimeError:
        raise
    except BaseException as exc:
        code = getattr(exc, "code", getattr(exc, "failure_code", None))
        if isinstance(code, str) and code in _PRESERVED_CODES:
            _fail(code, str(exc))
        _fail(FailureCode.MR05_MR04_DEPENDENCY_IDENTITY_MISMATCH, f"MR04 composition failed: {exc}")
    if package.get("package_identity") != package_identity or package.get("package_sha256") != package_sha256:
        _fail(FailureCode.MR05_MR04_DEPENDENCY_IDENTITY_MISMATCH, "MR04 package derived identity mismatch")
    semantic = {
        "schema_version": SCHEMA_VERSION,
        "invocation_identity": invocation["invocation_identity"],
        "task_identity": _sha(task_identity, "task_identity"),
        "source_set_identity": _sha(source_set_identity, "source_set_identity"),
        "mr03_result_identity": mr03_result_identity,
        "package_identity": package_identity,
        "package_sha256": package_sha256,
        "package_schema_version": package.get("package_schema_version"),
        "bounded_context_package": package,
        "token_budget": package.get("token_budget", {}),
        "verification_fields": {
            "decision": "ESCALATE",
            "code": "VERIFICATION_NOT_RUN",
            "approval": False,
        },
        "human_gate_fields": {
            "decision": "ESCALATE",
            "human_approval": False,
            "authority_granted": False,
            "action": "NONE",
        },
        "failure_status": {
            "status": "PASS",
            "failure_code": None,
            "failure_owner": None,
        },
    }
    return _identity_record(semantic, "result_identity")


__all__ = (
    "DependencyRuntimeError",
    "MR03_CALL_MODE",
    "MR03_TIMEOUT_SECONDS",
    "MR03_RETRY_POLICY",
    "MR04_CALL_MODE",
    "MR04_INTERFACE_IDENTITY",
    "MR03_EXECUTION_IMPLEMENTATION_COUNT",
    "MR04_EXECUTION_IMPLEMENTATION_COUNT",
    "SUBPROCESS_EXECUTION_COUNT",
    "FILESYSTEM_DEPENDENCY_EXECUTION_COUNT",
    "NETWORK_IMPLEMENTATION_COUNT",
    "MODEL_CALL_IMPLEMENTATION_COUNT",
    "AUTH_IMPLEMENTATION_COUNT",
    "AUTO_RETRY_IMPLEMENTATION_COUNT",
    "AUTO_FALLBACK_IMPLEMENTATION_COUNT",
    "PROVIDER_CLIENT_IMPLEMENTATION_COUNT",
    "CONTROLLER_IMPLEMENTATION_COUNT",
    "HUMAN_GATE_EXECUTION_COUNT",
    "EVIDENCE_PERSISTENCE_COUNT",
    "verify_mr03_dependency",
    "verify_mr04_dependency",
    "build_mr03_invocation",
    "invoke_mr03",
    "build_mr04_invocation",
    "invoke_mr04",
)
