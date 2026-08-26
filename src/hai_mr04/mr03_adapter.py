import json, os, subprocess, sys, tempfile
from .errors import HarnessError

FROZEN = "945559bf0f1811cb2f88e827ff1412081f1fbd75"
DEFAULT_ROOT = "/home/hor99/openclaw-guard-fixtures/HAI-MR-03-tool-worktrees/mr03b"
ROOT = DEFAULT_ROOT
REQUIRED_TOP_LEVEL = (
    "L0_IDENTITY_HEADER", "L1_CURRENT_STATE", "L2_REQUIRED_EVIDENCE",
    "L3_RELEVANT_HISTORICAL_DELTA", "L4_PROVENANCE_REFERENCES",
    "L5_EXCLUDED_EVIDENCE_INDEX", "L6_VALIDATION_REPORT",
)

def _resolved_root():
    configured = os.environ.get("HAI_MR03_ROOT", DEFAULT_ROOT)
    if configured != DEFAULT_ROOT:
        raise HarnessError("SOURCE_PATH_ESCAPE", "MR-03 root is not the frozen dependency path", "MR03_ADAPTER")
    if not os.path.exists(configured) or os.path.islink(configured):
        raise HarnessError("SOURCE_PATH_ESCAPE", "MR-03 root is missing or symlinked", "MR03_ADAPTER")
    root = os.path.realpath(configured)
    if root != configured or not os.path.isdir(root):
        raise HarnessError("SOURCE_PATH_ESCAPE", "MR-03 root realpath substitution", "MR03_ADAPTER")
    return root

def _verify_identity_at(root):
    if root != DEFAULT_ROOT or not isinstance(root, str) or not os.path.isdir(root) or os.path.islink(root) or os.path.realpath(root) != root:
        raise HarnessError("SOURCE_PATH_ESCAPE", "MR-03 root is missing or path-substituted", "MR03_ADAPTER")
    try:
        got = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True, timeout=5).strip()
    except Exception as exc:
        raise HarnessError("MR03_IDENTITY_MISMATCH", str(exc), "MR03_ADAPTER")
    if got != FROZEN:
        raise HarnessError("MR03_IDENTITY_MISMATCH", "frozen MR-03 commit mismatch", "MR03_ADAPTER")
    return got


def verify_identity(root=None):
    """Verify the supplied frozen root, resolving only when called standalone."""
    return _verify_identity_at(_resolved_root() if root is None else root)

def _validate_output(value):
    if not isinstance(value, dict) or set(value) != set(REQUIRED_TOP_LEVEL):
        raise HarnessError("INVALID_SCHEMA", "MR-03 package top-level schema mismatch", "MR03_ADAPTER")
    dict_layers = ("L0_IDENTITY_HEADER", "L1_CURRENT_STATE", "L6_VALIDATION_REPORT")
    if not all(isinstance(value[key], dict) for key in dict_layers):
        raise HarnessError("INVALID_SCHEMA", "MR-03 package layer type mismatch", "MR03_ADAPTER")
    if not isinstance(value["L2_REQUIRED_EVIDENCE"], list) or not isinstance(value["L3_RELEVANT_HISTORICAL_DELTA"], list) or not isinstance(value["L4_PROVENANCE_REFERENCES"], list) or not isinstance(value["L5_EXCLUDED_EVIDENCE_INDEX"], list):
        raise HarnessError("INVALID_SCHEMA", "MR-03 package reference layer type mismatch", "MR03_ADAPTER")
    if value["L0_IDENTITY_HEADER"].get("qualification_exposure") != 0:
        raise HarnessError("PROTECTED_CONTENT_SELECTED", "MR-03 package exposure is nonzero", "MR03_ADAPTER")
    return value

def invoke_read_only(source, task):
    root = _resolved_root()
    verify_identity(root)
    interpreter = os.path.realpath(sys.executable)
    if not os.path.isfile(interpreter):
        raise HarnessError("MR03_IDENTITY_MISMATCH", "interpreter is not a file", "MR03_ADAPTER")
    with tempfile.TemporaryDirectory() as td:
        task_path = os.path.join(td, "task.json")
        output_root = os.path.join(td, "out")
        with open(task_path, "w", encoding="utf-8") as stream:
            json.dump(task, stream, sort_keys=True, separators=(",", ":"))
        env = {"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": os.path.join(root, "src")}
        proc = subprocess.run(
            [interpreter, "-m", "hai_evidence", "package", "--source", source, "--task", task_path, "--output", output_root],
            cwd=root, env=env, text=True, capture_output=True, shell=False, timeout=10,
        )
        if proc.returncode:
            raise HarnessError("MR03_IDENTITY_MISMATCH", proc.stderr or "MR-03 nonzero exit", "MR03_ADAPTER")
        try:
            with open(os.path.join(output_root, "optimized_package.json"), encoding="utf-8") as stream:
                value = json.load(stream)
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            raise HarnessError("INVALID_SCHEMA", str(exc), "MR03_ADAPTER")
        return _validate_output(value)
