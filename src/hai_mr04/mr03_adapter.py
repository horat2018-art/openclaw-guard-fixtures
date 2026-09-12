import json, os, stat, subprocess, sys, tempfile
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


def _root_open_flags():
    flags = os.O_RDONLY
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    return flags


def _open_pinned_root(root):
    if root != DEFAULT_ROOT or not isinstance(root, str):
        raise HarnessError("SOURCE_PATH_ESCAPE", "MR-03 root is outside the frozen dependency path", "MR03_ADAPTER")
    if not os.path.isdir(root) or os.path.islink(root) or os.path.realpath(root) != root:
        raise HarnessError("SOURCE_PATH_ESCAPE", "MR-03 root is missing, linked, or substituted", "MR03_ADAPTER")
    try:
        fd = os.open(root, _root_open_flags())
    except OSError as exc:
        raise HarnessError("SOURCE_PATH_ESCAPE", str(exc), "MR03_ADAPTER")
    try:
        opened = os.fstat(fd)
        current = os.stat(root, follow_symlinks=False)
        if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
            raise HarnessError("SOURCE_PATH_ESCAPE", "MR-03 root changed while being pinned", "MR03_ADAPTER")
    except BaseException:
        os.close(fd)
        raise
    return fd


def _fd_root(fd):
    path = f"/proc/self/fd/{fd}"
    if not os.path.isdir(path):
        raise HarnessError("SOURCE_PATH_ESCAPE", "pinned MR-03 root descriptor is unavailable", "MR03_ADAPTER")
    return path


def _requalify_root(root, fd):
    if root != DEFAULT_ROOT or not isinstance(root, str) or os.path.islink(root) or not os.path.isdir(root) or os.path.realpath(root) != root:
        raise HarnessError("SOURCE_PATH_ESCAPE", "MR-03 root pathname changed during execution", "MR03_ADAPTER")
    try:
        opened = os.fstat(fd)
        current = os.stat(root, follow_symlinks=False)
    except OSError as exc:
        raise HarnessError("SOURCE_PATH_ESCAPE", str(exc), "MR03_ADAPTER")
    if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
        raise HarnessError("SOURCE_PATH_ESCAPE", "MR-03 root identity changed during execution", "MR03_ADAPTER")


def _verify_identity_fd(fd):
    try:
        got = subprocess.check_output(
            ["git", "-C", _fd_root(fd), "rev-parse", "HEAD"],
            text=True, timeout=5, pass_fds=(fd,),
        ).strip()
    except HarnessError:
        raise
    except Exception as exc:
        raise HarnessError("MR03_IDENTITY_MISMATCH", str(exc), "MR03_ADAPTER")
    if got != FROZEN:
        raise HarnessError("MR03_IDENTITY_MISMATCH", "frozen MR-03 commit mismatch", "MR03_ADAPTER")
    return got


def verify_identity(root=None):
    """Verify the exact frozen MR-03 dependency through a pinned root descriptor."""
    resolved = _resolved_root() if root is None else root
    fd = _open_pinned_root(resolved)
    try:
        got = _verify_identity_fd(fd)
        _requalify_root(resolved, fd)
        return got
    finally:
        os.close(fd)

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
    fd = _open_pinned_root(root)
    try:
        _verify_identity_fd(fd)
        pinned_root = _fd_root(fd)
        interpreter = os.path.realpath(sys.executable)
        if not os.path.isfile(interpreter):
            raise HarnessError("MR03_IDENTITY_MISMATCH", "interpreter is not a file", "MR03_ADAPTER")
        with tempfile.TemporaryDirectory() as td:
            task_path = os.path.join(td, "task.json")
            output_root = os.path.join(td, "out")
            with open(task_path, "w", encoding="utf-8") as stream:
                json.dump(task, stream, sort_keys=True, separators=(",", ":"))
            env = {"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": os.path.join(pinned_root, "src")}
            proc = subprocess.run(
                [interpreter, "-m", "hai_evidence", "package", "--source", source, "--task", task_path, "--output", output_root],
                cwd=pinned_root, env=env, text=True, capture_output=True, shell=False, timeout=10, pass_fds=(fd,),
            )
            if proc.returncode:
                raise HarnessError("MR03_IDENTITY_MISMATCH", proc.stderr or "MR-03 nonzero exit", "MR03_ADAPTER")
            try:
                with open(os.path.join(output_root, "optimized_package.json"), encoding="utf-8") as stream:
                    value = json.load(stream)
            except (OSError, json.JSONDecodeError, TypeError) as exc:
                raise HarnessError("INVALID_SCHEMA", str(exc), "MR03_ADAPTER")
            value = _validate_output(value)
            _requalify_root(root, fd)
            return value
    finally:
        os.close(fd)
