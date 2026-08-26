"""Repository-local import bootstrap for the canonical stdlib test command."""
from pathlib import Path
import sys

_ROOT = Path(__file__).resolve().parent
_SRC = (_ROOT / "src").resolve()
if _SRC.is_dir():
    _src_text = str(_SRC)
    if _src_text not in sys.path:
        sys.path.insert(0, _src_text)
