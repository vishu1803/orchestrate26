"""Repository-relative paths and shared imports for stdlib unittest discovery."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
CODE = ROOT / "code"
DATASET = ROOT / "dataset"
sys.path.insert(0, str(CODE))

from ghost_audit.io import read_contract_csv  # noqa: E402


def rows(name: str) -> list[dict[str, str]]:
    return read_contract_csv(DATASET / name)
