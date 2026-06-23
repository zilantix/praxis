import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app/lib"))

os.environ.setdefault("PRAXIS_DATA_DIR", str(ROOT / "examples"))

import praxis_core

def test_summary():
    s = praxis_core.summary()
    assert s["best_config"] == "default_c2_p1"

def test_ranking():
    r = praxis_core.controller_ranking()
    assert r["winner"] is not None
    assert "config_id" in r["winner"]

if __name__ == "__main__":
    test_summary()
    test_ranking()
    print("smoke tests passed")
