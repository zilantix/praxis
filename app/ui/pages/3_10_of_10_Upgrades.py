# PRAXIS portable path bootstrap
import sys
from pathlib import Path

_HERE = Path(__file__).resolve()
for _p in [_HERE.parent, *_HERE.parents]:
    _candidate = _p / "app" / "lib"
    if _candidate.exists():
        sys.path.insert(0, str(_candidate))
        break
# End PRAXIS portable path bootstrap

import streamlit as st

st.set_page_config(
    page_title="PRAXIS 10-of-10 Upgrades",
    layout="wide",
)

st.title("PRAXIS 10-of-10 Defense Readiness Upgrades")

def find_repo_root() -> Path:
    here = Path(__file__).resolve()
    for p in [here.parent, *here.parents]:
        if (p / "README.md").exists() and (p / "docs").exists():
            return p
    return here.parents[2]

root = find_repo_root()

files = [
    ("Upgrade Summary", root / "docs" / "upgrades.md"),
    ("Final Upgraded Claim", root / "docs" / "final-upgraded-claim.md"),
    ("Threat Model", root / "docs" / "threat-model.md"),
    ("Algorithm", root / "docs" / "algorithm.md"),
    ("Reproducibility", root / "docs" / "reproducibility.md"),
    ("External Researcher Workflow", root / "docs" / "external-researcher-workflow.md"),
]

tabs = st.tabs([name for name, _ in files])

for tab, (name, path) in zip(tabs, files):
    with tab:
        st.subheader(name)
        if path.exists():
            st.markdown(path.read_text())
        else:
            st.error(f"Missing file: {path}")

st.warning(
    "Claim boundary: PRAXIS supports detector-confidence reduction and adaptive selection "
    "under a controlled lab threat model. It does not claim complete detector bypass or "
    "real-world censorship evasion."
)
