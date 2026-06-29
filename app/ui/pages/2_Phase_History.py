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
    page_title="PRAXIS Phase History",
    layout="wide",
)

st.title("PRAXIS Phase History")

def find_repo_root() -> Path:
    here = Path(__file__).resolve()
    for p in [here.parent, *here.parents]:
        if (p / "README.md").exists() and (p / "docs").exists():
            return p
    return here.parents[2]

root = find_repo_root()
phase_file = root / "docs" / "phases.md"

if phase_file.exists():
    st.markdown(phase_file.read_text())
else:
    st.warning("docs/phases.md is not present in this repository yet.")
    st.markdown(
        """
The PRAXIS phase history should summarize Phases 1–32, including:

- initial negative detectability results,
- Adaptive Camouflage Controller development,
- public-benign MAWI baseline,
- Phase 17 confirmatory result,
- Phase 20/20B holdout detector robustness,
- Phase 21 resolver-independence validation,
- Phase 29/29B mechanism analysis,
- Phase 30 multi-detector robustness,
- Phase 31 MAWI+CICIDS baseline validation,
- Phase 32 final defense documentation.
"""
    )
