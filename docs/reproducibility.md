# PRAXIS Reproducibility Appendix

## Repository

```text
https://github.com/zilantix/praxis
Main Configuration
default_c2_p1
browser_profile = default
mux_mode        = c2
parallel        = 1
padding_mode    = none
Required Software
Python 3
pandas
numpy
scikit-learn
joblib
scipy
matplotlib
tcpdump
Streamlit
FastAPI
tmux
Core Feature Files
phase14_sweep_features.csv
phase16_candidate_features.csv
phase17_confirm_features.csv
Core Result Files
phase17_confirm_summary.txt
phase20_holdout_detector_summary.txt
phase20b_threshold_validation.txt
phase21_rq3_validation.txt
phase29_mechanism_summary.txt
phase29b_artifact_control_summary.txt
phase30_multidetector_summary.txt
phase31_mawi_cicids_summary.txt
Public Baselines
mawi_public_flows_active.csv
mawi_public_flows_20240302_1m.csv
cicids2017_benign_praxis_mapped.csv
Reproduction Sequence
Phase 28: validate AMI clone
Phase 29: mechanism analysis
Phase 29B: artifact-control mechanism check
Phase 30: multi-detector robustness
Phase 31: MAWI + CICIDS baseline sensitivity
Phase 32: formal algorithm, threat model, reproducibility appendix, and claim boundary
Expected Main Result
baseline_default_off:
  detector probability = 1.000
  corrected score      = 0.654

default_c2_p1:
  detector probability = 0.487
  corrected score      = 0.433
Limitations

PRAXIS does not confirm:

complete detector bypass
real-world censorship evasion
production blockchain DDNS
universal detector robustness

PRAXIS confirms:

adaptive configuration selection
detector-confidence reduction
out-of-sample confirmation
fresh-detector confidence reduction under several detector families
controlled resolver independence

