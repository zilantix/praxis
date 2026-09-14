# PRAXIS 10-of-10 Upgrade Summary

This page summarizes the final PRAXIS defense-readiness upgrades.

## Upgrade Goals

The upgrade work strengthens PRAXIS in seven areas:

```text
Upgrade 1: stronger mechanism analysis
Upgrade 2: multi-detector robustness
Upgrade 3: MAWI + CICIDS public-baseline validation
Upgrade 6: formal threat model
Upgrade 7: uniform statistical reporting
Upgrade 8: reproducibility appendix
Upgrade 9: external researcher workflow
Phase 29 — Mechanism Analysis

Phase 29 explains why default_c2_p1 worked.

The strongest observed changes were:

flow_duration_seconds decreased
packet_count decreased
out_packets decreased
in_packets decreased
burst_count decreased
payload and signed-length structure changed

Interpretation:

default_c2_p1 changes multiple observable traffic-shape dimensions.
Phase 29B — Artifact-Control Check

Phase 29B showed that the mechanism is not only a duration/count artifact.

The effect persisted in:

no_duration feature set
no_packet_counts feature set
no_duration_no_counts feature set
payload_only feature set
signed_lengths_only feature set
burst_only feature set

Interpretation:

The mechanism is broader than duration compression or packet-count reduction alone.
Phase 30 — Multi-Detector Robustness

Phase 30 tested several detector families.

Result:

random_forest: strong confidence reduction
extra_trees: moderate confidence reduction
linear_svc_calibrated: small confidence reduction
gradient_boosting: negligible confidence reduction
logistic: no meaningful reduction

Interpretation:

PRAXIS shows detector-family-dependent confidence reduction.
It does not prove universal detector robustness.
Phase 31 — MAWI + CICIDS Public-Baseline Validation

Phase 31 added CICIDS2017 benign mapped features as a secondary sanity-check baseline.

default_c2_p1 remained the winner across:

MAWI day 1
MAWI day 2
combined MAWI day 1 + day 2
CICIDS2017 mapped benign baseline
balanced MAWI + CICIDS baseline

Boundary:

MAWI remains the primary packet-derived baseline.
CICIDS2017 is a secondary mapped sanity check.
Phase 32 — Formal Defense Documentation

Phase 32 created:

algorithm.md
threat-model.md
reproducibility.md
external-researcher-workflow.md
final-upgraded-claim.md
Final Upgraded Claim

PRAXIS demonstrates statistically supported detector-confidence reduction, out-of-sample confirmation, mechanism evidence, detector-family-dependent robustness, public-baseline sensitivity validation, and controlled resolver independence.

It does not prove complete detector bypass, universal detector robustness, real-world censorship evasion, or production blockchain DDNS deployment.
