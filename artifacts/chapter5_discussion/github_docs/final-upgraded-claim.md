# PRAXIS Final Upgraded Claim

PRAXIS validates an Adaptive Camouflage Controller for measurement-guided proxy traffic configuration selection under a controlled cyber analytics threat model.

The controller selected `default_c2_p1`, which reduced detector confidence relative to baseline while preserving 100% compliance.

## Confirmed Phase 17 Result

```text
baseline_default_off:
  detector_probability = 1.000
  corrected_score      = 0.654

default_c2_p1:
  detector_probability = 0.487
  corrected_score      = 0.433

delta:
  detector_delta = -0.513
  score_delta    = -0.221
  compliance     = 100%
Mechanism Result

Phase 29 and Phase 29B show that the default_c2_p1 effect is not only a flow-duration artifact, not only a packet-count artifact, and not only a pcap-size artifact.

The effect persists in:

payload-only features
signed-length-only features
burst-only features
no-duration feature sets
no-packet-count feature sets

This supports the interpretation that c2 multiplexing with parallel=1 changes multiple observable flow-shape dimensions.

Multi-Detector Result

Phase 30 shows detector-family-dependent confidence reduction.

The reduction is strongest under:

random_forest
extra_trees

It is marginal or negligible under:

linear_svc_calibrated
gradient_boosting

It is not supported under:

logistic regression

Therefore, PRAXIS should not claim universal detector robustness.

Public-Baseline Result

Phase 31 shows that default_c2_p1 remains the winner across:

MAWI day 1
MAWI day 2
combined MAWI day 1 + day 2
CICIDS2017 mapped benign baseline
balanced MAWI + CICIDS baseline

MAWI remains the primary baseline. CICIDS2017 is a secondary mapped sanity-check baseline.

RQ3 Result

Phase 21 confirms controlled resolver independence:

standard_dns_lab: n=30 success=30
dns_blocked: n=30 success=0
decentralized_resolution: n=30 success=30

This validates controlled decentralized-style resolution, not production blockchain DDNS.

Final Defense-Safe Claim

PRAXIS demonstrates statistically supported detector-confidence reduction, out-of-sample confirmation, mechanism evidence, detector-family-dependent robustness, public-baseline sensitivity validation, and controlled resolver independence.

It does not prove complete detector bypass, universal detector robustness, real-world censorship evasion, or production blockchain DDNS deployment.
