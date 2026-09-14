# Algorithm 1: PRAXIS Adaptive Camouflage Controller

## Purpose

The PRAXIS Adaptive Camouflage Controller selects proxy traffic configurations using measurement-driven evidence rather than static assumptions.

The controller evaluates candidate configurations using:

```text
detector confidence
public-benign traffic distance
overhead
compliance
resolver-resilience evidence

Lower PRAXIS score is better.

Inputs
C = candidate configurations
B = public benign baseline
D = detector or detector score function
W = scoring weights
tau = compliance threshold
n = sessions per configuration
Procedure
for each configuration c in C:

    run n controlled sessions

    for each session s:
        capture packet trace
        capture session log
        extract PRAXIS traffic-shape features
        compute compliance(s)
        compute overhead(s)
        compute detector confidence D(s), if available
        compute public-benign distance dist(s, B)

    aggregate session metrics into config metrics:
        mean detector confidence
        mean public-benign distance
        mean overhead
        mean compliance

    compute PRAXIS score(c):
        score(c) =
            w_detector   * detector_confidence(c)
          + w_public     * public_distance(c)
          + w_overhead   * overhead(c)
          + w_compliance * compliance_penalty(c)

rank all configurations by score(c)

select the lowest-scoring compliant configuration

run out-of-sample confirmatory sessions

evaluate:
    detector-confidence delta
    public-distance delta
    overhead delta
    compliance
    confidence intervals
    fresh-detector robustness
    threshold-calibrated detection behavior
    resolver-resilience behavior if applicable
Output
ranked configuration list
selected best configuration
session-level score table
configuration-level score table
confirmatory evaluation report
claim-boundary statement
Cycle 2 Selected Configuration
default_c2_p1
browser_profile = default
mux_mode        = c2
parallel        = 1
padding_mode    = none
Confirmed Result
baseline detector probability      = 1.000
default_c2_p1 detector probability = 0.487
detector delta                     = -0.513
baseline corrected score           = 0.654
default_c2_p1 corrected score      = 0.433
compliance                         = 100%
Claim Boundary

The controller demonstrates adaptive configuration selection and detector-confidence reduction under a controlled lab threat model.

It does not prove complete detector bypass, real-world censorship evasion, production blockchain DDNS, or universal detector robustness.
