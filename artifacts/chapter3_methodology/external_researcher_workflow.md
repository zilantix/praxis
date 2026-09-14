# External Researcher Workflow

PRAXIS can be used by researchers who have their own packet captures and want to compute PRAXIS-compatible traffic-shape features and scores.

## Workflow

1. Run a controlled proxy/session experiment.
2. Capture authorized pcaps.
3. Open PRAXIS Controller Studio.
4. Go to the PCAP Analyzer page.
5. Upload a `.pcap` or `.pcapng`.
6. Enter the client/source IP.
7. Enter a session ID.
8. Enter a configuration ID.
9. Mark session success or failure.
10. Select or upload a public-benign baseline.
11. Optionally enter detector proxy probability.
12. Click Analyze.
13. Export CSV, JSON, and text reports.

## Outputs

```text
traffic-shape feature row
public-benign robust log distance
normalized overhead
compliance score
partial PRAXIS score
full PRAXIS score if detector probability is provided
CSV report
JSON summary
text report
Required Inputs
pcap or pcapng
client/source IP address
session ID
configuration ID
success label
public-benign baseline CSV
Optional Inputs
detector proxy probability
overhead budget
custom scoring weights
Interpretation Without Detector Probability

If no detector probability is supplied, PRAXIS computes:

traffic-shape features
public-benign distance
overhead
compliance
partial PRAXIS score

It cannot claim detector-confidence reduction.

Interpretation With Detector Probability

If detector probability is supplied, PRAXIS computes:

detector probability
public-benign distance
overhead
compliance
full PRAXIS score

Detector-confidence claims still require multiple sessions and appropriate baselines.

Minimum Recommended Research Dataset
baseline configuration: 30+ pcaps
candidate configuration: 30+ pcaps
public benign baseline: 5,000+ flows
holdout detector if detector-confidence claims are made
Responsible-Use Boundary

Researchers should only upload pcaps they are authorized to analyze.

Do not upload sensitive third-party traffic, credentials, private payloads, production captures without approval, or captures containing personally identifiable information.

Correct Use

Use PRAXIS to compare configurations under a controlled measurement framework.

Incorrect Use

Do not use PRAXIS to claim universal evasion, hide malicious traffic, or bypass a specific real-world censor.
