# PRAXIS Adaptive Camouflage Controller

PRAXIS is a measurement-guided research framework and web application for evaluating, scoring, and explaining proxy traffic configurations under a controlled lab threat model.

The core contribution is the **Adaptive Camouflage Controller**: a reusable controller that ranks candidate configurations using detector confidence, public-benign traffic distance, overhead, compliance, and resolver-resilience evidence.

> PRAXIS is a research and evaluation system. It demonstrates lab-measured detector-confidence reduction and adaptive configuration selection. It does **not** claim complete detector bypass or real-world censorship evasion.

---

## Table of Contents

- [Status](#status)
- [Main Result](#main-result)
- [What PRAXIS Is](#what-praxis-is)
- [What PRAXIS Is Not](#what-praxis-is-not)
- [Novelty](#novelty)
- [Research Questions](#research-questions)
- [Architecture](#architecture)
- [Scoring Framework](#scoring-framework)
- [Confirmed Cycle 2 Results](#confirmed-cycle-2-results)
- [Repository Layout](#repository-layout)
- [Installation](#installation)
- [Run the API](#run-the-api)
- [Run the GUI](#run-the-gui)
- [GUI Pages](#gui-pages)
- [PCAP Analyzer](#pcap-analyzer)
- [API Endpoints](#api-endpoints)
- [Example Usage](#example-usage)
- [Data and Reproducibility](#data-and-reproducibility)
- [Claim Boundary](#claim-boundary)
- [Responsible Use](#responsible-use)
- [Security Notes](#security-notes)
- [Roadmap](#roadmap)
- [Citation](#citation)
- [License](#license)

---

## Status

PRAXIS Cycle 2 produced a confirmed adaptive-controller result.

Best confirmed configuration:

```text
default_c2_p1
```

Configuration:

```text
browser_profile = default
mux_mode        = c2
parallel        = 1
padding_mode    = none
```

Main confirmed Phase 17 result:

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
```

Fresh holdout detectors confirmed lower detector confidence for `default_c2_p1`, but binary detection remained positive under tested thresholds.

Phase 21 confirmed controlled resolver-independence:

```text
standard_dns_lab succeeds
dns_blocked fails
decentralized_resolution succeeds
```

---

## Main Result

PRAXIS selected `default_c2_p1` as the strongest confirmed configuration.

The result shows that PRAXIS can:

1. evaluate multiple candidate proxy configurations,
2. compute traffic-shape features,
3. compare them against a public-benign traffic baseline,
4. score detector confidence, overhead, and compliance,
5. select a better configuration,
6. confirm the selected configuration out of sample,
7. validate controlled resolver independence under DNS-blocking conditions.

The strongest supported claim is:

```text
PRAXIS reduced detector confidence under the PRAXIS lab threat model and provides a reusable adaptive configuration-selection framework.
```

The result should **not** be described as complete detector bypass.

---

## What PRAXIS Is

PRAXIS is a controller and analysis framework for research workflows such as:

1. Define candidate proxy/browser/multiplexing configurations.
2. Run controlled sessions.
3. Capture packet traces.
4. Extract traffic-shape features.
5. Compare against public-benign traffic baselines.
6. Evaluate detector confidence.
7. Penalize overhead and failed sessions.
8. Rank configurations under adjustable objective weights.
9. Confirm the selected configuration out of sample.
10. Report claim boundaries.

PRAXIS can be used by researchers to compare new proxy configurations, new detectors, new public-benign baselines, and new scoring policies.

---

## What PRAXIS Is Not

PRAXIS is not:

- a turnkey censorship-bypass service,
- an undetectable proxy,
- a complete detector-bypass tool,
- a production deployment guide,
- a payload inspection system,
- a deanonymization tool,
- a tool for hiding malicious traffic.

The repository is intended for controlled research, reproducibility, measurement, and defensive evaluation.

---

## Novelty

The novelty is the **Adaptive Camouflage Controller**, not a single static proxy setting.

PRAXIS contributes:

### 1. Measurement-guided configuration selection

PRAXIS evaluates configurations empirically rather than assuming that one camouflage strategy will work.

Instead of asking:

```text
Which single proxy configuration is best?
```

PRAXIS asks:

```text
Given a detector, public-benign baseline, compliance constraint, and overhead constraint, which configuration should be selected?
```

### 2. Multi-objective scoring

PRAXIS ranks configurations using:

```text
detector confidence
public-benign traffic distance
overhead
compliance
resolver-resilience evidence
```

This prevents a configuration from being selected only because it improves one metric while failing another.

### 3. Public-benign baseline comparison

PRAXIS compares candidate traffic against features derived from public benign traffic. In Cycle 2, MAWI/WIDE-derived public traffic was used to define a public-benign flow-shape baseline.

### 4. Out-of-sample confirmation

Candidate discovery and confirmatory validation are separated. PRAXIS does not stop after a candidate wins one sweep; it reruns the selected candidate in a separate confirmatory phase.

### 5. Fresh-detector robustness testing

PRAXIS tests whether a selected configuration remains lower-confidence under fresh holdout detectors trained with an independent public-benign baseline.

### 6. Resolver-independence testing

PRAXIS includes controlled DNS-blocking and decentralized-style resolution experiments.

### 7. Reusable PCAP analysis interface

Researchers can upload their own packet captures and generate PRAXIS-compatible feature and scoring artifacts.

---

## Research Questions

PRAXIS Cycle 2 uses three research questions close to the original project framing.

### RQ1

**To what extent do browser-profile and proxy-configuration choices reduce non-timing proxy-detection confidence while preserving session compliance?**

Status:

```text
Confirmed with boundary.
```

Evidence:

```text
default_c2_p1 reduced detector probability from 1.000 to 0.487 with 100% compliance.
```

Boundary:

```text
Detector-confidence reduction, not complete detector bypass.
```

### RQ2

**How do multiplexing mode and browser-side parallelism affect proxy-traffic identifiability under non-timing traffic analysis?**

Status:

```text
Confirmed / mechanism suggested.
```

Evidence:

```text
default_c2_p1 beat camouflaged_c2_p1.
```

Interpretation:

```text
c2 multiplexing with parallel=1 appears to be the main driver, not browser camouflage alone.
```

### RQ3

**Can the best traffic-camouflage configuration be integrated with decentralized resolution to preserve access and compliance under DNS-blocking conditions?**

Status:

```text
Confirmed at controlled resolver-independence level.
```

Evidence:

```text
standard_dns_lab: n=30 success=30
dns_blocked: n=30 success=0
decentralized_resolution: n=30 success=30
```

Boundary:

```text
Controlled local decentralized-style mapping, not production blockchain DDNS integration.
```

---

## Architecture

```text
                +----------------------------+
                | Public benign traffic data |
                +-------------+--------------+
                              |
                              v
+-------------+     +-------------------+     +------------------+
| Candidate   | --> | Traffic capture   | --> | Feature extract  |
| configs     |     | and session logs  |     | PRAXIS schema    |
+-------------+     +-------------------+     +---------+--------+
                                                          |
                                                          v
                         +--------------------------------+------------------------------+
                         | Detector confidence + public distance + overhead + compliance |
                         +--------------------------------+------------------------------+
                                                          |
                                                          v
                                             +--------------------------+
                                             | Adaptive Controller rank |
                                             +------------+-------------+
                                                          |
                                                          v
                                             +--------------------------+
                                             | Confirmatory rerun       |
                                             +--------------------------+
```

The service implementation has two major components:

```text
FastAPI API
Streamlit GUI
```

The PCAP Analyzer is included as a Streamlit page.

---

## Scoring Framework

PRAXIS uses a weighted score:

```text
PRAXIS score =
  w_detector   * detector_probability
+ w_public     * public_benign_distance
+ w_overhead   * overhead_norm
+ w_compliance * compliance_penalty
```

Lower score is better.

### Detector Probability

The detector's estimate that a session is proxy/circumvention traffic.

```text
0.0 = low detector confidence
1.0 = high detector confidence
```

In the confirmed result:

```text
baseline_default_off = 1.000
default_c2_p1        = 0.487
```

### Public-Benign Distance

A robust distance between the candidate traffic feature vector and a public-benign traffic feature distribution.

This prevents the controller from choosing a configuration that only fools one detector while producing an obviously abnormal traffic shape.

### Overhead

A normalized cost metric based on traffic volume/session size.

This prevents selecting configurations that are lower-confidence only because they add excessive traffic.

### Compliance

Whether the session worked.

A configuration that reduces detector confidence but breaks the connection is not useful.

---

## Confirmed Cycle 2 Results

### Phase 17 Confirmatory Result

```text
baseline_default_off:
  detector_probability = 1.000
  corrected_score      = 0.654

default_c2_p1:
  detector_probability = 0.487
  corrected_score      = 0.433

improvement:
  detector_delta = -0.513
  score_delta    = -0.221
```

### Phase 20 Fresh-Detector Robustness

Fresh holdout detectors trained with an independent public-benign baseline showed that `default_c2_p1` remained lower-confidence than baseline.

```text
strict_unseen:
  baseline probability      = 0.959737
  default_c2_p1 probability = 0.666053
  delta                     = -0.293684

baseline_known:
  baseline probability      = 0.998023
  default_c2_p1 probability = 0.663093
  delta                     = -0.334930
```

### Phase 20B Threshold Validation

Binary detection remained positive under tested calibrated thresholds.

Therefore:

```text
Supported:
  detector-confidence reduction

Not supported:
  complete detector bypass
```

### Phase 21 Resolver-Independence

```text
standard_dns_lab: n=30 success=30
dns_blocked: n=30 success=0
decentralized_resolution: n=30 success=30
```

This confirms controlled resolver-independence, not production blockchain DDNS.

---

## Repository Layout

```text
app/
  api/
    praxis_api.py
  lib/
    praxis_core.py
    praxis_pcap_analyzer.py
  ui/
    praxis_dashboard.py
    pages/
      1_PCAP_Analyzer.py

docs/
  figures/
  tables/
  results/
  claim-boundary.md
  novelty.md
  research-questions.md

examples/
  public_data/
    features/
      mawi_public_flows_active.csv
  solution/
    reports/
    sweep/

scripts/
  run_api.sh
  run_ui.sh

tests/
  smoke_test.py

requirements.txt
README.md
SECURITY.md
ETHICS.md
LICENSE
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/zilantix/praxis.git
cd praxis
```

Create a Python virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Use bundled example data:

```bash
export PRAXIS_DATA_DIR="$PWD/examples"
export PYTHONPATH="$PWD/app/lib"
```

---

## Run the API

```bash
export PRAXIS_DATA_DIR="$PWD/examples"
export PYTHONPATH="$PWD/app/lib"

uvicorn praxis_api:app \
  --app-dir app/api \
  --host 127.0.0.1 \
  --port 8088
```

Test:

```bash
curl -s http://127.0.0.1:8088/health

curl -s http://127.0.0.1:8088/summary | python3 -m json.tool

curl -s 'http://127.0.0.1:8088/score?detector_weight=45&public_weight=35&overhead_weight=5&compliance_weight=15' | python3 -m json.tool
```

---

## Run the GUI

```bash
export PRAXIS_DATA_DIR="$PWD/examples"
export PYTHONPATH="$PWD/app/lib"

streamlit run app/ui/praxis_dashboard.py \
  --server.address 127.0.0.1 \
  --server.port 8501 \
  --server.headless true \
  --server.maxUploadSize 1024
```

Open:

```text
http://127.0.0.1:8501
```

---

## GUI Pages

### Controller

Interactive ranking page.

Researchers can adjust weights for:

```text
detector probability
public-benign distance
overhead
compliance penalty
```

The app recomputes the winner.

### Research Questions

Displays RQ1–RQ3, evidence, status, and claim boundaries.

### Robustness

Displays Phase 20 and Phase 20B fresh-detector robustness results.

### RQ3 Resolver

Displays Phase 21 resolver-mode success/failure results.

### Claims

Displays confirmed and not-confirmed claims.

### Artifacts

Displays file availability.

### PCAP Analyzer

Lets researchers upload packet captures and compute PRAXIS-compatible analysis.

---

## PCAP Analyzer

The PCAP Analyzer page supports external researchers who want to analyze their own packet captures.

Workflow:

```text
uploaded pcap
→ extract traffic-shape features
→ compare against public-benign baseline
→ compute public-benign distance
→ compute overhead
→ use optional detector probability
→ compute partial/full PRAXIS score
→ export CSV/JSON/text report
```

Required inputs:

```text
.pcap or .pcapng
client/source IP address
session ID
configuration ID
success label
public-benign baseline CSV
```

Optional input:

```text
detector proxy probability
```

If no detector probability is supplied, PRAXIS reports:

```text
traffic-shape features
public-benign distance
overhead
compliance
partial PRAXIS score
```

It does **not** claim detector-confidence reduction.

If detector probability is supplied, PRAXIS reports:

```text
detector probability
public-benign distance
overhead
compliance
full PRAXIS score
```

Minimum recommended research dataset:

```text
baseline config: 30+ pcaps
candidate config: 30+ pcaps
public benign baseline: 5,000+ flows
optional holdout detector
```

---

## API Endpoints

```text
GET  /
GET  /health
GET  /summary
GET  /files
GET  /rq-status
GET  /claim-boundary
GET  /score
GET  /phase21
GET  /final-claim
GET  /final-status
POST /export
```

Example scoring request:

```bash
curl -s 'http://127.0.0.1:8088/score?detector_weight=45&public_weight=35&overhead_weight=5&compliance_weight=15' | python3 -m json.tool
```

---

## Example Usage

### Recompute Controller Ranking

```bash
curl -s 'http://127.0.0.1:8088/score?detector_weight=45&public_weight=35&overhead_weight=5&compliance_weight=15' | python3 -m json.tool
```

### Show Research Question Status

```bash
curl -s http://127.0.0.1:8088/rq-status | python3 -m json.tool
```

### Show Claim Boundary

```bash
curl -s http://127.0.0.1:8088/claim-boundary | python3 -m json.tool
```

### Show RQ3 Resolver Results

```bash
curl -s http://127.0.0.1:8088/phase21 | python3 -m json.tool
```

---

## Data and Reproducibility

This repository includes small sanitized example artifacts.

It does not include:

```text
raw MAWI pcaps
raw PRAXIS pcaps
private AWS logs
full S3 archives
detector joblib models
tokens or credentials
proxy secrets
```

Researchers should obtain public datasets from their original sources and comply with dataset licenses.

Example data are provided only so the API and GUI can launch and demonstrate the PRAXIS workflow.

---

## Claim Boundary

Confirmed:

```text
adaptive controller
detector-confidence reduction
corrected PRAXIS score improvement
out-of-sample confirmation
fresh-detector confidence reduction
controlled resolver-independence
```

Not confirmed:

```text
complete detector bypass
real-world censorship evasion
production blockchain DDNS integration
universal generalization to all detectors
```

Correct statement:

```text
PRAXIS reduced detector confidence and improved corrected multi-objective score under a controlled lab threat model. It did not prove complete detector bypass or real-world censorship evasion.
```

---

## Responsible Use

PRAXIS is intended for authorized research and controlled measurement.

Do not use PRAXIS to:

```text
hide malicious activity
evade enterprise monitoring
bypass a specific real-world censor
analyze unauthorized third-party traffic
extract sensitive payloads
deanonymize users
```

Appropriate uses include:

```text
academic research
network measurement
defensive security evaluation
traffic-shape analysis
reproducibility review
controlled lab experiments
```

---

## Security Notes

Do not commit:

```text
GitHub tokens
AWS credentials
private keys
live proxy secrets
raw pcaps
private packet captures
sensitive browser logs
S3 credentials
detector models containing sensitive training data
```

If you accidentally expose a token, revoke it immediately and create a new one with minimal permissions.

---

## Development

Run smoke tests:

```bash
python3 tests/smoke_test.py
```

Compile Python files:

```bash
python3 -m py_compile \
  app/lib/praxis_core.py \
  app/lib/praxis_pcap_analyzer.py \
  app/api/praxis_api.py \
  app/ui/praxis_dashboard.py \
  app/ui/pages/1_PCAP_Analyzer.py
```

Run local secret scan before pushing:

```bash
grep -RInE \
  '(ghp_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY|aws_secret_access_key|aws_access_key_id)' \
  . \
  --exclude-dir=.git \
  || true
```

---

## Roadmap

Planned work:

```text
1. Production-grade holdout detector plugins.
2. Multiple public-benign baselines.
3. Optional detector-model upload support.
4. More robust PCAP feature extraction.
5. Protocol/plugin abstraction for new proxy systems.
6. Production DDNS integration experiment.
7. Reproducibility package for dissertation/paper review.
8. Batch PCAP Analyzer mode.
9. Exportable PDF/HTML report generation.
10. Docker packaging.
```

---

## Citation

If you use PRAXIS in academic work, cite the repository and describe the exact version or commit hash used.

Example:

```text
Ruslan Iakupov. PRAXIS Adaptive Camouflage Controller. GitHub repository, 2026.
```

---

## License

MIT License. See `LICENSE`.
