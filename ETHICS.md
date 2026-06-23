# Ethics and Responsible Use

PRAXIS was developed as a controlled research framework for studying proxy-traffic detectability, adaptive configuration selection, and resolver-independence under a lab threat model.

## Research boundary

PRAXIS results should be interpreted as lab-measured detector-confidence reduction, not proof of real-world censorship evasion.

The confirmed Cycle 2 result demonstrates that a selected configuration reduced detector confidence under the PRAXIS lab detector and fresh holdout detectors. Binary detection remained positive under tested calibrated thresholds, so the project does not claim complete detector bypass.

## Data handling

The PCAP Analyzer extracts aggregate traffic-shape metadata. Users should only upload packet captures they are authorized to analyze.

Do not upload:
- third-party traffic without authorization,
- private user traffic,
- credentials,
- sensitive payloads,
- production logs containing personally identifiable information.

## Public datasets

PRAXIS uses public-benign traffic features derived from MAWI/WIDE samples in the original experiment. Raw public pcaps are not redistributed in this repository. Researchers should obtain public datasets from their original sources and comply with dataset licenses.

## Intended audience

PRAXIS is intended for:
- academic researchers,
- network measurement researchers,
- censorship-measurement researchers,
- defensive security evaluators,
- reproducibility reviewers.

## Not intended for

PRAXIS is not intended for:
- unauthorized network access,
- bypassing specific real-world censorship systems,
- evading enterprise monitoring,
- hiding malicious activity,
- deanonymizing users,
- extracting sensitive payloads.
