# PRAXIS Threat Model

## Defender

The defender can choose and evaluate:

```text
browser profile
proxy configuration
multiplexing mode
browser-side parallelism
padding mode
resolver mode

The defender can run controlled sessions, capture packet traces, extract traffic-shape features, train/evaluate detectors, compare against public-benign baselines, and select configurations using the PRAXIS controller.

Adversary

The modeled adversary observes traffic metadata and flow-shape features.

The adversary may use:

packet counts
directional packet counts
byte counts
flow duration
burst structure
first signed packet lengths
classifier-based detection
threshold-based binary labels
Adversary Does Not Have
endpoint compromise
TLS session keys
decrypted payload
browser internals
server-side secrets
direct access to user devices
payload reconstruction capability
In Scope
non-payload traffic-shape detection
detector-confidence reduction
public-benign distance
overhead
compliance
fresh-detector robustness
threshold-calibrated detection behavior
controlled resolver independence
Out of Scope
complete detector bypass
real-world censorship evasion
nation-scale active probing
endpoint compromise
TLS key compromise
payload reconstruction
production blockchain DDNS deployment
universal generalization to all censors or detectors
Correct Claim

PRAXIS demonstrates adaptive configuration selection and detector-confidence reduction under a controlled cyber analytics threat model.

Incorrect Claim

PRAXIS does not prove universal proxy undetectability, complete detector bypass, or real-world censorship evasion.

Cycle 2 Result Under This Threat Model

Under this threat model, default_c2_p1 reduced detector confidence relative to baseline_default_off, preserved 100% compliance, remained lower-confidence under several fresh detector families, and passed controlled resolver-independence testing.

Binary detection remained positive under tested calibrated thresholds, so the result remains detector-confidence reduction rather than complete bypass.
