# Security Policy

## Research-use boundary

PRAXIS is a research and evaluation framework for traffic-shape measurement, proxy-configuration scoring, and adaptive configuration selection.

PRAXIS is not advertised as:
- a real-world censorship evasion service,
- an undetectable proxy,
- a complete detector-bypass tool,
- an operational deployment guide for bypassing a specific censor.

## Supported use

Appropriate uses include:
- evaluating proxy traffic configurations in a controlled lab,
- extracting aggregate traffic-shape features from authorized pcaps,
- comparing configurations against a public-benign baseline,
- studying detector-confidence changes,
- reproducing the PRAXIS Adaptive Camouflage Controller workflow.

## Sensitive files that should not be committed

Do not commit:
- raw pcaps containing third-party traffic,
- private keys,
- GitHub tokens,
- AWS credentials,
- Xray/proxy secrets,
- live infrastructure IPs or access details,
- raw browser logs containing sensitive material,
- S3 upload credentials.

## Reporting vulnerabilities

If you find a security issue in PRAXIS code, open a private issue or contact the maintainer directly.

## Token handling

Never hardcode personal access tokens in code, documentation, Git remotes, shell history, notebooks, or CI logs.
