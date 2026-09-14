#!/usr/bin/env python3

from pathlib import Path
import numpy as np
import pandas as pd

IN = Path("/opt/praxis/solution/reports/phase17_confirm_session_scores.csv")
OUT = Path("/opt/praxis/solution/reports/phase17_statistical_validation.txt")

BASELINE = "baseline_default_off"
COMPARE = ["camouflaged_c2_p1", "default_c2_p1"]

METRICS = [
    "detector_proxy_probability",
    "public_robust_log_distance_norm",
    "overhead_norm",
    "praxis_score_phase17",
]


def bootstrap_ci_delta(a, b, n_boot=10000, seed=42):
    rng = np.random.default_rng(seed)
    a = np.asarray(a, dtype=float)
    b = np.asarray(b, dtype=float)
    deltas = []
    for _ in range(n_boot):
        aa = rng.choice(a, size=len(a), replace=True)
        bb = rng.choice(b, size=len(b), replace=True)
        deltas.append(bb.mean() - aa.mean())
    return tuple(float(x) for x in np.percentile(deltas, [2.5, 97.5]))


def permutation_pvalue(a, b, n_perm=10000, seed=43):
    rng = np.random.default_rng(seed)
    a = np.asarray(a, dtype=float)
    b = np.asarray(b, dtype=float)
    observed = abs(b.mean() - a.mean())
    pooled = np.concatenate([a, b])
    n_a = len(a)
    count = 0
    for _ in range(n_perm):
        perm = rng.permutation(pooled)
        aa = perm[:n_a]
        bb = perm[n_a:]
        if abs(bb.mean() - aa.mean()) >= observed:
            count += 1
    return float((count + 1) / (n_perm + 1))


def main():
    df = pd.read_csv(IN)
    base = df[df["config_id"] == BASELINE]

    lines = []
    lines.append("PRAXIS Phase 17 Statistical Validation")
    lines.append("")
    lines.append(f"input={IN}")
    lines.append(f"baseline={BASELINE}")
    lines.append(f"n_baseline={len(base)}")
    lines.append("")

    for cfg in COMPARE:
        other = df[df["config_id"] == cfg]
        lines.append(f"Comparison: {cfg} vs {BASELINE}")
        lines.append(f"n_{cfg}={len(other)}")

        for m in METRICS:
            a = base[m].astype(float).to_numpy()
            b = other[m].astype(float).to_numpy()

            delta = b.mean() - a.mean()
            pct = np.nan if abs(a.mean()) < 1e-12 else 100.0 * delta / a.mean()
            ci_lo, ci_hi = bootstrap_ci_delta(a, b)
            p = permutation_pvalue(a, b)

            lines.append(f"metric={m}")
            lines.append(f"baseline_mean={a.mean():.6f}")
            lines.append(f"{cfg}_mean={b.mean():.6f}")
            lines.append(f"delta={delta:.6f}")
            lines.append(f"pct_delta={pct:.2f}%")
            lines.append(f"bootstrap_95ci_delta=[{ci_lo:.6f},{ci_hi:.6f}]")
            lines.append(f"permutation_p_two_sided={p:.6f}")

        lines.append("")

    lines.append("Interpretation guide:")
    lines.append("- Negative detector delta means lower detector confidence than baseline.")
    lines.append("- Negative score delta means better corrected PRAXIS score than baseline.")
    lines.append("- If both deltas are negative with confidence intervals excluding 0, the result is dissertation-grade within this lab threat model.")
    lines.append("- This validates lab-measured detector-confidence reduction, not real-world censorship evasion deployment.")

    OUT.write_text("\n".join(lines) + "\n")
    print(OUT.read_text())


if __name__ == "__main__":
    main()
