#!/usr/bin/env python3

from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

PUBLIC = Path("/opt/praxis/public_data/features/mawi_public_flows_20240302_1m.csv")

STRICT_MODEL = Path("/opt/praxis/solution/models/phase20_holdout_detector_strict_unseen.joblib")
KNOWN_MODEL = Path("/opt/praxis/solution/models/phase20_holdout_detector_baseline_known.joblib")

STRICT_SESS = Path("/opt/praxis/solution/reports/phase20_holdout_strict_unseen_session_scores.csv")
KNOWN_SESS = Path("/opt/praxis/solution/reports/phase20_holdout_baseline_known_session_scores.csv")

OUT = Path("/opt/praxis/solution/reports/phase20b_threshold_validation.txt")
OUT_CSV = Path("/opt/praxis/solution/reports/phase20b_threshold_validation.csv")

TARGET_FPRS = [0.000, 0.001, 0.005, 0.010, 0.050]

COMPARE = [
    "baseline_default_off",
    "default_c2_p1",
    "camouflaged_c2_p1",
]


def ensure_cols(df, cols):
    df = df.copy()
    for c in cols:
        if c not in df.columns:
            df[c] = 0
    return df[cols].fillna(0)


def signed_log_transform(df):
    x = df.copy().astype(float)
    for c in x.columns:
        x[c] = np.sign(x[c]) * np.log1p(np.abs(x[c]))
    return x


def bootstrap_ci_delta(a, b, n_boot=10000, seed=42):
    rng = np.random.default_rng(seed)
    a = np.asarray(a, dtype=float)
    b = np.asarray(b, dtype=float)

    deltas = []
    for _ in range(n_boot):
        aa = rng.choice(a, size=len(a), replace=True)
        bb = rng.choice(b, size=len(b), replace=True)
        deltas.append(bb.mean() - aa.mean())

    lo, hi = np.percentile(deltas, [2.5, 97.5])
    return float(lo), float(hi)


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


def load_model_bundle(path):
    bundle = joblib.load(path)
    if not isinstance(bundle, dict):
        raise SystemExit(f"Unexpected model bundle format: {path}")
    return bundle["model"], bundle["feature_cols"]


def public_holdout_probabilities(model, feature_cols):
    public = pd.read_csv(PUBLIC)

    _, public_holdout = train_test_split(
        public,
        test_size=0.30,
        random_state=2020,
        shuffle=True,
    )

    X_pub = signed_log_transform(ensure_cols(public_holdout, feature_cols))
    pub_prob = model.predict_proba(X_pub)[:, 1]
    return pub_prob


def threshold_for_target_fpr(pub_prob, target_fpr):
    pub_prob = np.asarray(pub_prob, dtype=float)

    if target_fpr <= 0:
        return float(np.max(pub_prob) + 1e-12)

    return float(np.quantile(pub_prob, 1.0 - target_fpr))


def evaluate_mode(mode, model_path, session_path):
    model, feature_cols = load_model_bundle(model_path)
    pub_prob = public_holdout_probabilities(model, feature_cols)

    sessions = pd.read_csv(session_path)
    prob_col = f"holdout_{mode}_proxy_probability"

    if prob_col not in sessions.columns:
        raise SystemExit(f"Missing probability column in {session_path}: {prob_col}")

    rows = []

    for target_fpr in TARGET_FPRS:
        threshold = threshold_for_target_fpr(pub_prob, target_fpr)
        empirical_fpr = float((pub_prob >= threshold).mean())

        for cfg in COMPARE:
            sub = sessions[sessions["config_id"] == cfg]
            if sub.empty:
                continue

            probs = sub[prob_col].astype(float).to_numpy()

            rows.append({
                "mode": mode,
                "target_fpr": target_fpr,
                "threshold": threshold,
                "empirical_public_fpr": empirical_fpr,
                "config_id": cfg,
                "n": len(probs),
                "mean_probability": float(np.mean(probs)),
                "min_probability": float(np.min(probs)),
                "max_probability": float(np.max(probs)),
                "detection_rate_at_threshold": float((probs >= threshold).mean()),
            })

    # Probability-level statistical validation.
    stats = []
    base = sessions[sessions["config_id"] == "baseline_default_off"][prob_col].astype(float).to_numpy()

    for cfg in ["default_c2_p1", "camouflaged_c2_p1"]:
        other = sessions[sessions["config_id"] == cfg][prob_col].astype(float).to_numpy()

        delta = float(np.mean(other) - np.mean(base))
        pct = float(100.0 * delta / np.mean(base)) if abs(np.mean(base)) > 1e-12 else np.nan
        ci_lo, ci_hi = bootstrap_ci_delta(base, other)
        p = permutation_pvalue(base, other)

        stats.append({
            "mode": mode,
            "config_id": cfg,
            "baseline_mean": float(np.mean(base)),
            "candidate_mean": float(np.mean(other)),
            "delta": delta,
            "pct_delta": pct,
            "bootstrap_95ci_low": ci_lo,
            "bootstrap_95ci_high": ci_hi,
            "permutation_p_two_sided": p,
        })

    return rows, stats


def main():
    for p in [PUBLIC, STRICT_MODEL, KNOWN_MODEL, STRICT_SESS, KNOWN_SESS]:
        if not p.exists():
            raise SystemExit(f"Missing required input: {p}")

    all_rows = []
    all_stats = []

    for mode, model_path, session_path in [
        ("strict_unseen", STRICT_MODEL, STRICT_SESS),
        ("baseline_known", KNOWN_MODEL, KNOWN_SESS),
    ]:
        rows, stats = evaluate_mode(mode, model_path, session_path)
        all_rows.extend(rows)
        all_stats.extend(stats)

    df = pd.DataFrame(all_rows)
    df.to_csv(OUT_CSV, index=False)

    lines = []
    lines.append("PRAXIS Phase 20B Threshold and Statistical Validation")
    lines.append("")
    lines.append("Purpose:")
    lines.append("Evaluate Phase 17 configurations under fresh holdout detectors using public-FPR-calibrated thresholds.")
    lines.append("")
    lines.append("Inputs:")
    lines.append(f"public_benign={PUBLIC}")
    lines.append(f"strict_model={STRICT_MODEL}")
    lines.append(f"baseline_known_model={KNOWN_MODEL}")
    lines.append(f"strict_sessions={STRICT_SESS}")
    lines.append(f"baseline_known_sessions={KNOWN_SESS}")
    lines.append("")

    lines.append("Threshold results:")
    for mode in ["strict_unseen", "baseline_known"]:
        lines.append("")
        lines.append(f"Detector mode: {mode}")
        sub = df[df["mode"] == mode]

        for target_fpr in TARGET_FPRS:
            ss = sub[sub["target_fpr"] == target_fpr]
            lines.append(f"target_fpr={target_fpr:.3f}")

            for _, r in ss.sort_values("config_id").iterrows():
                lines.append(
                    f"  {r['config_id']}: "
                    f"threshold={r['threshold']:.6f}, "
                    f"public_fpr={r['empirical_public_fpr']:.6f}, "
                    f"mean_prob={r['mean_probability']:.6f}, "
                    f"min_prob={r['min_probability']:.6f}, "
                    f"max_prob={r['max_probability']:.6f}, "
                    f"detection_rate={r['detection_rate_at_threshold']:.6f}"
                )

    lines.append("")
    lines.append("Probability delta statistical validation:")
    for s in all_stats:
        lines.append(
            f"{s['mode']} {s['config_id']}: "
            f"baseline_mean={s['baseline_mean']:.6f}, "
            f"candidate_mean={s['candidate_mean']:.6f}, "
            f"delta={s['delta']:.6f}, "
            f"pct_delta={s['pct_delta']:.2f}%, "
            f"bootstrap_95ci=[{s['bootstrap_95ci_low']:.6f},{s['bootstrap_95ci_high']:.6f}], "
            f"permutation_p_two_sided={s['permutation_p_two_sided']:.6f}"
        )

    lines.append("")
    lines.append("Interpretation:")
    lines.append("- If detection_rate remains 1.0 across thresholds, claim detector-confidence reduction only.")
    lines.append("- If default_c2_p1 detection_rate drops below baseline at strict public-FPR thresholds, claim threshold-calibrated detection-rate reduction.")
    lines.append("- Do not claim complete detector bypass unless detection_rate is near 0.0 under a defensible public-FPR threshold.")
    lines.append("- The strongest defensible result remains bounded to the PRAXIS lab threat model and tested detectors.")

    OUT.write_text("\n".join(lines) + "\n")

    print(OUT.read_text())
    print(f"Wrote {OUT_CSV}")


if __name__ == "__main__":
    main()
