#!/usr/bin/env python3

from pathlib import Path
import joblib
import numpy as np
import pandas as pd

IN = Path("/opt/praxis/solution/features/phase17_confirm_features.csv")
PUBLIC = Path("/opt/praxis/public_data/features/mawi_public_flows_active.csv")
MODEL = Path("/opt/praxis/analysis/phase9_proxy_detector.joblib")

OUT_SESSION = Path("/opt/praxis/solution/reports/phase17_confirm_session_scores.csv")
OUT_CONFIG = Path("/opt/praxis/solution/reports/phase17_confirm_config_scores.csv")
OUT_SUMMARY = Path("/opt/praxis/solution/reports/phase17_confirm_summary.txt")

DETECTOR_FEATURE_COLS = [
    "pcap_size_bytes", "packet_count", "out_packets", "in_packets",
    "unknown_packets", "out_payload_bytes", "in_payload_bytes",
    "total_payload_bytes", "flow_duration_seconds", "burst_count",
] + [f"len_{i}" for i in range(1, 21)]

PUBLIC_DISTANCE_COLS = [
    "packet_count", "out_packets", "in_packets", "unknown_packets",
    "out_payload_bytes", "in_payload_bytes", "total_payload_bytes",
    "flow_duration_seconds", "burst_count",
] + [f"len_{i}" for i in range(1, 21)]


def ensure_cols(df, cols):
    df = df.copy()
    for c in cols:
        if c not in df.columns:
            df[c] = 0
    return df[cols].fillna(0)


def minmax(series):
    s = pd.Series(series).astype(float)
    lo, hi = s.min(), s.max()
    if hi - lo < 1e-12:
        return pd.Series([0.0] * len(s), index=s.index)
    return (s - lo) / (hi - lo)


def model_probability(model, X):
    if hasattr(model, "predict_proba"):
        p = model.predict_proba(X)
        return p[:, 1] if p.shape[1] > 1 else p[:, 0]
    if hasattr(model, "decision_function"):
        z = model.decision_function(X)
        return 1 / (1 + np.exp(-z))
    return model.predict(X).astype(float)


def robust_log_distance(X_sweep, X_public):
    Xs = X_sweep.copy().astype(float)
    Xp = X_public.copy().astype(float)

    for c in Xs.columns:
        Xs[c] = np.sign(Xs[c]) * np.log1p(np.abs(Xs[c]))
        Xp[c] = np.sign(Xp[c]) * np.log1p(np.abs(Xp[c]))

    med = Xp.median(axis=0)
    iqr = (Xp.quantile(0.75, axis=0) - Xp.quantile(0.25, axis=0)).replace(0, 1.0)

    Z = (Xs - med) / iqr
    return np.sqrt((Z ** 2).sum(axis=1))


def main():
    for p in [IN, PUBLIC, MODEL]:
        if not p.exists():
            raise SystemExit(f"Missing required input: {p}")

    df = pd.read_csv(IN)
    public = pd.read_csv(PUBLIC)
    model = joblib.load(MODEL)

    detector_cols = list(model.feature_names_in_) if hasattr(model, "feature_names_in_") else DETECTOR_FEATURE_COLS

    X_detector = ensure_cols(df, detector_cols)
    df["detector_proxy_probability"] = model_probability(model, X_detector)

    X_distance = ensure_cols(df, PUBLIC_DISTANCE_COLS)
    X_public = ensure_cols(public, PUBLIC_DISTANCE_COLS)

    df["public_robust_log_distance"] = robust_log_distance(X_distance, X_public)
    df["public_robust_log_distance_norm"] = minmax(df["public_robust_log_distance"])

    df["compliance_score"] = pd.to_numeric(df["success"], errors="coerce").fillna(0.0)
    df["compliance_penalty"] = np.maximum(0.0, 0.95 - df["compliance_score"])
    df["overhead_norm"] = minmax(df["pcap_size_bytes"])

    df["praxis_score_phase17"] = (
        0.45 * df["detector_proxy_probability"]
        + 0.35 * df["public_robust_log_distance_norm"]
        + 0.15 * df["compliance_penalty"]
        + 0.05 * df["overhead_norm"]
    )

    OUT_SESSION.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUT_SESSION, index=False)

    agg = (
        df.groupby("config_id")
        .agg(
            n=("session_id", "count"),
            mean_success=("compliance_score", "mean"),
            mean_detector_proxy_probability=("detector_proxy_probability", "mean"),
            std_detector_proxy_probability=("detector_proxy_probability", "std"),
            mean_public_robust_log_distance=("public_robust_log_distance", "mean"),
            mean_public_robust_log_distance_norm=("public_robust_log_distance_norm", "mean"),
            mean_overhead_norm=("overhead_norm", "mean"),
            mean_praxis_score_phase17=("praxis_score_phase17", "mean"),
            std_praxis_score_phase17=("praxis_score_phase17", "std"),
        )
        .reset_index()
        .sort_values("mean_praxis_score_phase17")
    )

    agg.to_csv(OUT_CONFIG, index=False)

    base = agg[agg["config_id"] == "baseline_default_off"].iloc[0]
    winner = agg.iloc[0]
    best_detector = agg.sort_values("mean_detector_proxy_probability").iloc[0]

    lines = []
    lines.append("PRAXIS Phase 17 Confirm-Best Summary")
    lines.append("")
    lines.append(f"baseline_score={base['mean_praxis_score_phase17']:.6f}")
    lines.append(f"baseline_detector_probability={base['mean_detector_proxy_probability']:.6f}")
    lines.append(f"baseline_public_distance_norm={base['mean_public_robust_log_distance_norm']:.6f}")
    lines.append(f"baseline_overhead_norm={base['mean_overhead_norm']:.6f}")
    lines.append("")
    lines.append(f"best_tradeoff_config_id={winner['config_id']}")
    lines.append(f"best_tradeoff_score={winner['mean_praxis_score_phase17']:.6f}")
    lines.append(f"best_tradeoff_score_delta_vs_baseline={winner['mean_praxis_score_phase17'] - base['mean_praxis_score_phase17']:.6f}")
    lines.append(f"best_tradeoff_detector_probability={winner['mean_detector_proxy_probability']:.6f}")
    lines.append(f"best_tradeoff_detector_delta_vs_baseline={winner['mean_detector_proxy_probability'] - base['mean_detector_proxy_probability']:.6f}")
    lines.append("")
    lines.append(f"best_detector_config_id={best_detector['config_id']}")
    lines.append(f"best_detector_probability={best_detector['mean_detector_proxy_probability']:.6f}")
    lines.append(f"best_detector_delta_vs_baseline={best_detector['mean_detector_proxy_probability'] - base['mean_detector_proxy_probability']:.6f}")
    lines.append(f"best_detector_score={best_detector['mean_praxis_score_phase17']:.6f}")
    lines.append("")
    lines.append("Per-config deltas vs baseline:")

    for _, row in agg.iterrows():
        lines.append(
            f"{row['config_id']}: "
            f"score_delta={row['mean_praxis_score_phase17'] - base['mean_praxis_score_phase17']:.6f}, "
            f"detector_delta={row['mean_detector_proxy_probability'] - base['mean_detector_proxy_probability']:.6f}, "
            f"public_distance_delta={row['mean_public_robust_log_distance_norm'] - base['mean_public_robust_log_distance_norm']:.6f}, "
            f"overhead_delta={row['mean_overhead_norm'] - base['mean_overhead_norm']:.6f}"
        )

    lines.append("")
    lines.append("Interpretation rule:")
    lines.append("- If camouflaged_c2_p1 has negative score_delta and negative detector_delta, Phase 17 confirms the Phase 16 result.")
    lines.append("- If default_c2_p1 also has strong detector reduction, the mux/parallelism mechanism is likely the main driver.")
    lines.append("- If only camouflaged_c2_p1 wins, browser camouflage and c2_p1 likely interact.")

    OUT_SUMMARY.write_text("\n".join(lines) + "\n")

    print(agg.to_string(index=False))
    print()
    print(OUT_SUMMARY.read_text())


if __name__ == "__main__":
    main()
