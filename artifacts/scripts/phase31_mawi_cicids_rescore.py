#!/usr/bin/env python3

from pathlib import Path
import numpy as np
import pandas as pd

P17 = Path("/opt/praxis/solution/reports/phase17_confirm_session_scores.csv")
MAWI1 = Path("/opt/praxis/public_data/features/mawi_public_flows_active.csv")
MAWI2 = Path("/opt/praxis/public_data/features/mawi_public_flows_20240302_1m.csv")
CICIDS = Path("/opt/praxis/public_data/features/cicids2017_benign_praxis_mapped.csv")

OUT_DIR = Path("/opt/praxis/solution/reports/phase31")
OUT_SESSION = OUT_DIR / "phase31_mawi_cicids_rescored_sessions.csv"
OUT_CONFIG = OUT_DIR / "phase31_mawi_cicids_rescored_configs.csv"
OUT_SUMMARY = OUT_DIR / "phase31_mawi_cicids_summary.txt"

DIST_COLS = [
    "packet_count",
    "out_packets",
    "in_packets",
    "unknown_packets",
    "out_payload_bytes",
    "in_payload_bytes",
    "total_payload_bytes",
    "flow_duration_seconds",
    "burst_count",
] + [f"len_{i}" for i in range(1, 21)]


def ensure_cols(df, cols):
    out = pd.DataFrame(index=df.index)
    for c in cols:
        if c in df.columns:
            out[c] = pd.to_numeric(df[c], errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0.0)
        else:
            out[c] = 0.0
    return out


def signed_log(df):
    x = ensure_cols(df, DIST_COLS).astype(float)
    for c in x.columns:
        x[c] = np.sign(x[c]) * np.log1p(np.abs(x[c]))
    return x


def robust_distance(session_df, public_df):
    Xs = signed_log(session_df)
    Xp = signed_log(public_df)

    med = Xp.median(axis=0)
    iqr = (Xp.quantile(0.75, axis=0) - Xp.quantile(0.25, axis=0)).replace(0, 1.0)

    Z = (Xs - med) / iqr
    return np.sqrt((Z ** 2).sum(axis=1))


def minmax(s):
    s = pd.Series(s).astype(float)
    lo, hi = s.min(), s.max()
    if hi - lo < 1e-12:
        return pd.Series([0.0] * len(s), index=s.index)
    return (s - lo) / (hi - lo)


def sample_df(df, n, seed):
    if len(df) <= n:
        return df.copy()
    return df.sample(n=n, random_state=seed)


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    for p in [P17, MAWI1, MAWI2, CICIDS]:
        if not p.exists():
            raise SystemExit(f"Missing required file: {p}")

    p17 = pd.read_csv(P17)

    mawi1 = pd.read_csv(MAWI1)
    mawi2 = pd.read_csv(MAWI2)
    cicids = pd.read_csv(CICIDS)

    baselines = {
        "mawi_day1": sample_df(mawi1, 10000, 3101),
        "mawi_day2": sample_df(mawi2, 10000, 3102),
        "mawi_day1_day2": pd.concat([sample_df(mawi1, 10000, 3103), sample_df(mawi2, 10000, 3104)], ignore_index=True),
        "cicids2017_mapped": sample_df(cicids, 10000, 3105),
        "mawi_plus_cicids_balanced": pd.concat([
            sample_df(mawi1, 5000, 3106),
            sample_df(mawi2, 5000, 3107),
            sample_df(cicids, 10000, 3108),
        ], ignore_index=True),
    }

    rows = []

    for name, public in baselines.items():
        df = p17.copy()
        df["public_baseline"] = name
        df["public_baseline_rows"] = len(public)
        df["public_distance"] = robust_distance(df, public)
        df["public_distance_norm"] = minmax(df["public_distance"])

        df["overhead_norm_recalc"] = minmax(df["pcap_size_bytes"])
        df["compliance_score"] = pd.to_numeric(df["success"], errors="coerce").fillna(0.0)
        df["compliance_penalty"] = np.maximum(0.0, 0.95 - df["compliance_score"])

        if "detector_proxy_probability" not in df.columns:
            df["detector_proxy_probability"] = 1.0

        df["praxis_score_rebaseline"] = (
            0.45 * df["detector_proxy_probability"]
            + 0.35 * df["public_distance_norm"]
            + 0.05 * df["overhead_norm_recalc"]
            + 0.15 * df["compliance_penalty"]
        )

        rows.append(df)

    scored = pd.concat(rows, ignore_index=True)
    scored.to_csv(OUT_SESSION, index=False)

    agg = (
        scored.groupby(["public_baseline", "config_id"])
        .agg(
            n=("session_id", "count"),
            public_baseline_rows=("public_baseline_rows", "first"),
            mean_detector_proxy_probability=("detector_proxy_probability", "mean"),
            mean_public_distance_norm=("public_distance_norm", "mean"),
            mean_overhead_norm=("overhead_norm_recalc", "mean"),
            mean_success=("compliance_score", "mean"),
            mean_score=("praxis_score_rebaseline", "mean"),
            std_score=("praxis_score_rebaseline", "std"),
        )
        .reset_index()
    )

    out_rows = []
    for baseline_name, sub in agg.groupby("public_baseline"):
        base = sub[sub["config_id"] == "baseline_default_off"].iloc[0]

        for _, row in sub.iterrows():
            r = row.to_dict()
            r["score_delta_vs_baseline"] = row["mean_score"] - base["mean_score"]
            r["public_distance_delta_vs_baseline"] = row["mean_public_distance_norm"] - base["mean_public_distance_norm"]
            r["detector_delta_vs_baseline"] = row["mean_detector_proxy_probability"] - base["mean_detector_proxy_probability"]
            out_rows.append(r)

    config = pd.DataFrame(out_rows)
    config = config.sort_values(["public_baseline", "mean_score"])
    config.to_csv(OUT_CONFIG, index=False)

    lines = []
    lines.append("PRAXIS Phase 31 MAWI + CICIDS Public-Baseline Sensitivity")
    lines.append("")
    lines.append("Purpose:")
    lines.append("Test whether public-distance and score conclusions are stable across MAWI and a secondary CICIDS2017 mapped benign baseline.")
    lines.append("")
    lines.append("Baseline source rows:")
    lines.append(f"mawi_day1_rows={len(mawi1)}")
    lines.append(f"mawi_day2_rows={len(mawi2)}")
    lines.append(f"cicids2017_mapped_rows={len(cicids)}")
    lines.append("")
    lines.append("Config winners by public baseline:")

    for baseline_name, sub in config.groupby("public_baseline"):
        winner = sub.sort_values("mean_score").iloc[0]
        dcp1 = sub[sub["config_id"] == "default_c2_p1"].iloc[0]
        lines.append(f"Baseline={baseline_name}")
        lines.append(f"  winner={winner['config_id']}")
        lines.append(f"  winner_score={winner['mean_score']:.6f}")
        lines.append(f"  default_c2_p1_score={dcp1['mean_score']:.6f}")
        lines.append(f"  default_c2_p1_score_delta_vs_baseline={dcp1['score_delta_vs_baseline']:.6f}")
        lines.append(f"  default_c2_p1_public_distance_delta_vs_baseline={dcp1['public_distance_delta_vs_baseline']:.6f}")
        lines.append("")

    lines.append("Interpretation:")
    lines.append("MAWI baselines are primary because they are packet-derived and closest to PRAXIS feature extraction.")
    lines.append("CICIDS2017 is secondary because it is mapped from CICFlowMeter aggregate CSV features.")
    lines.append("If default_c2_p1 remains favorable across MAWI baselines, the public-baseline result is stronger.")
    lines.append("If CICIDS differs, report it as schema-mismatch sensitivity rather than failure.")

    OUT_SUMMARY.write_text("\n".join(lines) + "\n")

    print(OUT_SUMMARY.read_text())


if __name__ == "__main__":
    main()
