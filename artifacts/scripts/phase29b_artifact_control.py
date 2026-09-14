#!/usr/bin/env python3

from pathlib import Path
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score, accuracy_score
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

IN = Path("/opt/praxis/solution/reports/phase17_confirm_session_scores.csv")
OUT_DIR = Path("/opt/praxis/solution/reports/phase29b")
OUT_CSV = OUT_DIR / "phase29b_artifact_control_scores.csv"
OUT_SUMMARY = OUT_DIR / "phase29b_artifact_control_summary.txt"

BASELINE = "baseline_default_off"
BEST = "default_c2_p1"

ALL = [
    "pcap_size_bytes",
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

FEATURE_SETS = {
    "all_no_pcap_size": [f for f in ALL if f != "pcap_size_bytes"],
    "no_duration": [f for f in ALL if f not in {"pcap_size_bytes", "flow_duration_seconds"}],
    "no_packet_counts": [f for f in ALL if f not in {"pcap_size_bytes", "packet_count", "out_packets", "in_packets", "unknown_packets"}],
    "no_duration_no_counts": [f for f in ALL if f not in {"pcap_size_bytes", "flow_duration_seconds", "packet_count", "out_packets", "in_packets", "unknown_packets"}],
    "payload_only": ["out_payload_bytes", "in_payload_bytes", "total_payload_bytes"],
    "burst_only": ["burst_count"],
    "signed_lengths_only": [f"len_{i}" for i in range(1, 21)],
    "signed_lengths_no_6": [f"len_{i}" for i in range(1, 21) if i != 6],
}


def ensure_cols(df, cols):
    out = pd.DataFrame(index=df.index)
    for c in cols:
        if c in df.columns:
            out[c] = pd.to_numeric(df[c], errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0.0)
        else:
            out[c] = 0.0
    return out


def signed_log(df):
    x = df.copy().astype(float)
    for c in x.columns:
        x[c] = np.sign(x[c]) * np.log1p(np.abs(x[c]))
    return x


def model_specs():
    return {
        "logistic": Pipeline([
            ("scale", StandardScaler()),
            ("clf", LogisticRegression(max_iter=5000, class_weight="balanced", random_state=2929)),
        ]),
        "random_forest": RandomForestClassifier(
            n_estimators=500,
            min_samples_leaf=2,
            class_weight="balanced_subsample",
            random_state=2930,
            n_jobs=-1,
        ),
    }


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(IN)
    df = df[df["config_id"].isin([BASELINE, BEST])].copy()
    df["label"] = (df["config_id"] == BEST).astype(int)

    y = df["label"].to_numpy()
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=2931)

    rows = []

    for feature_set, cols in FEATURE_SETS.items():
        X = signed_log(ensure_cols(df, cols))

        for model_name, model in model_specs().items():
            prob = cross_val_predict(model, X, y, cv=cv, method="predict_proba")[:, 1]
            pred = (prob >= 0.5).astype(int)

            rows.append({
                "feature_set": feature_set,
                "model": model_name,
                "n_features": len(cols),
                "auc": roc_auc_score(y, prob),
                "accuracy_050": accuracy_score(y, pred),
                "baseline_mean_probability": float(prob[y == 0].mean()),
                "default_c2_p1_mean_probability": float(prob[y == 1].mean()),
                "delta_default_vs_baseline": float(prob[y == 1].mean() - prob[y == 0].mean()),
            })

    out = pd.DataFrame(rows).sort_values(["auc", "accuracy_050"], ascending=[False, False])
    out.to_csv(OUT_CSV, index=False)

    lines = []
    lines.append("PRAXIS Phase 29B Artifact-Control Mechanism Check")
    lines.append("")
    lines.append("Purpose:")
    lines.append("Check whether default_c2_p1 remains distinguishable after removing obvious separator features.")
    lines.append("")
    lines.append("Results:")
    for _, r in out.iterrows():
        lines.append(
            f"{r['feature_set']} / {r['model']}: "
            f"n_features={int(r['n_features'])}, "
            f"auc={r['auc']:.6f}, "
            f"accuracy_050={r['accuracy_050']:.6f}, "
            f"baseline_mean={r['baseline_mean_probability']:.6f}, "
            f"default_c2_p1_mean={r['default_c2_p1_mean_probability']:.6f}, "
            f"delta={r['delta_default_vs_baseline']:.6f}"
        )

    lines.append("")
    lines.append("Interpretation guide:")
    lines.append("- If no_duration and no_duration_no_counts remain high, the mechanism is not only session duration.")
    lines.append("- If payload_only or signed_lengths_only remain high, the mechanism includes payload balance or packet-shape effects.")
    lines.append("- If only duration/count features work, describe the mechanism as duration/count compression rather than broad camouflage.")
    lines.append("- This remains a lab mechanism explanation, not universal causality.")

    OUT_SUMMARY.write_text("\n".join(lines) + "\n")

    print(OUT_SUMMARY.read_text())
    print(f"Wrote {OUT_CSV}")


if __name__ == "__main__":
    main()
