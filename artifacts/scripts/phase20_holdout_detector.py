#!/usr/bin/env python3

from pathlib import Path
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score, accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split

PHASE13 = Path("/opt/praxis/solution/features/phase14_sweep_features.csv")
PHASE16 = Path("/opt/praxis/solution/features/phase16_candidate_features.csv")
EVAL = Path("/opt/praxis/solution/features/phase17_confirm_features.csv")
PUBLIC = Path("/opt/praxis/public_data/features/mawi_public_flows_20240302_1m.csv")

OUT_DIR = Path("/opt/praxis/solution/reports")
MODEL_DIR = Path("/opt/praxis/solution/models")

OUT_SUMMARY = OUT_DIR / "phase20_holdout_detector_summary.txt"
OUT_CONFIG = OUT_DIR / "phase20_holdout_detector_config_scores.csv"

FEATURE_COLS = [
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

EVAL_CONFIGS = {
    "baseline_default_off",
    "default_c2_p1",
    "camouflaged_c2_p1",
}


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


def load_inputs():
    for p in [PHASE13, PHASE16, EVAL, PUBLIC]:
        if not p.exists():
            raise SystemExit(f"Missing required input: {p}")

    p13 = pd.read_csv(PHASE13)
    p16 = pd.read_csv(PHASE16)
    eval_df = pd.read_csv(EVAL)
    public = pd.read_csv(PUBLIC)

    return p13, p16, eval_df, public


def make_train_positive(p13, p16, mode):
    pos = pd.concat([p13, p16], ignore_index=True)

    if mode == "strict_unseen":
        # Do not train on any final Phase 17 evaluation config.
        pos = pos[~pos["config_id"].isin(EVAL_CONFIGS)].copy()
    elif mode == "baseline_known":
        # Let the detector know baseline proxy behavior, but do not train on selected winning configs.
        pos = pos[~pos["config_id"].isin({"default_c2_p1", "camouflaged_c2_p1"})].copy()
    else:
        raise ValueError(f"Unknown mode: {mode}")

    pos["label"] = 1
    return pos


def train_and_eval(mode, p13, p16, eval_df, public):
    rng = np.random.default_rng(2020)

    pos = make_train_positive(p13, p16, mode)
    public = public.copy()
    public["label"] = 0

    # Split public benign data so the detector's public FPR is measured on unseen benign flows.
    public_train, public_holdout = train_test_split(
        public,
        test_size=0.30,
        random_state=2020,
        shuffle=True,
    )

    # Use more benign negatives than positives, but do not swamp the model.
    n_neg = min(len(public_train), max(len(pos) * 5, 500))
    public_train = public_train.sample(n=n_neg, random_state=2020)

    train = pd.concat([pos, public_train], ignore_index=True)
    y = train["label"].astype(int).to_numpy()
    X = signed_log_transform(ensure_cols(train, FEATURE_COLS))

    clf = RandomForestClassifier(
        n_estimators=500,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        random_state=2020,
        n_jobs=-1,
    )

    clf.fit(X, y)

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    model_path = MODEL_DIR / f"phase20_holdout_detector_{mode}.joblib"
    joblib.dump(
        {
            "model": clf,
            "feature_cols": FEATURE_COLS,
            "mode": mode,
            "train_positive_count": len(pos),
            "train_negative_count": len(public_train),
        },
        model_path,
    )

    # Public holdout FPR.
    X_pub_holdout = signed_log_transform(ensure_cols(public_holdout, FEATURE_COLS))
    pub_prob = clf.predict_proba(X_pub_holdout)[:, 1]
    public_holdout_fpr_050 = float((pub_prob >= 0.50).mean())

    # Training-set sanity metrics.
    train_prob = clf.predict_proba(X)[:, 1]
    train_pred = (train_prob >= 0.50).astype(int)

    train_metrics = {
        "train_accuracy": accuracy_score(y, train_pred),
        "train_precision": precision_score(y, train_pred, zero_division=0),
        "train_recall": recall_score(y, train_pred, zero_division=0),
        "train_f1": f1_score(y, train_pred, zero_division=0),
        "train_auc": roc_auc_score(y, train_prob),
    }

    # Evaluate Phase 17 confirm-best rows.
    eval_scored = eval_df.copy()
    X_eval = signed_log_transform(ensure_cols(eval_scored, FEATURE_COLS))
    eval_scored[f"holdout_{mode}_proxy_probability"] = clf.predict_proba(X_eval)[:, 1]
    eval_scored[f"holdout_{mode}_proxy_label_050"] = (
        eval_scored[f"holdout_{mode}_proxy_probability"] >= 0.50
    ).astype(int)

    out_session = OUT_DIR / f"phase20_holdout_{mode}_session_scores.csv"
    eval_scored.to_csv(out_session, index=False)

    agg = (
        eval_scored.groupby("config_id")
        .agg(
            n=("session_id", "count"),
            mean_holdout_proxy_probability=(f"holdout_{mode}_proxy_probability", "mean"),
            std_holdout_proxy_probability=(f"holdout_{mode}_proxy_probability", "std"),
            detection_rate_050=(f"holdout_{mode}_proxy_label_050", "mean"),
            mean_success=("success", "mean"),
            mean_pcap_size_bytes=("pcap_size_bytes", "mean"),
            mean_packet_count=("packet_count", "mean"),
            mean_burst_count=("burst_count", "mean"),
        )
        .reset_index()
    )

    baseline = agg[agg["config_id"] == "baseline_default_off"].iloc[0]
    agg[f"prob_delta_vs_baseline_{mode}"] = (
        agg["mean_holdout_proxy_probability"] - baseline["mean_holdout_proxy_probability"]
    )

    agg["mode"] = mode

    return {
        "mode": mode,
        "model_path": str(model_path),
        "out_session": str(out_session),
        "agg": agg,
        "train_positive_count": len(pos),
        "train_negative_count": len(public_train),
        "public_holdout_count": len(public_holdout),
        "public_holdout_fpr_050": public_holdout_fpr_050,
        **train_metrics,
    }


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    p13, p16, eval_df, public = load_inputs()

    results = []
    all_aggs = []

    for mode in ["strict_unseen", "baseline_known"]:
        r = train_and_eval(mode, p13, p16, eval_df, public)
        results.append(r)
        all_aggs.append(r["agg"])

    combined = pd.concat(all_aggs, ignore_index=True)
    combined.to_csv(OUT_CONFIG, index=False)

    lines = []
    lines.append("PRAXIS Phase 20 Holdout Detector Robustness Summary")
    lines.append("")
    lines.append("Purpose:")
    lines.append("Train fresh holdout detectors using Phase 13/16 proxy sessions and the second MAWI public-benign baseline, then evaluate Phase 17 confirm-best sessions.")
    lines.append("")
    lines.append("Inputs:")
    lines.append(f"phase13_features={PHASE13}")
    lines.append(f"phase16_features={PHASE16}")
    lines.append(f"phase17_eval_features={EVAL}")
    lines.append(f"public_benign_mawi2={PUBLIC}")
    lines.append("")
    lines.append("Feature policy:")
    lines.append("pcap_size_bytes is excluded from the holdout detector to reduce public/lab size leakage.")
    lines.append("Features use signed log transform.")
    lines.append("")

    for r in results:
        mode = r["mode"]
        lines.append(f"Detector mode: {mode}")
        lines.append(f"model_path={r['model_path']}")
        lines.append(f"train_positive_count={r['train_positive_count']}")
        lines.append(f"train_negative_count={r['train_negative_count']}")
        lines.append(f"public_holdout_count={r['public_holdout_count']}")
        lines.append(f"public_holdout_fpr_at_0.50={r['public_holdout_fpr_050']:.6f}")
        lines.append(f"train_accuracy={r['train_accuracy']:.6f}")
        lines.append(f"train_precision={r['train_precision']:.6f}")
        lines.append(f"train_recall={r['train_recall']:.6f}")
        lines.append(f"train_f1={r['train_f1']:.6f}")
        lines.append(f"train_auc={r['train_auc']:.6f}")
        lines.append("")

        agg = r["agg"].sort_values("mean_holdout_proxy_probability")
        base = agg[agg["config_id"] == "baseline_default_off"].iloc[0]

        lines.append(f"Phase 17 evaluation under {mode}:")
        lines.append(f"baseline_mean_probability={base['mean_holdout_proxy_probability']:.6f}")
        for _, row in agg.iterrows():
            lines.append(
                f"{row['config_id']}: "
                f"n={int(row['n'])}, "
                f"mean_probability={row['mean_holdout_proxy_probability']:.6f}, "
                f"delta_vs_baseline={row[f'prob_delta_vs_baseline_{mode}']:.6f}, "
                f"detection_rate_050={row['detection_rate_050']:.6f}, "
                f"mean_success={row['mean_success']:.6f}"
            )

        best = agg.iloc[0]
        lines.append(f"best_under_{mode}={best['config_id']}")
        lines.append("")

    lines.append("Interpretation rule:")
    lines.append("- If default_c2_p1 remains below baseline under both detectors, Phase 17 result is robust to fresh holdout detectors.")
    lines.append("- If only baseline_known shows reduction, the result is robust when baseline proxy behavior is known but selected config is unseen.")
    lines.append("- If neither shows reduction, the Phase 17 result is detector-specific and should be reported with that limitation.")
    lines.append("- Public holdout FPR should be inspected before making strong claims.")

    OUT_SUMMARY.write_text("\n".join(lines) + "\n")
    print(OUT_SUMMARY.read_text())
    print(f"Wrote {OUT_CONFIG}")


if __name__ == "__main__":
    main()
