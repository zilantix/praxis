#!/usr/bin/env python3

from pathlib import Path
import numpy as np
import pandas as pd
import joblib

from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import ExtraTreesClassifier, GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score, accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC

PHASE13 = Path("/opt/praxis/solution/features/phase14_sweep_features.csv")
PHASE16 = Path("/opt/praxis/solution/features/phase16_candidate_features.csv")
EVAL = Path("/opt/praxis/solution/features/phase17_confirm_features.csv")
PUBLIC1 = Path("/opt/praxis/public_data/features/mawi_public_flows_active.csv")
PUBLIC2 = Path("/opt/praxis/public_data/features/mawi_public_flows_20240302_1m.csv")

OUT = Path("/opt/praxis/solution/reports/phase30")
MODEL_DIR = Path("/opt/praxis/solution/models/phase30")

FEATURES = [
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
    out = pd.DataFrame(index=df.index)
    for c in cols:
        if c in df.columns:
            out[c] = (
                pd.to_numeric(df[c], errors="coerce")
                .replace([np.inf, -np.inf], np.nan)
                .fillna(0.0)
            )
        else:
            out[c] = 0.0
    return out


def signed_log(df):
    x = ensure_cols(df, FEATURES).astype(float)
    for c in x.columns:
        x[c] = np.sign(x[c]) * np.log1p(np.abs(x[c]))
    return x


def bootstrap_ci_delta(a, b, n_boot=10000, seed=3001):
    rng = np.random.default_rng(seed)
    a = np.asarray(a, dtype=float)
    b = np.asarray(b, dtype=float)
    vals = []
    for _ in range(n_boot):
        vals.append(
            rng.choice(b, len(b), replace=True).mean()
            - rng.choice(a, len(a), replace=True).mean()
        )
    return np.percentile(vals, [2.5, 97.5])


def permutation_pvalue(a, b, n_perm=10000, seed=3002):
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

    return (count + 1) / (n_perm + 1)


def load_data():
    for p in [PHASE13, PHASE16, EVAL, PUBLIC1, PUBLIC2]:
        if not p.exists():
            raise SystemExit(f"Missing required input: {p}")

    p13 = pd.read_csv(PHASE13)
    p16 = pd.read_csv(PHASE16)
    eval_df = pd.read_csv(EVAL)

    public = pd.concat([pd.read_csv(PUBLIC1), pd.read_csv(PUBLIC2)], ignore_index=True)
    public["label"] = 0

    pos = pd.concat([p13, p16], ignore_index=True)

    # Exclude Phase 17 evaluation configs from training to avoid direct train/test leakage.
    pos = pos[~pos["config_id"].isin(EVAL_CONFIGS)].copy()
    pos["label"] = 1

    return pos, public, eval_df


def model_specs():
    return {
        "logistic": Pipeline([
            ("scale", StandardScaler()),
            ("clf", LogisticRegression(max_iter=5000, class_weight="balanced", random_state=3010)),
        ]),
        "random_forest": RandomForestClassifier(
            n_estimators=500,
            min_samples_leaf=2,
            class_weight="balanced_subsample",
            random_state=3011,
            n_jobs=-1,
        ),
        "extra_trees": ExtraTreesClassifier(
            n_estimators=500,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=3012,
            n_jobs=-1,
        ),
        "gradient_boosting": GradientBoostingClassifier(random_state=3013),
        "linear_svc_calibrated": Pipeline([
            ("scale", StandardScaler()),
            ("clf", CalibratedClassifierCV(
                LinearSVC(class_weight="balanced", random_state=3014, max_iter=20000),
                cv=3,
            )),
        ]),
    }


def predict_prob(model, X):
    p = model.predict_proba(X)
    return p[:, 1] if p.ndim == 2 and p.shape[1] > 1 else p.ravel()


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    pos, public, eval_df = load_data()

    public_train, public_holdout = train_test_split(
        public,
        test_size=0.30,
        random_state=3020,
        shuffle=True,
    )

    n_neg = min(len(public_train), max(len(pos) * 5, 1000))
    public_train = public_train.sample(n=n_neg, random_state=3021)

    train = pd.concat([pos, public_train], ignore_index=True)

    X_train = signed_log(train)
    y_train = train["label"].astype(int).to_numpy()

    X_eval = signed_log(eval_df)
    X_public_holdout = signed_log(public_holdout)

    session_rows = []
    config_rows = []
    stat_rows = []
    train_rows = []

    for model_name, model in model_specs().items():
        print(f"Training {model_name}")

        model.fit(X_train, y_train)

        joblib.dump(
            {
                "model": model,
                "feature_cols": FEATURES,
                "model_name": model_name,
                "train_positive_count": int((y_train == 1).sum()),
                "train_negative_count": int((y_train == 0).sum()),
            },
            MODEL_DIR / f"phase30_{model_name}.joblib",
        )

        train_prob = predict_prob(model, X_train)
        train_pred = (train_prob >= 0.50).astype(int)

        public_prob = predict_prob(model, X_public_holdout)
        public_fpr_050 = float((public_prob >= 0.50).mean())

        train_rows.append({
            "model_name": model_name,
            "train_positive_count": int((y_train == 1).sum()),
            "train_negative_count": int((y_train == 0).sum()),
            "train_accuracy": accuracy_score(y_train, train_pred),
            "train_precision": precision_score(y_train, train_pred, zero_division=0),
            "train_recall": recall_score(y_train, train_pred, zero_division=0),
            "train_f1": f1_score(y_train, train_pred, zero_division=0),
            "train_auc": roc_auc_score(y_train, train_prob),
            "public_holdout_count": len(public_holdout),
            "public_fpr_050": public_fpr_050,
        })

        scored = eval_df.copy()
        scored["model_name"] = model_name
        scored["multidetector_proxy_probability"] = predict_prob(model, X_eval)
        scored["multidetector_label_050"] = (
            scored["multidetector_proxy_probability"] >= 0.50
        ).astype(int)
        session_rows.append(scored)

        agg = (
            scored.groupby("config_id")
            .agg(
                n=("session_id", "count"),
                mean_probability=("multidetector_proxy_probability", "mean"),
                std_probability=("multidetector_proxy_probability", "std"),
                detection_rate_050=("multidetector_label_050", "mean"),
                mean_success=("success", "mean"),
            )
            .reset_index()
        )

        base = agg[agg["config_id"] == "baseline_default_off"].iloc[0]
        agg["model_name"] = model_name
        agg["delta_vs_baseline"] = agg["mean_probability"] - base["mean_probability"]
        agg["public_fpr_050"] = public_fpr_050
        config_rows.append(agg)

        base_probs = scored[
            scored["config_id"] == "baseline_default_off"
        ]["multidetector_proxy_probability"].to_numpy()

        for cfg in ["default_c2_p1", "camouflaged_c2_p1"]:
            cand_probs = scored[
                scored["config_id"] == cfg
            ]["multidetector_proxy_probability"].to_numpy()

            delta = cand_probs.mean() - base_probs.mean()
            pct = np.nan if abs(base_probs.mean()) < 1e-12 else 100.0 * delta / base_probs.mean()
            ci_lo, ci_hi = bootstrap_ci_delta(base_probs, cand_probs)
            p = permutation_pvalue(base_probs, cand_probs)

            stat_rows.append({
                "model_name": model_name,
                "config_id": cfg,
                "baseline_mean": base_probs.mean(),
                "candidate_mean": cand_probs.mean(),
                "delta": delta,
                "pct_delta": pct,
                "bootstrap_95ci_low": ci_lo,
                "bootstrap_95ci_high": ci_hi,
                "permutation_p_two_sided": p,
            })

    session = pd.concat(session_rows, ignore_index=True)
    config = pd.concat(config_rows, ignore_index=True)
    stats = pd.DataFrame(stat_rows)
    train_metrics = pd.DataFrame(train_rows)

    session.to_csv(OUT / "phase30_multidetector_session_scores.csv", index=False)
    config.to_csv(OUT / "phase30_multidetector_config_scores.csv", index=False)
    stats.to_csv(OUT / "phase30_multidetector_statistics.csv", index=False)
    train_metrics.to_csv(OUT / "phase30_multidetector_train_metrics.csv", index=False)

    lines = []
    lines.append("PRAXIS Phase 30 Multi-Detector Robustness")
    lines.append("")
    lines.append("Purpose:")
    lines.append("Evaluate whether default_c2_p1 remains lower-confidence than baseline across multiple detector families.")
    lines.append("")
    lines.append("Training:")
    lines.append(f"positive_proxy_sessions={int((y_train == 1).sum())}")
    lines.append(f"negative_public_sessions={int((y_train == 0).sum())}")
    lines.append("public_negatives=MAWI active + MAWI 2024-03-02")
    lines.append("phase17_confirm_sessions_excluded_from_training=true")
    lines.append("")
    lines.append("Detector training/holdout summary:")

    for _, r in train_metrics.iterrows():
        lines.append(
            f"- {r['model_name']}: train_auc={r['train_auc']:.6f}, "
            f"train_f1={r['train_f1']:.6f}, "
            f"public_fpr_050={r['public_fpr_050']:.6f}"
        )

    lines.append("")
    lines.append("Phase 17 evaluation by detector:")

    for model_name in sorted(config["model_name"].unique()):
        sub = config[config["model_name"] == model_name].sort_values("mean_probability")
        lines.append(f"Detector={model_name}")
        for _, r in sub.iterrows():
            lines.append(
                f"  {r['config_id']}: mean_probability={r['mean_probability']:.6f}, "
                f"delta_vs_baseline={r['delta_vs_baseline']:.6f}, "
                f"detection_rate_050={r['detection_rate_050']:.6f}, "
                f"n={int(r['n'])}"
            )

    lines.append("")
    lines.append("Statistical validation:")
    for _, r in stats.iterrows():
        lines.append(
            f"- {r['model_name']} {r['config_id']}: "
            f"baseline_mean={r['baseline_mean']:.6f}, "
            f"candidate_mean={r['candidate_mean']:.6f}, "
            f"delta={r['delta']:.6f}, "
            f"pct_delta={r['pct_delta']:.2f}%, "
            f"ci=[{r['bootstrap_95ci_low']:.6f},{r['bootstrap_95ci_high']:.6f}], "
            f"p={r['permutation_p_two_sided']:.6f}"
        )

    lines.append("")
    lines.append("Interpretation:")
    lines.append("If default_c2_p1 remains below baseline across detector families, this strengthens the PRAXIS robustness claim.")
    lines.append("If binary detection_rate_050 remains 1.0, claim confidence reduction, not complete detector bypass.")

    (OUT / "phase30_multidetector_summary.txt").write_text("\n".join(lines) + "\n")

    print((OUT / "phase30_multidetector_summary.txt").read_text())


if __name__ == "__main__":
    main()
