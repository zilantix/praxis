#!/usr/bin/env python3

from pathlib import Path
import warnings
import numpy as np
import pandas as pd

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score, accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

try:
    from scipy.stats import mannwhitneyu
    HAVE_SCIPY = True
except Exception:
    HAVE_SCIPY = False


BASE = Path("/opt/praxis")
IN = BASE / "solution/reports/phase17_confirm_session_scores.csv"
OUT = BASE / "solution/reports/phase29"
FIG = OUT / "figures"

BASELINE = "baseline_default_off"
BEST = "default_c2_p1"
CAMO = "camouflaged_c2_p1"

FEATURES = [
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

FEATURES_NO_SIZE = [f for f in FEATURES if f != "pcap_size_bytes"]

FEATURE_GROUPS = {
    "all_no_pcap_size": FEATURES_NO_SIZE,
    "packet_counts_direction": [
        "packet_count",
        "out_packets",
        "in_packets",
        "unknown_packets",
        "burst_count",
    ],
    "payload_duration": [
        "out_payload_bytes",
        "in_payload_bytes",
        "total_payload_bytes",
        "flow_duration_seconds",
    ],
    "signed_lengths_all": [f"len_{i}" for i in range(1, 21)],
    "signed_lengths_1_to_5": [f"len_{i}" for i in range(1, 6)],
    "signed_lengths_6_to_20": [f"len_{i}" for i in range(6, 21)],
    "burst_only": ["burst_count"],
}


def safe_series(df: pd.DataFrame, col: str) -> pd.Series:
    if col not in df.columns:
        return pd.Series([0.0] * len(df), index=df.index)
    return (
        pd.to_numeric(df[col], errors="coerce")
        .replace([np.inf, -np.inf], np.nan)
        .fillna(0.0)
        .astype(float)
    )


def ensure_cols(df: pd.DataFrame, cols) -> pd.DataFrame:
    out = pd.DataFrame(index=df.index)
    for c in cols:
        out[c] = safe_series(df, c)
    return out


def signed_log_df(df: pd.DataFrame) -> pd.DataFrame:
    x = df.copy().astype(float)
    for c in x.columns:
        x[c] = np.sign(x[c]) * np.log1p(np.abs(x[c]))
    return x


def cohen_d(a, b) -> float:
    a = np.asarray(a, dtype=float)
    b = np.asarray(b, dtype=float)
    if len(a) < 2 or len(b) < 2:
        return 0.0

    va = np.var(a, ddof=1)
    vb = np.var(b, ddof=1)
    pooled = np.sqrt(((len(a) - 1) * va + (len(b) - 1) * vb) / max(len(a) + len(b) - 2, 1))

    if pooled == 0 or not np.isfinite(pooled):
        return 0.0

    return float((np.mean(b) - np.mean(a)) / pooled)


def bootstrap_ci_delta(a, b, n_boot=5000, seed=2901):
    rng = np.random.default_rng(seed)
    a = np.asarray(a, dtype=float)
    b = np.asarray(b, dtype=float)

    if len(a) == 0 or len(b) == 0:
        return np.nan, np.nan

    vals = []
    for _ in range(n_boot):
        aa = rng.choice(a, size=len(a), replace=True)
        bb = rng.choice(b, size=len(b), replace=True)
        vals.append(bb.mean() - aa.mean())

    lo, hi = np.percentile(vals, [2.5, 97.5])
    return float(lo), float(hi)


def mw_pvalue(a, b):
    if not HAVE_SCIPY:
        return np.nan
    try:
        return float(mannwhitneyu(a, b, alternative="two-sided").pvalue)
    except Exception:
        return np.nan


def feature_delta_report(df: pd.DataFrame) -> pd.DataFrame:
    rows = []

    base = df[df["config_id"] == BASELINE]
    candidates = [BEST, CAMO]

    for candidate in candidates:
        cand = df[df["config_id"] == candidate]

        for f in FEATURES:
            a = safe_series(base, f).to_numpy()
            b = safe_series(cand, f).to_numpy()

            base_mean = float(np.mean(a)) if len(a) else 0.0
            cand_mean = float(np.mean(b)) if len(b) else 0.0
            delta = cand_mean - base_mean
            pct = np.nan if abs(base_mean) < 1e-12 else 100.0 * delta / base_mean
            ci_lo, ci_hi = bootstrap_ci_delta(a, b)
            d = cohen_d(a, b)
            p = mw_pvalue(a, b)

            rows.append({
                "candidate": candidate,
                "feature": f,
                "baseline_mean": base_mean,
                "candidate_mean": cand_mean,
                "delta": delta,
                "pct_delta": pct,
                "bootstrap_95ci_low": ci_lo,
                "bootstrap_95ci_high": ci_hi,
                "cohen_d": d,
                "abs_cohen_d": abs(d),
                "mannwhitney_p_two_sided": p,
            })

    out = pd.DataFrame(rows)
    out = out.sort_values(["candidate", "abs_cohen_d"], ascending=[True, False])
    return out


def train_binary_mechanism_models(df: pd.DataFrame):
    sub = df[df["config_id"].isin([BASELINE, BEST])].copy()
    sub["label"] = (sub["config_id"] == BEST).astype(int)

    X_raw = ensure_cols(sub, FEATURES_NO_SIZE)
    X = signed_log_df(X_raw)
    y = sub["label"].to_numpy()

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.30,
        random_state=2902,
        stratify=y,
    )

    logit = Pipeline([
        ("scale", StandardScaler()),
        ("clf", LogisticRegression(max_iter=5000, class_weight="balanced", random_state=2903)),
    ])

    rf = RandomForestClassifier(
        n_estimators=600,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        random_state=2904,
        n_jobs=-1,
    )

    logit.fit(X_train, y_train)
    rf.fit(X_train, y_train)

    logit_prob = logit.predict_proba(X_test)[:, 1]
    rf_prob = rf.predict_proba(X_test)[:, 1]

    metrics = {
        "n_rows": int(len(sub)),
        "n_baseline": int((sub["config_id"] == BASELINE).sum()),
        "n_default_c2_p1": int((sub["config_id"] == BEST).sum()),
        "logistic_auc": float(roc_auc_score(y_test, logit_prob)),
        "random_forest_auc": float(roc_auc_score(y_test, rf_prob)),
        "logistic_accuracy_050": float(accuracy_score(y_test, (logit_prob >= 0.5).astype(int))),
        "random_forest_accuracy_050": float(accuracy_score(y_test, (rf_prob >= 0.5).astype(int))),
    }

    logit_clf = logit.named_steps["clf"]
    logit_coef = np.ravel(logit_clf.coef_)

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        perm = permutation_importance(
            rf,
            X_test,
            y_test,
            n_repeats=100,
            random_state=2905,
            n_jobs=-1,
        )

    importance_rows = []
    for i, f in enumerate(FEATURES_NO_SIZE):
        importance_rows.append({
            "feature": f,
            "logistic_coef": float(logit_coef[i]),
            "logistic_abs_coef": float(abs(logit_coef[i])),
            "rf_feature_importance": float(rf.feature_importances_[i]),
            "rf_permutation_importance_mean": float(perm.importances_mean[i]),
            "rf_permutation_importance_std": float(perm.importances_std[i]),
        })

    importance = pd.DataFrame(importance_rows)
    importance = importance.sort_values("rf_permutation_importance_mean", ascending=False)

    return metrics, importance


def train_feature_group_ablation(df: pd.DataFrame) -> pd.DataFrame:
    sub = df[df["config_id"].isin([BASELINE, BEST])].copy()
    sub["label"] = (sub["config_id"] == BEST).astype(int)

    y = sub["label"].to_numpy()
    rows = []

    for group_name, cols in FEATURE_GROUPS.items():
        X_raw = ensure_cols(sub, cols)
        X = signed_log_df(X_raw)

        X_train, X_test, y_train, y_test = train_test_split(
            X,
            y,
            test_size=0.30,
            random_state=2910,
            stratify=y,
        )

        logit = Pipeline([
            ("scale", StandardScaler()),
            ("clf", LogisticRegression(max_iter=5000, class_weight="balanced", random_state=2911)),
        ])

        rf = RandomForestClassifier(
            n_estimators=500,
            min_samples_leaf=2,
            class_weight="balanced_subsample",
            random_state=2912,
            n_jobs=-1,
        )

        logit.fit(X_train, y_train)
        rf.fit(X_train, y_train)

        logit_prob = logit.predict_proba(X_test)[:, 1]
        rf_prob = rf.predict_proba(X_test)[:, 1]

        rows.append({
            "feature_group": group_name,
            "n_features": len(cols),
            "logistic_auc": float(roc_auc_score(y_test, logit_prob)),
            "random_forest_auc": float(roc_auc_score(y_test, rf_prob)),
            "logistic_accuracy_050": float(accuracy_score(y_test, (logit_prob >= 0.5).astype(int))),
            "random_forest_accuracy_050": float(accuracy_score(y_test, (rf_prob >= 0.5).astype(int))),
        })

    return pd.DataFrame(rows).sort_values("random_forest_auc", ascending=False)


def make_figures(delta: pd.DataFrame, importance: pd.DataFrame, ablation: pd.DataFrame):
    FIG.mkdir(parents=True, exist_ok=True)

    # Figure 1: top effect sizes.
    top = (
        delta[delta["candidate"] == BEST]
        .sort_values("abs_cohen_d", ascending=False)
        .head(15)
        .iloc[::-1]
    )

    plt.figure(figsize=(10, 7))
    plt.barh(top["feature"], top["abs_cohen_d"])
    plt.title("Phase 29: Top feature effect sizes, default_c2_p1 vs baseline")
    plt.xlabel("Absolute Cohen's d")
    plt.tight_layout()
    plt.savefig(FIG / "phase29_top_feature_effect_sizes.png", dpi=200)
    plt.close()

    # Figure 2: permutation importances.
    top_imp = importance.sort_values("rf_permutation_importance_mean", ascending=False).head(15).iloc[::-1]

    plt.figure(figsize=(10, 7))
    plt.barh(top_imp["feature"], top_imp["rf_permutation_importance_mean"])
    plt.title("Phase 29: Random-forest permutation importance")
    plt.xlabel("Permutation importance")
    plt.tight_layout()
    plt.savefig(FIG / "phase29_rf_permutation_importance.png", dpi=200)
    plt.close()

    # Figure 3: ablation AUC.
    ab = ablation.sort_values("random_forest_auc", ascending=True)

    plt.figure(figsize=(10, 6))
    plt.barh(ab["feature_group"], ab["random_forest_auc"])
    plt.title("Phase 29: Feature-group ablation AUC")
    plt.xlabel("Random-forest AUC")
    plt.tight_layout()
    plt.savefig(FIG / "phase29_feature_group_ablation_auc.png", dpi=200)
    plt.close()


def write_summary(delta: pd.DataFrame, metrics: dict, importance: pd.DataFrame, ablation: pd.DataFrame):
    lines = []
    lines.append("PRAXIS Phase 29 Mechanism Analysis")
    lines.append("")
    lines.append("Purpose:")
    lines.append("Explain why default_c2_p1 reduced detector confidence relative to baseline_default_off.")
    lines.append("")
    lines.append("Input:")
    lines.append(f"- {IN}")
    lines.append("")
    lines.append("Compared configurations:")
    lines.append(f"- baseline: {BASELINE}")
    lines.append(f"- best confirmed: {BEST}")
    lines.append(f"- camouflage comparison: {CAMO}")
    lines.append("")
    lines.append("Binary mechanism model: baseline_default_off vs default_c2_p1")
    lines.append(f"n_rows={metrics['n_rows']}")
    lines.append(f"n_baseline={metrics['n_baseline']}")
    lines.append(f"n_default_c2_p1={metrics['n_default_c2_p1']}")
    lines.append(f"logistic_auc={metrics['logistic_auc']:.6f}")
    lines.append(f"random_forest_auc={metrics['random_forest_auc']:.6f}")
    lines.append(f"logistic_accuracy_050={metrics['logistic_accuracy_050']:.6f}")
    lines.append(f"random_forest_accuracy_050={metrics['random_forest_accuracy_050']:.6f}")
    lines.append("")
    lines.append("Top feature deltas for default_c2_p1 vs baseline by absolute Cohen's d:")

    top_delta = (
        delta[delta["candidate"] == BEST]
        .sort_values("abs_cohen_d", ascending=False)
        .head(15)
    )

    for _, r in top_delta.iterrows():
        lines.append(
            f"- {r['feature']}: baseline_mean={r['baseline_mean']:.6f}, "
            f"default_c2_p1_mean={r['candidate_mean']:.6f}, "
            f"delta={r['delta']:.6f}, "
            f"pct_delta={r['pct_delta']:.2f}%, "
            f"cohen_d={r['cohen_d']:.6f}, "
            f"p={r['mannwhitney_p_two_sided']:.6f}"
        )

    lines.append("")
    lines.append("Top random-forest permutation-importance features:")

    for _, r in importance.head(15).iterrows():
        lines.append(
            f"- {r['feature']}: permutation_importance={r['rf_permutation_importance_mean']:.6f}, "
            f"rf_importance={r['rf_feature_importance']:.6f}, "
            f"logistic_coef={r['logistic_coef']:.6f}"
        )

    lines.append("")
    lines.append("Feature-group ablation:")

    for _, r in ablation.iterrows():
        lines.append(
            f"- {r['feature_group']}: n_features={int(r['n_features'])}, "
            f"logistic_auc={r['logistic_auc']:.6f}, "
            f"random_forest_auc={r['random_forest_auc']:.6f}"
        )

    lines.append("")
    lines.append("Mechanism interpretation:")
    lines.append("Phase 29 identifies which observable flow-shape features distinguish default_c2_p1 from baseline_default_off.")
    lines.append("If burst, direction, payload-balance, or signed-length features dominate, the result supports the interpretation that c2 multiplexing with parallel=1 changed traffic shape in a way that reduced detector confidence.")
    lines.append("This supports RQ2 but does not prove universal causality across all proxy systems or all detectors.")
    lines.append("")
    lines.append("Claim boundary:")
    lines.append("This is a mechanism explanation for the PRAXIS lab result. It is not a claim of complete detector bypass or real-world censorship evasion.")

    (OUT / "phase29_mechanism_summary.txt").write_text("\n".join(lines) + "\n")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    FIG.mkdir(parents=True, exist_ok=True)

    if not IN.exists():
        raise SystemExit(f"Missing input: {IN}")

    df = pd.read_csv(IN)

    required_configs = {BASELINE, BEST, CAMO}
    present = set(df["config_id"].astype(str))
    missing = required_configs - present
    if missing:
        raise SystemExit(f"Missing required configs in {IN}: {missing}")

    delta = feature_delta_report(df)
    metrics, importance = train_binary_mechanism_models(df)
    ablation = train_feature_group_ablation(df)

    delta.to_csv(OUT / "phase29_feature_delta_effect_sizes.csv", index=False)
    importance.to_csv(OUT / "phase29_feature_importance.csv", index=False)
    ablation.to_csv(OUT / "phase29_feature_group_ablation.csv", index=False)

    make_figures(delta, importance, ablation)
    write_summary(delta, metrics, importance, ablation)

    print((OUT / "phase29_mechanism_summary.txt").read_text())
    print()
    print("Wrote:")
    print(f"- {OUT / 'phase29_feature_delta_effect_sizes.csv'}")
    print(f"- {OUT / 'phase29_feature_importance.csv'}")
    print(f"- {OUT / 'phase29_feature_group_ablation.csv'}")
    print(f"- {OUT / 'phase29_mechanism_summary.txt'}")
    print(f"- {FIG / 'phase29_top_feature_effect_sizes.png'}")
    print(f"- {FIG / 'phase29_rf_permutation_importance.png'}")
    print(f"- {FIG / 'phase29_feature_group_ablation_auc.png'}")


if __name__ == "__main__":
    main()
