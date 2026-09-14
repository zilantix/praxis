#!/usr/bin/env python3

from pathlib import Path
import hashlib
import math
import numpy as np
import pandas as pd

try:
    from scipy import stats
    HAVE_SCIPY = True
except Exception:
    HAVE_SCIPY = False


BASE = Path("/opt/praxis")
OUT = BASE / "solution/reports/phase34_inferential_statistics"
TABLES = OUT / "tables"
MANIFESTS = OUT / "manifests"

OUT.mkdir(parents=True, exist_ok=True)
TABLES.mkdir(parents=True, exist_ok=True)
MANIFESTS.mkdir(parents=True, exist_ok=True)

PHASE17_SESSION = BASE / "solution/reports/phase17_confirm_session_scores.csv"
PHASE17_CONFIG = BASE / "solution/reports/phase17_confirm_config_scores.csv"

PHASE20_STRICT = BASE / "solution/reports/phase20_holdout_strict_unseen_session_scores.csv"
PHASE20_KNOWN = BASE / "solution/reports/phase20_holdout_baseline_known_session_scores.csv"

PHASE20B = BASE / "solution/reports/phase20b_threshold_validation.csv"
PHASE21 = BASE / "solution/sweep/phase21_rq3_curl_catalog.csv"

PHASE29B = BASE / "solution/reports/phase29b/phase29b_artifact_control_scores.csv"
PHASE30_STATS = BASE / "solution/reports/phase30/phase30_multidetector_statistics.csv"
PHASE30_CONFIG = BASE / "solution/reports/phase30/phase30_multidetector_config_scores.csv"
PHASE31_CONFIG = BASE / "solution/reports/phase31/phase31_mawi_cicids_rescored_configs.csv"

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


def read_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame()
    return pd.read_csv(path)


def find_col(df: pd.DataFrame, candidates):
    for c in candidates:
        if c in df.columns:
            return c
    return None


def numeric(s):
    return pd.to_numeric(s, errors="coerce").replace([np.inf, -np.inf], np.nan).dropna().astype(float)


def bootstrap_ci_delta(a, b, n_boot=10000, seed=3401):
    rng = np.random.default_rng(seed)
    a = np.asarray(a, dtype=float)
    b = np.asarray(b, dtype=float)

    if len(a) == 0 or len(b) == 0:
        return np.nan, np.nan

    vals = np.empty(n_boot, dtype=float)
    for i in range(n_boot):
        aa = rng.choice(a, size=len(a), replace=True)
        bb = rng.choice(b, size=len(b), replace=True)
        vals[i] = bb.mean() - aa.mean()

    lo, hi = np.percentile(vals, [2.5, 97.5])
    return float(lo), float(hi)


def permutation_pvalue(a, b, n_perm=10000, seed=3402):
    rng = np.random.default_rng(seed)
    a = np.asarray(a, dtype=float)
    b = np.asarray(b, dtype=float)

    if len(a) == 0 or len(b) == 0:
        return np.nan

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


def cohen_d(a, b):
    a = np.asarray(a, dtype=float)
    b = np.asarray(b, dtype=float)

    if len(a) < 2 or len(b) < 2:
        return np.nan

    va = np.var(a, ddof=1)
    vb = np.var(b, ddof=1)
    pooled = np.sqrt(((len(a)-1)*va + (len(b)-1)*vb) / max(len(a)+len(b)-2, 1))

    if pooled == 0 or not np.isfinite(pooled):
        return 0.0

    return float((b.mean() - a.mean()) / pooled)


def cliffs_delta(a, b):
    a = np.asarray(a, dtype=float)
    b = np.asarray(b, dtype=float)

    if len(a) == 0 or len(b) == 0:
        return np.nan

    gt = 0
    lt = 0

    for x in a:
        gt += np.sum(x > b)
        lt += np.sum(x < b)

    return float((lt - gt) / (len(a) * len(b)))
    # Positive means b tends to be larger than a.


def mannwhitney_p(a, b):
    if not HAVE_SCIPY:
        return np.nan

    try:
        return float(stats.mannwhitneyu(a, b, alternative="two-sided").pvalue)
    except Exception:
        return np.nan


def fisher_p(table):
    if not HAVE_SCIPY:
        return np.nan

    try:
        return float(stats.fisher_exact(table).pvalue)
    except Exception:
        return np.nan


def wilson_ci(success, n, z=1.96):
    if n <= 0:
        return np.nan, np.nan

    p = success / n
    denom = 1 + z**2 / n
    center = (p + z**2 / (2*n)) / denom
    half = z * math.sqrt((p*(1-p) / n) + (z**2 / (4*n**2))) / denom

    return max(0.0, center - half), min(1.0, center + half)


def bh_adjust(pvals):
    p = np.asarray([np.nan if x is None else x for x in pvals], dtype=float)
    out = np.full_like(p, np.nan)

    valid = np.where(np.isfinite(p))[0]
    if len(valid) == 0:
        return out

    order = valid[np.argsort(p[valid])]
    m = len(order)
    prev = 1.0

    for rank in range(m, 0, -1):
        idx = order[rank - 1]
        val = p[idx] * m / rank
        prev = min(prev, val)
        out[idx] = min(prev, 1.0)

    return out


def continuous_compare(df, metric, comparison, candidate=BEST):
    if "config_id" not in df.columns or metric not in df.columns:
        return None

    if BASELINE not in set(df["config_id"].astype(str)) or candidate not in set(df["config_id"].astype(str)):
        return None

    a = numeric(df[df["config_id"].astype(str) == BASELINE][metric]).to_numpy()
    b = numeric(df[df["config_id"].astype(str) == candidate][metric]).to_numpy()

    if len(a) == 0 or len(b) == 0:
        return None

    delta = float(b.mean() - a.mean())
    pct = np.nan if abs(a.mean()) < 1e-12 else float(100 * delta / a.mean())
    lo, hi = bootstrap_ci_delta(a, b)
    p_perm = permutation_pvalue(a, b)
    p_mw = mannwhitney_p(a, b)

    return {
        "comparison": comparison,
        "metric": metric,
        "baseline": BASELINE,
        "candidate": candidate,
        "n_baseline": len(a),
        "n_candidate": len(b),
        "baseline_mean": float(a.mean()),
        "candidate_mean": float(b.mean()),
        "baseline_median": float(np.median(a)),
        "candidate_median": float(np.median(b)),
        "delta": delta,
        "pct_delta": pct,
        "bootstrap_95ci_low": lo,
        "bootstrap_95ci_high": hi,
        "permutation_p_two_sided": p_perm,
        "mannwhitney_p_two_sided": p_mw,
        "cohen_d": cohen_d(a, b),
        "cliffs_delta": cliffs_delta(a, b),
    }


def phase17_continuous_tests():
    df = read_csv(PHASE17_SESSION)
    rows = []

    if df.empty:
        return pd.DataFrame()

    score_col = find_col(df, [
        "praxis_score_phase17",
        "praxis_score",
        "praxis_score_confirmatory",
        "mean_praxis_score_phase17",
    ])

    public_col = find_col(df, [
        "public_robust_log_distance_norm",
        "public_distance_norm",
        "mean_public_robust_log_distance_norm",
        "mean_public_distance_norm",
    ])

    overhead_col = find_col(df, [
        "overhead_norm",
        "mean_overhead_norm",
        "pcap_size_bytes",
    ])

    metrics = [
        "detector_proxy_probability",
        score_col,
        public_col,
        overhead_col,
        "pcap_size_bytes",
        "packet_count",
        "burst_count",
        "flow_duration_seconds",
        "out_payload_bytes",
        "in_payload_bytes",
        "total_payload_bytes",
    ]

    metrics = [m for m in metrics if m and m in df.columns]

    for metric in metrics:
        for candidate in [BEST, CAMO]:
            r = continuous_compare(df, metric, "phase17_confirm", candidate)
            if r:
                rows.append(r)

    out = pd.DataFrame(rows)
    out.to_csv(TABLES / "phase34_phase17_continuous_tests.csv", index=False)
    return out


def phase17_feature_tests():
    df = read_csv(PHASE17_SESSION)
    rows = []

    if df.empty:
        return pd.DataFrame()

    for feature in FEATURES:
        if feature in df.columns:
            r = continuous_compare(df, feature, "phase17_feature_level", BEST)
            if r:
                rows.append(r)

    out = pd.DataFrame(rows)

    if not out.empty and "mannwhitney_p_two_sided" in out.columns:
        out["mannwhitney_p_bh_adjusted"] = bh_adjust(out["mannwhitney_p_two_sided"].to_numpy())

    out = out.sort_values("cohen_d", key=lambda s: s.abs(), ascending=False) if not out.empty else out
    out.to_csv(TABLES / "phase34_phase17_feature_tests.csv", index=False)
    return out


def phase17_compliance_tests():
    df = read_csv(PHASE17_SESSION)
    rows = []

    if df.empty or "success" not in df.columns or "config_id" not in df.columns:
        out = pd.DataFrame()
        out.to_csv(TABLES / "phase34_phase17_compliance_tests.csv", index=False)
        return out

    df["success"] = pd.to_numeric(df["success"], errors="coerce").fillna(0).astype(int)

    for cfg, sub in df.groupby("config_id"):
        n = len(sub)
        s = int(sub["success"].sum())
        lo, hi = wilson_ci(s, n)
        rows.append({
            "comparison": "phase17_compliance_rate",
            "config_id": cfg,
            "n": n,
            "success": s,
            "failure": n - s,
            "success_rate": s / n if n else np.nan,
            "wilson_95ci_low": lo,
            "wilson_95ci_high": hi,
        })

    baseline = df[df["config_id"] == BASELINE]

    for candidate in [BEST, CAMO]:
        cand = df[df["config_id"] == candidate]

        if len(baseline) and len(cand):
            table = [
                [int(baseline["success"].sum()), len(baseline) - int(baseline["success"].sum())],
                [int(cand["success"].sum()), len(cand) - int(cand["success"].sum())],
            ]

            rows.append({
                "comparison": "phase17_compliance_fisher_exact",
                "config_id": f"{BASELINE}_vs_{candidate}",
                "n": len(baseline) + len(cand),
                "success": "",
                "failure": "",
                "success_rate": "",
                "wilson_95ci_low": "",
                "wilson_95ci_high": "",
                "fisher_p_two_sided": fisher_p(table),
                "table": str(table),
            })

    out = pd.DataFrame(rows)
    out.to_csv(TABLES / "phase34_phase17_compliance_tests.csv", index=False)
    return out


def phase20_holdout_tests():
    rows = []

    inputs = [
        ("phase20_strict_unseen", PHASE20_STRICT, "holdout_strict_unseen_proxy_probability"),
        ("phase20_baseline_known", PHASE20_KNOWN, "holdout_baseline_known_proxy_probability"),
    ]

    for name, path, metric in inputs:
        df = read_csv(path)
        if df.empty:
            continue

        if metric not in df.columns:
            # Find any likely probability column.
            probs = [c for c in df.columns if "probability" in c.lower()]
            if probs:
                metric = probs[0]

        for candidate in [BEST, CAMO]:
            r = continuous_compare(df, metric, name, candidate)
            if r:
                rows.append(r)

    out = pd.DataFrame(rows)
    out.to_csv(TABLES / "phase34_phase20_holdout_tests.csv", index=False)
    return out


def phase21_rq3_tests():
    df = read_csv(PHASE21)
    rows = []

    if df.empty or "resolution_mode" not in df.columns or "success" not in df.columns:
        out = pd.DataFrame()
        out.to_csv(TABLES / "phase34_phase21_rq3_success_tests.csv", index=False)
        return out

    # Prefer full RQ3 run, fallback to pilot.
    full = df[df["session_id"].astype(str).str.startswith("RQ8C_RQ3_")].copy()
    if full.empty:
        full = df[df["session_id"].astype(str).str.startswith("RQ8C_PILOT_")].copy()
    if full.empty:
        full = df.copy()

    full["success"] = pd.to_numeric(full["success"], errors="coerce").fillna(0).astype(int)

    for mode, sub in full.groupby("resolution_mode"):
        n = len(sub)
        s = int(sub["success"].sum())
        lo, hi = wilson_ci(s, n)

        rows.append({
            "comparison": "phase21_rq3_success_rate",
            "mode": mode,
            "n": n,
            "success": s,
            "failure": n - s,
            "success_rate": s / n if n else np.nan,
            "wilson_95ci_low": lo,
            "wilson_95ci_high": hi,
        })

    pairs = [
        ("standard_dns_lab", "dns_blocked"),
        ("decentralized_resolution", "dns_blocked"),
        ("standard_dns_lab", "decentralized_resolution"),
    ]

    for a, b in pairs:
        da = full[full["resolution_mode"] == a]
        db = full[full["resolution_mode"] == b]

        if len(da) and len(db):
            table = [
                [int(da["success"].sum()), len(da) - int(da["success"].sum())],
                [int(db["success"].sum()), len(db) - int(db["success"].sum())],
            ]

            rows.append({
                "comparison": "phase21_rq3_fisher_exact",
                "mode": f"{a}_vs_{b}",
                "n": len(da) + len(db),
                "success": "",
                "failure": "",
                "success_rate": "",
                "wilson_95ci_low": "",
                "wilson_95ci_high": "",
                "fisher_p_two_sided": fisher_p(table),
                "table": str(table),
            })

    out = pd.DataFrame(rows)
    out.to_csv(TABLES / "phase34_phase21_rq3_success_tests.csv", index=False)
    return out


def copy_reference_tables():
    refs = []

    mapping = [
        (PHASE20B, "phase34_phase20b_threshold_reference.csv"),
        (PHASE29B, "phase34_phase29b_artifact_control_reference.csv"),
        (PHASE30_STATS, "phase34_phase30_multidetector_statistics_reference.csv"),
        (PHASE30_CONFIG, "phase34_phase30_multidetector_config_reference.csv"),
        (PHASE31_CONFIG, "phase34_phase31_public_baseline_reference.csv"),
    ]

    for src, dst_name in mapping:
        if src.exists():
            df = pd.read_csv(src)
            dst = TABLES / dst_name
            df.to_csv(dst, index=False)
            refs.append((src, dst, len(df)))
    return refs


def phase31_summary_table():
    df = read_csv(PHASE31_CONFIG)
    rows = []

    if df.empty:
        out = pd.DataFrame()
        out.to_csv(TABLES / "phase34_phase31_public_baseline_summary.csv", index=False)
        return out

    for baseline, sub in df.groupby("public_baseline"):
        winner = sub.sort_values("mean_score").iloc[0]
        dcp1 = sub[sub["config_id"] == BEST]

        if not dcp1.empty:
            d = dcp1.iloc[0]
            rows.append({
                "public_baseline": baseline,
                "winner": winner["config_id"],
                "winner_score": winner["mean_score"],
                "default_c2_p1_score": d["mean_score"],
                "default_c2_p1_score_delta_vs_baseline": d.get("score_delta_vs_baseline", np.nan),
                "default_c2_p1_public_distance_delta_vs_baseline": d.get("public_distance_delta_vs_baseline", np.nan),
            })

    out = pd.DataFrame(rows)
    out.to_csv(TABLES / "phase34_phase31_public_baseline_summary.csv", index=False)
    return out


def chapter4_summary_table(phase17, phase20, rq3, phase31):
    rows = []

    if not phase17.empty:
        for metric in ["detector_proxy_probability", "praxis_score_phase17", "praxis_score", "pcap_size_bytes"]:
            sub = phase17[(phase17["metric"] == metric) & (phase17["candidate"] == BEST)]
            if not sub.empty:
                r = sub.iloc[0]
                rows.append({
                    "section": "Phase 17",
                    "analysis": metric,
                    "baseline_mean": r["baseline_mean"],
                    "candidate_or_mode": BEST,
                    "candidate_mean_or_rate": r["candidate_mean"],
                    "delta": r["delta"],
                    "ci": f"[{r['bootstrap_95ci_low']:.6f},{r['bootstrap_95ci_high']:.6f}]",
                    "p_value": r["permutation_p_two_sided"],
                    "interpretation": "primary confirmatory inference",
                })

    if not phase20.empty:
        for _, r in phase20[(phase20["candidate"] == BEST)].iterrows():
            rows.append({
                "section": "Phase 20",
                "analysis": r["comparison"],
                "baseline_mean": r["baseline_mean"],
                "candidate_or_mode": BEST,
                "candidate_mean_or_rate": r["candidate_mean"],
                "delta": r["delta"],
                "ci": f"[{r['bootstrap_95ci_low']:.6f},{r['bootstrap_95ci_high']:.6f}]",
                "p_value": r["permutation_p_two_sided"],
                "interpretation": "fresh holdout detector inference",
            })

    if not rq3.empty:
        for _, r in rq3[rq3["comparison"] == "phase21_rq3_success_rate"].iterrows():
            rows.append({
                "section": "Phase 21",
                "analysis": "RQ3 success rate",
                "baseline_mean": "",
                "candidate_or_mode": r["mode"],
                "candidate_mean_or_rate": r["success_rate"],
                "delta": "",
                "ci": f"[{r['wilson_95ci_low']},{r['wilson_95ci_high']}]",
                "p_value": "",
                "interpretation": "resolver-mode compliance inference",
            })

    if not phase31.empty:
        for _, r in phase31.iterrows():
            rows.append({
                "section": "Phase 31",
                "analysis": "public baseline sensitivity",
                "baseline_mean": "",
                "candidate_or_mode": r["public_baseline"],
                "candidate_mean_or_rate": r["default_c2_p1_score"],
                "delta": r["default_c2_p1_score_delta_vs_baseline"],
                "ci": "",
                "p_value": "",
                "interpretation": f"winner={r['winner']}",
            })

    out = pd.DataFrame(rows)
    out.to_csv(TABLES / "phase34_chapter4_inferential_summary_table.csv", index=False)
    return out


def sha256_file(path: Path):
    if not path.exists() or not path.is_file():
        return ""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def make_manifest():
    files = sorted(TABLES.glob("*.csv")) + [OUT / "phase34_inferential_statistics_summary.md"]
    rows = []
    for f in files:
        rows.append({
            "path": str(f),
            "exists": f.exists(),
            "size_bytes": f.stat().st_size if f.exists() else 0,
            "sha256": sha256_file(f),
        })

    out = pd.DataFrame(rows)
    out.to_csv(MANIFESTS / "phase34_manifest.csv", index=False)


def write_summary(phase17, features, compliance, phase20, rq3, phase31):
    lines = []
    lines.append("# PRAXIS Phase 34 Inferential Statistics Summary")
    lines.append("")
    lines.append("## Purpose")
    lines.append("")
    lines.append("Convert PRAXIS collected logs, session-level CSVs, detector outputs, and public-baseline datasets into inferential statistical evidence for dissertation Chapters 3–5.")
    lines.append("")
    lines.append("## Method")
    lines.append("")
    lines.append("The unit of inference is one PRAXIS session. Individual packets are not treated as independent observations.")
    lines.append("")
    lines.append("Continuous outcomes are analyzed using bootstrap confidence intervals, permutation tests, Mann–Whitney U tests, Cohen's d, and Cliff's delta.")
    lines.append("")
    lines.append("Binary success outcomes are analyzed using Wilson confidence intervals and Fisher exact tests.")
    lines.append("")

    # Main Phase 17 detector result.
    if not phase17.empty:
        det = phase17[(phase17["metric"] == "detector_proxy_probability") & (phase17["candidate"] == BEST)]
        if not det.empty:
            r = det.iloc[0]
            lines.append("## Main Phase 17 detector-confidence inference")
            lines.append("")
            lines.append(f"- baseline_mean={r['baseline_mean']:.6f}")
            lines.append(f"- default_c2_p1_mean={r['candidate_mean']:.6f}")
            lines.append(f"- delta={r['delta']:.6f}")
            lines.append(f"- pct_delta={r['pct_delta']:.2f}%")
            lines.append(f"- bootstrap_95ci=[{r['bootstrap_95ci_low']:.6f},{r['bootstrap_95ci_high']:.6f}]")
            lines.append(f"- permutation_p_two_sided={r['permutation_p_two_sided']:.6f}")
            lines.append(f"- cohen_d={r['cohen_d']:.6f}")
            lines.append("")

        score_candidates = phase17[
            (phase17["candidate"] == BEST)
            & (phase17["metric"].astype(str).str.contains("score", case=False, na=False))
        ]
        if not score_candidates.empty:
            r = score_candidates.iloc[0]
            lines.append("## Phase 17 PRAXIS-score inference")
            lines.append("")
            lines.append(f"- metric={r['metric']}")
            lines.append(f"- baseline_mean={r['baseline_mean']:.6f}")
            lines.append(f"- default_c2_p1_mean={r['candidate_mean']:.6f}")
            lines.append(f"- delta={r['delta']:.6f}")
            lines.append(f"- bootstrap_95ci=[{r['bootstrap_95ci_low']:.6f},{r['bootstrap_95ci_high']:.6f}]")
            lines.append(f"- permutation_p_two_sided={r['permutation_p_two_sided']:.6f}")
            lines.append("")

    if not compliance.empty:
        lines.append("## Phase 17 compliance inference")
        lines.append("")
        for _, r in compliance[compliance["comparison"] == "phase17_compliance_rate"].iterrows():
            lines.append(
                f"- {r['config_id']}: success={r['success']}/{r['n']}, "
                f"success_rate={r['success_rate']}, "
                f"wilson_95ci=[{r['wilson_95ci_low']},{r['wilson_95ci_high']}]"
            )
        lines.append("")

    if not rq3.empty:
        lines.append("## Phase 21 RQ3 resolver success inference")
        lines.append("")
        for _, r in rq3[rq3["comparison"] == "phase21_rq3_success_rate"].iterrows():
            lines.append(
                f"- {r['mode']}: success={r['success']}/{r['n']}, "
                f"success_rate={r['success_rate']}, "
                f"wilson_95ci=[{r['wilson_95ci_low']},{r['wilson_95ci_high']}]"
            )
        lines.append("")

    if not phase20.empty:
        lines.append("## Phase 20 holdout-detector inference")
        lines.append("")
        for _, r in phase20[phase20["candidate"] == BEST].iterrows():
            lines.append(
                f"- {r['comparison']}: baseline={r['baseline_mean']:.6f}, "
                f"default_c2_p1={r['candidate_mean']:.6f}, "
                f"delta={r['delta']:.6f}, "
                f"ci=[{r['bootstrap_95ci_low']:.6f},{r['bootstrap_95ci_high']:.6f}], "
                f"p={r['permutation_p_two_sided']:.6f}"
            )
        lines.append("")

    if not phase31.empty:
        lines.append("## Phase 31 public-baseline sensitivity")
        lines.append("")
        for _, r in phase31.iterrows():
            lines.append(
                f"- {r['public_baseline']}: winner={r['winner']}, "
                f"default_c2_p1_score_delta_vs_baseline={r['default_c2_p1_score_delta_vs_baseline']}"
            )
        lines.append("")

    if not features.empty:
        lines.append("## Feature-level inference")
        lines.append("")
        lines.append("Top feature-level effects by absolute Cohen's d:")
        top = features.copy()
        top["abs_d"] = top["cohen_d"].abs()
        top = top.sort_values("abs_d", ascending=False).head(10)
        for _, r in top.iterrows():
            lines.append(
                f"- {r['metric']}: delta={r['delta']:.6f}, "
                f"cohen_d={r['cohen_d']:.6f}, "
                f"BH_adjusted_p={r.get('mannwhitney_p_bh_adjusted', np.nan)}"
            )
        lines.append("")

    lines.append("## Interpretation")
    lines.append("")
    lines.append("Phase 34 strengthens PRAXIS by adding inferential statistics to the already completed engineering and experimental work.")
    lines.append("")
    lines.append("The results should be interpreted as support for detector-confidence reduction and adaptive configuration selection under the PRAXIS lab threat model.")
    lines.append("")
    lines.append("They should not be interpreted as complete detector bypass, universal detector robustness, real-world censorship evasion, or production blockchain DDNS deployment.")
    lines.append("")

    (OUT / "phase34_inferential_statistics_summary.md").write_text("\n".join(lines) + "\n")


def main():
    phase17 = phase17_continuous_tests()
    features = phase17_feature_tests()
    compliance = phase17_compliance_tests()
    phase20 = phase20_holdout_tests()
    rq3 = phase21_rq3_tests()
    refs = copy_reference_tables()
    phase31 = phase31_summary_table()
    chapter4 = chapter4_summary_table(phase17, phase20, rq3, phase31)

    write_summary(phase17, features, compliance, phase20, rq3, phase31)
    make_manifest()

    print((OUT / "phase34_inferential_statistics_summary.md").read_text())
    print("Wrote outputs under:", OUT)
    print("Tables:")
    for p in sorted(TABLES.glob("*.csv")):
        print("-", p)
    print("References copied:")
    for src, dst, n in refs:
        print(f"- {src} -> {dst} rows={n}")


if __name__ == "__main__":
    main()
