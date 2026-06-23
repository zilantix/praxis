from pathlib import Path
import os
from typing import Dict, List, Any
import json
import pandas as pd
import numpy as np

BASE = Path(os.environ.get("PRAXIS_DATA_DIR", "/opt/praxis")).expanduser().resolve()

PATHS = {
    "phase17_scores": BASE / "solution/reports/phase17_confirm_config_scores.csv",
    "phase20_scores": BASE / "solution/reports/phase20_holdout_detector_config_scores.csv",
    "phase20b_thresholds": BASE / "solution/reports/phase20b_threshold_validation.csv",
    "phase21_catalog": BASE / "solution/sweep/phase21_rq3_curl_catalog.csv",
    "final_claim": BASE / "solution/reports/praxis_cycle2_final_claim_with_rq3.md",
    "final_status": BASE / "solution/reports/praxis_cycle2_status_final_with_rq3.txt",
    "phase22_index": BASE / "solution/reports/phase22/phase22_output_index.md",
}


def file_status() -> List[Dict[str, Any]]:
    rows = []
    for name, path in PATHS.items():
        rows.append({
            "name": name,
            "path": str(path),
            "exists": path.exists(),
            "size_bytes": path.stat().st_size if path.exists() else 0,
        })
    return rows


def read_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame()
    return pd.read_csv(path)


def read_text(path: Path, fallback: str = "") -> str:
    if not path.exists():
        return fallback
    return path.read_text()


def phase17_scores() -> pd.DataFrame:
    return read_csv(PATHS["phase17_scores"])


def phase20_scores() -> pd.DataFrame:
    return read_csv(PATHS["phase20_scores"])


def phase20b_thresholds() -> pd.DataFrame:
    return read_csv(PATHS["phase20b_thresholds"])


def phase21_summary() -> pd.DataFrame:
    df = read_csv(PATHS["phase21_catalog"])
    if df.empty:
        return pd.DataFrame(columns=["resolution_mode", "n", "success", "success_rate"])

    full = df[df["session_id"].astype(str).str.startswith("RQ8C_RQ3_")].copy()
    if full.empty:
        full = df[df["session_id"].astype(str).str.startswith("RQ8C_PILOT_")].copy()

    if full.empty:
        return pd.DataFrame(columns=["resolution_mode", "n", "success", "success_rate"])

    full["success"] = pd.to_numeric(full["success"], errors="coerce").fillna(0)

    return (
        full.groupby("resolution_mode")
        .agg(
            n=("session_id", "count"),
            success=("success", "sum"),
            success_rate=("success", "mean"),
        )
        .reset_index()
        .sort_values("resolution_mode")
    )


def rq_status() -> List[Dict[str, str]]:
    return [
        {
            "rq": "RQ1",
            "question": "To what extent do browser-profile and proxy-configuration choices reduce non-timing proxy-detection confidence while preserving session compliance?",
            "status": "Confirmed with boundary",
            "evidence": "Phase 17: default_c2_p1 reduced detector probability from 1.000 to 0.487 with 100% compliance.",
            "boundary": "Detector-confidence reduction, not complete detector bypass.",
        },
        {
            "rq": "RQ2",
            "question": "How do multiplexing mode and browser-side parallelism affect proxy-traffic identifiability under non-timing traffic analysis?",
            "status": "Confirmed / mechanism suggested",
            "evidence": "default_c2_p1 beat camouflaged_c2_p1, suggesting c2 multiplexing with parallel=1 is the main driver.",
            "boundary": "Mechanism is supported by comparison and should be explained with Phase 18 feature deltas.",
        },
        {
            "rq": "RQ3",
            "question": "Can the best traffic-camouflage configuration be integrated with decentralized resolution to preserve access and compliance under DNS-blocking conditions?",
            "status": "Confirmed at controlled resolver-independence level",
            "evidence": "Phase 21: standard_dns_lab 30/30, dns_blocked 0/30, decentralized_resolution 30/30.",
            "boundary": "Controlled local decentralized-style mapping, not production blockchain DDNS integration.",
        },
    ]


def claim_boundary() -> List[Dict[str, str]]:
    return [
        {"category": "Confirmed", "item": "Adaptive controller", "description": "PRAXIS evaluates, scores, selects, and confirms candidate configurations."},
        {"category": "Confirmed", "item": "Detector-confidence reduction", "description": "default_c2_p1 reduced detector confidence relative to baseline."},
        {"category": "Confirmed", "item": "Corrected PRAXIS score improvement", "description": "default_c2_p1 improved corrected multi-objective score."},
        {"category": "Confirmed", "item": "Fresh-detector confidence reduction", "description": "Phase 20/20B confirmed lower confidence under fresh holdout detectors."},
        {"category": "Confirmed", "item": "Controlled resolver independence", "description": "Phase 21 confirmed DNS-blocked failure and decentralized-style recovery."},
        {"category": "Not confirmed", "item": "Complete detector bypass", "description": "Binary detection remained positive under tested thresholds."},
        {"category": "Not confirmed", "item": "Real-world censorship evasion", "description": "Experiments are bounded to the PRAXIS lab threat model."},
        {"category": "Not confirmed", "item": "Production blockchain DDNS", "description": "Phase 21 used controlled local decentralized-style mapping."},
    ]


def normalize_weights(detector: float, public: float, overhead: float, compliance: float) -> Dict[str, float]:
    total = detector + public + overhead + compliance
    if total <= 0:
        total = 1.0
    return {
        "detector": detector / total,
        "public": public / total,
        "overhead": overhead / total,
        "compliance": compliance / total,
    }


def controller_ranking(
    detector_weight: float = 45,
    public_weight: float = 35,
    overhead_weight: float = 5,
    compliance_weight: float = 15,
) -> Dict[str, Any]:
    df = phase17_scores()

    if df.empty:
        return {
            "weights": normalize_weights(detector_weight, public_weight, overhead_weight, compliance_weight),
            "winner": None,
            "ranking": [],
            "error": "Missing phase17 scores.",
        }

    required = [
        "config_id",
        "n",
        "mean_success",
        "mean_detector_proxy_probability",
        "mean_public_robust_log_distance_norm",
        "mean_overhead_norm",
    ]

    for c in required:
        if c not in df.columns:
            return {
                "weights": normalize_weights(detector_weight, public_weight, overhead_weight, compliance_weight),
                "winner": None,
                "ranking": [],
                "error": f"Missing required column: {c}",
            }

    w = normalize_weights(detector_weight, public_weight, overhead_weight, compliance_weight)

    out = df.copy()
    out["compliance_penalty"] = np.maximum(0.0, 0.95 - pd.to_numeric(out["mean_success"], errors="coerce").fillna(0.0))

    out["adjusted_score"] = (
        w["detector"] * pd.to_numeric(out["mean_detector_proxy_probability"], errors="coerce").fillna(1.0)
        + w["public"] * pd.to_numeric(out["mean_public_robust_log_distance_norm"], errors="coerce").fillna(1.0)
        + w["overhead"] * pd.to_numeric(out["mean_overhead_norm"], errors="coerce").fillna(1.0)
        + w["compliance"] * out["compliance_penalty"]
    )

    keep = [
        "config_id",
        "n",
        "mean_success",
        "mean_detector_proxy_probability",
        "mean_public_robust_log_distance_norm",
        "mean_overhead_norm",
        "adjusted_score",
    ]

    out = out[keep].sort_values("adjusted_score").reset_index(drop=True)
    out["rank"] = out.index + 1

    ranking = out.to_dict(orient="records")
    winner = ranking[0] if ranking else None

    return {
        "weights": w,
        "winner": winner,
        "ranking": ranking,
        "error": None,
    }


def summary() -> Dict[str, Any]:
    return {
        "service": "PRAXIS Adaptive Camouflage Controller Service",
        "version": "0.1.0",
        "best_config": "default_c2_p1",
        "baseline_detector_probability": 1.000,
        "best_detector_probability": 0.487,
        "detector_delta": -0.513,
        "compliance": 1.0,
        "claim": "Detector-confidence reduction and adaptive configuration selection under PRAXIS lab threat model.",
        "not_claimed": [
            "complete detector bypass",
            "real-world censorship evasion",
            "production blockchain DDNS integration",
        ],
        "files": file_status(),
    }


def export_json(path: Path) -> Path:
    data = {
        "summary": summary(),
        "rq_status": rq_status(),
        "claim_boundary": claim_boundary(),
        "ranking": controller_ranking(),
        "phase21": phase21_summary().to_dict(orient="records"),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))
    return path
