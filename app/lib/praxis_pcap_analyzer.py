from pathlib import Path
from typing import Optional, Dict, Any
import json
import math
import os
import re
import subprocess
import uuid

import numpy as np
import pandas as pd


FEATURE_FIELDS = [
    "session_id",
    "config_id",
    "success",
    "pcap_file",
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


PUBLIC_DISTANCE_COLS = [
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


def default_data_dir() -> Path:
    env = os.environ.get("PRAXIS_DATA_DIR")
    if env:
        return Path(env).expanduser().resolve()

    repo_root = Path(__file__).resolve().parents[2]
    examples = repo_root / "examples"
    if examples.exists():
        return examples.resolve()

    return Path("/opt/praxis").resolve()


def default_public_baseline() -> Path:
    base = default_data_dir()

    candidates = [
        base / "public_data/features/mawi_public_flows_active.csv",
        base / "public_data/features/mawi_public_flows_20240302_1m.csv",
        base / "examples/public_data/features/mawi_public_flows_sample.csv",
    ]

    for p in candidates:
        if p.exists():
            return p

    return candidates[0]


def ensure_cols(df: pd.DataFrame, cols):
    df = df.copy()
    for c in cols:
        if c not in df.columns:
            df[c] = 0
    return df[cols].fillna(0)


def signed_log_transform(df: pd.DataFrame) -> pd.DataFrame:
    x = df.copy().astype(float)
    for c in x.columns:
        x[c] = np.sign(x[c]) * np.log1p(np.abs(x[c]))
    return x


def robust_log_distance(X_sweep: pd.DataFrame, X_public: pd.DataFrame) -> np.ndarray:
    Xs = signed_log_transform(X_sweep)
    Xp = signed_log_transform(X_public)

    med = Xp.median(axis=0)
    iqr = (Xp.quantile(0.75, axis=0) - Xp.quantile(0.25, axis=0)).replace(0, 1.0)

    Z = (Xs - med) / iqr
    return np.sqrt((Z ** 2).sum(axis=1))


def bounded_distance(distance: float) -> float:
    if not math.isfinite(distance):
        return float("nan")
    return float(distance / (1.0 + distance))


def parse_pcap(pcap_path: Path, client_ip: str, timeout_seconds: int = 300) -> Dict[str, Any]:
    if not pcap_path.exists():
        raise FileNotFoundError(f"Missing pcap: {pcap_path}")

    result = {
        "pcap_size_bytes": pcap_path.stat().st_size,
        "packet_count": 0,
        "out_packets": 0,
        "in_packets": 0,
        "unknown_packets": 0,
        "out_payload_bytes": 0,
        "in_payload_bytes": 0,
        "total_payload_bytes": 0,
        "flow_duration_seconds": 0.0,
        "burst_count": 0,
    }

    for i in range(1, 21):
        result[f"len_{i}"] = 0

    proc = subprocess.run(
        ["tcpdump", "-tt", "-nn", "-r", str(pcap_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout_seconds,
    )

    first_ts = None
    last_ts = None
    prev_dir = None
    signed_lengths = []

    client_as_source = re.compile(rf"\bIP6?\s+{re.escape(client_ip)}[.\s]")
    client_as_destination = re.compile(rf">\s+{re.escape(client_ip)}[.\s]")

    for line in proc.stdout.splitlines():
        parts = line.split()
        if not parts:
            continue

        try:
            ts = float(parts[0])
        except Exception:
            continue

        if first_ts is None:
            first_ts = ts
        last_ts = ts

        result["packet_count"] += 1

        m = re.search(r"length (\d+)", line)
        payload_len = int(m.group(1)) if m else 0

        if client_as_source.search(line):
            direction = "out"
            result["out_packets"] += 1
            result["out_payload_bytes"] += payload_len
            signed_len = payload_len
        elif client_as_destination.search(line):
            direction = "in"
            result["in_packets"] += 1
            result["in_payload_bytes"] += payload_len
            signed_len = -payload_len
        else:
            direction = "unknown"
            result["unknown_packets"] += 1
            signed_len = 0

        if len(signed_lengths) < 20:
            signed_lengths.append(signed_len)

        if direction != "unknown" and direction != prev_dir:
            result["burst_count"] += 1
            prev_dir = direction

    result["total_payload_bytes"] = result["out_payload_bytes"] + result["in_payload_bytes"]

    if first_ts is not None and last_ts is not None:
        result["flow_duration_seconds"] = round(last_ts - first_ts, 6)

    for i, value in enumerate(signed_lengths, start=1):
        result[f"len_{i}"] = value

    result["tcpdump_stderr"] = proc.stderr.strip()

    return result


def analyze_pcap(
    pcap_path: Path,
    client_ip: str,
    session_id: str,
    config_id: str,
    success: int,
    public_baseline_path: Optional[Path] = None,
    detector_probability: Optional[float] = None,
    overhead_budget_bytes: int = 1000000,
    detector_weight: float = 45,
    public_weight: float = 35,
    overhead_weight: float = 5,
    compliance_weight: float = 15,
) -> Dict[str, Any]:
    if public_baseline_path is None:
        public_baseline_path = default_public_baseline()

    features = parse_pcap(pcap_path, client_ip)

    row = {
        "session_id": session_id,
        "config_id": config_id,
        "success": int(success),
        "pcap_file": str(pcap_path),
        **features,
    }

    feature_df = pd.DataFrame([row])

    public_distance = float("nan")
    public_distance_norm = float("nan")

    if public_baseline_path.exists():
        public = pd.read_csv(public_baseline_path)
        X_session = ensure_cols(feature_df, PUBLIC_DISTANCE_COLS)
        X_public = ensure_cols(public, PUBLIC_DISTANCE_COLS)
        public_distance = float(robust_log_distance(X_session, X_public)[0])
        public_distance_norm = bounded_distance(public_distance)

    compliance_score = float(success)
    compliance_penalty = max(0.0, 0.95 - compliance_score)

    if overhead_budget_bytes <= 0:
        overhead_budget_bytes = 1

    overhead_norm = min(1.0, float(features["pcap_size_bytes"]) / float(overhead_budget_bytes))

    weights = {
        "detector": float(detector_weight),
        "public": float(public_weight),
        "overhead": float(overhead_weight),
        "compliance": float(compliance_weight),
    }

    has_detector = detector_probability is not None and math.isfinite(float(detector_probability))

    if has_detector:
        total_weight = sum(weights.values())
        detector_component = float(detector_probability)
    else:
        total_weight = weights["public"] + weights["overhead"] + weights["compliance"]
        detector_component = 0.0

    if total_weight <= 0:
        total_weight = 1.0

    score = 0.0
    if has_detector:
        score += (weights["detector"] / total_weight) * detector_component

    score += (weights["public"] / total_weight) * (0.0 if math.isnan(public_distance_norm) else public_distance_norm)
    score += (weights["overhead"] / total_weight) * overhead_norm
    score += (weights["compliance"] / total_weight) * compliance_penalty

    score_type = "full_score" if has_detector else "partial_score_no_detector"

    scored_row = {
        **row,
        "detector_proxy_probability": detector_probability if has_detector else np.nan,
        "detector_probability_missing": not has_detector,
        "public_robust_log_distance": public_distance,
        "public_robust_log_distance_norm": public_distance_norm,
        "compliance_score": compliance_score,
        "compliance_penalty": compliance_penalty,
        "overhead_budget_bytes": overhead_budget_bytes,
        "overhead_norm": overhead_norm,
        "praxis_score": score,
        "score_type": score_type,
        "public_baseline_file": str(public_baseline_path),
    }

    scored_df = pd.DataFrame([scored_row])

    summary = {
        "session_id": session_id,
        "config_id": config_id,
        "client_ip": client_ip,
        "success": int(success),
        "packet_count": int(features["packet_count"]),
        "pcap_size_bytes": int(features["pcap_size_bytes"]),
        "total_payload_bytes": int(features["total_payload_bytes"]),
        "flow_duration_seconds": float(features["flow_duration_seconds"]),
        "detector_proxy_probability": detector_probability if has_detector else None,
        "public_robust_log_distance": public_distance,
        "public_robust_log_distance_norm": public_distance_norm,
        "overhead_norm": overhead_norm,
        "compliance_score": compliance_score,
        "praxis_score": score,
        "score_type": score_type,
        "claim_boundary": (
            "Full detector-confidence scoring is available because detector probability was supplied."
            if has_detector
            else "Partial score only. No detector probability was supplied, so do not claim detector-confidence reduction."
        ),
    }

    return {
        "summary": summary,
        "features_df": feature_df,
        "scored_df": scored_df,
    }


def write_analysis_outputs(result: Dict[str, Any], out_dir: Path) -> Dict[str, str]:
    out_dir.mkdir(parents=True, exist_ok=True)

    features_path = out_dir / "praxis_pcap_features.csv"
    scored_path = out_dir / "praxis_pcap_scored.csv"
    summary_path = out_dir / "praxis_pcap_summary.json"
    text_path = out_dir / "praxis_pcap_report.txt"

    result["features_df"].to_csv(features_path, index=False)
    result["scored_df"].to_csv(scored_path, index=False)
    summary_path.write_text(json.dumps(result["summary"], indent=2))

    s = result["summary"]
    text_path.write_text(
        "PRAXIS PCAP Analysis Report\n\n"
        f"session_id={s['session_id']}\n"
        f"config_id={s['config_id']}\n"
        f"client_ip={s['client_ip']}\n"
        f"success={s['success']}\n"
        f"packet_count={s['packet_count']}\n"
        f"pcap_size_bytes={s['pcap_size_bytes']}\n"
        f"total_payload_bytes={s['total_payload_bytes']}\n"
        f"flow_duration_seconds={s['flow_duration_seconds']}\n"
        f"detector_proxy_probability={s['detector_proxy_probability']}\n"
        f"public_robust_log_distance={s['public_robust_log_distance']}\n"
        f"public_robust_log_distance_norm={s['public_robust_log_distance_norm']}\n"
        f"overhead_norm={s['overhead_norm']}\n"
        f"compliance_score={s['compliance_score']}\n"
        f"praxis_score={s['praxis_score']}\n"
        f"score_type={s['score_type']}\n\n"
        f"claim_boundary={s['claim_boundary']}\n"
    )

    return {
        "features_csv": str(features_path),
        "scored_csv": str(scored_path),
        "summary_json": str(summary_path),
        "report_txt": str(text_path),
    }


def make_upload_dir(base: Optional[Path] = None) -> Path:
    if base is None:
        base = Path("/opt/praxis/app/uploads")
    run_id = uuid.uuid4().hex[:12]
    path = base / run_id
    path.mkdir(parents=True, exist_ok=True)
    return path
