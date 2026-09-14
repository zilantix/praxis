#!/usr/bin/env python3

from pathlib import Path
import zipfile
import numpy as np
import pandas as pd

ZIP = Path("/opt/praxis/public_data/cicids2017/MachineLearningCSV.zip")
WORK = Path("/opt/praxis/public_data/cicids2017/extracted")
OUT = Path("/opt/praxis/public_data/features/cicids2017_benign_praxis_mapped.csv")
SUMMARY = Path("/opt/praxis/solution/reports/phase31/phase31_cicids_mapping_summary.txt")

FIELDS = [
    "source_dataset",
    "public_ground_truth",
    "session_id",
    "client_endpoint",
    "server_endpoint",
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


def norm_col(c):
    return str(c).strip().lower().replace(" ", "_").replace("/", "_").replace("-", "_")


def find_col(cols, names):
    normalized = {norm_col(c): c for c in cols}
    for name in names:
        key = norm_col(name)
        if key in normalized:
            return normalized[key]
    return None


def safe_num(s, length=None):
    if s is None:
        return pd.Series([0.0] * length)
    return pd.to_numeric(s, errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0.0)


def main():
    SUMMARY.parent.mkdir(parents=True, exist_ok=True)

    if not ZIP.exists():
        raise SystemExit(f"Missing {ZIP}. Put the official CICIDS2017 MachineLearningCSV.zip there first.")

    WORK.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(ZIP, "r") as z:
        z.extractall(WORK)

    csvs = sorted(WORK.rglob("*.csv"))

    if not csvs:
        raise SystemExit(f"No CSV files found under {WORK}")

    mapped_parts = []
    source_counts = []
    total_benign = 0

    for csv_path in csvs:
        print(f"Reading {csv_path}")

        try:
            reader = pd.read_csv(csv_path, chunksize=100000, low_memory=False, encoding_errors="ignore")
        except TypeError:
            reader = pd.read_csv(csv_path, chunksize=100000, low_memory=False)

        file_rows = 0
        benign_rows = 0

        for chunk in reader:
            chunk.columns = [str(c).strip() for c in chunk.columns]
            file_rows += len(chunk)

            label_col = find_col(chunk.columns, ["Label"])
            if label_col is None:
                continue

            benign = chunk[chunk[label_col].astype(str).str.upper().str.strip() == "BENIGN"].copy()

            if benign.empty:
                continue

            benign_rows += len(benign)

            out_p_col = find_col(benign.columns, ["Total Fwd Packets", "Tot Fwd Pkts", "Total_Fwd_Packets"])
            in_p_col = find_col(benign.columns, ["Total Backward Packets", "Tot Bwd Pkts", "Total_Backward_Packets"])
            out_b_col = find_col(benign.columns, ["Total Length of Fwd Packets", "TotLen Fwd Pkts", "Fwd Packet Length Total"])
            in_b_col = find_col(benign.columns, ["Total Length of Bwd Packets", "TotLen Bwd Pkts", "Bwd Packet Length Total"])
            dur_col = find_col(benign.columns, ["Flow Duration"])

            fwd_mean_col = find_col(benign.columns, ["Fwd Packet Length Mean", "Fwd Pkt Len Mean"])
            bwd_mean_col = find_col(benign.columns, ["Bwd Packet Length Mean", "Bwd Pkt Len Mean"])
            fwd_max_col = find_col(benign.columns, ["Fwd Packet Length Max", "Fwd Pkt Len Max"])
            bwd_max_col = find_col(benign.columns, ["Bwd Packet Length Max", "Bwd Pkt Len Max"])

            n = len(benign)

            out_packets = safe_num(benign[out_p_col] if out_p_col else None, n)
            in_packets = safe_num(benign[in_p_col] if in_p_col else None, n)
            out_bytes = safe_num(benign[out_b_col] if out_b_col else None, n)
            in_bytes = safe_num(benign[in_b_col] if in_b_col else None, n)
            duration_seconds = safe_num(benign[dur_col] if dur_col else None, n) / 1_000_000.0

            fwd_mean = safe_num(benign[fwd_mean_col] if fwd_mean_col else None, n)
            bwd_mean = safe_num(benign[bwd_mean_col] if bwd_mean_col else None, n)
            fwd_max = safe_num(benign[fwd_max_col] if fwd_max_col else None, n)
            bwd_max = safe_num(benign[bwd_max_col] if bwd_max_col else None, n)

            packet_count = out_packets + in_packets
            total_bytes = out_bytes + in_bytes
            burst_count = np.where(
                (out_packets > 0) & (in_packets > 0),
                2,
                np.where(packet_count > 0, 1, 0),
            )

            part = pd.DataFrame({
                "source_dataset": "cicids2017_benign_mapped",
                "public_ground_truth": 0,
                "session_id": [f"CICIDS_BENIGN_{total_benign + i + 1:08d}" for i in range(n)],
                "client_endpoint": "cicids_unknown",
                "server_endpoint": "cicids_unknown",
                "pcap_size_bytes": 0,
                "packet_count": packet_count,
                "out_packets": out_packets,
                "in_packets": in_packets,
                "unknown_packets": 0,
                "out_payload_bytes": out_bytes,
                "in_payload_bytes": in_bytes,
                "total_payload_bytes": total_bytes,
                "flow_duration_seconds": duration_seconds,
                "burst_count": burst_count,
            })

            # CICIDS CSV does not preserve first-20 packet order. Use deterministic aggregate approximations.
            approximations = [
                fwd_mean,
                -bwd_mean,
                fwd_max,
                -bwd_max,
                fwd_mean,
                -bwd_mean,
                fwd_mean,
                -bwd_mean,
            ]

            for i in range(1, 21):
                if i <= len(approximations):
                    part[f"len_{i}"] = approximations[i - 1]
                else:
                    part[f"len_{i}"] = 0

            mapped_parts.append(part[FIELDS])
            total_benign += n

        source_counts.append((str(csv_path), file_rows, benign_rows))

    if not mapped_parts:
        raise SystemExit("No BENIGN rows found in CICIDS files.")

    mapped = pd.concat(mapped_parts, ignore_index=True)
    mapped = mapped.replace([np.inf, -np.inf], np.nan).fillna(0)
    mapped.to_csv(OUT, index=False)

    lines = []
    lines.append("PRAXIS Phase 31 CICIDS2017 benign mapping summary")
    lines.append("")
    lines.append(f"input_zip={ZIP}")
    lines.append(f"output={OUT}")
    lines.append(f"mapped_benign_rows={len(mapped)}")
    lines.append("")
    lines.append("Important boundary:")
    lines.append("CICIDS2017 is mapped from CICFlowMeter aggregate CSV features into the PRAXIS schema.")
    lines.append("It is a secondary sanity-check baseline, not a replacement for MAWI packet-derived public traffic.")
    lines.append("len_1..len_8 are approximated from forward/backward packet length means and maxima.")
    lines.append("len_9..len_20 are zero-filled.")
    lines.append("")
    lines.append("Per-file counts:")
    for path, total, benign in source_counts:
        lines.append(f"{path}: rows_seen={total}, benign_rows={benign}")

    SUMMARY.write_text("\n".join(lines) + "\n")

    print(SUMMARY.read_text())


if __name__ == "__main__":
    main()
