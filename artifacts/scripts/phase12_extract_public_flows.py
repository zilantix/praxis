#!/usr/bin/env python3

import argparse
import csv
import re
import subprocess
from pathlib import Path

SERVICE_PORTS = {
    20, 21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 853, 873,
    993, 995, 1194, 3306, 3389, 5222, 5432, 6379, 8080, 8443, 9443
}

FEATURE_FIELDS = [
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


def parse_endpoint(endpoint: str):
    endpoint = endpoint.rstrip(":")
    m = re.match(r"^(.+)\.(\d+)$", endpoint)
    if not m:
        return None, None
    return m.group(1), int(m.group(2))


def canonical_key(a: str, b: str):
    return tuple(sorted([a, b]))


def infer_client_server(a_ep: str, b_ep: str):
    a_ip, a_port = parse_endpoint(a_ep)
    b_ip, b_port = parse_endpoint(b_ep)

    if a_port is None or b_port is None:
        return a_ep, b_ep

    a_service = a_port in SERVICE_PORTS or a_port < 1024
    b_service = b_port in SERVICE_PORTS or b_port < 1024

    if a_service and not b_service:
        return b_ep, a_ep
    if b_service and not a_service:
        return a_ep, b_ep

    # Fallback: use first-observed source as positive direction.
    return a_ep, b_ep


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-flows", type=int, default=5000)
    ap.add_argument("--min-packets", type=int, default=6)
    args = ap.parse_args()

    pcap = Path(args.pcap)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    if not pcap.exists():
        raise SystemExit(f"Missing pcap: {pcap}")

    proc = subprocess.run(
        ["tcpdump", "-tt", "-nn", "-r", str(pcap), "tcp"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=900,
    )

    flows = {}

    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue

        try:
            ts = float(parts[0])
        except Exception:
            continue

        if parts[1] != "IP":
            continue

        src_ep = parts[2]
        dst_ep = parts[4].rstrip(":")

        src_ip, src_port = parse_endpoint(src_ep)
        dst_ip, dst_port = parse_endpoint(dst_ep)
        if src_ip is None or dst_ip is None:
            continue

        key = canonical_key(src_ep, dst_ep)

        m_len = re.search(r"length (\d+)", line)
        payload_len = int(m_len.group(1)) if m_len else 0

        if key not in flows:
            client_ep, server_ep = infer_client_server(src_ep, dst_ep)
            flows[key] = {
                "client_endpoint": client_ep,
                "server_endpoint": server_ep,
                "first_ts": ts,
                "last_ts": ts,
                "packet_count": 0,
                "out_packets": 0,
                "in_packets": 0,
                "unknown_packets": 0,
                "out_payload_bytes": 0,
                "in_payload_bytes": 0,
                "burst_count": 0,
                "prev_dir": None,
                "lengths": [],
            }

        f = flows[key]
        f["packet_count"] += 1
        f["last_ts"] = ts

        if src_ep == f["client_endpoint"]:
            direction = "out"
            f["out_packets"] += 1
            f["out_payload_bytes"] += payload_len
            signed_len = payload_len
        elif dst_ep == f["client_endpoint"]:
            direction = "in"
            f["in_packets"] += 1
            f["in_payload_bytes"] += payload_len
            signed_len = -payload_len
        else:
            direction = "unknown"
            f["unknown_packets"] += 1
            signed_len = 0

        if len(f["lengths"]) < 20:
            f["lengths"].append(signed_len)

        if direction != "unknown" and direction != f["prev_dir"]:
            f["burst_count"] += 1
            f["prev_dir"] = direction

    rows = []
    pcap_size = pcap.stat().st_size

    for _, f in flows.items():
        if f["packet_count"] < args.min_packets:
            continue

        row = {
            "source_dataset": "mawi_202403011400_samplepoint_F",
            "public_ground_truth": 0,
            "session_id": f"MAWI_FLOW_{len(rows) + 1:06d}",
            "client_endpoint": f["client_endpoint"],
            "server_endpoint": f["server_endpoint"],
            "pcap_size_bytes": pcap_size,
            "packet_count": f["packet_count"],
            "out_packets": f["out_packets"],
            "in_packets": f["in_packets"],
            "unknown_packets": f["unknown_packets"],
            "out_payload_bytes": f["out_payload_bytes"],
            "in_payload_bytes": f["in_payload_bytes"],
            "total_payload_bytes": f["out_payload_bytes"] + f["in_payload_bytes"],
            "flow_duration_seconds": round(f["last_ts"] - f["first_ts"], 6),
            "burst_count": f["burst_count"],
        }

        for i in range(1, 21):
            row[f"len_{i}"] = f["lengths"][i - 1] if i <= len(f["lengths"]) else 0

        rows.append(row)

        if len(rows) >= args.max_flows:
            break

    with open(out, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FEATURE_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {out}")
    print(f"rows={len(rows)}")
    print(f"input_pcap={pcap}")
    print(f"input_pcap_size_bytes={pcap_size}")


if __name__ == "__main__":
    main()
