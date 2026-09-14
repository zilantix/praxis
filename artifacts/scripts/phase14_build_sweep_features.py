#!/usr/bin/env python3

import csv
import re
import subprocess
from pathlib import Path

CATALOG = Path("/opt/praxis/solution/sweep/phase13_sweep_catalog.csv")
OUT = Path("/opt/praxis/solution/features/phase14_sweep_features.csv")
IP_ENV = Path("/opt/praxis/configs/lab_ips_cycle2.env")

FEATURE_FIELDS = [
    "session_id", "config_id", "browser_profile", "mux_mode", "parallel",
    "padding_mode", "resolver_mode", "success", "pcap_file", "browser_log",
    "pcap_size_bytes", "packet_count", "out_packets", "in_packets",
    "unknown_packets", "out_payload_bytes", "in_payload_bytes",
    "total_payload_bytes", "flow_duration_seconds", "burst_count",
] + [f"len_{i}" for i in range(1, 21)]


def read_env(path):
    d = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            d[k.strip()] = v.strip()
    return d


def formal(session_id):
    return bool(re.match(r"^RQ4_SWEEP_.+_(0[1-9]|10)$", session_id))


def parse_pcap(path, client_ip):
    f = {
        "pcap_size_bytes": 0,
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
        f[f"len_{i}"] = 0

    p = Path(path)
    if not p.exists():
        return f

    f["pcap_size_bytes"] = p.stat().st_size

    proc = subprocess.run(
        ["tcpdump", "-tt", "-nn", "-r", str(p)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=120,
    )

    first_ts = None
    last_ts = None
    prev_dir = None
    signed = []

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
        f["packet_count"] += 1

        m = re.search(r"length (\d+)", line)
        plen = int(m.group(1)) if m else 0

        if re.search(rf"\bIP6?\s+{re.escape(client_ip)}\.", line):
            direction = "out"
            f["out_packets"] += 1
            f["out_payload_bytes"] += plen
            signed_len = plen
        elif re.search(rf">\s+{re.escape(client_ip)}\.", line):
            direction = "in"
            f["in_packets"] += 1
            f["in_payload_bytes"] += plen
            signed_len = -plen
        else:
            direction = "unknown"
            f["unknown_packets"] += 1
            signed_len = 0

        if len(signed) < 20:
            signed.append(signed_len)

        if direction != "unknown" and direction != prev_dir:
            f["burst_count"] += 1
            prev_dir = direction

    f["total_payload_bytes"] = f["out_payload_bytes"] + f["in_payload_bytes"]

    if first_ts is not None and last_ts is not None:
        f["flow_duration_seconds"] = round(last_ts - first_ts, 6)

    for i, v in enumerate(signed, start=1):
        f[f"len_{i}"] = v

    return f


def main():
    env = read_env(IP_ENV)
    client_ip = env.get("CLIENT_IP", "10.42.1.43")

    rows = list(csv.DictReader(open(CATALOG)))
    rows = [r for r in rows if formal(r["session_id"])]

    if not rows:
        raise SystemExit("No formal RQ4_SWEEP rows found.")

    OUT.parent.mkdir(parents=True, exist_ok=True)

    out_rows = []
    for r in rows:
        features = parse_pcap(r["pcap_file"], client_ip)
        out_rows.append({
            "session_id": r["session_id"],
            "config_id": r["config_id"],
            "browser_profile": r["browser_profile"],
            "mux_mode": r["mux_mode"],
            "parallel": r["parallel"],
            "padding_mode": r["padding_mode"],
            "resolver_mode": r["resolver_mode"],
            "success": r["success"],
            "pcap_file": r["pcap_file"],
            "browser_log": r["browser_log"],
            **features,
        })

    with open(OUT, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FEATURE_FIELDS)
        writer.writeheader()
        writer.writerows(out_rows)

    print(f"Wrote {OUT}")
    print(f"rows={len(out_rows)}")
    print(f"client_ip={client_ip}")


if __name__ == "__main__":
    main()
