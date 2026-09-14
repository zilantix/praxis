#!/usr/bin/env bash
set -euo pipefail

PREFIX="${1:-RQ8C_RQ3}"
N="${2:-1}"

LOG="/opt/praxis/solution/reports/phase21_rq3_curl_sweep.log"
mkdir -p /opt/praxis/solution/reports

exec > >(tee -a "$LOG") 2>&1

echo "=== PRAXIS Phase 21 RQ3 curl sweep started ==="
echo "started_utc=$(date -u +%FT%TZ)"
echo "prefix=$PREFIX"
echo "sessions_per_mode=$N"
echo

for MODE in standard_dns_lab dns_blocked decentralized_resolution; do
  for i in $(seq 1 "$N"); do
    IDX="$(printf "%02d" "$i")"
    SESSION_ID="${PREFIX}_default_c2_p1_${MODE}_${IDX}"

    echo
    echo "============================================================"
    echo "Running $SESSION_ID"
    echo "mode=$MODE"
    echo "============================================================"

    /opt/praxis/bin/run_praxis_cycle2_phase21_rq3_curl_session.sh \
      "$SESSION_ID" \
      "default_c2_p1" \
      "c2" \
      "$MODE"
  done
done

echo
echo "=== PRAXIS Phase 21 RQ3 curl sweep completed ==="
echo "completed_utc=$(date -u +%FT%TZ)"
