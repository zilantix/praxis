#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export PRAXIS_DATA_DIR="${PRAXIS_DATA_DIR:-$REPO_ROOT/examples}"
export PYTHONPATH="$REPO_ROOT/app/lib"

streamlit run "$REPO_ROOT/app/ui/praxis_dashboard.py" \
  --server.address 127.0.0.1 \
  --server.port 8501 \
  --server.headless true \
  --server.maxUploadSize 1024
