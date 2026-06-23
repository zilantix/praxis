#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export PRAXIS_DATA_DIR="${PRAXIS_DATA_DIR:-$REPO_ROOT/examples}"
export PYTHONPATH="$REPO_ROOT/app/lib"

uvicorn praxis_api:app \
  --app-dir "$REPO_ROOT/app/api" \
  --host 127.0.0.1 \
  --port 8088
