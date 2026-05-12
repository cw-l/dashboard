#!/bin/bash
set -e

# Load .env if it exists (local dev), skip in CI
if [ -f .env ]; then
  set -a
  source .env
  set +a
fi

mkdir -p sources/bcf_nw

# ── Run DuckDB ────────────────────────────────────────────────────────────────
echo "Running DuckDB ingest..."
envsubst < ingest_nw_logs.sql | duckdb

echo "Done."