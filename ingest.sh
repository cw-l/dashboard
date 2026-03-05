#!/bin/bash
# Load .env if it exists (local dev), skip in CI
if [ -f .env ]; then
  set -a
  source .env
  set +a
fi

mkdir -p sources/bcf_fw

# Debug: show substituted SQL
envsubst < ingest_trends.sql

# Run DuckDB
envsubst < ingest_trends.sql | duckdb