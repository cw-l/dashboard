#!/bin/bash
# Load .env if it exists (local dev), skip in CI
if [ -f .env ]; then
  set -a
  source .env
  set +a
fi

# Debug: check vars are set (masked in logs)
echo "ENDPOINT is set: ${EVIDENCE_S3_ENDPOINT:+yes}"
echo "KEY is set: ${EVIDENCE_S3_ACCESS_KEY_ID:+yes}"
echo "SECRET is set: ${EVIDENCE_S3_SECRET_ACCESS_KEY:+yes}"
echo "BUCKET is set: ${EVIDENCE_S3_BUCKET_NAME:+yes}"

mkdir -p sources/bcf_fw

# Debug: show substituted SQL
envsubst < ingest_trends.sql

# Run DuckDB
envsubst < ingest_trends.sql | duckdb