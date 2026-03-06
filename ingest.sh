#!/bin/bash
# Load .env if it exists (local dev), skip in CI
if [ -f .env ]; then
  set -a
  source .env
  set +a
fi

mkdir -p sources/bcf_fw

# Run DuckDB
envsubst < ingest_trends.sql | duckdb

# Upload malicious_paths.parquet to R2
export AWS_ACCESS_KEY_ID=${MALICIOUS_S3_ACCESS_KEY_ID}
export AWS_SECRET_ACCESS_KEY=${MALICIOUS_S3_SECRET_ACCESS_KEY}

aws s3 cp malicious_paths.parquet s3://${EVIDENCE_S3_BUCKET_NAME}/malicious_paths.parquet \
  --endpoint-url https://${EVIDENCE_S3_ENDPOINT} \
  --region auto

# Delete local file
rm malicious_paths.parquet