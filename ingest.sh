#!/bin/bash
set -e

# Load .env if it exists (local dev), skip in CI
if [ -f .env ]; then
  set -a
  source .env
  set +a
fi

mkdir -p sources/bcf_nw

# ── Download MMDB files from threat-intel-feeds R2 bucket ────────────────────
echo "Downloading MMDB filess..."

export AWS_ACCESS_KEY_ID=${TIF_R2_R_ACCESS_KEY}
export AWS_SECRET_ACCESS_KEY=${TIF_R2_R_SECRET_KEY}

aws s3 cp s3://${TIF_R2_BUCKET_NAME}/IP2LOCATION-LITE-DB11.MMDB /tmp/db11.mmdb \
  --endpoint-url https://${R2_ENDPOINT} \
  --region auto

aws s3 cp s3://${TIF_R2_BUCKET_NAME}/IP2PROXY-LITE-PX11.MMDB /tmp/px11.mmdb \
  --endpoint-url https://${R2_ENDPOINT} \
  --region auto

echo "MMDBs ready."

# Set MMDB paths for envsubst
export DB11_MMDB_PATH=/tmp/db11.mmdb
export PX11_MMDB_PATH=/tmp/px11.mmdb

# ── Run DuckDB ────────────────────────────────────────────────────────────────
echo "Running DuckDB ingest..."
envsubst < ingest_nw_logs.sql | duckdb

rm /tmp/db11.mmdb
rm /tmp/px11.mmdb

echo "Done."