#!/bin/bash
set -a
source .env
set +a

mkdir -p sources/bcf_fw
envsubst < ingest_trends.sql | duckdb