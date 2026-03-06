INSTALL json;
LOAD json;
INSTALL parquet;
LOAD parquet;
INSTALL httpfs;
LOAD httpfs;

SET s3_access_key_id = '${EVIDENCE_S3_ACCESS_KEY_ID}';
SET s3_secret_access_key = '${EVIDENCE_S3_SECRET_ACCESS_KEY}';
SET s3_endpoint = '${EVIDENCE_S3_ENDPOINT}';
SET s3_url_style = 'vhost';
SET s3_region = 'auto';
SET s3_use_ssl = true;

COPY (
  SELECT * FROM read_json_auto(
    's3://${EVIDENCE_S3_BUCKET_NAME}/**/*.json',
    union_by_name=true,
    ignore_errors=true
  )
) TO 'sources/bcf_fw/trends.parquet' (FORMAT PARQUET);

-- Stage 1: Extract high value paths not in SecLists
COPY (
  SELECT *
  FROM read_parquet('sources/bcf_fw/trends.parquet')
  WHERE clientRequestPath IS NOT NULL
    AND trim(clientRequestPath) != '/'
    AND clientRequestPath NOT IN (
      SELECT '/' || trim(column0)
      FROM read_csv(
        'https://raw.githubusercontent.com/cw-l/SecLists/master/Discovery/Web-Content/raft-large-files.txt',
        header=false, columns={'column0': 'VARCHAR'}, delim='\n'
      )
      UNION
      SELECT '/' || trim(column0)
      FROM read_csv(
        'https://raw.githubusercontent.com/cw-l/SecLists/master/Discovery/Web-Content/raft-large-directories.txt',
        header=false, columns={'column0': 'VARCHAR'}, delim='\n'
      )
    )
) TO 'malicious_paths.parquet' (FORMAT PARQUET);