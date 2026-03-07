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

-- Stage 0: Build lookups
CREATE TEMP TABLE country_lookup AS
  SELECT "alpha-2" AS country_code, name AS country_name
  FROM read_csv_auto(
    'https://raw.githubusercontent.com/cw-l/ISO-3166-Countries-with-Regional-Codes/master/all/all.csv'
  )
  UNION ALL
  SELECT * FROM (VALUES
    ('XX', 'Unknown'),
    ('T1', 'Tor Network')
  ) AS cf(country_code, country_name);

CREATE TEMP TABLE asn_lookup AS
  SELECT
    column2 AS asn,
    column3 AS asn_name
  FROM read_csv_auto(
    'https://raw.githubusercontent.com/sapics/ip-location-db/main/asn/asn-ipv4.csv',
    header=false
  );

COPY (
  SELECT
    f.*,
    COALESCE(c.country_name, f.clientCountryName) AS isoCountryName,
    COALESCE(a.asn_name, f.clientAsn) AS clientAsnName,
    CASE
      WHEN userAgent IS NULL OR trim(userAgent) = '' THEN 'Unknown'
      WHEN userAgent ILIKE '%claudebot%' OR userAgent ILIKE '%claude-searchbot%' THEN 'Bot'
      WHEN userAgent ILIKE '%yabrowser%' THEN 'Yandex'
      WHEN userAgent ILIKE '%edg/%' OR userAgent ILIKE '%edge/%' THEN 'Edge'
      WHEN userAgent ILIKE '%opr/%' OR userAgent ILIKE '%opera%' THEN 'Opera'
      WHEN userAgent ILIKE '%firefox%' THEN 'Firefox'
      WHEN userAgent ILIKE '%chrome%' THEN 'Chrome'
      WHEN userAgent ILIKE '%safari%' THEN 'Safari'
      ELSE 'Unknown'
    END AS uaBrowser,
    CASE
      WHEN userAgent IS NULL OR trim(userAgent) = '' THEN 'Unknown'
      WHEN userAgent ILIKE '%android%' THEN 'Android'
      WHEN userAgent ILIKE '%iphone%' OR userAgent ILIKE '%ipad%' THEN 'iOS'
      WHEN userAgent ILIKE '%mac os x%' OR userAgent ILIKE '%macintosh%' THEN 'macOS'
      WHEN userAgent ILIKE '%cros%' THEN 'ChromeOS'
      WHEN userAgent ILIKE '%linux%' THEN 'Linux'
      WHEN userAgent ILIKE '%windows%' THEN 'Windows'
      ELSE 'Unknown'
    END AS uaOS,
    CASE
      WHEN userAgent IS NULL OR trim(userAgent) = '' THEN 'Unknown'
      WHEN userAgent ILIKE '%claudebot%' OR userAgent ILIKE '%claude-searchbot%' THEN 'Bot'
      WHEN userAgent ILIKE '%ipad%' THEN 'Tablet'
      WHEN userAgent ILIKE '%mobile%' OR userAgent ILIKE '%iphone%' OR userAgent ILIKE '%android%' THEN 'Mobile'
      ELSE 'Desktop'
    END AS uaDevice    
  FROM read_json_auto(
    's3://${EVIDENCE_S3_BUCKET_NAME}/**/*.json',
    union_by_name=true,
    ignore_errors=true
  ) f
  LEFT JOIN country_lookup c ON c.country_code = f.clientCountryName
  LEFT JOIN asn_lookup a ON a.asn = TRY_CAST(f.clientAsn AS INTEGER)
) TO 'sources/bcf_fw/trends.parquet' (FORMAT PARQUET);

-- Stage 1: Extract high value paths not in SecLists
COPY (
  SELECT *
  FROM read_parquet('sources/bcf_fw/trends.parquet')
  WHERE clientRequestPath IS NOT NULL
    AND regexp_replace(clientRequestPath, '\s+', '') != '/'
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