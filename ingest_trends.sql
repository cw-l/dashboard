INSTALL json;
LOAD json;
INSTALL parquet;
LOAD parquet;
INSTALL httpfs;
LOAD httpfs;
INSTALL maxmind FROM community;
LOAD maxmind;

SET s3_access_key_id = '${LOGS_R2_R_ACCESS_KEY}';
SET s3_secret_access_key = '${LOGS_R2_R_SECRET_KEY}';
SET s3_endpoint = '${R2_ENDPOINT}';
SET s3_url_style = 'vhost';
SET s3_region = 'auto';
SET s3_use_ssl = true;

-- Stage 0: Build IP enrichment lookup from MMDB files
-- PX11 takes priority for country/geo; DB11 fills in for non-proxy IPs
CREATE TEMP TABLE ip_enrichment AS
SELECT DISTINCT
    clientIP,

    -- Geo: prefer PX11 (already has flat country fields), fall back to DB11
    COALESCE(
        NULLIF(mmdb_record('${DB11_MMDB_PATH}', clientIP, '')::json ->> 'country_name', '-'),
        mmdb_record('${DB11_MMDB_PATH}', clientIP, '')::json -> 'country' -> 'names' ->> 'en'
    ) AS country_name,
    COALESCE(
        NULLIF(mmdb_record('${DB11_MMDB_PATH}', clientIP, '')::json ->> 'country_code', '-'),
        mmdb_record('${DB11_MMDB_PATH}', clientIP, '')::json -> 'country' ->> 'iso_code'
    ) AS country_code,
    mmdb_record('${DB11_MMDB_PATH}', clientIP, '')::json -> 'subdivisions' -> 0 -> 'names' ->> 'en' AS region,
    mmdb_record('${DB11_MMDB_PATH}', clientIP, '')::json -> 'city' -> 'names' ->> 'en' AS city,
    (mmdb_record('${DB11_MMDB_PATH}', clientIP, '')::json -> 'location' ->> 'latitude')::DOUBLE AS latitude,
    (mmdb_record('${DB11_MMDB_PATH}', clientIP, '')::json -> 'location' ->> 'longitude')::DOUBLE AS longitude,
    mmdb_record('${DB11_MMDB_PATH}', clientIP, '')::json -> 'postal' ->> 'code' AS zip_code,
    mmdb_record('${DB11_MMDB_PATH}', clientIP, '')::json -> 'location' ->> 'time_zone' AS time_zone,

    -- Proxy fields from PX11 (NULL if IP not in proxy database)
    NULLIF(mmdb_record('${PX11_MMDB_PATH}', clientIP, '')::json ->> 'proxy_type', '-') AS proxy_type,
    NULLIF(mmdb_record('${PX11_MMDB_PATH}', clientIP, '')::json ->> 'isp', '-') AS isp,
    NULLIF(mmdb_record('${PX11_MMDB_PATH}', clientIP, '')::json ->> 'domain', '-') AS domain,
    NULLIF(mmdb_record('${PX11_MMDB_PATH}', clientIP, '')::json ->> 'usage_type', '-') AS usage_type,
    NULLIF(mmdb_record('${PX11_MMDB_PATH}', clientIP, '')::json ->> 'asn', '-') AS asn,
    NULLIF(mmdb_record('${PX11_MMDB_PATH}', clientIP, '')::json ->> 'as', '-') AS as_name,
    NULLIF(mmdb_record('${PX11_MMDB_PATH}', clientIP, '')::json ->> 'threat', '-') AS threat,
    NULLIF(mmdb_record('${PX11_MMDB_PATH}', clientIP, '')::json ->> 'provider', '-') AS provider,
    NULLIF(mmdb_record('${PX11_MMDB_PATH}', clientIP, '')::json ->> 'last_seen', '-') AS last_seen

FROM read_json_auto(
    's3://${LOGS_R2_BUCKET_NAME}/firewall/**/*.json',
    union_by_name=true,
    ignore_errors=true
);

-- Stage 1: Deduplicate raw logs, enrich with MMDB data, write trends.parquet
COPY (
  SELECT
    f.*,
    -- Enriched geo/proxy fields (replacing GitHub CSV country lookup)
    e.country_name AS isoCountryName,
    e.country_code AS isoCountryCode,
    e.region,
    e.city,
    e.latitude,
    e.longitude,
    e.zip_code,
    e.time_zone,
    e.proxy_type,
    e.isp,
    e.domain       AS ipDomain,
    e.usage_type,
    e.asn,
    e.as_name,
    e.threat,
    e.provider,
    e.last_seen,
    -- UA parsing (unchanged)
    f.clientASNDescription AS clientAsnName,
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
  FROM (
    SELECT *, ROW_NUMBER() OVER (PARTITION BY rayName ORDER BY datetime) AS rn
    FROM read_json_auto(
      's3://${LOGS_R2_BUCKET_NAME}/firewall/**/*.json',
      union_by_name=true,
      ignore_errors=true
    )
  ) f
  LEFT JOIN ip_enrichment e ON e.clientIP = f.clientIP
  WHERE f.rn = 1
) TO 'sources/bcf_fw/trends.parquet' (FORMAT PARQUET);

-- Stage 2: Extract high value paths not in SecLists
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