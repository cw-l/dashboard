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

-- Stage 0a: Build IP enrichment lookup from MMDB files
-- PX11 takes priority for country/geo; DB11 fills in for non-proxy IPs
CREATE TEMP TABLE ip_enrichment AS
SELECT
    clientIP,
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
FROM (
    SELECT clientIP FROM read_json_auto('s3://${LOGS_R2_BUCKET_NAME}/firewall/**/*.json', union_by_name=true, ignore_errors=true)
    UNION
    SELECT clientIP FROM read_json_auto('s3://${LOGS_R2_BUCKET_NAME}/http/**/*.json', union_by_name=true, ignore_errors=true)
) ips;


-- Stage 0b: Confirmed attackers from incidents
CREATE TEMP TABLE confirmed_attackers AS
SELECT DISTINCT src_ip AS clientIP
FROM read_json('s3://${LOGS_R2_BUCKET_NAME}/incident/**/*.json');

-- Credentials for TIF_R2_BUCKET_NAME
SET s3_access_key_id = '${TIF_R2_R_ACCESS_KEY}';
SET s3_secret_access_key = '${TIF_R2_R_SECRET_KEY}';

-- Stage 0c: Consensus threat scoring from TXT threat intel feeds
CREATE TEMP TABLE ip_threat_score AS
WITH
    feed_abuseipdb AS (SELECT TRIM(column0) AS ip FROM read_csv('s3://${TIF_R2_BUCKET_NAME}/AbuseIPDB.txt', header=false, columns={column0: 'VARCHAR'})),
    feed_emergingt AS (SELECT TRIM(column0) AS ip FROM read_csv('s3://${TIF_R2_BUCKET_NAME}/EmergingThreats.txt', header=false, columns={column0: 'VARCHAR'})),
    feed_blocklist AS (SELECT TRIM(column0) AS ip FROM read_csv('s3://${TIF_R2_BUCKET_NAME}/Blocklist.txt', header=false, columns={column0: 'VARCHAR'})),
    feed_cinsarmy  AS (SELECT TRIM(column0) AS ip FROM read_csv('s3://${TIF_R2_BUCKET_NAME}/CINSArmyList.txt',  header=false, columns={column0: 'VARCHAR'}))
SELECT
    clientIP,
    (
        (clientIP IN (SELECT ip FROM feed_abuseipdb))::INTEGER +
        (clientIP IN (SELECT ip FROM feed_emergingt))::INTEGER +
        (clientIP IN (SELECT ip FROM feed_blocklist))::INTEGER +
        (clientIP IN (SELECT ip FROM feed_cinsarmy))::INTEGER +
        (e.threat IS NOT NULL)::INTEGER +
        (clientIP IN (SELECT clientIP FROM confirmed_attackers))::INTEGER  -- BCFS
    ) AS threat_score,
    NULLIF(ARRAY_TO_STRING(LIST_FILTER([
        CASE WHEN clientIP IN (SELECT ip FROM feed_abuseipdb) THEN 'AbuseIPDB'       END,
        CASE WHEN clientIP IN (SELECT ip FROM feed_emergingt) THEN 'EmergingThreats' END,
        CASE WHEN clientIP IN (SELECT ip FROM feed_blocklist) THEN 'Blocklist'       END,
        CASE WHEN clientIP IN (SELECT ip FROM feed_cinsarmy)  THEN 'CINSArmyList'    END,
        CASE WHEN e.threat IS NOT NULL THEN 'IP2Location'                            END,
        CASE WHEN clientIP IN (SELECT clientIP FROM confirmed_attackers) THEN 'BCFS' END
    ], x -> x IS NOT NULL), ' | '), '') AS matched_feeds
FROM (
    SELECT DISTINCT clientIP, threat FROM ip_enrichment
    UNION
    SELECT clientIP, NULL AS threat FROM confirmed_attackers
) e;


-- Load LOGS_R2_BUCKET_NAME credentials
SET s3_access_key_id = '${LOGS_R2_R_ACCESS_KEY}';
SET s3_secret_access_key = '${LOGS_R2_R_SECRET_KEY}';

-- Stage 1: Deduplicate raw logs, enrich with MMDB data, write firewall.parquet
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
    -- Threat intel consensus
    t.threat_score,
    t.matched_feeds,
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
  LEFT JOIN ip_threat_score t ON t.clientIP = f.clientIP
  WHERE f.rn = 1
) TO 'sources/bcf_nw/firewall.parquet' (FORMAT PARQUET);

-- Stage 2: Enrich with MMDB data, write http.parquet
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
    -- Threat intel consensus
    t.threat_score,
    t.matched_feeds,    
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
    SELECT * FROM read_json_auto('s3://${LOGS_R2_BUCKET_NAME}/http/**/*.json', union_by_name=true, ignore_errors=true)
  ) f
  LEFT JOIN ip_enrichment e ON e.clientIP = f.clientIP
  LEFT JOIN ip_threat_score t ON t.clientIP = f.clientIP
) TO 'sources/bcf_nw/http.parquet' (FORMAT PARQUET);

-- Stage 3: Confirmed incidents
COPY (
  WITH raw AS (
    SELECT * FROM read_json('s3://${LOGS_R2_BUCKET_NAME}/incident/**/*.json')
  )
  SELECT
    to_timestamp(raw.time_of_hit)           AS timestamp,
    raw.src_ip,
    raw.is_tor_relay,
    raw.token_type,
    raw.alert_status,
    raw.geo_info->>'org'                    AS org,
    raw.geo_info->>'country'                AS country,
    raw.geo_info->>'city'                   AS city,
    raw.geo_info->>'region'                 AS region,
    raw.geo_info->>'timezone'               AS timezone,
    raw.geo_info->>'hostname'               AS hostname,
    raw.geo_info->'asn'->>'asn'             AS asn,
    raw.geo_info->'asn'->>'name'            AS asn_name,
    raw.geo_info->'asn'->>'type'            AS network_type,
    raw.geo_info->'asn'->>'domain'          AS domain,
    raw.additional_info->'aws_key_log_data'->>'eventName' AS aws_events,
    t.threat_score,
    t.matched_feeds
  FROM raw
  LEFT JOIN ip_threat_score t ON t.clientIP = raw.src_ip
  ORDER BY raw.time_of_hit DESC
) TO 'sources/bcf_nw/incidents.parquet' (FORMAT PARQUET);