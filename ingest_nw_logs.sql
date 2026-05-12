INSTALL json;
LOAD json;
INSTALL parquet;
LOAD parquet;
INSTALL httpfs;
LOAD httpfs;

SET s3_access_key_id = '${LOGS_R2_R_ACCESS_KEY}';
SET s3_secret_access_key = '${LOGS_R2_R_SECRET_KEY}';
SET s3_endpoint = '${R2_ENDPOINT}';
SET s3_url_style = 'vhost';
SET s3_region = 'auto';
SET s3_use_ssl = true;




-- Stage 0a: Create temp table containing all client IPs
CREATE TEMP TABLE excluded_ips AS
SELECT TRIM(UNNEST(STRING_SPLIT('${EXCLUDED_IPS}', ','))) AS clientIP;

CREATE TEMP TABLE all_ips AS
WITH regular_ips AS (
    SELECT DISTINCT clientIP
    FROM read_json_auto('s3://${LOGS_R2_BUCKET_NAME}/firewall/**/*.json', union_by_name=true, ignore_errors=true)
    WHERE clientIP NOT IN (SELECT clientIP FROM excluded_ips)
    UNION
    SELECT DISTINCT clientIP
    FROM read_json_auto('s3://${LOGS_R2_BUCKET_NAME}/http/**/*.json', union_by_name=true, ignore_errors=true)
    WHERE clientIP NOT IN (SELECT clientIP FROM excluded_ips)
),
incident_ips AS (
    SELECT DISTINCT src_ip AS clientIP
    FROM read_json('s3://${LOGS_R2_BUCKET_NAME}/incident/**/*.json', union_by_name=true, ignore_errors=true)
    WHERE src_ip NOT IN (SELECT clientIP FROM excluded_ips)
)
SELECT
    clientIP,
    clientIP IN (SELECT clientIP FROM incident_ips) AS is_incident
FROM (
    SELECT clientIP FROM regular_ips
    UNION
    SELECT clientIP FROM incident_ips
) combined;


-- Credentials for TIF_R2_BUCKET_NAME
SET s3_access_key_id = '${TIF_R2_R_ACCESS_KEY}';
SET s3_secret_access_key = '${TIF_R2_R_SECRET_KEY}';

-- Stage 0c: Enrich ISO country code with country names
CREATE TEMP TABLE iso_countries AS
SELECT TRIM(Code) AS country_code, MIN(TRIM(Name)) AS country_name
FROM read_csv('s3://${TIF_R2_BUCKET_NAME}/DataHub.csv', header=true)
GROUP BY TRIM(Code);

-- Stage 0d: Consensus threat scoring from threat intel feeds
CREATE TEMP TABLE ip_threat_score AS
WITH
    feed_abuseipdb    AS (SELECT TRIM(column0) AS ip FROM read_csv('s3://${TIF_R2_BUCKET_NAME}/AbuseIPDB.txt', header=false, columns={column0: 'VARCHAR'})),
    feed_binarydefense AS (SELECT TRIM(column0) AS ip FROM read_csv('s3://${TIF_R2_BUCKET_NAME}/BinaryDefense.txt', header=false, columns={column0: 'VARCHAR'})),
    feed_blocklist    AS (SELECT TRIM(column0) AS ip FROM read_csv('s3://${TIF_R2_BUCKET_NAME}/Blocklist.txt', header=false, columns={column0: 'VARCHAR'})),
    feed_cinsarmy     AS (SELECT TRIM(column0) AS ip FROM read_csv('s3://${TIF_R2_BUCKET_NAME}/CINSArmyList.txt', header=false, columns={column0: 'VARCHAR'})),
    feed_emergingt    AS (SELECT TRIM(column0) AS ip FROM read_csv('s3://${TIF_R2_BUCKET_NAME}/EmergingThreats.txt', header=false, columns={column0: 'VARCHAR'})),
    feed_spamhaus     AS (
        SELECT TRIM(column0) AS cidr
        FROM read_csv('s3://${TIF_R2_BUCKET_NAME}/SpamhausDROP.txt', header=false, columns={column0: 'VARCHAR'})
        WHERE TRIM(column0) != ''
    )
SELECT DISTINCT ON (e.clientIP)
    e.clientIP,
    (
        (e.clientIP IN (SELECT ip FROM feed_abuseipdb))::INTEGER +
        (e.clientIP IN (SELECT ip FROM feed_binarydefense))::INTEGER +
        (e.clientIP IN (SELECT ip FROM feed_blocklist))::INTEGER +
        (e.clientIP IN (SELECT ip FROM feed_cinsarmy))::INTEGER +
        (e.clientIP IN (SELECT ip FROM feed_emergingt))::INTEGER +
        (EXISTS (SELECT 1 FROM feed_spamhaus WHERE e.clientIP::INET <<= cidr::INET))::INTEGER +
        (e.clientIP IN (SELECT clientIP FROM all_ips WHERE is_incident))::INTEGER
    ) AS threat_score,
    NULLIF(ARRAY_TO_STRING(LIST_FILTER([
        CASE WHEN e.clientIP IN (SELECT ip FROM feed_abuseipdb)      THEN 'AbuseIPDB'                            END,
        CASE WHEN e.clientIP IN (SELECT ip FROM feed_binarydefense)   THEN 'BinaryDefense'                       END,
        CASE WHEN e.clientIP IN (SELECT ip FROM feed_blocklist)       THEN 'Blocklist'                           END,
        CASE WHEN e.clientIP IN (SELECT ip FROM feed_cinsarmy)        THEN 'CINSArmyList'                        END,
        CASE WHEN e.clientIP IN (SELECT ip FROM feed_emergingt)       THEN 'EmergingThreats'                     END,
        CASE WHEN EXISTS (SELECT 1 FROM feed_spamhaus WHERE e.clientIP::INET <<= cidr::INET) THEN 'SpamhausDROP' END,
        CASE WHEN e.clientIP IN (SELECT clientIP FROM all_ips WHERE is_incident) THEN 'BCFS'                     END
    ], x -> x IS NOT NULL), ' | '), '') AS matched_feeds
FROM all_ips e;


-- Load LOGS_R2_BUCKET_NAME credentials
SET s3_access_key_id = '${LOGS_R2_R_ACCESS_KEY}';
SET s3_secret_access_key = '${LOGS_R2_R_SECRET_KEY}';

-- Stage 1: Enrich with threat score and matched feeds, write firewall.parquet
COPY (
  SELECT
    f.*,
    c.country_name,
    t.threat_score,
    t.matched_feeds,
    CASE
      WHEN userAgent IS NULL OR trim(userAgent) = '' THEN 'Unknown'
      -- Bots (check first)
      WHEN userAgent ILIKE '%claudebot%' OR userAgent ILIKE '%claude-searchbot%' THEN 'ClaudeBot'
      WHEN userAgent ILIKE '%googlebot%' OR userAgent ILIKE '%googlebot-mobile%' THEN 'Googlebot'
      WHEN userAgent ILIKE '%bingbot%' THEN 'Bingbot'
      WHEN userAgent ILIKE '%ahrefsbot%' THEN 'AhrefsBot'
      WHEN userAgent ILIKE '%semrushbot%' THEN 'SemrushBot'
      WHEN userAgent ILIKE '%dotbot%' THEN 'DotBot'
      WHEN userAgent ILIKE '%mj12bot%' THEN 'MJ12Bot'
      WHEN userAgent ILIKE '%yandexbot%' THEN 'YandexBot'
      WHEN userAgent ILIKE '%baiduspider%' THEN 'Baiduspider'
      WHEN userAgent ILIKE '%facebookexternalhit%' THEN 'FacebookBot'
      WHEN userAgent ILIKE '%twitterbot%' THEN 'TwitterBot'
      WHEN userAgent ILIKE '%bot%' OR userAgent ILIKE '%crawler%' OR userAgent ILIKE '%spider%' THEN 'Other Bot'
      -- Browsers (specific before generic)
      WHEN userAgent ILIKE '%vivaldi%' THEN 'Vivaldi'
      WHEN userAgent ILIKE '%ucbrowser%' THEN 'UC Browser'
      WHEN userAgent ILIKE '%samsungbrowser%' THEN 'Samsung Internet'
      WHEN userAgent ILIKE '%brave%' THEN 'Brave'
      WHEN userAgent ILIKE '%yabrowser%' THEN 'Yandex'
      WHEN userAgent ILIKE '%opr/%' OR userAgent ILIKE '%opera%' THEN 'Opera'
      WHEN userAgent ILIKE '%edg/%' OR userAgent ILIKE '%edge/%' THEN 'Edge'
      WHEN userAgent ILIKE '%firefox%' THEN 'Firefox'
      WHEN userAgent ILIKE '%chrome%' THEN 'Chrome'
      WHEN userAgent ILIKE '%safari%' AND userAgent NOT ILIKE '%chrome%' THEN 'Safari'
      ELSE 'Unknown'
    END AS uaBrowser,
    CASE
      WHEN userAgent IS NULL OR trim(userAgent) = '' THEN 'Unknown'
      WHEN userAgent ILIKE '%android%' THEN 'Android'
      WHEN userAgent ILIKE '%iphone%' OR userAgent ILIKE '%ipad%' THEN 'iOS'
      WHEN userAgent ILIKE '%mac os x%' OR userAgent ILIKE '%macintosh%' THEN 'macOS'
      WHEN userAgent ILIKE '%windows%' THEN 'Windows'
      WHEN userAgent ILIKE '%cros%' THEN 'ChromeOS'
      WHEN userAgent ILIKE '%linux%' THEN 'Linux'
      WHEN userAgent ILIKE '%freebsd%' THEN 'FreeBSD'
      ELSE 'Unknown'
    END AS uaOS,
    CASE
      WHEN userAgent IS NULL OR trim(userAgent) = '' THEN 'Unknown'
      WHEN userAgent ILIKE '%claudebot%' OR userAgent ILIKE '%googlebot%' OR userAgent ILIKE '%bingbot%'
        OR userAgent ILIKE '%bot%' OR userAgent ILIKE '%crawler%' OR userAgent ILIKE '%spider%' THEN 'Bot'
      WHEN userAgent ILIKE '%smart-tv%' OR userAgent ILIKE '%smarttv%' OR userAgent ILIKE '%hbbtv%'
        OR userAgent ILIKE '%roku%' OR userAgent ILIKE '%apple tv%' OR userAgent ILIKE '%netcast%' THEN 'Smart TV'
      WHEN userAgent ILIKE '%ipad%' THEN 'Tablet'
      WHEN userAgent ILIKE '%mobile%' OR userAgent ILIKE '%iphone%' OR userAgent ILIKE '%android%' THEN 'Mobile'
      ELSE 'Desktop'
    END AS uaDevice
  FROM (
    SELECT * FROM read_json_auto('s3://${LOGS_R2_BUCKET_NAME}/firewall/**/*.json', union_by_name=true, ignore_errors=true)
    WHERE clientIP NOT IN (SELECT clientIP FROM excluded_ips)
    QUALIFY ROW_NUMBER() OVER (
        PARTITION BY zone, clientAsn, clientASNDescription, clientCountryName, clientIP, clientIPClass, 
            clientRefererHost, clientRequestHTTPMethodName, clientRequestHTTPProtocol, clientRequestPath,
            clientRequestQuery, datetime, edgeResponseStatus, userAgent, verifiedBotCategory,
            action, source, rayName
        ORDER BY datetime
    ) = 1
  ) f
  LEFT JOIN iso_countries c ON c.country_code = f.clientCountryName
  LEFT JOIN ip_threat_score t ON t.clientIP = f.clientIP
) TO 'sources/bcf_nw/firewall.parquet' (FORMAT PARQUET);

-- Stage 2: Enrich with threat score and matched feeds, write http.parquet
COPY (
  SELECT
    f.*,
    c.country_name,
    t.threat_score,
    t.matched_feeds,    
    CASE
      WHEN userAgent IS NULL OR trim(userAgent) = '' THEN 'Unknown'
      -- Bots (check first)
      WHEN userAgent ILIKE '%claudebot%' OR userAgent ILIKE '%claude-searchbot%' THEN 'ClaudeBot'
      WHEN userAgent ILIKE '%googlebot%' OR userAgent ILIKE '%googlebot-mobile%' THEN 'Googlebot'
      WHEN userAgent ILIKE '%bingbot%' THEN 'Bingbot'
      WHEN userAgent ILIKE '%ahrefsbot%' THEN 'AhrefsBot'
      WHEN userAgent ILIKE '%semrushbot%' THEN 'SemrushBot'
      WHEN userAgent ILIKE '%dotbot%' THEN 'DotBot'
      WHEN userAgent ILIKE '%mj12bot%' THEN 'MJ12Bot'
      WHEN userAgent ILIKE '%yandexbot%' THEN 'YandexBot'
      WHEN userAgent ILIKE '%baiduspider%' THEN 'Baiduspider'
      WHEN userAgent ILIKE '%facebookexternalhit%' THEN 'FacebookBot'
      WHEN userAgent ILIKE '%twitterbot%' THEN 'TwitterBot'
      WHEN userAgent ILIKE '%bot%' OR userAgent ILIKE '%crawler%' OR userAgent ILIKE '%spider%' THEN 'Other Bot'
      -- Browsers (specific before generic)
      WHEN userAgent ILIKE '%vivaldi%' THEN 'Vivaldi'
      WHEN userAgent ILIKE '%ucbrowser%' THEN 'UC Browser'
      WHEN userAgent ILIKE '%samsungbrowser%' THEN 'Samsung Internet'
      WHEN userAgent ILIKE '%brave%' THEN 'Brave'
      WHEN userAgent ILIKE '%yabrowser%' THEN 'Yandex'
      WHEN userAgent ILIKE '%opr/%' OR userAgent ILIKE '%opera%' THEN 'Opera'
      WHEN userAgent ILIKE '%edg/%' OR userAgent ILIKE '%edge/%' THEN 'Edge'
      WHEN userAgent ILIKE '%firefox%' THEN 'Firefox'
      WHEN userAgent ILIKE '%chrome%' THEN 'Chrome'
      WHEN userAgent ILIKE '%safari%' AND userAgent NOT ILIKE '%chrome%' THEN 'Safari'
      ELSE 'Unknown'
    END AS uaBrowser,
    CASE
      WHEN userAgent IS NULL OR trim(userAgent) = '' THEN 'Unknown'
      WHEN userAgent ILIKE '%android%' THEN 'Android'
      WHEN userAgent ILIKE '%iphone%' OR userAgent ILIKE '%ipad%' THEN 'iOS'
      WHEN userAgent ILIKE '%mac os x%' OR userAgent ILIKE '%macintosh%' THEN 'macOS'
      WHEN userAgent ILIKE '%windows%' THEN 'Windows'
      WHEN userAgent ILIKE '%cros%' THEN 'ChromeOS'
      WHEN userAgent ILIKE '%linux%' THEN 'Linux'
      WHEN userAgent ILIKE '%freebsd%' THEN 'FreeBSD'
      ELSE 'Unknown'
    END AS uaOS,
    CASE
      WHEN userAgent IS NULL OR trim(userAgent) = '' THEN 'Unknown'
      WHEN userAgent ILIKE '%claudebot%' OR userAgent ILIKE '%googlebot%' OR userAgent ILIKE '%bingbot%'
        OR userAgent ILIKE '%bot%' OR userAgent ILIKE '%crawler%' OR userAgent ILIKE '%spider%' THEN 'Bot'
      WHEN userAgent ILIKE '%smart-tv%' OR userAgent ILIKE '%smarttv%' OR userAgent ILIKE '%hbbtv%'
        OR userAgent ILIKE '%roku%' OR userAgent ILIKE '%apple tv%' OR userAgent ILIKE '%netcast%' THEN 'Smart TV'
      WHEN userAgent ILIKE '%ipad%' THEN 'Tablet'
      WHEN userAgent ILIKE '%mobile%' OR userAgent ILIKE '%iphone%' OR userAgent ILIKE '%android%' THEN 'Mobile'
      ELSE 'Desktop'
    END AS uaDevice
  FROM (
    SELECT * FROM read_json_auto('s3://${LOGS_R2_BUCKET_NAME}/http/**/*.json', union_by_name=true, ignore_errors=true)
    WHERE clientIP NOT IN (SELECT clientIP FROM excluded_ips)
    QUALIFY ROW_NUMBER() OVER (
        PARTITION BY zone, clientAsn, clientASNDescription, clientCountryName, clientIP,
            clientRequestHTTPMethodName, clientRequestHTTPProtocol, clientRequestPath,
            clientRequestQuery, datetime, edgeResponseStatus, userAgent, verifiedBotCategory
        ORDER BY datetime
    ) = 1
  ) f
  LEFT JOIN ip_threat_score t ON t.clientIP = f.clientIP
  LEFT JOIN iso_countries c ON c.country_code = f.clientCountryName
) TO 'sources/bcf_nw/http.parquet' (FORMAT PARQUET);

-- Stage 3: Confirmed honeytoken incidents
COPY (
  SELECT
    strptime(time, '%Y-%m-%d %H:%M:%S (UTC)')              AS timestamp,
    src_ip,
    token,
    token_type,
    channel,
    memo,
    -- Manual-only fields (NULL for webhook records)
    is_tor_relay,
    alert_status,
    -- Geo (nested under additional_data)
    c.country_name                                         AS country,
    additional_data->'geo_info'->>'city'                   AS city,
    additional_data->'geo_info'->>'region'                 AS region,
    additional_data->'geo_info'->>'timezone'               AS timezone,
    additional_data->'geo_info'->>'hostname'               AS hostname,
    additional_data->'geo_info'->'asn'->>'asn'             AS asn,
    additional_data->'geo_info'->'asn'->>'name'            AS asn_name,
    additional_data->'geo_info'->'asn'->>'type'            AS network_type,
    additional_data->'geo_info'->'asn'->>'domain'          AS domain,
    additional_data->>'useragent'                          AS useragent,
    additional_data->'request_headers'->>'Referer'         AS referer,
    CAST(additional_data->'additional_info'->'aws_key_log_data'->'eventName' AS VARCHAR[]) AS aws_events,
    t.threat_score,
    t.matched_feeds
  FROM (
      SELECT * FROM read_json(
          's3://${LOGS_R2_BUCKET_NAME}/incident/**/*.json',
          union_by_name=true,
          ignore_errors=true
      )
      WHERE src_ip NOT IN (SELECT clientIP FROM excluded_ips)
  ) raw
  LEFT JOIN iso_countries c ON c.country_code = (additional_data->'geo_info'->>'country')
  LEFT JOIN ip_threat_score t ON t.clientIP = raw.src_ip
  ORDER BY timestamp DESC
) TO 'sources/bcf_nw/incidents.parquet' (FORMAT PARQUET);
