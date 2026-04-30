---
title: Members 
---


```sql incident_type
SELECT
    token_type AS incident_type,
    REGEXP_REPLACE(src_ip, '(\\d+)\\.(\\d+)\\.\\d+\\.\\d+', '\\1.\\2.x.x') AS attacker,
    threat_score,
    matched_feeds,
    strftime(MIN(timestamp), '%Y-%m-%d %H:%M:%S') AS first_seen,
    strftime(MAX(timestamp), '%Y-%m-%d %H:%M:%S') AS last_seen,
    CASE
        WHEN DATEDIFF('second', MIN(timestamp), MAX(timestamp)) < 1
            THEN DATEDIFF('millisecond', MIN(timestamp), MAX(timestamp))::VARCHAR || 'ms'
        WHEN DATEDIFF('second', MIN(timestamp), MAX(timestamp)) < 60
            THEN DATEDIFF('second', MIN(timestamp), MAX(timestamp))::VARCHAR || 's'
        WHEN DATEDIFF('minute', MIN(timestamp), MAX(timestamp)) < 60
            THEN DATEDIFF('minute', MIN(timestamp), MAX(timestamp))::VARCHAR || 'm'
        WHEN DATEDIFF('hour', MIN(timestamp), MAX(timestamp)) < 24
            THEN DATEDIFF('hour', MIN(timestamp), MAX(timestamp))::VARCHAR || 'h'
        ELSE
            DATEDIFF('day', MIN(timestamp), MAX(timestamp))::VARCHAR || 'd'
    END AS active_duration,
    LIST(DISTINCT city) AS cities,
    LIST(DISTINCT network_type) AS network_types,
    LIST(DISTINCT asn_name) AS asn_names,
    BOOL_OR(is_tor_relay) AS any_tor
FROM bcf_nw.incidents
GROUP BY token, token_type, attacker, threat_score, matched_feeds
ORDER BY incident_type ASC, first_seen ASC, attacker ASC;
```

```sql attackers
SELECT
    REGEXP_REPLACE(src_ip, '(\\d+)\\.(\\d+)\\.\\d+\\.\\d+', '\\1.\\2.x.x') AS attacker,
    threat_score,
    matched_feeds,
    useragent,
    country,
    region,
    city,
    asn_name,
    network_type
FROM (
    SELECT *, ROW_NUMBER() OVER (PARTITION BY src_ip ORDER BY timestamp DESC) AS rn
    FROM bcf_nw.incidents
)
WHERE rn = 1
ORDER BY threat_score DESC
```

```sql attack_path
SELECT
    REGEXP_REPLACE(src_ip, '(\\d+)\\.(\\d+)\\.\\d+\\.\\d+', '\\1.\\2.x.x') AS attacker,
    token_type AS incident_type,
    threat_score,
    matched_feeds,
    strftime(MIN(timestamp), '%Y-%m-%d %H:%M:%S') AS first_seen,
    strftime(MAX(timestamp), '%Y-%m-%d %H:%M:%S') AS last_seen,
    CASE
        WHEN DATEDIFF('second', MIN(timestamp), MAX(timestamp)) < 1
            THEN DATEDIFF('millisecond', MIN(timestamp), MAX(timestamp))::VARCHAR || 'ms'
        WHEN DATEDIFF('second', MIN(timestamp), MAX(timestamp)) < 60
            THEN DATEDIFF('second', MIN(timestamp), MAX(timestamp))::VARCHAR || 's'
        WHEN DATEDIFF('minute', MIN(timestamp), MAX(timestamp)) < 60
            THEN DATEDIFF('minute', MIN(timestamp), MAX(timestamp))::VARCHAR || 'm'
        WHEN DATEDIFF('hour', MIN(timestamp), MAX(timestamp)) < 24
            THEN DATEDIFF('hour', MIN(timestamp), MAX(timestamp))::VARCHAR || 'h'
        ELSE
            DATEDIFF('day', MIN(timestamp), MAX(timestamp))::VARCHAR || 'd'
    END AS active_duration,
    LIST(aws_events ORDER BY timestamp ASC) AS attack_sequence,
    LIST(DISTINCT city) AS cities,
    LIST(DISTINCT network_type) AS network_types,
    LIST(DISTINCT asn_name) AS asn_names,
    BOOL_OR(is_tor_relay) AS any_tor
FROM bcf_nw.incidents
GROUP BY attacker, token, token_type, threat_score, matched_feeds
ORDER BY first_seen ASC;
```

```sql high_entropy
WITH unique_paths AS (
    /* Identify unique paths to calculate entropy ONLY ONCE per string */
    SELECT DISTINCT clientRequestPath 
    FROM bcf_nw.http 
    WHERE len(clientRequestPath) > 5
),
path_chars AS (
    /* Breakdown unique strings into characters */
    SELECT 
        clientRequestPath,
        unnest(string_split(clientRequestPath, '')) AS char_val,
        len(clientRequestPath) AS total_len
    FROM unique_paths
),
char_frequencies AS (
    /* Calculate probability of each character within that specific string */
    SELECT 
        clientRequestPath,
        char_val,
        count(*) AS char_count,
        MAX(total_len) AS total_len
    FROM path_chars
    WHERE char_val != ''  -- guard against empty string split artifact
    GROUP BY 1, 2
),
entropy_map AS (
    /* The true Shannon Entropy (Bits per Character) */
    SELECT 
        clientRequestPath,
        -SUM((char_count::DOUBLE / total_len) * log2(char_count::DOUBLE / total_len)) AS entropy_score
    FROM char_frequencies
    GROUP BY 1
)
/* Final Harvest - Aggregating by path to identify shared infrastructure (Blocks) */
SELECT 
    i.clientRequestPath AS request_path,
    ROUND(e.entropy_score, 3) AS entropy,
    --COUNT(*) AS total_hit_count,
    COUNT(DISTINCT i.clientIP) AS unique_bot_count,
    STRING_AGG(DISTINCT i.edgeResponseStatus::INTEGER::VARCHAR, ', ') AS response_codes,
    LIST(DISTINCT REGEXP_REPLACE(i.clientIP, '(\\d+)\\.(\\d+)\\.\\d+\\.\\d+', '\\1.\\2.x.x')) AS attackers,    
    LIST(DISTINCT i.as_name) FILTER (WHERE i.as_name IS NOT NULL AND i.as_name != '') AS providers,
    strftime(MIN(i.datetime), '%Y-%m-%d %H:%M:%S') AS first_seen,
    strftime(MAX(i.datetime), '%Y-%m-%d %H:%M:%S') AS last_seen,
FROM bcf_nw.http i
JOIN entropy_map e ON i.clientRequestPath = e.clientRequestPath
GROUP BY i.clientRequestPath, e.entropy_score
HAVING entropy > 4.2 
   AND unique_bot_count > 1  -- This pulls out the "blocks" shared by different IPs
ORDER BY unique_bot_count DESC, entropy DESC;
```


## Incident Type
<DataTable data={incident_type}/>

## Attackers
<DataTable data={attackers}/>

## Attack Path
<DataTable data={attack_path}/>

## High Entropy Path
<DataTable data={high_entropy}/>