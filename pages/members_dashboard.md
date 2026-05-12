---
title: Members 
---


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

```sql incidents_summary
SELECT
    COALESCE(
        MAX(CASE 
            WHEN token_type = 'aws_keys' THEN 'Compromised AWS API Key'
            WHEN token_type = 'wireguard' THEN 'Compromised Wireguard VPN Client Config'
        END),
        'UC'
    ) AS incident_type,
    strftime(MIN(timestamp), '%Y-%m-%d %H:%M:%S') AS first_seen,
    strftime(MAX(timestamp), '%Y-%m-%d %H:%M:%S') AS last_seen,
    CASE
        WHEN date_diff('second', MIN(timestamp), MAX(timestamp)) < 1
            THEN date_diff('millisecond', MIN(timestamp), MAX(timestamp))::VARCHAR || 'ms'
        WHEN date_diff('second', MIN(timestamp), MAX(timestamp)) < 60
            THEN date_diff('second', MIN(timestamp), MAX(timestamp))::VARCHAR || 's'
        WHEN date_diff('minute', MIN(timestamp), MAX(timestamp)) < 60
            THEN date_diff('minute', MIN(timestamp), MAX(timestamp))::VARCHAR || 'm'
        WHEN date_diff('hour', MIN(timestamp), MAX(timestamp)) < 24
            THEN date_diff('hour', MIN(timestamp), MAX(timestamp))::VARCHAR || 'h'
        ELSE
            date_diff('day', MIN(timestamp), MAX(timestamp))::VARCHAR || 'd'
    END AS active_duration
FROM bcf_nw.incidents
GROUP BY token
ORDER BY first_seen ASC;
```

```sql aws_api_key_1_attack_chain
SELECT
    REGEXP_REPLACE(i.src_ip, '(\\d+)\\.(\\d+)\\.\\d+\\.\\d+', '\\1.\\2.x.x') AS attacker,
    COALESCE(MAX(CASE WHEN h.clientRequestPath = '/robots.txt' THEN '✓' END), '✗') AS via_robots_txt,
    COALESCE(MAX(CASE WHEN h.clientRequestPath = '/nguyen/nguyen_aws_creds_bak' THEN '✓' END), '✗') AS via_direct_path,
    strftime(MIN(i.timestamp), '%Y-%m-%d %H:%M:%S') AS first_seen,
    strftime(MAX(i.timestamp), '%Y-%m-%d %H:%M:%S') AS last_seen,
    CASE
        WHEN DATEDIFF('second', MIN(i.timestamp), MAX(i.timestamp)) < 1
            THEN DATEDIFF('millisecond', MIN(i.timestamp), MAX(i.timestamp))::VARCHAR || 'ms'
        WHEN DATEDIFF('second', MIN(i.timestamp), MAX(i.timestamp)) < 60
            THEN DATEDIFF('second', MIN(i.timestamp), MAX(i.timestamp))::VARCHAR || 's'
        WHEN DATEDIFF('minute', MIN(i.timestamp), MAX(i.timestamp)) < 60
            THEN DATEDIFF('minute', MIN(i.timestamp), MAX(i.timestamp))::VARCHAR || 'm'
        WHEN DATEDIFF('hour', MIN(i.timestamp), MAX(i.timestamp)) < 24
            THEN DATEDIFF('hour', MIN(i.timestamp), MAX(i.timestamp))::VARCHAR || 'h'
        ELSE
            DATEDIFF('day', MIN(i.timestamp), MAX(i.timestamp))::VARCHAR || 'd'
    END AS active_duration,
    LIST(i.aws_events ORDER BY i.timestamp ASC) AS attack_sequence
FROM bcf_nw.incidents i
LEFT JOIN bcf_nw.http h ON h.clientIP = i.src_ip
WHERE i.token = 'su6lxwiw15qy6gylx0s0323j1'
GROUP BY i.token, attacker
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
    --LIST(DISTINCT i.clientIP) AS attackers, 
    LIST(DISTINCT i.clientASNDescription) FILTER (WHERE i.clientASNDescription IS NOT NULL AND i.clientASNDescription != '') AS as_name,
    strftime(MIN(i.datetime), '%Y-%m-%d %H:%M:%S') AS first_seen,
    strftime(MAX(i.datetime), '%Y-%m-%d %H:%M:%S') AS last_seen,
FROM bcf_nw.http i
JOIN entropy_map e ON i.clientRequestPath = e.clientRequestPath
GROUP BY i.clientRequestPath, e.entropy_score
HAVING entropy > 4.2 
   AND unique_bot_count > 1  -- This pulls out the "blocks" shared by different IPs
ORDER BY unique_bot_count DESC, entropy DESC;
```


## Attackers
<DataTable data={attackers}/>

## Incidents
<DataTable data={incidents_summary}/>

## Attack Chain - AWS Token Compromise
<DataTable data={aws_api_key_1_attack_chain}/>

## High Entropy Path
<DataTable data={high_entropy}/>