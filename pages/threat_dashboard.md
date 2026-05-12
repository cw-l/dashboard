---
title: Threat Intel 
---


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
LIMIT 10
```

```sql aws_api_key__1_incident
SELECT
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
    i.country,
    i.city, 
    i.asn_name
FROM bcf_nw.incidents i
LEFT JOIN bcf_nw.http h ON h.clientIP = i.src_ip
WHERE i.token = 'su6lxwiw15qy6gylx0s0323j1'
GROUP BY i.token, i.src_ip, i.country, i.city, i.asn_name
ORDER BY first_seen ASC;
LIMIT 10
```

```sql consensus_threat_indicators
SELECT
  threat_score, matched_feeds, COUNT(*) AS hits, country_name AS country
FROM bcf_nw.http
WHERE 
  threat_score > 0
GROUP BY ALL
ORDER BY threat_score DESC, hits DESC
LIMIT 10
```

```sql suspicious_requests
SELECT 
  strftime(datetime, '%Y-%m-%d %H:%M:%S') AS datetime,
  clientRequestPath AS path, 
  clientRequestQuery AS query, threat_score, matched_feeds,
  country_name AS country
FROM bcf_nw.http
WHERE threat_score > 0
ORDER BY threat_score DESC
LIMIT 10
```

```sql unknown_ua
SELECT 
    userAgent AS user_agent,
    uaBrowser AS browser,
    uaOS AS operating_system,
    uaDevice AS device_type,
    NULLIF(ARRAY_TO_STRING(LIST_FILTER([
        CASE WHEN uaBrowser = 'Unknown' THEN 'browser' END,
        CASE WHEN uaOS = 'Unknown' THEN 'os' END,
        CASE WHEN uaDevice = 'Unknown' THEN 'device' END
    ], x -> x IS NOT NULL), ', '), '') AS unknown_fields
FROM bcf_nw.http
WHERE uaBrowser = 'Unknown' OR uaOS = 'Unknown' OR uaDevice = 'Unknown'
LIMIT 10
```


Providing real-time visibility into high-confidence, actionable threat indicators. This public view is limited to 10 records. 

Members [Coming Soon] will have access to expanded datasets.



## Incidents Summary
<DataTable data={incidents_summary}/>

## Incident Details - Compromised AWS API Key
<DataTable data={aws_api_key__1_incident}/>

## Consensus-Based Threat Indicators
Based on multi-feed reputation and observed activity.
<DataTable data={consensus_threat_indicators}/>

## Suspicious Requests
Request paths and query strings being probed.
<DataTable data={suspicious_requests}/>

## Unknown User Agents
<DataTable data={unknown_ua}/>