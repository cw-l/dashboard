---
title: Threat Intel 
---

> This dashboard uses the Cloudflare httpRequestsAdaptive dataset from multiple Zones.

> ⚠️ **Disclaimer:** Data is provided as-is without warranty or guarantee of accuracy. Users should exercise caution when interpreting and acting on this information. If you use or reference this data, please attribute back to the original source.

> This site uses the IP2Location LITE database for <a href="https://www.ip2location.com" target="_blank">IP geolocation</a>.


```sql usage_types
SELECT
  threat_score, matched_feeds,
  usage_type, ipDomain AS ip_domain, isp, 
  isoCountryName AS country, region, city, as_name AS asn,
  COUNT(*) AS hit_count
FROM bcf_nw.http
WHERE 
  usage_type IN ('GOV', 'EDU', 'ORG', 'COM', 'MIL', 'LIB', 'MOB', 'ISP')
  AND threat_score > 0
GROUP BY ALL
ORDER BY threat_score DESC, hit_count DESC
```
```sql threats
SELECT 
  datetime AS timestamp, clientRequestPath AS path, 
  clientRequestQuery AS query, threat_score, matched_feeds,
  usage_type, isoCountryName AS country, region, city
FROM bcf_nw.http
WHERE threat_score > 0
ORDER BY datetime DESC
LIMIT 50
```
```sql suspicious_ips
SELECT
  threat_score, matched_feeds, COUNT(*) AS hits, usage_type, 
  isp, isoCountryName AS country, region, city
FROM bcf_nw.http
WHERE 
  threat_score > 0
GROUP BY ALL
ORDER BY threat_score DESC, hits DESC
```
```sql incidents
SELECT
  DATE(timestamp)  AS date,
  token_type       AS incident_type,
  COUNT(*)         AS hits,
  country,
  city,
  region,
  network_type,
  asn_name,
  is_tor_relay
FROM bcf_nw.incidents
GROUP BY ALL
ORDER BY date DESC, hits DESC
```


## Incidents
<DataTable data={incidents}/>

## Live Threat Request Log
Raw request log from threat-flagged IPs: shows exact paths and query strings being probed.
<DataTable data={threats}/>

## Flagged Attackers by Threat Intelligence Consensus
All flagged attacker IPs ranked by threat intelligence consensus and request volume.
<DataTable data={suspicious_ips}/>

## Threat Activity from Legitimate Networks
Suspicious IPs from legitimate networks: residential, mobile, institutional, that have been flagged by one or more threat intelligence feeds.
<DataTable data={usage_types}/>