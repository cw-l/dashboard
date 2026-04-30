---
title: Threat Intel 
---


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
  timestamp         AS date,
  token_type        AS incident_type,
  region,
  city,
  network_type,
  asn_name
FROM bcf_nw.incidents
GROUP BY ALL
ORDER BY date DESC
```


## Incidents
<DataTable data={incidents}/>

## Live Threat Request Log
Raw request log from threat-flagged IPs: shows exact paths and query strings being probed.
<DataTable data={threats}/>

## Flagged Attackers by Threat Intelligence Consensus
All flagged attacker IPs ranked by threat intelligence consensus and request volume.
<DataTable data={suspicious_ips}/>