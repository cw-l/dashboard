---
title: Security Events Dashboard
---

```sql top_countries
SELECT 
  country,
  COUNT(*) as total
FROM (
  SELECT COALESCE(clientCountryName, country) as country
  FROM bcf_fw.trends
  WHERE COALESCE(clientCountryName, country) IS NOT NULL
)
GROUP BY country
ORDER BY total DESC
LIMIT 10
```

```sql top_ips
SELECT 
  ip,
  COUNT(*) as total
FROM (
  SELECT COALESCE(clientIP, ip) as ip
  FROM bcf_fw.trends
  WHERE COALESCE(clientIP, ip) IS NOT NULL
)
GROUP BY ip
ORDER BY total DESC
LIMIT 10
```

```sql top_user_agents
SELECT 
  user_agent,
  COUNT(*) as total
FROM (
  SELECT COALESCE(userAgent, user_agent) as user_agent
  FROM bcf_fw.trends
  WHERE COALESCE(userAgent, user_agent) IS NOT NULL
)
GROUP BY user_agent
ORDER BY total DESC
LIMIT 10
```

```sql top_paths
SELECT 
  path,
  COUNT(*) as total
FROM (
  SELECT COALESCE(clientRequestPath, path) as path
  FROM bcf_fw.trends
  WHERE COALESCE(clientRequestPath, path) IS NOT NULL
)
GROUP BY path
ORDER BY total DESC
LIMIT 10
```


## Top Countries

<BarChart 
  data={top_countries} 
  x=country 
  y=total 
  title="Top 10 Countries"
/>

## Top IPs

<DataTable data={top_ips}/>

## Top User Agents

<DataTable data={top_user_agents}/>

## Top Request Paths

<DataTable data={top_paths}/>

<LastRefreshed prefix="Last updated:" slot="footer"/>