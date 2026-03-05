---
title: Security Events Dashboard
---

> ⚠️ **Disclaimer:** Data is provided as-is without warranty or guarantee of accuracy. Users should exercise caution when interpreting and acting on this information. If you use or reference this data, please attribute back to the original source.

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

```sql bottom_countries
SELECT 
  country,
  COUNT(*) as total
FROM (
  SELECT COALESCE(clientCountryName, country) as country
  FROM bcf_fw.trends
  WHERE COALESCE(clientCountryName, country) IS NOT NULL
)
GROUP BY country
ORDER BY total ASC
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
  AND COALESCE(clientRequestPath, path) != '/'
)
GROUP BY path
ORDER BY total DESC
LIMIT 10
```

```sql bottom_paths
SELECT 
  path,
  COUNT(*) as total
FROM (
  SELECT COALESCE(clientRequestPath, path) as path
  FROM bcf_fw.trends
  WHERE COALESCE(clientRequestPath, path) IS NOT NULL
)
GROUP BY path
ORDER BY total ASC
LIMIT 10
```

```sql top_paths_tor
SELECT 
  COALESCE(clientRequestPath, path) as path,
  COUNT(*) as total
FROM bcf_fw.trends
WHERE COALESCE(clientRequestPath, path) IS NOT NULL
AND country = 'T1'
GROUP BY COALESCE(clientRequestPath, path)
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

## Bottom Countries

<BarChart 
  data={bottom_countries} 
  x=country 
  y=total 
  title="Bottom 10 Countries"
/>

## Top User Agents

<DataTable data={top_user_agents}/>

## Top Request Paths

<DataTable data={top_paths}/>

## Bottom Request Paths

<DataTable data={bottom_paths}/>

## Top Paths by Tor Exits

<DataTable data={top_paths_tor}/>

---
*© 2026 BCF SECURITY. All rights reserved.*
<LastRefreshed prefix="Last updated:" slot="footer"/>