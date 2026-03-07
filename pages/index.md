---
title: Security Events Dashboard
---
> ⚠️ **Disclaimer:** Data is provided as-is without warranty or guarantee of accuracy. Users should exercise caution when interpreting and acting on this information. If you use or reference this data, please attribute back to the original source.
```sql top_countries
SELECT 
  isoCountryName AS country,
  COUNT(*) as total
FROM bcf_fw.trends
WHERE isoCountryName IS NOT NULL
GROUP BY isoCountryName
ORDER BY total DESC
LIMIT 10
```
```sql bottom_countries
SELECT 
  isoCountryName AS country,
  COUNT(*) as total
FROM bcf_fw.trends
WHERE isoCountryName IS NOT NULL
GROUP BY isoCountryName
ORDER BY total ASC
LIMIT 10
```
```sql top_user_agents
SELECT 
  userAgent AS user_agent,
  COUNT(*) as total
FROM bcf_fw.trends
WHERE userAgent IS NOT NULL
GROUP BY userAgent
ORDER BY total DESC
LIMIT 10
```
```sql top_paths
SELECT 
  clientRequestPath AS path,
  COUNT(*) as total
FROM bcf_fw.trends
WHERE clientRequestPath IS NOT NULL
  AND clientRequestPath != '/'
GROUP BY clientRequestPath
ORDER BY total DESC
LIMIT 10
```
```sql bottom_paths
SELECT 
  clientRequestPath AS path,
  COUNT(*) as total
FROM bcf_fw.trends
WHERE clientRequestPath IS NOT NULL
GROUP BY clientRequestPath
ORDER BY total ASC
LIMIT 10
```
```sql top_paths_tor
SELECT 
  clientRequestPath AS path,
  COUNT(*) as total
FROM bcf_fw.trends
WHERE clientRequestPath IS NOT NULL
  AND clientCountryName = 'T1'
GROUP BY clientRequestPath
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