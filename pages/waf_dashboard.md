---
title: WAF 
---


```sql fw_actions
SELECT
  action AS fw_action,
  COUNT(*) AS total
FROM bcf_nw.firewall
WHERE action IS NOT NULL
  AND action != ''
GROUP BY action
ORDER BY total DESC
```
```sql top_countries
SELECT 
  country_name AS country,
  COUNT(*) as total
FROM bcf_nw.firewall
WHERE country_name IS NOT NULL
GROUP BY country_name
ORDER BY total DESC
LIMIT 10
```
```sql bottom_countries
SELECT 
  country_name AS country,
  COUNT(*) as total
FROM bcf_nw.firewall
WHERE country_name IS NOT NULL
GROUP BY country_name
ORDER BY total ASC
LIMIT 10
```
```sql top_asn
SELECT 
  clientASNDescription AS asn,
  COUNT(*) as total
FROM bcf_nw.firewall
WHERE clientASNDescription IS NOT NULL
GROUP BY clientASNDescription
ORDER BY total DESC
LIMIT 10
```
```sql bottom_asn
SELECT 
  clientASNDescription AS asn,
  COUNT(*) as total
FROM bcf_nw.firewall
WHERE clientASNDescription IS NOT NULL
GROUP BY clientASNDescription
ORDER BY total ASC
LIMIT 10
```
```sql ua_os
SELECT uaOS AS os, COUNT(*) AS total
FROM bcf_nw.firewall
WHERE uaOS IS NOT NULL
GROUP BY uaOS
ORDER BY total DESC
```
```sql ua_device
SELECT uaDevice AS device, COUNT(*) AS total
FROM bcf_nw.firewall
WHERE uaDevice IS NOT NULL
GROUP BY uaDevice
ORDER BY total DESC
```
```sql ua_browser
SELECT uaBrowser AS browser, COUNT(*) AS total
FROM bcf_nw.firewall
WHERE uaBrowser IS NOT NULL
GROUP BY uaBrowser
ORDER BY total DESC
```
```sql top_paths
SELECT 
  clientRequestPath AS path,
  COUNT(*) as total
FROM bcf_nw.firewall
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
FROM bcf_nw.firewall
WHERE clientRequestPath IS NOT NULL
GROUP BY clientRequestPath
ORDER BY total ASC
LIMIT 10
```
```sql top_paths_tor
SELECT 
  clientRequestPath AS path,
  COUNT(*) as total
FROM bcf_nw.firewall
WHERE clientRequestPath IS NOT NULL
  AND clientCountryName = 'T1'
GROUP BY clientRequestPath
ORDER BY total DESC
LIMIT 10
```
```sql ip_class
SELECT
  clientIPClass AS ip_class,
  COUNT(*) AS total
FROM bcf_nw.firewall
WHERE clientIPClass IS NOT NULL
  AND clientIPClass != ''
GROUP BY clientIPClass
ORDER BY total DESC
```
```sql http_methods
SELECT
  clientRequestHTTPMethodName AS http_method_name,
  COUNT(*) AS total
FROM bcf_nw.firewall
WHERE clientRequestHTTPMethodName IS NOT NULL
  AND clientRequestHTTPMethodName != ''
GROUP BY clientRequestHTTPMethodName
ORDER BY total DESC
```
```sql http_protocol_versions
SELECT
  clientRequestHTTPProtocol AS http_protocol_version,
  COUNT(*) AS total
FROM bcf_nw.firewall
WHERE clientRequestHTTPProtocol IS NOT NULL
  AND clientRequestHTTPProtocol != ''
GROUP BY clientRequestHTTPProtocol
ORDER BY total DESC
```
```sql unique_ips_per_day
SELECT
  DATE_TRUNC('day', datetime::TIMESTAMP) AS day,
  COUNT(DISTINCT clientIP) AS unique_ips
FROM bcf_nw.firewall
WHERE datetime IS NOT NULL
GROUP BY day
ORDER BY day ASC
```
```sql unique_ips_per_hour
SELECT
  DATE_TRUNC('hour', datetime::TIMESTAMP) AS hour,
  COUNT(DISTINCT clientIP) AS unique_ips
FROM bcf_nw.firewall
WHERE datetime IS NOT NULL
GROUP BY hour
ORDER BY hour ASC
```


## Firewall Actions
<ECharts config={
  {
    tooltip: { trigger: 'item' },
    series: [{
      type: 'pie',
      data: fw_actions.map(d => ({ name: d.fw_action, value: d.total }))
    }]
  }
}/>

## Top 10 Countries
<BarChart 
  data={top_countries} 
  x=country 
  y=total
  swapXY=true
/>

## Bottom 10 Countries
<BarChart 
  data={bottom_countries} 
  x=country 
  y=total 
  swapXY=true
/>

## Top 10 ASNs
<BarChart 
  data={top_asn} 
  x=asn 
  y=total
  swapXY=true
/>

## Bottom 10 ASNs
<BarChart 
  data={bottom_asn} 
  x=asn 
  y=total 
  swapXY=true
/>

## Operating Systems
<ECharts config={
  {
    tooltip: { trigger: 'item' },
    series: [{
      type: 'pie',
      data: ua_os.map(d => ({ name: d.os, value: d.total }))
    }]
  }
}/>

## Device Types
<ECharts config={
  {
    tooltip: { trigger: 'item' },
    series: [{
      type: 'pie',
      data: ua_device.map(d => ({ name: d.device, value: d.total }))
    }]
  }
}/>

## Browsers
<ECharts config={
  {
    tooltip: { trigger: 'item' },
    series: [{
      type: 'pie',
      data: ua_browser.map(d => ({ name: d.browser, value: d.total }))
    }]
  }
}/>

## Top 10 Request Paths
<DataTable data={top_paths}/>

## Bottom 10 Request Paths
<DataTable data={bottom_paths}/>

## Top Paths by Tor Exits
<DataTable data={top_paths_tor}/>

## IP Classes
<ECharts config={
  {
    tooltip: { trigger: 'item' },
    series: [{
      type: 'pie',
      data: ip_class.map(d => ({ name: d.ip_class, value: d.total }))
    }]
  }
}/>

## HTTP Methods
<ECharts config={
  {
    tooltip: { trigger: 'item' },
    series: [{
      type: 'pie',
      data: http_methods.map(d => ({ name: d.http_method_name, value: d.total }))
    }]
  }
}/>

## HTTP Protocol
<ECharts config={
  {
    tooltip: { trigger: 'item' },
    series: [{
      type: 'pie',
      data: http_protocol_versions.map(d => ({ name: d.http_protocol_version, value: d.total }))
    }]
  }
}/>

## Unique IPs per Day
<LineChart 
  data={unique_ips_per_day} 
  x=day 
  y=unique_ips
/>

## Unique IPs per Hour
<LineChart 
  data={unique_ips_per_hour} 
  x=hour 
  y=unique_ips
/>