---
title: HTTP 
---


```sql top_countries
SELECT 
  isoCountryName AS country,
  COUNT(*) as total
FROM bcf_nw.http
WHERE isoCountryName IS NOT NULL
GROUP BY isoCountryName
ORDER BY total DESC
LIMIT 10
```
```sql bottom_countries
SELECT 
  isoCountryName AS country,
  COUNT(*) as total
FROM bcf_nw.http
WHERE isoCountryName IS NOT NULL
GROUP BY isoCountryName
ORDER BY total ASC
LIMIT 10
```
```sql top_cities
SELECT 
  city,
  COUNT(*) as total
FROM bcf_nw.http
WHERE city IS NOT NULL
GROUP BY city
ORDER BY total DESC
LIMIT 10
```
```sql bottom_cities
SELECT 
  city,
  COUNT(*) as total
FROM bcf_nw.http
WHERE city IS NOT NULL
GROUP BY city
ORDER BY total ASC
LIMIT 10
```
```sql top_asn
SELECT 
  clientAsnName AS asn,
  COUNT(*) as total
FROM bcf_nw.http
WHERE clientAsnName IS NOT NULL
GROUP BY clientAsnName
ORDER BY total DESC
LIMIT 10
```
```sql bottom_asn
SELECT 
  clientAsnName AS asn,
  COUNT(*) as total
FROM bcf_nw.http
WHERE clientAsnName IS NOT NULL
GROUP BY clientAsnName
ORDER BY total ASC
LIMIT 10
```
```sql top_isp
SELECT 
  isp,
  COUNT(*) as total
FROM bcf_nw.http
WHERE isp IS NOT NULL
GROUP BY isp
ORDER BY total DESC
LIMIT 10
```
```sql bottom_isp
SELECT 
  isp,
  COUNT(*) as total
FROM bcf_nw.http
WHERE isp IS NOT NULL
GROUP BY isp
ORDER BY total ASC
LIMIT 10
```
```sql ua_os
SELECT uaOS AS os, COUNT(*) AS total
FROM bcf_nw.http
WHERE uaOS IS NOT NULL
GROUP BY uaOS
ORDER BY total DESC
```
```sql ua_device
SELECT uaDevice AS device, COUNT(*) AS total
FROM bcf_nw.http
WHERE uaDevice IS NOT NULL
GROUP BY uaDevice
ORDER BY total DESC
```
```sql ua_browser
SELECT uaBrowser AS browser, COUNT(*) AS total
FROM bcf_nw.http
WHERE uaBrowser IS NOT NULL
GROUP BY uaBrowser
ORDER BY total DESC
```
```sql top_paths
SELECT 
  clientRequestPath AS path,
  COUNT(*) as total
FROM bcf_nw.http
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
FROM bcf_nw.http
WHERE clientRequestPath IS NOT NULL
GROUP BY clientRequestPath
ORDER BY total ASC
LIMIT 10
```
```sql top_paths_tor
SELECT 
  clientRequestPath AS path,
  COUNT(*) as total
FROM bcf_nw.http
WHERE clientRequestPath IS NOT NULL
  AND clientCountryName = 'T1'
GROUP BY clientRequestPath
ORDER BY total DESC
LIMIT 10
```
```sql http_methods
SELECT
  clientRequestHTTPMethodName AS http_method_name,
  COUNT(*) AS total
FROM bcf_nw.http
WHERE clientRequestHTTPMethodName IS NOT NULL
  AND clientRequestHTTPMethodName != ''
GROUP BY clientRequestHTTPMethodName
ORDER BY total DESC
```
```sql http_protocol_versions
SELECT
  clientRequestHTTPProtocol AS http_protocol_version,
  COUNT(*) AS total
FROM bcf_nw.http
WHERE clientRequestHTTPProtocol IS NOT NULL
  AND clientRequestHTTPProtocol != ''
GROUP BY clientRequestHTTPProtocol
ORDER BY total DESC
```
```sql unique_ips_per_day
SELECT
  DATE_TRUNC('day', datetime::TIMESTAMP) AS day,
  COUNT(DISTINCT clientIP) AS unique_ips
FROM bcf_nw.http
WHERE datetime IS NOT NULL
GROUP BY day
ORDER BY day ASC
```
```sql unique_ips_per_hour
SELECT
  DATE_TRUNC('hour', datetime::TIMESTAMP) AS hour,
  COUNT(DISTINCT clientIP) AS unique_ips
FROM bcf_nw.http
WHERE datetime IS NOT NULL
GROUP BY hour
ORDER BY hour ASC
```
```sql usage_type
SELECT
  usage_type,
  COUNT(*) AS total
FROM bcf_nw.http
WHERE usage_type IS NOT NULL
GROUP BY usage_type
ORDER BY total DESC
```
```sql unique_ips_by_usage_type
SELECT
  usage_type,
  COUNT(DISTINCT clientIP) AS unique_ips
FROM bcf_nw.http
WHERE usage_type IS NOT NULL
GROUP BY usage_type
ORDER BY unique_ips DESC
```
```sql int_domain_name_assoc_ip_range
SELECT
  ipDomain,
  COUNT(*) AS total
FROM bcf_nw.http
WHERE ipDomain IS NOT NULL
GROUP BY ipDomain
ORDER BY ipDomain DESC
```


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

## Top 10 Cities
<BarChart 
  data={top_cities} 
  x=city 
  y=total
  swapXY=true
/>

## Bottom 10 Cities
<BarChart 
  data={bottom_cities} 
  x=city 
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

## Top 10 ISPs
<BarChart 
  data={top_isp} 
  x=isp 
  y=total
  swapXY=true
/>

## Bottom 10 ISPs
<BarChart 
  data={bottom_isp} 
  x=isp 
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

## Usage Types
<ECharts config={
  {
    tooltip: { trigger: 'item' },
    series: [{
      type: 'pie',
      data: usage_type.map(d => ({ name: d.usage_type, value: d.total }))
    }]
  }
}/>

## Unique IPs by Usage Type
<ECharts config={
  {
    tooltip: { trigger: 'item' },
    series: [{
      type: 'pie',
      data: unique_ips_by_usage_type.map(d => ({ name: d.usage_type, value: d.unique_ips }))
    }]
  }
}/>

## Internet Domain Name Associated with IP Range
<ECharts config={
  {
    tooltip: { trigger: 'item' },
    series: [{
      type: 'pie',
      data: int_domain_name_assoc_ip_range.map(d => ({ name: d.ipDomain, value: d.total }))
    }]
  }
}/>