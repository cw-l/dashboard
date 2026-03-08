# backfill.py

import boto3
import json
import os
import sys
import requests
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

load_dotenv()

DRY_RUN = "--dry-run" in sys.argv

endpoint = os.getenv('EVIDENCE_S3_ENDPOINT')
if not endpoint.startswith('http'):
    endpoint = f'https://{endpoint}'

s3 = boto3.client(
    's3',
    endpoint_url=endpoint,
    aws_access_key_id=os.getenv('MALICIOUS_S3_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('MALICIOUS_S3_SECRET_ACCESS_KEY'),
    region_name='auto'
)

BUCKET = os.getenv('EVIDENCE_S3_BUCKET_NAME')
API_TOKEN = os.getenv('CF_API_TOKEN')
ZONES = json.loads(os.getenv('CF_ZONES'))  # [{"name": "abc.com", "zoneId": "xxx"}]
EXCLUDED_IPS = set(os.getenv('EXCLUDED_IPS', '').split(','))

GRAPHQL_URL = 'https://api.cloudflare.com/client/v4/graphql'

def fetch_events(zone, datetime_geq, datetime_leq):
    query = {
        "query": f"""{{
            viewer {{
                zones(filter: {{ zoneTag: "{zone['zoneId']}" }}) {{
                    firewallEventsAdaptive(
                        filter: {{
                            datetime_geq: "{datetime_geq}"
                            datetime_leq: "{datetime_leq}"
                        }}
                        limit: 10000
                        orderBy: [datetime_DESC]
                    ) {{
                        action
                        clientAsn
                        clientASNDescription
                        clientCountryName
                        clientIP
                        clientIPClass
                        clientRefererHost
                        clientRequestHTTPMethodName
                        clientRequestHTTPProtocol
                        clientRequestPath
                        clientRequestQuery
                        datetime
                        edgeResponseStatus
                        rayName
                        source
                        userAgent
                        verifiedBotCategory
                    }}
                }}
            }}
        }}"""
    }
    response = requests.post(
        GRAPHQL_URL,
        headers={
            'Authorization': f'Bearer {API_TOKEN}',
            'Content-Type': 'application/json'
        },
        json=query
    )
    data = response.json()
    if data.get('errors'):
        print(f"  GraphQL error for {zone['name']}: {data['errors']}")
        return []
    return data.get('data', {}).get('viewer', {}).get('zones', [{}])[0].get('firewallEventsAdaptive', [])

if DRY_RUN:
    print("=== DRY RUN — no changes will be written ===\n")

now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
total_files = 0
total_events = 0

for days_ago in range(14, -1, -1):  # -1 instead of 0 to include today    
    for hour in range(24):
        slot_start = (now - timedelta(days=days_ago)).replace(hour=hour)
        slot_end = slot_start + timedelta(hours=1)

        if slot_start >= now:
            continue

        datetime_geq = slot_start.isoformat().replace('+00:00', 'Z')
        datetime_leq = slot_end.isoformat().replace('+00:00', 'Z')
        date_str = slot_start.strftime('%Y-%m-%d')
        hour_str = str(slot_start.hour).zfill(2)
        key = f"firewall/{date_str}/{hour_str}.json"

        print(f"Processing {key}...")

        all_events = []
        for zone in ZONES:
            events = fetch_events(zone, datetime_geq, datetime_leq)
            tagged = [
                {**e, 'zone': zone['name']}
                for e in events
                if e.get('clientIP') not in EXCLUDED_IPS
            ]
            all_events.extend(tagged)

        if len(all_events) == 0:
            print(f"  No events returned, skipping to preserve existing data")
            continue

        print(f"  {len(all_events)} events fetched")

        if not DRY_RUN:
            s3.put_object(
                Bucket=BUCKET,
                Key=key,
                Body=json.dumps(all_events, indent=2)
            )
            print(f"  Written to R2: {key}")

        total_files += 1
        total_events += len(all_events)

print(f"\nDone. {total_events} events across {total_files} files.", end="")
if DRY_RUN:
    print(" (DRY RUN — nothing written)", end="")
print()