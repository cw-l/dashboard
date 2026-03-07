import boto3
import json
import os
import sys
from dotenv import load_dotenv

load_dotenv()

EXCLUDED_IPS = set(os.getenv('EXCLUDED_IPS', '').split(','))
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

paginator = s3.get_paginator('list_objects_v2')
pages = paginator.paginate(Bucket=BUCKET, Prefix='firewall/')

scrubbed_files = 0
scrubbed_events = 0

if DRY_RUN:
    print("=== DRY RUN — no changes will be written ===\n")

for page in pages:
    for obj in page.get('Contents', []):
        key = obj['Key']
        response = s3.get_object(Bucket=BUCKET, Key=key)
        events = json.loads(response['Body'].read())

        original_count = len(events)
        cleaned = [e for e in events if e.get('clientIP') not in EXCLUDED_IPS]
        removed = original_count - len(cleaned)

        if removed > 0:
            if not DRY_RUN:
                s3.put_object(Bucket=BUCKET, Key=key, Body=json.dumps(cleaned, indent=2))
            print(f"{'[DRY RUN] ' if DRY_RUN else ''}Scrubbed {removed} events from {key}")
            scrubbed_files += 1
            scrubbed_events += removed
        else:
            print(f"Clean: {key}")

print(f"\nDone. {scrubbed_events} events removed across {scrubbed_files} files.", end="")
if DRY_RUN:
    print(" (DRY RUN — nothing written)", end="")
print()