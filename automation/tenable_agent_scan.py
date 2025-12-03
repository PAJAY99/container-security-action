#!/usr/bin/env python3
"""
tenable_agent_scan.py
- Assumes Tenable agent is installed and linked on the test EC2 instance (agent-based).
- Creates a Tenable scan via API (targeting agent by hostname or agent group),
  launches the scan, waits for completion, exports CSV, uploads to S3.
Environment variables required:
  TENABLE_ACCESS_KEY, TENABLE_SECRET_KEY, S3_BUCKET, AWS_REGION, TARGET_AGENT_NAME
Optional:
  SCAN_FOLDER_ID (to organize scans), SCAN_NAME, VULN_FAIL_THRESHOLD_HIGH
"""

import os, sys, time, json, requests, boto3

API_BASE = "https://cloud.tenable.com"
ACCESS_KEY = os.getenv("TENABLE_ACCESS_KEY")
SECRET_KEY = os.getenv("TENABLE_SECRET_KEY")
S3_BUCKET = os.getenv("S3_BUCKET")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
TARGET_AGENT_NAME = os.getenv("TARGET_AGENT_NAME")  # hostname or agent filter
SCAN_NAME = os.getenv("SCAN_NAME", f"AMI-Agent-Scan-{int(time.time())}")
FOLDER_ID = os.getenv("SCAN_FOLDER_ID")  # optional
VULN_FAIL_THRESHOLD_HIGH = int(os.getenv("VULN_FAIL_THRESHOLD_HIGH", "5"))

if not ACCESS_KEY or not SECRET_KEY or not S3_BUCKET or not TARGET_AGENT_NAME:
    print("Missing required environment variables. Need TENABLE_ACCESS_KEY, TENABLE_SECRET_KEY, S3_BUCKET, TARGET_AGENT_NAME")
    sys.exit(2)

HEADERS = {"X-ApiKeys": f"accessKey={ACCESS_KEY}; secretKey={SECRET_KEY}", "Content-Type": "application/json"}

def create_scan_for_agent(agent_name):
    # Simpler approach: set text_targets to the agent's hostname; Tenable will map agent asset
    settings = {
        "name": SCAN_NAME,
        "text_targets": agent_name
    }
    if FOLDER_ID:
        settings["folder_id"] = int(FOLDER_ID)
    body = {"settings": settings}
    r = requests.post(API_BASE + "/scans", headers=HEADERS, json=body)
    r.raise_for_status()
    return r.json()["id"]

def launch_scan(scan_id):
    r = requests.post(f"{API_BASE}/scans/{scan_id}/launch", headers=HEADERS)
    r.raise_for_status()
    return r.json()

def wait_for_scan_completion(scan_id, poll_interval=10):
    while True:
        r = requests.get(f"{API_BASE}/scans/{scan_id}", headers=HEADERS)
        r.raise_for_status()
        status = r.json().get("info", {}).get("status", "")
        print("[tenable] Scan status:", status)
        if status.lower() == "completed":
            return r.json()
        time.sleep(poll_interval)

def export_scan(scan_id, fmt="csv"):
    r = requests.post(f"{API_BASE}/scans/{scan_id}/export", headers=HEADERS, json={"format": fmt})
    r.raise_for_status()
    file_id = r.json()["file"]
    # poll export
    while True:
        rs = requests.get(f"{API_BASE}/scans/{scan_id}/export/{file_id}", headers=HEADERS)
        rs.raise_for_status()
        if rs.json().get("status") == "ready":
            break
        time.sleep(3)
    dl = requests.get(f"{API_BASE}/scans/{scan_id}/export/{file_id}/download", headers=HEADERS)
    dl.raise_for_status()
    return dl.content

def upload_to_s3(content, key):
    s3 = boto3.client("s3", region_name=AWS_REGION)
    s3.put_object(Bucket=S3_BUCKET, Key=key, Body=content)
    print(f"[s3] Uploaded report to s3://{S3_BUCKET}/{key}")

def count_high_vulns(scan_id):
    # Simple approach: call /scans/{scan_id}/hosts and count severity 4 (if present)
    r = requests.get(f"{API_BASE}/scans/{scan_id}/hosts", headers=HEADERS)
    r.raise_for_status()
    high = 0
    for host in r.json().get("hosts", []):
        for v in host.get("vulnerabilities", []):
            # Tenable severity mapping may differ; plugin severity may be numeric 0-4
            if v.get("severity") == 4:
                high += 1
    return high

def main():
    print("[*] Creating Tenable scan for agent:", TARGET_AGENT_NAME)
    scan_id = create_scan_for_agent(TARGET_AGENT_NAME)
    print("[*] Created scan id:", scan_id)

    print("[*] Launching scan...")
    launch_scan(scan_id)

    print("[*] Waiting for completion...")
    wait_for_scan_completion(scan_id)

    print("[*] Exporting results...")
    content = export_scan(scan_id)
    key = f"tenable-reports/{scan_id}_{int(time.time())}.csv"
    upload_to_s3(content, key)

    high_count = count_high_vulns(scan_id)
    print(f"[result] High severity vulns: {high_count}")
    if high_count >= VULN_FAIL_THRESHOLD_HIGH:
        print("[result] Scan FAILED (high vulns exceed threshold)")
        sys.exit(1)
    else:
        print("[result] Scan PASSED")
        sys.exit(0)

if __name__ == "__main__":
    main()