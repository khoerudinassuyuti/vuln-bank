import json
import os
import requests

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

def send_slack(message):
    if not SLACK_WEBHOOK_URL:
        print("⚠️ SLACK_WEBHOOK_URL tidak ada di secrets")
        return
    payload = {"text": message}
    requests.post(SLACK_WEBHOOK_URL, json=payload)

def check_snyk():
    try:
        with open("snyk-report.json") as f:
            data = json.load(f)
        # cari vulnerability high/critical
        issues = [v for v in data.get("vulnerabilities", []) if v["severity"] in ["high", "critical"]]
        if issues:
            send_slack(f"🚨 Snyk menemukan {len(issues)} vuln HIGH/CRITICAL!")
    except Exception as e:
        print(f"Skip Snyk: {e}")

def check_semgrep():
    try:
        with open("semgrep-report.json") as f:
            data = json.load(f)
        # rules dengan severity ERROR = critical finding
        issues = [r for r in data.get("results", []) if r.get("extra", {}).get("severity") == "ERROR"]
        if issues:
            send_slack(f"🚨 Semgrep menemukan {len(issues)} issue severity ERROR!")
    except Exception as e:
        print(f"Skip Semgrep: {e}")

if __name__ == "__main__":
    check_snyk()
    check_semgrep()
