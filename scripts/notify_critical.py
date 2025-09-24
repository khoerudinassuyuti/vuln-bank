import json
import os
import requests

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

def send_slack(message):
    if not SLACK_WEBHOOK_URL:
        print("⚠️ SLACK_WEBHOOK_URL tidak ada di secrets")
        return
    payload = {"text": message}
    try:
        requests.post(SLACK_WEBHOOK_URL, json=payload)
    except Exception as e:
        print(f"Failed to send Slack message: {e}")

def check_snyk():
    try:
        with open("snyk-report.json") as f:
            data = json.load(f)
        issues = [v for v in data.get("vulnerabilities", []) if v["severity"] in ["high", "critical"]]
        if issues:
            send_slack(f"🚨 Snyk menemukan {len(issues)} HIGH/CRITICAL vulnerabilities!")
    except Exception as e:
        print(f"Skip Snyk: {e}")

def check_semgrep():
    try:
        with open("semgrep-report.json") as f:
            data = json.load(f)
        issues = [r for r in data.get("results", []) if r.get("extra", {}).get("severity") == "ERROR"]
        if issues:
            send_slack(f"🚨 Semgrep menemukan {len(issues)} issue severity ERROR!")
    except Exception as e:
        print(f"Skip Semgrep: {e}")

def check_trivy():
    try:
        with open("trivy-misconfig-report.json") as f:
            data = json.load(f)
        issues = []
        for result in data.get("Results", []):
            misconfigs = result.get("Misconfigurations", [])
            if misconfigs:
                issues.extend(misconfigs)
        if issues:
            send_slack(f"🚨 Trivy menemukan {len(issues)} misconfig HIGH/CRITICAL!")
    except Exception as e:
        print(f"Skip Trivy: {e}")

def check_gitleaks():
    try:
        with open("gitleaks-report.json") as f:
            data = json.load(f)
        issues = [i for i in data if i.get("severity") in ["high", "critical"]]
        if issues:
            send_slack(f"🚨 Gitleaks menemukan {len(issues)} secret HIGH/CRITICAL!")
    except Exception as e:
        print(f"Skip Gitleaks: {e}")

if __name__ == "__main__":
    check_snyk()
    check_semgrep()
    check_trivy()
    check_gitleaks()
