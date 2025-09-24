import json
import os
import requests
import glob

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

def send_slack(message):
    if not SLACK_WEBHOOK_URL:
        print("⚠️ SLACK_WEBHOOK_URL tidak ada di secrets")
        return
    payload = {"text": message}
    try:
        response = requests.post(SLACK_WEBHOOK_URL, json=payload)
        if response.status_code != 200:
            print(f"⚠️ Gagal kirim Slack: {response.text}")
    except Exception as e:
        print(f"⚠️ Error kirim Slack: {e}")

def check_snyk():
    try:
        with open("snyk-report.json") as f:
            data = json.load(f)
        issues = [v for v in data.get("vulnerabilities", []) if v["severity"].lower() in ["high", "critical"]]
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
        issues = data.get("Misconfigurations", [])
        critical = [i for i in issues if i.get("Severity", "").upper() in ["HIGH", "CRITICAL"]]
        if critical:
            send_slack(f"🚨 Trivy menemukan {len(critical)} misconfig HIGH/CRITICAL!")
    except Exception as e:
        print(f"Skip Trivy: {e}")

def check_gitleaks():
    try:
        with open("gitleaks-report.json") as f:
            data = json.load(f)
        if data:  # setiap entry dianggap sensitive
            send_slack(f"🚨 Gitleaks menemukan {len(data)} potential secrets!")
    except Exception as e:
        print(f"Skip Gitleaks: {e}")

def check_zap():
    try:
        zap_files = glob.glob("zap_scan/*.json")
        total = 0
        for file in zap_files:
            with open(file) as f:
                data = json.load(f)
            alerts = data.get("site", [])
            for site in alerts:
                for alert in site.get("alerts", []):
                    if alert.get("risk") in ["High", "Critical"]:
                        total += 1
        if total > 0:
            send_slack(f"🚨 OWASP ZAP menemukan {total} HIGH/CRITICAL issues!")
    except Exception as e:
        print(f"Skip ZAP: {e}")

if __name__ == "__main__":
    check_snyk()
    check_semgrep()
    check_trivy()
    check_gitleaks()
    check_zap()
