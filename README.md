# 📌 Vuln-Bank – DevSecOps Final Project  

![DevSecOps Flowchart](A_flowchart_in_the_image_illustrates_a_DevSecOps_p.png)  

## 🔹 Deskripsi Proyek  
**Vuln-Bank** adalah aplikasi web banking sederhana berbasis Flask yang sengaja dibuat dengan celah keamanan.  
Tujuannya untuk digunakan sebagai bahan praktik **DevSecOps Pipeline**.  

Pipeline ini mengintegrasikan:  
- **SAST (Static Application Security Testing)** → Semgrep  
- **SCA (Software Composition Analysis)** → Snyk  
- **Secret Scanning** → Gitleaks  
- **Misconfiguration Scan** → Trivy  
- **DAST (Dynamic Application Security Testing)** → OWASP ZAP  
- **Slack Alert** → Notifikasi otomatis untuk vuln HIGH/CRITICAL  

Semua hasil scan dikumpulkan sebagai laporan JSON dan diupload sebagai artifacts.  

---

## 🔹 Arsitektur Pipeline  

1. **Code Checkout** dari repo  
2. **Install Dependencies** → Python, Semgrep, Snyk, Docker Compose  
3. **Security Scans**:  
   - Semgrep (SAST)  
   - Snyk (SCA)  
   - Gitleaks (Secret Scan)  
   - Trivy (Misconfiguration)  
   - OWASP ZAP (DAST)  
4. **Report & Notification**  
   - Semua hasil scan diupload sebagai artifacts  
   - Slack menerima notifikasi jika ada **HIGH/CRITICAL vulnerabilities**  
## 📊 Notifikasi Slack
Contoh notifikasi pipeline ke Slack:

![Slack Alerts](images/slack-alerts.png)

---

## 📈 Diagram Pipeline
Diagram DevSecOps Pipeline:

![Pipeline](images/devsecops-pipeline.png)
---

## 🔹 Cara Menjalankan Aplikasi  

### 1. Clone Repository  
```bash
git clone https://github.com/khoerudinassuyuti/vuln-bank.git
cd vuln-bank

2. Setup Environment

Buat file .env berisi:

FLASK_APP=app.py
DATABASE_URL=postgresql://postgres:postgres@db:5432/vulnerable_bank

3. Jalankan dengan Docker Compose

docker-compose up -d

4. Akses Aplikasi

http://localhost:5000


---

🔹 Cara Menjalankan Pipeline GitHub Actions

Pipeline otomatis jalan ketika:

Push ke branch main

Pull request ke branch main


Untuk run manual:

1. Push perubahan ke repo


2. Buka tab Actions di GitHub


3. Pilih DevSecOps Pipeline → klik Run workflow




---

🔹 Secrets yang Harus Ditambahkan

Tambahkan di Settings > Secrets and variables > Actions:

DATABASE_URL → URL database PostgreSQL

SLACK_WEBHOOK_URL → Webhook Slack

SNYK_TOKEN → API token dari Snyk



---

🔹 Struktur Repo

vuln-bank/
│── app.py
│── requirements.txt
│── docker-compose.yml
│── scripts/
│    └── notify_critical.py
│── .github/
│    └── workflows/
│         └── devsecops-pipeline.yml
└── README.md


---

🔹 Tools yang Digunakan

Semgrep → Static Analysis (SAST)

Snyk → Dependency Vulnerability (SCA)

Gitleaks → Secret Scanning

Trivy → Misconfiguration Scan

OWASP ZAP → Dynamic Testing (DAST)

Slack → Notifikasi otomatis



---

🔹 Hasil Pipeline

Semua laporan (semgrep-report.json, snyk-report.json, gitleaks-report.json, trivy-misconfig-report.json, zap_scan/) diupload ke GitHub Actions.

Slack akan menerima notifikasi jika ada HIGH/CRITICAL vuln.


Contoh notifikasi:

🚨 Snyk menemukan 3 vuln HIGH/CRITICAL!
🚨 Semgrep menemukan 2 issue severity ERROR!
🚨 Trivy menemukan 1 misconfiguration HIGH!


---

🔹 Quick Start

git clone https://github.com/khoerudinassuyuti/vuln-bank.git
cd vuln-bank
docker-compose up -d

Akses aplikasi:

http://localhost:5000


---

📌 Author: Khoerudin Assuyuti
📌 Tujuan: Final Project DevSecOps – Integrasi Security ke CI/CD Pipeline

---
