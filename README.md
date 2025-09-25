# 🏦 Vuln Bank – DevSecOps Final Project

Proyek ini adalah bagian dari **Final Project DevSecOps** dengan studi kasus *Vuln Bank*, sebuah aplikasi perbankan digital yang masih memiliki banyak celah keamanan.  
Tujuan utama dari proyek ini adalah membangun **CI/CD Pipeline dengan Security Scanning otomatis** agar setiap perubahan kode dapat langsung dipindai kerentanannya.

---

## 📌 Fitur Pipeline

Pipeline CI/CD ini berjalan otomatis setiap kali ada perubahan pada branch `main` dan setiap ada Pull Request ke `main`.  
Tahapan yang diintegrasikan:

1. **Secret Scanning (🔑 Gitleaks)**  
   - Mendeteksi kebocoran kredensial, API key, atau password di dalam kode.

2. **Software Composition Analysis (📦 Snyk / Trivy)**  
   - Memeriksa dependency pihak ketiga untuk menemukan library yang memiliki CVE.  
   - Snyk: Fokus pada `requirements.txt`.  
   - Trivy: Fokus pada `Dockerfile` dan image container.

3. **Static Application Security Testing (📖 Semgrep)**  
   - Analisis kode Python (`app.py` dan modul terkait).  
   - Mendeteksi insecure coding patterns sesuai OWASP Top 10.

4. **Misconfiguration Scanning (⚙️ Trivy Config)**  
   - Mengecek Dockerfile, docker-compose, dan konfigurasi lainnya.  
   - Contoh: penggunaan user root, port terbuka, privilege escalation.

5. **Dynamic Application Security Testing (🌐 OWASP ZAP / DAST)**  
   - Menguji aplikasi yang sedang berjalan pada `localhost:5000`.  
   - Mendeteksi celah seperti SQL Injection, XSS, dll.

6. **Notifikasi (📢 Slack / Email / Telegram)**  
   - Jika ditemukan **High atau Critical vulnerability**, pipeline akan mengirimkan notifikasi otomatis ke channel yang sudah dikonfigurasi.

---

## 📂 Struktur Repository

vuln-bank/ ├── app.py ├── requirements.txt ├── Dockerfile ├── docker-compose.yml ├── .github/workflows/ │   ├── ci.yml           # Pipeline utama │   ├── gitleaks.yml     # Secret Scanning │   ├── semgrep.yml      # SAST │   └── trivy.yml        # SCA + Misconfig └── reports/ ├── snyk-report.json ├── semgrep-report.json ├── trivy-report.json └── zap-report.html

---

## 🚀 Cara Menjalankan Pipeline

1. **Clone Repository**
   ```bash
   git clone https://github.com/khoerudinassuyuti/vuln-bank.git
   cd vuln-bank

2. Push ke Branch main

git add .
git commit -m "update pipeline"
git push origin main


3. GitHub Actions akan otomatis berjalan dan melakukan scanning sesuai tahapan di atas.




---

📊 Contoh Hasil Scan

Gitleaks → gitleaks-report.json

Snyk → snyk-report.json

Trivy → trivy-report.json

Semgrep → semgrep-report.json

OWASP ZAP → zap-report.html


Semua laporan bisa diunduh dari menu Actions → Artifacts di GitHub.


---

📢 Notifikasi Critical Vulnerability

Jika pipeline menemukan vulnerability dengan severity High atau Critical, notifikasi otomatis akan dikirim ke Slack.

Pesan notifikasi berisi:

Nama vulnerability

Severity

Lokasi file / dependency

Link ke laporan lengkap




---

📖 Dokumentasi

1. Arsitektur Pipeline

Setiap commit ke branch main → trigger GitHub Actions.

Workflow berjalan: Secret Scan → SCA → SAST → Misconfig → DAST.

Jika ada temuan Critical, kirim notifikasi → Slack.

Semua laporan tersimpan sebagai artifact.



2. Tools yang Digunakan

Gitleaks → Secret Scanning

Snyk + Trivy → Dependency & Misconfig Scanning

Semgrep → Static Analysis (SAST)

OWASP ZAP → Dynamic Testing (DAST)

Slack/Email/Telegram → Alert Notifikasi



3. Improvement

Branch protection rules pada main (opsional).

Deployment aplikasi ke server Ubuntu dengan hardening.

Export laporan ke GitHub Issues untuk vulnerability High/Critical.





---

🏁 Kesimpulan

Dengan pipeline ini, Vuln Bank dapat lebih cepat mendeteksi celah keamanan sebelum aplikasi masuk ke production.
Pipeline DevSecOps ini membantu developer dan security engineer bekerja sama secara otomatis, konsisten, dan terukur.


---

✍️ Author: gisma hoerudin 
📌 Role: demo DevSecOps Engineer Final Project
