FROM python:3.9-slim

# Install PostgreSQL client dengan no-install-recommends
RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Buat user non-root
RUN useradd -m appuser
RUN mkdir -p /app/static/uploads /app/templates && chown -R appuser:appuser /app

COPY . .

# Pastikan directory bisa ditulis oleh user non-root
RUN chmod 755 /app/static/uploads

# Ganti user ke non-root
USER appuser

EXPOSE 5000

# Tambahkan healthcheck (cek aplikasi berjalan)
HEALTHCHECK CMD curl --fail http://localhost:5000 || exit 1

CMD ["python", "app.py"]

