FROM python:3.9-slim

# Install PostgreSQL client
RUN apt-get update && apt-get install -y \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create necessary directories
RUN mkdir -p static/uploads templates

COPY . .

# Ensure uploads directory exists and has proper permissions
RUN chmod 777 static/uploads

# Buat user non-root
RUN addgroup --system appgroup && adduser --system appuser --ingroup appgroup

# Ubah ownership folder /app ke user baru
RUN chown -R appuser:appgroup /app

# Pindah ke user non-root
USER appuser

EXPOSE 5000

# Tambahkan healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:5000/ || exit 1

# Jalankan aplikasi
CMD ["python", "app.py"]
