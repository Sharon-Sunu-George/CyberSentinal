FROM python:3.11-slim

# Avoid buffering and interactive prompts during package installs
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Install system dependencies:
# - tesseract-ocr: for document image OCR parsing in Linux
# - curl & ca-certificates: for health checks and certificate verification
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency definition
COPY requirements.txt .

# Install dependencies (filter out Windows-specific winocr gracefully on Linux)
RUN grep -v "winocr" requirements.txt > requirements-linux.txt && \
    pip install --no-cache-dir -r requirements-linux.txt

# Install Playwright Chromium engine and only its required OS system libraries
RUN playwright install --with-deps chromium

# Copy application source code
COPY . .

# Expose container port (default 8010, overridden at runtime via $PORT)
EXPOSE 8010

# Start command: dynamically binds to $PORT provided by hosting environment, defaulting to 8010
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8010}"]
