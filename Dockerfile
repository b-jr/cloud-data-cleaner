# Use updated Python image
FROM python:3.11-slim-bookworm

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    default-libmysqlclient-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# First copy requirements to leverage Docker cache
COPY requirements.txt .

# Upgrade pip before installing packages
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Environment variables
ENV PORT=8080
ENV PYTHONUNBUFFERED=1

# Run Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:$PORT", "--timeout", "120", "main:app"]
