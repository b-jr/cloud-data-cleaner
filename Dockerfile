# Use updated Python image with supported Debian version
FROM python:3.11-slim-bookworm

# Install system dependencies with clean cache
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    default-libmysqlclient-dev \
    && rm -rf /var/lib/apt/lists/*

# Set work directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies with pip cache disabled
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Set environment variables
ENV PORT=8080
ENV PYTHONUNBUFFERED=1
ENV GUNICORN_CMD_ARGS="--timeout 120 --workers 4 --bind 0.0.0.0:${PORT}"

# Expose port
EXPOSE $PORT

# Run the application
CMD ["gunicorn", "main:app"]
