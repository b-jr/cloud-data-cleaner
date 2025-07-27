# Use updated Python image with supported Debian version
FROM python:3.9-slim-bullseye

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc python3-dev default-libmysqlclient-dev && \
    rm -rf /var/lib/apt/lists/*

# Set work directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Set the PORT environment variable (Cloud Run uses 8080 by default)
ENV PORT=8080
EXPOSE $PORT

# Run the application with Gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:$PORT", "--timeout", "120", "main:app"]
