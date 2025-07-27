FROM python:3.9-slim-buster

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc python3-dev && \
    rm -rf /var/lib/apt/lists/*

# Set work directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Set the PORT environment variable
ENV PORT=8080
EXPOSE $PORT

# Run the application with Gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:$PORT", "main:app"]
