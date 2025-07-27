# Use the official Python image as a base.
# We're choosing Python 3.9 on a slim Debian Buster distribution for a smaller image size.
FROM python:3.9-slim-buster

# Set the working directory inside the container.
# All subsequent commands will be executed relative to this directory.
WORKDIR /app

# Copy the requirements.txt file into the container's working directory.
# This is done separately to leverage Docker's build cache. If only requirements.txt changes,
# the pip install step will be re-run; otherwise, it uses the cached layer.
COPY requirements.txt .
COPY main.py .

# Install the Python dependencies listed in requirements.txt.
# --no-cache-dir: Prevents pip from storing downloaded packages in a cache, saving space.
# -r requirements.txt: Installs packages from the specified file.
RUN pip install --no-cache-dir -r requirements.txt

# Define the port that the container will listen on.
# Cloud Run injects the PORT environment variable, typically 8080.
# Setting ENV PORT 8080 here provides a default if PORT isn't set,
# and also informs Docker that the container intends to expose this port.
ENV PORT 8080
EXPOSE $PORT

# Run the application
CMD ["python", "main.py"]
