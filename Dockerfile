FROM python:3.11-slim

# Install Nmap and required system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code
COPY . .

# Expose port
EXPOSE 8000

# Start Uvicorn with Railway's dynamic PORT
CMD uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}
