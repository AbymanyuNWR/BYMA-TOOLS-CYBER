FROM python:3.11-slim

LABEL maintainer="BYMA SECURITY"
LABEL description="BYMA TOOLS - Multi-Purpose Cybersecurity Toolkit"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    dnsutils \
    whois \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for Docker cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Make scripts executable
RUN chmod +x main.py byma.py

# Default command
ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
