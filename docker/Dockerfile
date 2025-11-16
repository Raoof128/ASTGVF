FROM python:3.11-slim

LABEL maintainer="Security Research Team"
LABEL description="API Security Testing & GraphQL Vulnerability Framework"
LABEL version="1.0.0"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    libcairo2-dev \
    libpango1.0-dev \
    libgdk-pixbuf2.0-dev \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install the package
RUN pip install -e .

# Create output directory
RUN mkdir -p /app/reports

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Run as non-root user
RUN useradd -m -u 1000 scanner && \
    chown -R scanner:scanner /app
USER scanner

# Default command
ENTRYPOINT ["python", "-m", "orchestration.cli"]
CMD ["--help"]
