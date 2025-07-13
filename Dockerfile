# Multi-stage Dockerfile for Network Threat Analyzer
FROM python:3.11-slim as dependencies

# Install system dependencies for packet capture
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    net-tools \
    iproute2 \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim as production

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    tcpdump \
    net-tools \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r analyzer && useradd -r -g analyzer analyzer

# Set working directory
WORKDIR /app

# Copy Python dependencies from previous stage
COPY --from=dependencies /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=dependencies /usr/local/bin /usr/local/bin

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p logs data configs templates static \
    && chown -R analyzer:analyzer /app

# Copy default config if not exists
RUN if [ ! -f configs/config.yaml ]; then \
    cp configs/config.yaml.example configs/config.yaml 2>/dev/null || \
    echo "monitoring:\n  interface: eth0\n  packet_count: 0\n  timeout: 30\nthresholds:\n  brute_force_attempts: 5\n  ddos_packets_per_second: 1000\n  port_scan_threshold: 10\nintegrations:\n  enable_api_lookups: false\nnotifications:\n  email_enabled: false" > configs/config.yaml; \
    fi

# Set permissions for packet capture
# Note: This requires --cap-add=NET_ADMIN or --privileged when running container
RUN chmod +s /usr/bin/tcpdump

# Switch to non-root user
USER analyzer

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/status || exit 1

# Environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Default command
CMD ["python", "-m", "src.web_server", "--host", "0.0.0.0", "--port", "8000"]