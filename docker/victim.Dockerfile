# Base image (default : 3.14-slim)
ARG PYTHON_VERSION=3.14-slim
FROM python:${PYTHON_VERSION}

# Import of uv manager
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Environment variables for Python
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH="/app" \
    PATH="/app/.venv/bin:$PATH"

# Install essential packages for network diagnostics and security
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    iproute2 \
    iputils-ping

WORKDIR /app

# Dynamic installation of Python dependencies using uv
COPY pyproject.toml uv.lock* ./
RUN uv sync --frozen --no-install-project --group victim

# Set up the CA certificate for mitmproxy to enable HTTPS interception
COPY config/certs/mitmproxy-ca-cert.crt /usr/local/share/ca-certificates/mitmproxy-ca-cert.crt
RUN update-ca-certificates

ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

# Default route set to the gateway IP & Keep the container running indefinitely
COPY docker/victim-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["sleep", "infinity"]