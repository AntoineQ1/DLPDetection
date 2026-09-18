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
    iptables \
    iproute2 \
    libpcap-dev

WORKDIR /app

# Dynamic installation of Python dependencies using uv
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project --group gateway

# Network configuration setup & Keep the container running indefinitely
COPY docker/gateway-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]