FROM python:3.12-slim-bookworm

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r aegis && useradd -r -g aegis -d /app aegis

COPY pyproject.toml README.md ./
COPY aegis ./aegis
COPY knowledge-base ./knowledge-base

RUN pip install --no-cache-dir -e . \
    && mkdir -p /app/data/models \
    && chown -R aegis:aegis /app

USER aegis

ENV DEPLOYMENT_PROFILE=personal
ENV ENVIRONMENT=production
ENV DATA_DIR=/app/data
ENV PYTHONUNBUFFERED=1
ENV AUTO_RESPONSE_ENABLED=false
ENV SOAR_SIMULATION_MODE=true

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

CMD ["aegis", "serve", "--host", "0.0.0.0", "--port", "8080"]
