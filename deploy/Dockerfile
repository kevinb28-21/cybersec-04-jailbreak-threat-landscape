FROM python:3.12-slim-bookworm

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY aegis ./aegis
COPY knowledge-base ./knowledge-base

RUN pip install --no-cache-dir -e .

ENV DEPLOYMENT_PROFILE=personal
ENV DATA_DIR=/app/data
ENV PYTHONUNBUFFERED=1

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

CMD ["aegis", "serve", "--host", "0.0.0.0", "--port", "8080"]
