# syntax=docker/dockerfile:1.6
FROM python:3.11-slim AS base

WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev build-essential iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml requirements.txt ./
COPY src ./src
COPY configs ./configs
COPY tests ./tests
COPY reproduce.sh README.md ./

RUN pip install --upgrade pip && pip install -e ".[dev]"

EXPOSE 8000
CMD ["uvicorn", "maestro.server.app:app", "--host", "0.0.0.0", "--port", "8000"]
