# syntax=docker/dockerfile:1
# Production image for the xtester control plane (API + worker share this image).
# Hardening notes:
#  - runs as non-root (UID 10001)
#  - read-only root filesystem (writable mounts for /data, /tmp)
#  - no debug tooling; python:3.12-slim as base
#  - Playwright chromium installed for the detection worker
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv

RUN groupadd --gid 10001 appuser \
    && useradd --uid 10001 --gid appuser --home-dir /srv --shell /usr/sbin/nologin appuser \
    && mkdir -p /data /srv/frontend \
    && chown -R appuser:appuser /data /srv

COPY backend/requirements.txt /srv/requirements.txt
RUN pip install --no-cache-dir -r /srv/requirements.txt

# Playwright chromium + deps (kept in the same layer for atomicity)
RUN playwright install chromium --with-deps \
    && playwright install-deps chromium

COPY backend/app /srv/app
COPY backend/frontend /srv/frontend

USER appuser

# writable runtime dirs (overwritten by compose volume mounts for persistence)
RUN mkdir -p /data/audit

VOLUME ["/data"]

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--no-access-log"]