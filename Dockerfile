# syntax=docker/dockerfile:1

# ---------- Stage 1: build the frontend ----------
FROM node:22-slim AS frontend-build
WORKDIR /app/web

COPY web/package.json web/package-lock.json ./
RUN npm ci

COPY web/ ./
RUN npm run build


# ---------- Stage 2: Python runtime ----------
# Pinned to bookworm (Debian 12) explicitly, not just "slim" (which floats
# to whatever Debian release is current -- already trixie/13 as of this
# writing): Guardtime's own ksi-tool APT repo only publishes a bookworm
# build, and it's amd64-only, hence --platform below. Railway's own build
# infrastructure is amd64, so pinning it here removes any ambiguity rather
# than relying on the host architecture at build time.
FROM --platform=linux/amd64 python:3.12-slim-bookworm AS runtime
WORKDIR /app

# core/ first (changes less often than api/), for better layer caching.
COPY core/pyproject.toml core/pyproject.toml
COPY core/eidas_inspect_core core/eidas_inspect_core
RUN pip install --no-cache-dir ./core

# api/'s own (production-only -- no httpx/pytest) requirements.
COPY api/requirements.txt api/requirements.txt
RUN pip install --no-cache-dir -r api/requirements.txt

# ksi-tool (Apache-2.0, github.com/guardtime/ksi-tool): Guardtime's own
# reference implementation for verifying KSI (Keyless Signature
# Infrastructure) seals -- eidas_inspect_core.ksi_tool subprocesses out to
# this rather than reimplementing KSI's hash-chain/publications-file
# cryptography ourselves, the same rule this project already applies to
# pyHanko for PAdES/CMS. Versions pinned (ksi-tools/libksi/libparamset,
# all Apache-2.0) so a Dockerfile rebuild can't silently pick up a newer
# release with different behavior; bump deliberately. curl/gnupg only
# exist to fetch and verify Guardtime's own APT signing key -- not needed
# at runtime, but keeping them is cheap and they're tiny.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl gnupg ca-certificates \
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://download.guardtime.com/ksi/GUARDTIME-GPG-KEY-2 \
        | gpg --dearmor -o /etc/apt/keyrings/GUARDTIME-GPG-KEY-2 \
    && curl -fsSL https://download.guardtime.com/ksi/configuration/guardtime.bookworm.list \
        -o /etc/apt/sources.list.d/guardtime.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ksi-tools=2.10.1387 libksi=3.21.3087 libparamset=1.1.244 \
    && rm -rf /var/lib/apt/lists/*

COPY api api

# The built frontend lands in the exact directory FastAPI serves as static
# files (see api/config.py's static_dir default) -- no separate web server,
# no CORS, same origin for API and UI in production.
COPY --from=frontend-build /app/web/dist api/static

EXPOSE 8000

# --proxy-headers (uvicorn's default) trusts X-Forwarded-For/-Proto to set
# the real client IP/scheme; --forwarded-allow-ips='*' is required for that
# to actually take effect behind Railway's proxy, whose address isn't a
# fixed, allowlist-able IP. Without this, every request looks like it comes
# from the same internal proxy IP -- which would put every real user behind
# the app in the *same* rate-limit bucket. $PORT is injected by Railway.
CMD ["sh", "-c", "uvicorn api.main:app --host 0.0.0.0 --port ${PORT:-8000} --forwarded-allow-ips='*'"]
