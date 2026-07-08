# syntax=docker/dockerfile:1

# ---------- Stage 1: build the frontend ----------
FROM node:22-slim AS frontend-build
WORKDIR /app/web

COPY web/package.json web/package-lock.json ./
RUN npm ci

COPY web/ ./
RUN npm run build


# ---------- Stage 2: Python runtime ----------
FROM python:3.12-slim AS runtime
WORKDIR /app

# core/ first (changes less often than api/), for better layer caching.
COPY core/pyproject.toml core/pyproject.toml
COPY core/eidas_inspect_core core/eidas_inspect_core
RUN pip install --no-cache-dir ./core

# api/'s own (production-only -- no httpx/pytest) requirements.
COPY api/requirements.txt api/requirements.txt
RUN pip install --no-cache-dir -r api/requirements.txt

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
