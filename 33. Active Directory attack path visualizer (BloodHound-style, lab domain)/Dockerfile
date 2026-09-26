# SentinelGraph — backend + built SPA (multi-stage)
FROM node:20-alpine AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci --no-audit --no-fund || npm install --no-audit --no-fund
COPY frontend/ .
# vite.config.ts outputs to ../backend/static relative to frontend/,
# so build with an override to keep it inside the builder stage:
RUN npx vite build --outDir dist

FROM python:3.12-slim
WORKDIR /srv
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt python-multipart
COPY backend/ .
RUN rm -rf static
COPY --from=ui /ui/dist ./static

ENV SG_ENVIRONMENT=production \
    SG_HOST=0.0.0.0 \
    SG_PORT=8000
EXPOSE 8000
# SG_JWT_SECRET must be injected at deploy time (>= 32 chars) — see SECURITY.md
CMD ["python", "run.py"]
