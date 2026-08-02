FROM node:22-bookworm-slim AS frontend

WORKDIR /build

COPY package.json package-lock.json tailwind.config.cjs ./
RUN npm ci

COPY static ./static
RUN npm run build:css

FROM node:22-bookworm-slim AS codex

ARG CODEX_VERSION=0.144.5

RUN npm install --global \
        "@openai/codex@${CODEX_VERSION}" \
        "@openai/codex-linux-x64@npm:@openai/codex@${CODEX_VERSION}-linux-x64" \
    && codex --version

FROM python:3.12-slim

ARG FY_VERSION=0.2.0
ARG VCS_REF=unknown

LABEL org.opencontainers.image.title="fy-infinite-canvas" \
    org.opencontainers.image.description="扶摇定制版 Infinite Canvas" \
    org.opencontainers.image.version="${FY_VERSION}" \
    org.opencontainers.image.revision="${VCS_REF}" \
    org.opencontainers.image.source="https://github.com/Hazey-Rookie/fy-infinite-canvas"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/home/app \
    CODEX_HOME=/home/app/.codex

WORKDIR /app

COPY --from=codex /usr/local/bin/node /usr/local/bin/node
COPY --from=codex /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s /usr/local/lib/node_modules/@openai/codex/bin/codex.js /usr/local/bin/codex \
    && codex --version

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt websockets

COPY . .
COPY --from=frontend /build/static/css/tailwind.generated.css /app/static/css/tailwind.generated.css

RUN mkdir -p API data assets output workflows/custom \
    && useradd --create-home --uid 10001 app \
    && mkdir -p /home/app/.codex \
    && chown -R app:app /app /home/app/.codex

USER app

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:3000/', timeout=3)" || exit 1

CMD ["python", "main.py"]
