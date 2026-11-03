FROM ghcr.io/astral-sh/uv:0.13.7@sha256:96f40d3904aad8d0bd010539001d36c8e2188b981e1334471a90c4a1d93bb490 AS uv

FROM python:alpine@sha256:f6a589d43c42b9e7f7dc67a12d37132491f362859a5d750607710cc56da3bc72
COPY --from=uv /uv /usr/local/bin/uv
RUN apk add --no-cache build-base libffi-dev libxml2-dev libxslt-dev
WORKDIR /app
COPY . /app
# Install from uv.lock so every dependency is pinned by hash
RUN UV_PROJECT_ENVIRONMENT=/usr/local uv sync --frozen --no-dev --no-editable --no-cache
ENTRYPOINT ["dnsrecon"]
