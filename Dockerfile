FROM ghcr.io/astral-sh/uv:0.13.6@sha256:af22a52f5eafef3d78e551599d405c02df61919d18028f0cea8eda93bc9986d0 AS uv

FROM python:alpine@sha256:f6a589d43c42b9e7f7dc67a12d37132491f362859a5d750607710cc56da3bc72
COPY --from=uv /uv /usr/local/bin/uv
RUN apk add --no-cache build-base libffi-dev libxml2-dev libxslt-dev
WORKDIR /app
COPY . /app
# Install from uv.lock so every dependency is pinned by hash
RUN UV_PROJECT_ENVIRONMENT=/usr/local uv sync --frozen --no-dev --no-editable --no-cache
ENTRYPOINT ["dnsrecon"]
