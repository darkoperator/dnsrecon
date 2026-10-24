FROM ghcr.io/astral-sh/uv:0.13.1@sha256:4a1f3666816dafadd20ceb71eac9a7d56d7ef30279f7d64048519ab901ada336 AS uv

FROM python:alpine@sha256:f6a589d43c42b9e7f7dc67a12d37132491f362859a5d750607710cc56da3bc72
COPY --from=uv /uv /usr/local/bin/uv
RUN apk add --no-cache build-base libffi-dev libxml2-dev libxslt-dev
WORKDIR /app
COPY . /app
# Install from uv.lock so every dependency is pinned by hash
RUN UV_PROJECT_ENVIRONMENT=/usr/local uv sync --frozen --no-dev --no-editable --no-cache
ENTRYPOINT ["dnsrecon"]
