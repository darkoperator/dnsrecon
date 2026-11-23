FROM ghcr.io/astral-sh/uv:0.13.9@sha256:d3b601f0c7b118bc1753febf7c41cc80981df678445e0254284eecf84db79a7d AS uv

FROM python:alpine@sha256:0f9552bb28711333da16915ec146f5e6bb44a7fdac9ced15dc17c2e0206346dd
COPY --from=uv /uv /usr/local/bin/uv
RUN apk add --no-cache build-base libffi-dev libxml2-dev libxslt-dev
WORKDIR /app
COPY . /app
# Install from uv.lock so every dependency is pinned by hash
RUN UV_PROJECT_ENVIRONMENT=/usr/local uv sync --frozen --no-dev --no-editable --no-cache
ENTRYPOINT ["dnsrecon"]
