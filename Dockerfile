FROM python:3.13-slim@sha256:a0779d7c12fc20be6ec6b4ddc901a4fd7657b8a6bc9def9d3fde89ed5efe0a3d AS builder

ARG MINDROOM_APPROVED_EGRESS_PROXY_VERSION=0.0.0

ENV SETUPTOOLS_SCM_PRETEND_VERSION=${MINDROOM_APPROVED_EGRESS_PROXY_VERSION} \
    SETUPTOOLS_SCM_PRETEND_VERSION_FOR_MINDROOM_APPROVED_EGRESS_PROXY=${MINDROOM_APPROVED_EGRESS_PROXY_VERSION} \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:0.11.3@sha256:90bbb3c16635e9627f49eec6539f956d70746c409209041800a0280b93152823 /uv /uvx /bin/

COPY pyproject.toml uv.lock ./
COPY README.md ./
COPY src ./src
RUN uv sync --locked --no-dev

FROM python:3.13-slim@sha256:a0779d7c12fc20be6ec6b4ddc901a4fd7657b8a6bc9def9d3fde89ed5efe0a3d

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates squid \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /etc/mindroom-egress /run/squid /var/lib/mindroom-egress /var/log/squid /var/spool/squid \
    && chown -R 1000:1000 /etc/mindroom-egress /run/squid /var/lib/mindroom-egress /var/log/squid /var/spool/squid

COPY --from=builder /app/.venv /app/.venv
COPY squid.conf /etc/squid/squid.conf
COPY allowed-domains.txt /etc/mindroom-egress/allowed-domains.txt
RUN squid -k parse -f /etc/squid/squid.conf

CMD ["mindroom-egress-proxy"]
