FROM node:22-bookworm-slim AS workbench-build

WORKDIR /workbench
COPY ./cairn/web/package.json ./cairn/web/package-lock.json ./
RUN npm ci
COPY ./cairn/web/ ./
RUN npm run build


FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

ENV PYTHONUNBUFFERED=1 \
    TZ=Asia/Shanghai \
    UV_COMPILE_BYTECODE=1 \
    UV_CACHE_DIR=/tmp/uv-cache \
    UV_FROZEN=1 \
    UV_LINK_MODE=copy \
    UV_NO_SYNC=1

ARG DEBIAN_MIRROR=https://deb.debian.org/debian
ARG DEBIAN_SECURITY_MIRROR=https://deb.debian.org/debian-security

RUN sed -i \
        -e "s|http://deb.debian.org/debian-security|${DEBIAN_SECURITY_MIRROR}|g" \
        -e "s|http://deb.debian.org/debian|${DEBIAN_MIRROR}|g" \
        /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Retries=5 update \
    && apt-get -o Acquire::Retries=5 install --yes --no-install-recommends \
        ca-certificates \
        git \
        openssh-client \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system cairn \
    && useradd --system --gid cairn --home-dir /home/cairn --create-home cairn \
    && mkdir -p \
        /cairn \
        /var/lib/cairn/artifacts \
        /var/lib/cairn/ingestion \
        /var/lib/cairn/sandbox-state \
        /var/lib/cairn/sandbox-work \
    && chown -R cairn:cairn /cairn /var/lib/cairn

WORKDIR /cairn
USER cairn

COPY --chown=cairn:cairn ./cairn/pyproject.toml ./pyproject.toml
COPY --chown=cairn:cairn ./cairn/uv.lock ./uv.lock
RUN uv sync --frozen --no-dev --no-install-project

COPY --chown=cairn:cairn ./cairn/src ./src
COPY --from=workbench-build --chown=cairn:cairn \
    /workbench/dist ./src/cairn/server/static
COPY --chown=cairn:cairn ./cairn/alembic.ini ./alembic.ini
COPY --chown=cairn:cairn ./cairn/migrations ./migrations
RUN uv sync --frozen --no-dev

ENV PATH="/cairn/.venv/bin:${PATH}"

EXPOSE 8000 8001
CMD ["uv", "run", "cairn", "serve", "--host", "0.0.0.0", "--no-access-log"]
