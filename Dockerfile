FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

ENV PYTHONUNBUFFERED=1 \
    TZ=Asia/Shanghai \
    UV_COMPILE_BYTECODE=1 \
    UV_CACHE_DIR=/tmp/uv-cache \
    UV_FROZEN=1 \
    UV_LINK_MODE=copy \
    UV_NO_SYNC=1

RUN groupadd --system cairn \
    && useradd --system --gid cairn --home-dir /home/cairn --create-home cairn \
    && mkdir -p /cairn \
    && chown cairn:cairn /cairn

WORKDIR /cairn
USER cairn

COPY --chown=cairn:cairn ./cairn/pyproject.toml ./pyproject.toml
COPY --chown=cairn:cairn ./cairn/uv.lock ./uv.lock
RUN uv sync --frozen --no-dev --no-install-project

COPY --chown=cairn:cairn ./cairn/src ./src
COPY --chown=cairn:cairn ./cairn/alembic.ini ./alembic.ini
COPY --chown=cairn:cairn ./cairn/migrations ./migrations
RUN uv sync --frozen --no-dev

ENV PATH="/cairn/.venv/bin:${PATH}"

EXPOSE 8000
CMD ["uv", "run", "cairn", "serve", "--host", "0.0.0.0", "--no-access-log"]
