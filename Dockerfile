# One image for api, scheduler and collector; the first argument picks the role.
FROM docker.io/library/python:3.12-slim AS build
COPY --from=ghcr.io/astral-sh/uv:0.5.11 /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
# Built where it runs: console scripts keep the venv path in their shebang.
WORKDIR /app
COPY pyproject.toml uv.lock .python-version ./
COPY packages packages
COPY services services
RUN uv sync --frozen --no-dev --no-editable

FROM docker.io/library/python:3.12-slim
RUN useradd --uid 10001 --no-create-home periskope
COPY --from=build /app/.venv /app/.venv
COPY docker/entrypoint.sh /app/entrypoint.sh
ENV PATH=/app/.venv/bin:$PATH PYTHONUNBUFFERED=1
USER 10001
ENTRYPOINT ["/app/entrypoint.sh"]
