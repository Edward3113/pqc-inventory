# pqc-inventory itself, on Debian 13 so the post-quantum probe has OpenSSL 3.5.
# Build context is the repository root (see lab/compose.yaml).
FROM python:3.12-slim-trixie

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl openssh-client \
 && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev

RUN useradd --create-home scanner && mkdir -p /output && chown scanner /output
USER scanner

ENTRYPOINT ["/app/.venv/bin/pqc-inventory"]
