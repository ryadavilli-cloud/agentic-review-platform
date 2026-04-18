# Stage 1: Build

FROM python:3.12-slim-bookworm AS builder

WORKDIR /build
RUN pip install poetry==2.2.0 poetry-plugin-export
COPY pyproject.toml poetry.lock ./
RUN poetry export -f requirements.txt --output requirements.txt --without-hashes --only main


#Stage 2: Runtime

FROM python:3.12-slim-bookworm
RUN useradd --system --create-home --shell /bin/bash --uid 1001 appuser
WORKDIR /app

COPY --from=builder /build/requirements.txt ./

ENV PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin
RUN pip install --no-cache-dir pipx && \
    pipx install semgrep==1.159.0 && \
    pipx install pip-audit==2.10.0
    
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY demo-packs/ ./demo-packs/

RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

