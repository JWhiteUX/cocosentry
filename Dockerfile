# ── Stage 1: base ────────────────────────────────────────────────
FROM python:3.11-slim-bookworm AS base

ARG INSTALL_EDGETPU=true

ENV PYTHONUNBUFFERED=1

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libpcap0.8 \
        usbutils \
        gnupg \
        curl && \
    if [ "$INSTALL_EDGETPU" = "true" ]; then \
        curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg \
            | gpg --dearmor -o /usr/share/keyrings/coral-edgetpu.gpg && \
        echo "deb [signed-by=/usr/share/keyrings/coral-edgetpu.gpg] https://packages.cloud.google.com/apt coral-edgetpu-stable main" \
            > /etc/apt/sources.list.d/coral-edgetpu.list && \
        apt-get update && \
        apt-get install -y --no-install-recommends libedgetpu1-std; \
    fi && \
    apt-get purge -y gnupg curl && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── Stage 2: runtime (default) ──────────────────────────────────
FROM base AS runtime

COPY pyproject.toml README.md ./
COPY cocosentry/ cocosentry/
RUN pip install --no-cache-dir ".[coral,mqtt]"

COPY config.example.toml .

RUN mkdir -p /app/models /data

ENTRYPOINT ["python", "-m", "cocosentry"]
CMD ["--config", "/app/config.toml", "-v"]

# ── Stage 3: training ───────────────────────────────────────────
FROM runtime AS training

RUN pip install --no-cache-dir ".[training]"

COPY training/ training/

ENTRYPOINT ["python"]

# ── Stage 4: dev ─────────────────────────────────────────────────
FROM training AS dev

RUN pip install --no-cache-dir ".[dev]"

COPY tests/ tests/

ENTRYPOINT ["python", "-m", "pytest"]
