# ── Stage 1: base ────────────────────────────────────────────────
FROM python:3.15-rc-slim-trixie AS base

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

# Create non-root user for runtime.
# Note: The container still requires privileged mode and host networking
# for USB device access (WiFi Coconut adapter and Coral Edge TPU).
RUN groupadd -r cocosentry && \
    useradd -r -g cocosentry -d /app -s /sbin/nologin cocosentry && \
    mkdir -p /app/models /data && \
    chown -R cocosentry:cocosentry /app /data

USER cocosentry

ENTRYPOINT ["python", "-m", "cocosentry"]
CMD ["--config", "/app/config.toml", "-v"]

# ── Stage 3: training ───────────────────────────────────────────
FROM runtime AS training

USER root
RUN pip install --no-cache-dir ".[training]"
USER cocosentry

COPY training/ training/

ENTRYPOINT ["python"]

# ── Stage 4: dev ─────────────────────────────────────────────────
FROM training AS dev

USER root
RUN pip install --no-cache-dir ".[dev]"
USER cocosentry

COPY tests/ tests/

ENTRYPOINT ["python", "-m", "pytest"]
