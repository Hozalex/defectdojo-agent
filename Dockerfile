FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/deps -r requirements.txt

# ── Runtime image ──────────────────────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

COPY --from=builder /deps /usr/local
COPY *.py ./

RUN useradd -m -u 1000 agent \
    && chown -R agent:agent /app
USER agent

ENV LOG_LEVEL=INFO
ENV NOTIFY_FORMAT=slack
ENV MAX_FINDINGS=10

CMD ["python", "main.py"]
