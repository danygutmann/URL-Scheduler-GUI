FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_DATA_DIR=/app/data \
    APP_HOST=0.0.0.0

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r requirements.txt \
    && groupadd --system scheduler && useradd --system --gid scheduler --home-dir /app scheduler \
    && mkdir -p /app/data && chown scheduler:scheduler /app/data
COPY --chown=scheduler:scheduler app ./app
COPY --chown=scheduler:scheduler alembic.ini .
USER scheduler
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:'+__import__('os').getenv('APP_PORT','8080')+'/healthz', timeout=3)"
CMD ["python", "-m", "app.main"]
