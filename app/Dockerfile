# Imagen endurecida: base fija, usuario sin privilegios, sin debug, servidor WSGI de produccion
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    DATABASE=/app/data/securedev.db METRICS_PORT=9102
WORKDIR /app

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin appuser
COPY requirements.txt .
RUN pip install --no-cache-dir --disable-pip-version-check -r requirements.txt

COPY app.py init_db.py ./
RUN mkdir -p /app/data && python init_db.py && chown -R appuser:appuser /app/data

USER appuser
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:5000/login')"
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", "--access-logfile", "-", "app:app"]
