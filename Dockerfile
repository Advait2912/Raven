# Multi-stage / lightweight container for RAVEN platform
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install security and test dependencies if needed
RUN pip install --no-cache-dir pytest requests

# Copy source code and frontend assets
COPY raven/ /app/raven/
COPY attack/ /app/attack/
COPY web/ /app/web/
COPY tests/ /app/tests/

# Non-root user for security best practices
RUN useradd -m -u 1000 raven && chown -R raven:raven /app
USER raven

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/demo/evidence')" || exit 1

ENTRYPOINT ["python", "-m", "raven.main"]
CMD ["--port", "8000", "--host", "0.0.0.0"]
