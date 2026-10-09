# Build stage: install dependencies into a separate prefix
FROM python:3.12-slim AS build
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Runtime stage: only the installed packages and the app, run as a non-root user
FROM python:3.12-slim
RUN useradd --create-home --uid 10001 alibi
COPY --from=build /install /usr/local
WORKDIR /app
COPY src ./src
ENV PYTHONPATH=/app/src PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER alibi
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request, sys; sys.exit(urllib.request.urlopen('http://127.0.0.1:8000/v1/health', timeout=4).status != 200)"
CMD ["uvicorn", "ittravel.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
