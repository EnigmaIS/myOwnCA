# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1

WORKDIR /opt/license-issuer
COPY pyproject.toml ./
COPY src/ ./src/
RUN pip install --no-cache-dir .

WORKDIR /work
ENTRYPOINT ["myownca-license"]
CMD ["--help"]
