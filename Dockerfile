# syntax=docker/dockerfile:1
FROM python:latest AS builder
WORKDIR /app
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"
COPY --parents requirements.txt parsers/*/requirements.txt ./
RUN python -m venv "${VIRTUAL_ENV}" && \
    find /app -name requirements.txt -exec pip install --no-cache-dir -r {} \; && \
    chmod -R a+rX "${VIRTUAL_ENV}"

FROM python:slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1
ENV MAGENTA_HOME=/app
ENV MPLCONFIGDIR=/tmp
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"
RUN apt-get update && \
    apt-get install -y --no-install-recommends fontconfig fonts-dejavu-core && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder "${VIRTUAL_ENV}" "${VIRTUAL_ENV}"
COPY . /app
RUN echo '{"internal_cache": "/app/cache/.magenta.cache"}' > /app/magenta.json5 && \
    python -c "from libmagenta.engine import MagentaReporter; MagentaReporter().set_language('en')" && \
    python -m compileall . && \
    useradd magenta && \
    mkdir /app/cache && chown magenta: /app/cache
VOLUME ["/app/cache"]
USER magenta
ENTRYPOINT [ "python", "/app/magenta.py", "-c", "/app/magenta.json5" ]
