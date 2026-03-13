FROM python:latest
WORKDIR /app
ENV PYTHONUNBUFFERED=1
ENV MAGENTA_HOME=/app
ENV MPLCONFIGDIR=/tmp
COPY . /app
RUN find /app -name requirements.txt -exec pip install -r {} \; -exec rm {} \; ; \
    python -c "from libmagenta.engine import MagentaReporter; MagentaReporter().set_language('en')" ; \
    python -m compileall . ; \
    useradd magenta
USER magenta
ENTRYPOINT [ "python", "/app/magenta.py" ]