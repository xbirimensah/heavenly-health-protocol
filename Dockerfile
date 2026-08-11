FROM python:3.14-alpine@sha256:a1321512d6a287428c50dcdf2ab3857761127e03a23b1f648e9c1c0de59288f8

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HEAVENLY_MCP_HOST=0.0.0.0 \
    HEAVENLY_MCP_PORT=8791

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . && \
    addgroup -g 10001 heavenly && \
    adduser -D -u 10001 -G heavenly heavenly && \
    mkdir -p /home/heavenly/data && \
    chown -R heavenly:heavenly /home/heavenly/data

USER heavenly
WORKDIR /home/heavenly

EXPOSE 8791
ENTRYPOINT ["heavenly-mcp"]
