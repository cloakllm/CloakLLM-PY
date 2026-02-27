FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY cloakllm/ ./cloakllm/

RUN pip install --no-cache-dir . && \
    python -m spacy download en_core_web_sm

# Create audit log volume mount point
RUN mkdir -p /data/audit
ENV CLOAKLLM_LOG_DIR=/data/audit

COPY examples/ ./examples/

ENTRYPOINT ["python", "-m", "cloakllm"]
CMD ["--help"]
