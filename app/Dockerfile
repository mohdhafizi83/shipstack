FROM python:3.12-alpine@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4

WORKDIR /srv

RUN adduser -D -u 10001 appuser
COPY app.py .

# Same contract the ECS task definition expects:
# - listens on 8080
# - GET /healthz -> 200 (ALB target-group health check)
# - runs as non-root
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Container-level liveness: ECS/cloud-init style healthcheck against the same
# /healthz the ALB target group uses, stdlib only (no curl in alpine python).
HEALTHCHECK --interval=30s --timeout=3s --retries=3 --start-period=5s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=2).status==200 else 1)"

EXPOSE 8080
USER appuser
CMD ["python", "app.py"]
