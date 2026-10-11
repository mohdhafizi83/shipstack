FROM python:3.12-alpine

WORKDIR /srv

RUN adduser -D -u 10001 appuser
COPY app.py .

# Same contract the ECS task definition expects:
# - listens on 8080
# - GET /healthz -> 200 (ALB target-group health check)
# - runs as non-root
EXPOSE 8080
USER appuser
CMD ["python", "app.py"]
