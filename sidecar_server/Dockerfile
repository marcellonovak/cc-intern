# sidecar_server/Dockerfile

FROM python:3.8-slim

WORKDIR /app

COPY sidecar_server.py .

RUN pip install flask pyOpenSSL requests

CMD ["python", "sidecar_server.py"]
