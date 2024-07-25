# client/Dockerfile

FROM python:3.8-slim

WORKDIR /app

COPY client_server.py .

RUN pip install pyOpenSSL requests

CMD ["python", "client_server.py"]
