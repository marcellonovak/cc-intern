FROM python:3.8-slim

WORKDIR /app

COPY web_server.py .

RUN pip install requests pyOpenSSL flask

CMD ["python", "web_server.py"]