FROM python:3.9-slim

WORKDIR /app

COPY client_server.py /app/

RUN pip install requests pyopenssl

CMD ["python", "client_server.py"]
