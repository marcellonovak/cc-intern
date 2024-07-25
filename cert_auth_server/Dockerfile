# cert_auth_server/Dockerfile

FROM python:3.8-slim

WORKDIR /app

COPY cert_auth_server.py .
COPY generate_cert.py .

RUN pip install pyOpenSSL flask

# Run the script to generate the CA key and certificate
RUN python generate_cert.py

CMD ["python", "cert_auth_server.py"]
