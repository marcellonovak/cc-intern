FROM python:3.9-slim

WORKDIR /app

COPY sidecar_server.py /app/

RUN pip install flask requests pyopenssl

EXPOSE 5000

CMD ["python", "sidecar_server.py"]
