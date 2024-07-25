FROM python:3.8-slim

WORKDIR /app

COPY web_server.py /app/

RUN pip install flask pyopenssl requests

CMD ["python", "web_server.py"]
