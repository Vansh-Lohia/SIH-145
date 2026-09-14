FROM python:3.11-slim
RUN apt-get update && apt-get install -y dnsutils && rm -rf /var/lib/apt/lists/*
CMD ["python3", "-m", "http.server", "80"]