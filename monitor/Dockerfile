# monitor/Dockerfile
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y tcpdump && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]