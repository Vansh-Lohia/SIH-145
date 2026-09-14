FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y dnsmasq tcpdump && rm -rf /var/lib/apt/lists/*
COPY dnsmasq.conf /etc/dnsmasq.conf
CMD ["dnsmasq", "--no-daemon"]