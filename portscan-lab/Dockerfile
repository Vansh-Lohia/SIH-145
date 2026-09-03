FROM zeek/zeek:latest

# Attack + capture tooling on top of the official Zeek image.
RUN apt-get update && \
    apt-get install -y --no-install-recommends nmap tcpdump ncat curl iproute2 && \
    rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
