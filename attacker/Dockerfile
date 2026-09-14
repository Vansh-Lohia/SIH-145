FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y hping3 curl dnsutils python3 python3-pip iproute2 && \
    pip3 install scapy --break-system-packages && \
    rm -rf /var/lib/apt/lists/*
COPY spoof_query.py /spoof_query.py
CMD ["sleep", "infinity"]