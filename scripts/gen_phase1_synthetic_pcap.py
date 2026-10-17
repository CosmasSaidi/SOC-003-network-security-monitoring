#!/usr/bin/env python3
"""
SOC-003 Phase 1 -- deterministic synthetic PCAP generator.

Purpose : Produce a small, fully synthetic, harmless packet capture for OFFLINE
          Zeek validation. Contains representative DNS, HTTP and TCP metadata
          only. No real hosts, credentials, personal data or captured traffic.

Determinism: fixed timestamps, fixed IP IDs, fixed MAC addresses, fixed sequence
          numbers and fixed payloads. Running this script always produces a
          byte-identical PCAP (see SHA256 in the Phase 1 report).

Addressing: RFC 5737 / RFC 6761 style placeholders. 192.168.56.101 is a
          synthetic lab client; 198.51.100.80 is TEST-NET-2 (never routable);
          QNAME uses the reserved .test TLD.
"""

from datetime import datetime, timezone
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap

# ---------------------------------------------------------------------------
# Fixed parameters (do not introduce randomness)
# ---------------------------------------------------------------------------
OUT = "/home/saidi/soc-lab/soc-003/evidence/phase1-zeek-baseline/phase1-synthetic-baseline.pcap"
T0 = datetime(2026, 10, 16, 6, 0, 0, tzinfo=timezone.utc).timestamp()  # fixed base epoch

MAC_CLIENT = "00:11:22:33:44:55"
MAC_DNS    = "00:11:22:33:44:66"
MAC_WEB    = "00:11:22:33:44:77"

CLIENT_IP = "192.168.56.101"
DNS_IP    = "192.168.56.53"
WEB_IP    = "198.51.100.80"

QNAME = "example.test"

HTTP_REQ_BODY = (
    "GET /index.html HTTP/1.1\r\n"
    "Host: example.test\r\n"
    "User-Agent: soc-lab-zeek-baseline/1.0\r\n"
    "Accept: */*\r\n"
    "Connection: close\r\n"
    "\r\n"
).encode()

HTML = b"<html><body><h1>SOC-003 synthetic baseline</h1></body></html>"
HTTP_RESP_BODY = (
    "HTTP/1.1 200 OK\r\n"
    "Server: soc-lab-synthetic/1.0\r\n"
    "Content-Type: text/html\r\n"
    f"Content-Length: {len(HTML)}\r\n"
    "Connection: close\r\n"
    "\r\n"
).encode() + HTML

packets = []

def eth(src, dst):
    return Ether(src=src, dst=dst)

def tcp_seg(src, dst, sport, dport, seq, ack, flags, window=64240, payload=b""):
    p = eth(MAC_CLIENT if src == CLIENT_IP else (MAC_DNS if src == DNS_IP else MAC_WEB),
            MAC_CLIENT if dst == CLIENT_IP else (MAC_DNS if dst == DNS_IP else MAC_WEB))
    p = p / IP(src=src, dst=dst, id=0x4000, ttl=64, flags="DF")
    p = p / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, window=window)
    if payload:
        p = p / Raw(load=payload)
    return p

# ---------------------------------------------------------------------------
# 1. DNS query / response (UDP/53) -- tests dns.log
# ---------------------------------------------------------------------------
packets.append(
    eth(MAC_CLIENT, MAC_DNS) / IP(src=CLIENT_IP, dst=DNS_IP, id=0x1001, ttl=64) /
    UDP(sport=52000, dport=53) /
    DNS(id=0x1234, rd=1, qd=DNSQR(qname=QNAME, qtype="A", qclass="IN"))
)
packets[-1].time = T0 + 0.000

packets.append(
    eth(MAC_DNS, MAC_CLIENT) / IP(src=DNS_IP, dst=CLIENT_IP, id=0x1002, ttl=64) /
    UDP(sport=53, dport=52000) /
    DNS(id=0x1234, qr=1, aa=1, rd=1, ra=1,
        qd=DNSQR(qname=QNAME, qtype="A", qclass="IN"),
        an=DNSRR(rrname=QNAME, type="A", ttl=300, rdata=WEB_IP))
)
packets[-1].time = T0 + 0.021

# ---------------------------------------------------------------------------
# 2. HTTP over TCP (client 49152 -> server 80) -- tests conn.log + http.log
# ---------------------------------------------------------------------------
CPORT, SPORT = 49152, 80
ISN_C, ISN_S = 1000, 5000000

packets.append(tcp_seg(CLIENT_IP, WEB_IP, CPORT, SPORT, ISN_C, 0, "S"))            # SYN
packets[-1].time = T0 + 0.100
packets.append(tcp_seg(WEB_IP, CLIENT_IP, SPORT, CPORT, ISN_S, ISN_C + 1, "SA"))   # SYN-ACK
packets[-1].time = T0 + 0.121
packets.append(tcp_seg(CLIENT_IP, WEB_IP, CPORT, SPORT, ISN_C + 1, ISN_S + 1, "A"))  # ACK
packets[-1].time = T0 + 0.122

cseq = ISN_C + 1
packets.append(tcp_seg(CLIENT_IP, WEB_IP, CPORT, SPORT, cseq, ISN_S + 1, "PA", payload=HTTP_REQ_BODY))
packets[-1].time = T0 + 0.123
cseq += len(HTTP_REQ_BODY)

packets.append(tcp_seg(WEB_IP, CLIENT_IP, SPORT, CPORT, ISN_S + 1, cseq, "A"))
packets[-1].time = T0 + 0.145
packets.append(tcp_seg(WEB_IP, CLIENT_IP, SPORT, CPORT, ISN_S + 1, cseq, "PA", payload=HTTP_RESP_BODY))
packets[-1].time = T0 + 0.146
sseq = ISN_S + 1 + len(HTTP_RESP_BODY)

packets.append(tcp_seg(CLIENT_IP, WEB_IP, CPORT, SPORT, cseq, sseq, "A"))
packets[-1].time = T0 + 0.147
packets.append(tcp_seg(CLIENT_IP, WEB_IP, CPORT, SPORT, cseq, sseq, "FA"))  # client FIN
packets[-1].time = T0 + 0.150
packets.append(tcp_seg(WEB_IP, CLIENT_IP, SPORT, CPORT, sseq, cseq + 1, "A"))
packets[-1].time = T0 + 0.171
packets.append(tcp_seg(WEB_IP, CLIENT_IP, SPORT, CPORT, sseq, cseq + 1, "FA"))  # server FIN
packets[-1].time = T0 + 0.172
packets.append(tcp_seg(CLIENT_IP, WEB_IP, CPORT, SPORT, cseq + 1, sseq + 1, "A"))
packets[-1].time = T0 + 0.193

# ---------------------------------------------------------------------------
# 3. Plain TCP connection, no payload (client 49153 -> 8080) -- conn.log SF
# ---------------------------------------------------------------------------
CP2, SP2 = 49153, 8080
I2C, I2S = 2000, 6000000
packets.append(tcp_seg(CLIENT_IP, WEB_IP, CP2, SP2, I2C, 0, "S"))
packets[-1].time = T0 + 0.300
packets.append(tcp_seg(WEB_IP, CLIENT_IP, SP2, CP2, I2S, I2C + 1, "SA"))
packets[-1].time = T0 + 0.321
packets.append(tcp_seg(CLIENT_IP, WEB_IP, CP2, SP2, I2C + 1, I2S + 1, "A"))
packets[-1].time = T0 + 0.322
packets.append(tcp_seg(CLIENT_IP, WEB_IP, CP2, SP2, I2C + 1, I2S + 1, "FA"))
packets[-1].time = T0 + 0.325
packets.append(tcp_seg(WEB_IP, CLIENT_IP, SP2, CP2, I2S + 1, I2C + 2, "FA"))
packets[-1].time = T0 + 0.346
packets.append(tcp_seg(CLIENT_IP, WEB_IP, CP2, SP2, I2C + 2, I2S + 2, "A"))
packets[-1].time = T0 + 0.367

# ---------------------------------------------------------------------------
# 4. Unanswered SYN (client 49154 -> 8443) -- conn.log S0 (no reply)
# ---------------------------------------------------------------------------
packets.append(tcp_seg(CLIENT_IP, WEB_IP, 49154, 8443, 3000, 0, "S"))
packets[-1].time = T0 + 0.400

# ---------------------------------------------------------------------------
# Write pcap (fixed link-layer type EN10MB)
# ---------------------------------------------------------------------------
for p in packets:
    p.time = round(p.time, 6)

wrpcap(OUT, packets)
print(f"wrote {len(packets)} packets -> {OUT}")
print(f"base time T0 = {T0:.0f} ({datetime.fromtimestamp(T0, timezone.utc).isoformat()})")
