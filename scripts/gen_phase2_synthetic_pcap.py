#!/usr/bin/env python3
"""
SOC-003 Phase 2 -- deterministic synthetic PCAP generator.

Purpose
-------
Produce ONE bounded, fully synthetic, harmless packet capture that contains a
benign baseline plus three controlled "suspicious-looking" behaviours, for
OFFLINE Zeek processing and detection engineering:

  A. BENIGN BASELINE
       - normal DNS query/response
       - normal HTTP request/response
       - a normal (payload-free) TCP connection
       - three deliberately SUB-THRESHOLD control patterns that must NOT
         trigger any Phase 2 detection.

  B. CONTROLLED NETWORK SERVICE DISCOVERY
       - bounded TCP probing from one synthetic source to 4 synthetic
         destinations across 5 ports each (20 SYNs), inside a ~6 s window;
         mostly unanswered SYNs, two refused, two answered-then-reset.

  C. CONTROLLED DNS BURST
       - 30 unique subdomains under the reserved `.test` TLD from one synthetic
         source inside a ~10 s window.

  D. PERIODIC HTTP
       - 6 short HTTP requests from one synthetic source to one synthetic
         destination at an exact 30.000 s interval.

Safety
------
* OFFLINE generation only: packets are written to a file with `wrpcap`. Nothing
  is transmitted, no interface is opened, no capture is taken, no host is
  contacted. The script cannot generate live traffic.
* All addresses are reserved / documentation ranges (RFC 5737 TEST-NET-1/2/3,
  RFC 1918 host-only 192.168.56.0/24) and all names are synthetic under the
  RFC 6761 reserved `.test` TLD. No real host, domain, credential or personal
  data is referenced anywhere.
* No malicious payload: the "suspicious" content is protocol metadata only
  (connection attempts, DNS questions, HTTP requests). No exploit, no malware.

Determinism
-----------
Fixed base timestamp, fixed IPs, fixed MACs, fixed IP IDs, fixed TCP initial
sequence numbers, fixed deterministic source ports and fixed payloads. No
randomness of any kind. Re-running yields a byte-identical PCAP (verified over
two independent runs; see evidence .../reproducibility/).

Usage
-----
    python3 gen_phase2_synthetic_pcap.py [OUTPUT.pcap]
"""

import sys
from datetime import datetime, timezone

from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, Raw, TCP, UDP, wrpcap

# ---------------------------------------------------------------------------
# Fixed parameters -- do not introduce randomness
# ---------------------------------------------------------------------------
DEFAULT_OUT = (
    "/home/saidi/soc-lab/soc-003/evidence/phase2-controlled-network-behaviour/"
    "phase2-controlled-network-behaviour.pcap"
)
T0 = datetime(2026, 10, 16, 7, 0, 0, tzinfo=timezone.utc).timestamp()

# Synthetic hosts (all reserved / lab-only)
LAB_CLIENT = "192.168.56.101"      # benign baseline client
LAB_RESOLVER = "192.168.56.53"     # synthetic resolver
BENIGN_WEB = "198.51.100.20"       # RFC 5737 TEST-NET-2
PROBE_HOST = "192.168.56.150"      # synthetic scanning source
DNSBURST_HOST = "192.168.56.151"   # synthetic DNS-burst source
PERIODIC_HOST = "192.168.56.152"   # synthetic periodic-HTTP source
SINK = "192.168.56.90"             # synthetic answer target for lookups

SCAN_TARGETS = ["198.51.100.10", "198.51.100.11", "203.0.113.20", "203.0.113.21"]
SCAN_PORTS = [22, 80, 443, 445, 3389]
# Which probes get a response (deterministic choice, no randomness)
SYNACK_PROBES = {("198.51.100.10", 80), ("198.51.100.10", 443)}   # answered -> reset by scanner
REJ_PROBES = {("198.51.100.11", 443), ("203.0.113.20", 22)}       # refused by responder (RST)

PERIODIC_WEB = "203.0.113.30"      # RFC 5737 TEST-NET-3
PERIODIC_INTERVAL = 30.0           # exact, deliberate

MAC_GW = "00:11:22:33:44:aa"       # synthetic next-hop for off-link destinations
MAC_OF = {
    LAB_CLIENT: "00:11:22:33:44:55",
    LAB_RESOLVER: "00:11:22:33:44:66",
    PROBE_HOST: "00:11:22:33:45:50",
    DNSBURST_HOST: "00:11:22:33:45:51",
    PERIODIC_HOST: "00:11:22:33:45:52",
}

LAB_DOMAIN = "lab.test"
BENIGN_QNAME = "www.example.test"

packets = []


def mac_for(ip: str) -> str:
    return MAC_OF.get(ip, MAC_GW)


def l2_l3(src: str, dst: str, ip_id: int, ttl: int = 64, df: bool = True):
    return Ether(src=mac_for(src), dst=mac_for(dst)) / IP(
        src=src, dst=dst, id=ip_id, ttl=ttl, flags="DF" if df else 0
    )


def tcp_seg(src, dst, sport, dport, seq, ack, flags, payload=b"", ip_id=0x4000, window=64240):
    pkt = l2_l3(src, dst, ip_id) / TCP(
        sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, window=window
    )
    if payload:
        pkt = pkt / Raw(load=payload)
    return pkt


def dns_pkt(src, dst, sport, dport, layer, ip_id):
    return l2_l3(src, dst, ip_id, df=False) / UDP(sport=sport, dport=dport) / layer


def emit(pkt, t):
    pkt.time = round(t, 6)
    packets.append(pkt)


def http_request_payload(path, host, ua):
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {ua}\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()


def http_response_payload(body: bytes, ctype=b"text/html", server=b"soc-lab-synthetic/2.0"):
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: " + server + b"\r\n"
        b"Content-Type: " + ctype + b"\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    ) + body


# Fixed per-packet offsets (seconds) for a full HTTP exchange (11 packets).
HTTP_OFFSETS = [0.000, 0.021, 0.022, 0.023, 0.045, 0.046, 0.047, 0.050, 0.071, 0.072, 0.093]


def add_http_conn(client, server, cport, sport, isn_c, isn_s, request, response, t, ipc):
    """Append a complete HTTP/1.1 request+response connection (11 packets)."""
    ips = ipc + 0x100
    c_after = isn_c + 1 + len(request)
    s_after = isn_s + 1 + len(response)
    segs = [
        tcp_seg(client, server, cport, sport, isn_c, 0, "S", ip_id=ipc),
        tcp_seg(server, client, sport, cport, isn_s, isn_c + 1, "SA", ip_id=ips),
        tcp_seg(client, server, cport, sport, isn_c + 1, isn_s + 1, "A", ip_id=ipc + 1),
        tcp_seg(client, server, cport, sport, isn_c + 1, isn_s + 1, "PA", payload=request, ip_id=ipc + 2),
        tcp_seg(server, client, sport, cport, isn_s + 1, c_after, "A", ip_id=ips + 1),
        tcp_seg(server, client, sport, cport, isn_s + 1, c_after, "PA", payload=response, ip_id=ips + 2),
        tcp_seg(client, server, cport, sport, c_after, s_after, "A", ip_id=ipc + 3),
        tcp_seg(client, server, cport, sport, c_after, s_after, "FA", ip_id=ipc + 4),
        tcp_seg(server, client, sport, cport, s_after, c_after + 1, "A", ip_id=ips + 3),
        tcp_seg(server, client, sport, cport, s_after, c_after + 1, "FA", ip_id=ips + 4),
        tcp_seg(client, server, cport, sport, c_after + 1, s_after + 1, "A", ip_id=ipc + 5),
    ]
    for pkt, off in zip(segs, HTTP_OFFSETS):
        emit(pkt, t + off)


# ===========================================================================
# A. BENIGN BASELINE
# ===========================================================================
print("A. benign baseline")

# A1 -- normal DNS query/response
q = DNS(id=0x1234, rd=1, qd=DNSQR(qname=BENIGN_QNAME, qtype="A", qclass="IN"))
emit(dns_pkt(LAB_CLIENT, LAB_RESOLVER, 52000, 53, q, 0x1001), T0 + 0.000)
r = DNS(id=0x1234, qr=1, aa=1, rd=1, ra=1,
        qd=DNSQR(qname=BENIGN_QNAME, qtype="A", qclass="IN"),
        an=DNSRR(rrname=BENIGN_QNAME, type="A", ttl=300, rdata=BENIGN_WEB))
emit(dns_pkt(LAB_RESOLVER, LAB_CLIENT, 53, 52000, r, 0x1002), T0 + 0.021)

# A2 -- normal HTTP request/response
add_http_conn(
    LAB_CLIENT, BENIGN_WEB, 49152, 80, 1000, 5000000,
    http_request_payload("/index.html", "www.example.test", "soc-lab-zeek-phase2/1.0"),
    http_response_payload(b"<html><body><h1>SOC-003 Phase 2 benign baseline</h1></body></html>"),
    T0 + 0.100, 0x2000,
)

# A3 -- normal, payload-free TCP connection
I2C, I2S = 2000, 6000000
for pkt, off in [
    (tcp_seg(LAB_CLIENT, BENIGN_WEB, 49153, 8080, I2C, 0, "S", ip_id=0x3000), 0.000),
    (tcp_seg(BENIGN_WEB, LAB_CLIENT, 8080, 49153, I2S, I2C + 1, "SA", ip_id=0x3100), 0.021),
    (tcp_seg(LAB_CLIENT, BENIGN_WEB, 49153, 8080, I2C + 1, I2S + 1, "A", ip_id=0x3001), 0.022),
    (tcp_seg(LAB_CLIENT, BENIGN_WEB, 49153, 8080, I2C + 1, I2S + 1, "FA", ip_id=0x3002), 0.025),
    (tcp_seg(BENIGN_WEB, LAB_CLIENT, 8080, 49153, I2S + 1, I2C + 2, "FA", ip_id=0x3101), 0.046),
    (tcp_seg(LAB_CLIENT, BENIGN_WEB, 49153, 8080, I2C + 2, I2S + 2, "A", ip_id=0x3003), 0.067),
]:
    emit(pkt, T0 + 0.300 + off)

# A4a -- control: 3 HTTP requests at IRREGULAR intervals (count < DET-203 min;
#        intervals 1.4 s and 12.5 s -> high spread). Must NOT fire DET-203.
for i, (t_off, path, ipc) in enumerate([
    (20.0, "/health", 0x4000),
    (21.4, "/version", 0x4100),
    (33.9, "/status", 0x4200),
]):
    add_http_conn(
        LAB_CLIENT, BENIGN_WEB, 49200 + i, 80, 10000 + i * 1000, 7000000 + i * 1000,
        http_request_payload(path, "www.example.test", "soc-lab-zeek-phase2/1.0"),
        http_response_payload(b'{"ok":true}', ctype=b"application/json", server=b"soc-lab-synthetic/2.0"),
        T0 + t_off, ipc,
    )

# A4b -- control: 4 low-rate DNS lookups spread over ~45 s (< DET-202 unique min
#        of 20). Must NOT fire DET-202.
for i, (t_off, name) in enumerate([
    (25.0, "a.lab.test"), (40.0, "b.lab.test"), (52.0, "c.lab.test"), (70.0, "d.lab.test"),
]):
    qid = 0x1300 + i
    qq = DNS(id=qid, rd=1, qd=DNSQR(qname=name, qtype="A", qclass="IN"))
    emit(dns_pkt(LAB_CLIENT, LAB_RESOLVER, 53000 + i, 53, qq, 0x1200 + i), T0 + t_off)
    rr = DNS(id=qid, qr=1, aa=1, rd=1, ra=1, rcode=3,
             qd=DNSQR(qname=name, qtype="A", qclass="IN"))
    emit(dns_pkt(LAB_RESOLVER, LAB_CLIENT, 53, 53000 + i, rr, 0x1210 + i), T0 + t_off + 0.020)

# A4c -- control: 3 unanswered SYNs to ONE host / 3 ports (< DET-201 minimum of
#        10 attempts, 5 ports, 2 hosts). Must NOT fire DET-201.
for i, port in enumerate([9000, 9001, 9002]):
    emit(tcp_seg(LAB_CLIENT, BENIGN_WEB, 49300 + i, port, 20000 + i, 0, "S", ip_id=0x4300 + i),
         T0 + 95.0 + i * 0.5)

# ===========================================================================
# B. CONTROLLED NETWORK SERVICE DISCOVERY  (T0+120 .. T0+126)
# ===========================================================================
print("B. controlled network service discovery")
SCAN_T0 = T0 + 120.0
idx = 0
for host_i, target in enumerate(SCAN_TARGETS):
    for port_i, port in enumerate(SCAN_PORTS):
        sport = 40000 + idx
        isn = 50000 + idx * 37
        ipc = 0x5000 + idx
        t = SCAN_T0 + idx * 0.30          # deterministic 300 ms probe spacing
        if (target, port) in SYNACK_PROBES:
            emit(tcp_seg(PROBE_HOST, target, sport, port, isn, 0, "S", ip_id=ipc), t)
            emit(tcp_seg(target, PROBE_HOST, port, sport, 900000 + idx, isn + 1, "SA", ip_id=0x6000 + idx), t + 0.018)
            emit(tcp_seg(PROBE_HOST, target, sport, port, isn + 1, 900001 + idx, "R", ip_id=ipc + 1), t + 0.019)
        elif (target, port) in REJ_PROBES:
            emit(tcp_seg(PROBE_HOST, target, sport, port, isn, 0, "S", ip_id=ipc), t)
            emit(tcp_seg(target, PROBE_HOST, port, sport, 0, isn + 1, "RA", ip_id=0x6000 + idx), t + 0.018)
        else:
            emit(tcp_seg(PROBE_HOST, target, sport, port, isn, 0, "S", ip_id=ipc), t)
        idx += 1
SCAN_END = SCAN_T0 + idx * 0.30

# ===========================================================================
# C. CONTROLLED DNS BURST  (T0+200 .. T0+210)
# ===========================================================================
print("C. controlled DNS burst")
BURST_T0 = T0 + 200.0
N_BURST = 30
for i in range(N_BURST):
    name = f"c{i + 1:03d}.{LAB_DOMAIN}"
    qid = 0x2000 + i
    t = BURST_T0 + i * 0.33
    qq = DNS(id=qid, rd=1, qd=DNSQR(qname=name, qtype="A", qclass="IN"))
    emit(dns_pkt(DNSBURST_HOST, LAB_RESOLVER, 55000 + i, 53, qq, 0x7000 + i), t)
    if i % 2 == 0:
        rr = DNS(id=qid, qr=1, aa=1, rd=1, ra=1,
                 qd=DNSQR(qname=name, qtype="A", qclass="IN"),
                 an=DNSRR(rrname=name, type="A", ttl=60, rdata=SINK))
    else:
        rr = DNS(id=qid, qr=1, aa=1, rd=1, ra=1, rcode=3,
                 qd=DNSQR(qname=name, qtype="A", qclass="IN"))
    emit(dns_pkt(LAB_RESOLVER, DNSBURST_HOST, 53, 55000 + i, rr, 0x7100 + i), t + 0.015)
BURST_END = BURST_T0 + (N_BURST - 1) * 0.33

# ===========================================================================
# D. PERIODIC HTTP  (T0+300 .. T0+450)
# ===========================================================================
print("D. periodic HTTP")
PERIODIC_T0 = T0 + 300.0
N_PERIODIC = 6
for i in range(N_PERIODIC):
    t = PERIODIC_T0 + i * PERIODIC_INTERVAL
    add_http_conn(
        PERIODIC_HOST, PERIODIC_WEB, 44000 + i, 80, 300000 + i * 10000, 8000000 + i * 10000,
        http_request_payload(f"/api/v1/heartbeat?id={1000 + i}", f"updates.{LAB_DOMAIN}",
                             "soc-lab-synthetic-agent/2.0"),
        http_response_payload(b'{"status":"ok","seq":' + str(i).encode() + b'}',
                              ctype=b"application/json", server=b"soc-lab-synthetic/2.0"),
        t, 0x8000 + i * 0x20,
    )

# ---------------------------------------------------------------------------
# Write
# ---------------------------------------------------------------------------
out = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_OUT
# Write in strict timestamp order (stable sort preserves intra-exchange order).
packets.sort(key=lambda pkt: pkt.time)
wrpcap(out, packets)

print()
print(f"wrote {len(packets)} packets -> {out}")
print(f"base T0 = {T0:.0f}  ({datetime.fromtimestamp(T0, timezone.utc).isoformat()})")
print(f"A benign baseline : T0+{0:.3f} .. T0+{95.0 + 1.0:.3f}")
print(f"B service discovery: T0+{SCAN_T0 - T0:.3f} .. T0+{SCAN_END - T0:.3f}  ({idx} probes)")
print(f"C dns burst        : T0+{BURST_T0 - T0:.3f} .. T0+{BURST_END - T0:.3f}  ({N_BURST} unique subdomains)")
print(f"D periodic http    : T0+{PERIODIC_T0 - T0:.3f} .. "
      f"T0+{PERIODIC_T0 - T0 + (N_PERIODIC - 1) * PERIODIC_INTERVAL:.3f}  "
      f"({N_PERIODIC} requests x {PERIODIC_INTERVAL:.3f}s)")
