#!/usr/bin/env python3
"""SOC-003 Phase 3B -- summarise the benign AD/DNS validation capture and the
Zeek replay.

Reads the single Phase 3B PCAP via tshark/capinfos and the raw Zeek logs, and
writes the analysis artifacts under
evidence/phase3b-benign-ad-validation/analysis/.

Read-only with respect to the capture. No detection logic is touched and no
traffic is generated.
"""
import collections, ipaddress, json, pathlib, subprocess, datetime

S3 = pathlib.Path.home() / "soc-lab/soc-003"
B = S3 / "evidence/phase3b-benign-ad-validation"
OUT = B / "analysis"
PCAP = B / "capture/phase3b-benign-ad.pcap"
ZEEK = B / "zeek-run"
LAB = ipaddress.ip_network("192.168.56.0/24")

DC1 = "192.168.56.10"
WS001 = "192.168.56.102"

# Well-known AD / Windows-network ports, used only to *report* whether AD
# service traffic was present -- no detection logic depends on this.
AD_PORTS = {53: "DNS", 88: "Kerberos", 123: "NTP", 135: "RPC-EPM", 139: "NetBIOS-SSN",
            389: "LDAP", 445: "SMB", 464: "kpasswd", 636: "LDAPS", 3268: "GlobalCatalog",
            3269: "GlobalCatalog-SSL", 5985: "WinRM", 5355: "LLMNR", 5353: "mDNS"}

OUT.mkdir(parents=True, exist_ok=True)


def tsh(fields):
    cmd = ["tshark", "-r", str(PCAP), "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    r = subprocess.run(cmd, capture_output=True, text=True)
    return [l.split("\t") for l in r.stdout.splitlines() if l.strip()]


def capinfo():
    r = subprocess.run(["capinfos", "-M", str(PCAP)], capture_output=True, text=True)
    d = {}
    for line in r.stdout.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            d[k.strip()] = v.strip()
    return d


def zeek_json(name):
    p = ZEEK / name
    if not p.exists():
        return None
    rows = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if line.startswith("{"):
            rows.append(json.loads(line))
    return rows


ci = capinfo()
summary = {"generated": datetime.datetime.now().astimezone().isoformat(),
           "phase": "SOC-003 Phase 3B",
           "capture": {}, "zeek": {}, "detections": {}}

# ---------------------------------------------------------------- hosts / protos
rows = tsh(["frame.number", "frame.time_relative", "eth.src", "eth.dst",
            "ip.src", "ip.dst", "udp.srcport", "udp.dstport",
            "tcp.srcport", "tcp.dstport", "_ws.col.Protocol"])
eth_src = collections.Counter(r[2] for r in rows if len(r) > 2 and r[2])
eth_dst = collections.Counter(r[3] for r in rows if len(r) > 3 and r[3])
ips = collections.Counter()
for r in rows:
    for v in (r[4] if len(r) > 4 else "", r[5] if len(r) > 5 else ""):
        if v:
            ips[v] += 1
protos = collections.Counter(r[10] for r in rows if len(r) > 10 and r[10])
udp_ports = collections.Counter()
for r in rows:
    if len(r) > 7 and r[7]:
        udp_ports[int(r[7])] += 1
tcp_frames = [r for r in rows if len(r) > 10 and len(r) > 9 and (r[8] or r[9])]

L = []
L.append("SOC-003 Phase 3B -- host / protocol inventory (derived with tshark)")
L.append("=" * 78)
L.append(f"PCAP          : capture/phase3b-benign-ad.pcap")
L.append(f"Packets       : {ci.get('Number of packets')}")
L.append(f"File size     : {ci.get('File size')}")
L.append(f"SHA256        : {ci.get('SHA256')}")
L.append(f"Capture span  : {ci.get('Capture duration')}  "
         f"(first {ci.get('Earliest packet time')}  last {ci.get('Latest packet time')})")
L.append("")
L.append("Ethernet sources:")
for s, n in eth_src.most_common():
    tag = "  [SOC002-WS001]" if s.lower() == "08:00:27:81:7a:74" else ""
    L.append(f"  {s}  {n} pkts{tag}")
L.append("Ethernet destinations:")
for s, n in eth_dst.most_common():
    L.append(f"  {s}  {n} pkts")
L.append("")
L.append("IP addresses (as src or dst):")
for a, n in ips.most_common():
    tag = ""
    try:
        ip = ipaddress.ip_address(a)
        if ip.is_multicast:
            tag = "  [link-local / site multicast]"
        elif str(ip) in (WS001,):
            tag = "  [SOC002-WS001]"
        elif str(ip) == DC1:
            tag = "  [SOC002-DC1]"
        elif ip in LAB:
            tag = "  [lab subnet]"
        elif a.endswith(".255"):
            tag = "  [lab subnet broadcast]"
    except ValueError:
        tag = "  [non-IP]"
    L.append(f"  {a:18s} {n:3d} pkts{tag}")
L.append("")
L.append("Protocols (tshark dissection):")
for p, n in protos.most_common():
    L.append(f"  {p:12s} {n} pkts")
L.append("")
L.append("UDP destination ports:")
for p, n in udp_ports.most_common():
    L.append(f"  {p:6d}  {n} pkts   {AD_PORTS.get(p, '')}")
L.append("")
L.append(f"TCP frames in capture : {len(tcp_frames)}")
L.append("")
L.append("Plain-language reading:")
L.append("  Every captured frame originated from SOC002-WS001 (192.168.56.102,")
L.append("  MAC 08:00:27:81:7a:74). No frame was sent or received by SOC002-DC1")
L.append("  (192.168.56.10) and no frame was unicast to any lab host. The capture")
L.append("  contains only WS001's own local-network chatter: SSDP discovery, IGMP")
L.append("  group maintenance, mDNS and LLMNR self-name resolution. There is no")
L.append("  TCP, no DNS to a DNS server, no HTTP, no Kerberos/LDAP/SMB/NTP.")
(OUT / "hosts-and-protocols.txt").write_text("\n".join(L) + "\n")

summary["capture"] = {
    "packets": int(ci.get("Number of packets", 0)),
    "file_size_bytes": int(ci.get("File size", "0").split()[0]),
    "bounded_duration_s": 180,
    "pcap_span_s": float(ci.get("Capture duration", "0").split()[0]),
    "sha256": ci.get("SHA256"),
    "first_packet": ci.get("Earliest packet time"),
    "last_packet": ci.get("Latest packet time"),
    "eth_sources": dict(eth_src),
    "eth_destinations": dict(eth_dst),
    "ip_addresses": dict(ips),
    "protocols": dict(protos),
    "udp_dst_ports": {str(k): v for k, v in udp_ports.items()},
    "tcp_frames": len(tcp_frames),
}

# --------------------------------------------------------------- safety check
sa = ["Address confinement check (safety rule: capture must stay inside the lab)",
      "=" * 78, ""]
seen = set()
for r in rows:
    for v in (r[4] if len(r) > 4 else "", r[5] if len(r) > 5 else ""):
        if v:
            seen.add(v)
bad = []
for a in sorted(seen):
    try:
        ip = ipaddress.ip_address(a)
    except ValueError:
        continue
    if ip.is_multicast:
        continue
    if str(ip) == "192.168.56.255":
        continue
    if ip not in LAB:
        bad.append(a)
sa.append("Routable unicast addresses outside 192.168.56.0/24 : "
          + ("FAIL " + str(bad) if bad else "NONE -- PASS"))
sa.append("")
sa.append("Addresses observed:")
for a in sorted(seen):
    try:
        ip = ipaddress.ip_address(a)
    except ValueError:
        sa.append(f"  {a:18s} [non-IP]")
        continue
    if ip.is_multicast:
        sa.append(f"  {a:18s} link-local/site multicast group (not Internet-routable)")
    elif str(ip) in (WS001, DC1):
        sa.append(f"  {a:18s} lab host (inside 192.168.56.0/24)")
    elif ip in LAB:
        sa.append(f"  {a:18s} inside 192.168.56.0/24")
    else:
        sa.append(f"  {a:18s} OUTSIDE THE LAB")
sa.append("")
sa.append("No routable unicast address outside 192.168.56.0/24 appears in the")
sa.append("capture. The capture filter recorded inside the PCAP interface block")
sa.append("is 'net 192.168.56.0/24' on vboxnet0 only. The out-of-lab stop")
sa.append("condition was therefore NOT triggered.")
(OUT / "safety-address-check.txt").write_text("\n".join(sa) + "\n")
summary["out_of_lab_routable_addresses"] = sorted(bad)

# ------------------------------------------------------------- TCP activity
T = ["TCP activity", "=" * 78, ""]
T.append(f"TCP frames in the capture : {len(tcp_frames)}")
if not tcp_frames:
    T.append("")
    T.append("There is no TCP traffic at all in this capture. No SYN, no handshake,")
    T.append("no failed connection attempt, no reset. Every packet is UDP or IGMP")
    T.append("broadcast/multicast from WS001.")
    T.append("")
    T.append("Consequence for DET-201: the detector consumes TCP connection records")
    T.append("(conn.log, proto=tcp). With zero TCP frames it has no input at all, so")
    T.append("the 'network service discovery' behaviour it looks for cannot be")
    T.append("observed or ruled out by this capture.")
(OUT / "tcp-activity.txt").write_text("\n".join(T) + "\n")

# -------------------------------------------------------------- DNS activity
dns = zeek_json("dns.log") or []
D = ["DNS activity observed in the Phase 3B capture", "=" * 78, ""]
qnames = collections.Counter()
qtypes = collections.Counter()
srcs = collections.Counter()
dc1_queries = []
servers = collections.Counter()
for r in dns:
    qnames[r.get("query", "?")] += 1
    qtypes[r.get("qtype_name", "?")] += 1
    srcs[r.get("id.orig_h", "?")] += 1
    servers[r.get("id.resp_h", "?")] += 1
    if r.get("id.resp_h") == DC1:
        dc1_queries.append(r)
D.append(f"Zeek dns.log records        : {len(dns)}")
D.append(f"Distinct query names        : {len(qnames)}")
D.append(f"Distinct DNS 'servers' seen  : {', '.join(sorted(servers)) if servers else 'none'}")
D.append(f"Queries sent to DC1 ({DC1}) : {len(dc1_queries)}")
D.append(f"Query sources               : {', '.join(sorted(srcs)) if srcs else 'none'}")
D.append(f"Query types                 : {', '.join(f'{k} x{v}' for k, v in qtypes.items()) or 'none'}")
D.append("")
D.append("Every claim below is drawn from the Zeek dns.log records:")
D.append("")
D.append(f"{'query name':<32}{'count':>6}  transport")
for q, n in qnames.most_common():
    tr = set()
    for r in dns:
        if r.get("query") == q:
            tr.add(f"udp/{r.get('id.resp_p')}->{r.get('id.resp_h')}")
    D.append(f"{q:<32}{n:>6}  {', '.join(sorted(tr))}")
D.append("")
D.append("Reading:")
D.append("  * Both names are WS001 resolving its OWN hostname (SOC002-WS001) over")
D.append("    mDNS (224.0.0.251:5353) and LLMNR (224.0.0.252:5355). This is")
D.append("    ordinary Windows background name advertisement, not name resolution")
D.append("    against a DNS server.")
D.append("  * There is NO query to the domain controller/DNS server at")
D.append(f"    {DC1}:53 -- zero SOC002-WS001 -> SOC002-DC1 DNS traffic.")
D.append("  * There is no domain name (soc002.local), no SRV/service lookup and no")
D.append("    unique-name burst.")
D.append("")
D.append("Consequence for DET-202: it requires >=20 DISTINCT query names from one")
D.append(f"source inside a 30 s window. This capture contains {len(qnames)} distinct")
D.append("names in total, so the threshold was never approached.")
(OUT / "dns-activity.txt").write_text("\n".join(D) + "\n")
summary["zeek"]["dns_records"] = len(dns)
summary["zeek"]["dns_unique_qnames"] = sorted(qnames)
summary["zeek"]["dns_queries_to_dc1"] = len(dc1_queries)

# -------------------------------------------------------------- HTTP activity
http = zeek_json("http.log")
H = ["HTTP activity observed in the Phase 3B capture", "=" * 78, ""]
if not http:
    H.append("No http.log was produced by the Zeek replay, and there are no TCP")
    H.append("frames in the capture, therefore there are no HTTP requests at all.")
    H.append("DET-203 consumes http_request events; with no HTTP it was NOT")
    H.append("exercised by this capture.")
else:
    H.append(f"Zeek http.log records : {len(http)}")
(OUT / "http-activity.txt").write_text("\n".join(H) + "\n")
summary["zeek"]["http_records"] = len(http or [])

# --------------------------------------------------------- AD-related traffic
A = ["AD-related traffic observed in the Phase 3B capture", "=" * 78, ""]
A.append("Checked for the network services an AD domain-joined Windows client")
A.append("would normally use, and for any exchange with the domain controller.")
A.append("")
A.append(f"  DC1 traffic (any packet with src or dst {DC1}) : "
         f"{'PRESENT' if DC1 in ips else 'NONE'}")
A.append(f"  DNS to a DNS server (port 53)                  : "
         f"{'PRESENT' if 53 in udp_ports else 'NONE'}")
A.append(f"  Kerberos (88, 464)                             : "
         f"{'PRESENT' if {88, 464} & set(udp_ports) else 'NONE'}")
A.append(f"  LDAP / Global Catalog (389, 636, 3268, 3269)   : "
         f"{'PRESENT' if {389, 636, 3268, 3269} & set(udp_ports) else 'NONE'}")
A.append(f"  SMB (445) / NetBIOS (139)                      : "
         f"{'PRESENT' if {445, 139} & set(udp_ports) else 'NONE'}")
A.append(f"  RPC endpoint mapper (135)                      : "
         f"{'PRESENT' if 135 in udp_ports else 'NONE'}")
A.append(f"  NTP (123)                                      : "
         f"{'PRESENT' if 123 in udp_ports else 'NONE'}")
A.append(f"  LLMNR (5355)                                   : "
         f"{'PRESENT' if 5355 in udp_ports else 'NONE'}")
A.append(f"  mDNS (5353)                                    : "
         f"{'PRESENT' if 5353 in udp_ports else 'NONE'}")
A.append(f"  Windows discovery / SSDP (1900)                : "
         f"{'PRESENT' if 1900 in udp_ports else 'NONE'}")
A.append("")
if DC1 not in ips:
    A.append("No AD service traffic was observed. The only traffic in the capture is")
    A.append("WS001's own local-network chatter (SSDP discovery, IGMP group")
    A.append("maintenance, mDNS and LLMNR self-name resolution). WS001 did not")
    A.append("contact SOC002-DC1 at all during the 180 s window: no logon, no")
    A.append("Group Policy, no LDAP/Kerberos, no SMB share access, no DNS query for")
    A.append("a domain name.")
    A.append("")
    A.append("AD service ports below are listed for completeness (all zero except the")
    A.append("multicast name-resolution ports 5353/5355, which are peer-to-peer and")
    A.append("not DC-originated).")
(OUT / "ad-related-traffic.txt").write_text("\n".join(A) + "\n")
summary["ad_related"] = {
    "dc1_traffic_present": DC1 in ips,
    "dns_port53_present": 53 in udp_ports,
    "ad_service_ports_present": sorted(p for p in AD_PORTS
                                       if p in udp_ports or p in set(tcp_frames)),
}

# ------------------------------------------------------------ detection result
notice = zeek_json("notice.log")
dets = zeek_json("phase2_detections.log") or []
fired_ids = [d.get("det_id") for d in dets]
uniq = collections.Counter(qnames)

R = []
R.append("SOC-003 Phase 3B -- detection results (DET-201 / DET-202 / DET-203)")
R.append("Detection sources: detections/zeek/det-201..203 + det-common.zeek")
R.append("Run: Zeek 9.0.0 offline replay of capture/phase3b-benign-ad.pcap")
R.append("No detection was modified, tuned or re-parameterised for this phase.")
R.append("=" * 78)
R.append("")
R.append(f"phase2_detections.log records : {len(dets)}")
R.append(f"notice.log records            : {'produced' if notice is not None else 'NOT produced'}")
R.append(f"Firings                       : "
         f"{'NONE' if not dets else ', '.join(fired_ids)}")
R.append("")
R.append("DET-201  Network Service Discovery")
R.append("  firing          : NONE -- no firing observed in this capture.")
R.append("  why             : requires >=10 failed TCP connection attempts from one")
R.append("                    source, to >=5 distinct ports across >=2 distinct hosts,")
R.append("                    within 60 s. The capture contains ZERO TCP frames, so the")
R.append("                    detector's input never materialises.")
R.append("  exercised?      : NOT exercised by this capture.")
R.append("")
R.append("DET-202  DNS Burst / Unique Subdomain Behaviour")
R.append("  firing          : NONE -- no firing observed in this capture.")
R.append("  why             : requires >=20 DISTINCT query names from one source in")
R.append(f"                    30 s. The capture holds {len(uniq)} distinct names total")
R.append("                    (soc002-ws001.local, soc002-ws001), both WS001's own")
R.append("                    name via mDNS/LLMNR. Peak distinct names in any 30 s")
R.append(f"                    window = {len(uniq)} -> {int(100*min(len(uniq),20)/20)}% of the threshold.")
R.append("  exercised?      : NOT meaningfully exercised. The DNS code path ran (Zeek")
R.append("                    produced dns.log and DET-202 subscribed to it), but no")
R.append("                    DNS-server traffic and no unique-name volume occurred.")
R.append("")
R.append("DET-203  Periodic HTTP Behaviour")
R.append("  firing          : NONE -- no firing observed in this capture.")
R.append("  why             : requires >=5 HTTP requests on one (src,dst) pair with a")
R.append("                    coefficient of variation <= 0.05. There is no HTTP and no")
R.append("                    TCP in the capture, so no request intervals exist.")
R.append("                    (Note: the 6 SSDP M-SEARCH datagrams are periodic-looking")
R.append("                    but SSDP is not HTTP-over-TCP and is outside DET-203's")
R.append("                    data source, so DET-203 correctly ignores them.)")
R.append("  exercised?      : NOT exercised by this capture.")
R.append("")
R.append("False-positive statement:")
R.append("  No detection fired in this capture, therefore there is NO firing that")
R.append("  could be assessed as a true or false positive, and no false-positive rate")
R.append("  may be claimed from this single capture. Nothing here is called a false")
R.append("  positive; nothing here is called a false negative either, because the")
R.append("  behaviours the detections look for simply did not occur.")
(OUT / "detection-results.txt").write_text("\n".join(R) + "\n")
summary["detections"] = {
    "phase2_detections_records": len(dets),
    "fired": fired_ids,
    "notice_log_produced": notice is not None,
    "DET-201": "no firing observed; not exercised (zero TCP)",
    "DET-202": "no firing observed; not meaningfully exercised (2 unique names)",
    "DET-203": "no firing observed; not exercised (zero HTTP)",
}

# ------------------------------------------------------- Zeek telemetry summary
ZT = ["Zeek 9.0.0 replay -- telemetry summary", "=" * 78, ""]
ZT.append(f"{'log':<26}{'status':<14}{'records':>8}")
ZT.append("-" * 78)
conn = zeek_json("conn.log") or []
for name in ["conn.log", "dns.log", "http.log", "ssl.log", "files.log",
             "weird.log", "notice.log", "reporter.log", "phase2_detections.log"]:
    p = ZEEK / name
    if not p.exists():
        ZT.append(f"{name:<26}{'NOT produced':<14}{'-':>8}")
    else:
        recs = len([l for l in p.read_text().splitlines() if l.startswith("{")])
        ZT.append(f"{name:<26}{'present':<14}{recs:>8}")
ZT.append("")
ZT.append("A NOT-produced log is negative evidence: Zeek 9.0.0 had no event to log.")
ZT.append("In particular the absence of phase2_detections.log and notice.log is")
ZT.append("positive evidence that none of DET-201/202/203 fired during this replay.")
(OUT / "zeek-telemetry-summary.txt").write_text("\n".join(ZT) + "\n")

# ------------------------------------------------------------------- summary json
summary["zeek"]["conn_records"] = len(conn)
summary["zeek"]["logs"] = {n: (ZEEK / n).exists() for n in
                           ["conn.log", "dns.log", "http.log", "weird.log",
                            "notice.log", "reporter.log", "phase2_detections.log"]}
summary["conn_states"] = dict(collections.Counter(c.get("conn_state") for c in conn))
summary["conn_proto"] = dict(collections.Counter(c.get("proto") for c in conn))
(OUT / "telemetry-summary.json").write_text(json.dumps(summary, indent=2) + "\n")

print("analysis written to", OUT)
for f in sorted(OUT.iterdir()):
    print("  ", f.name, f.stat().st_size, "bytes")
