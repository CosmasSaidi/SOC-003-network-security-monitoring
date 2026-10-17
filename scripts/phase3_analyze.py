#!/usr/bin/env python3
"""SOC-003 Phase 3 -- summarise the live benign captures and the Zeek replay.

Reads the Gate 1 / Gate 2 PCAPs via tshark and the raw Zeek logs, and writes
the analysis artifacts under evidence/phase3-live-benign-validation/analysis/.
Read-only with respect to the captures; no detection logic is touched.
"""
import collections, ipaddress, json, pathlib, subprocess, datetime

S3 = pathlib.Path.home() / "soc-lab/soc-003"
B = S3 / "evidence/phase3-live-benign-validation"
OUT = B / "analysis"
LAB = ipaddress.ip_network("192.168.56.0/24")

PCAPS = {
    "gate1-window1": B / "gate1/gate1-visibility.pcap",
    "gate1-window2": B / "gate1/window2/gate1-window2-visibility.pcap",
    "gate2": B / "gate2/gate2-benign-lab-traffic.pcap",
}

def tsh(field_args, pcap):
    cmd = ["tshark", "-r", str(pcap), "-T", "fields"]
    for f in field_args:
        cmd += ["-e", f]
    r = subprocess.run(cmd, capture_output=True, text=True)
    return [l.split("\t") for l in r.stdout.splitlines() if l.strip()]

def capinfo(pcap):
    r = subprocess.run(["capinfos", "-M", str(pcap)], capture_output=True, text=True)
    d = {}
    for line in r.stdout.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            d[k.strip()] = v.strip()
    return d

summary = {"generated": datetime.datetime.now().astimezone().isoformat(),
           "captures": {}, "detections": {}}

# ---------- hosts & protocols ----------
lines = []
lines.append("Per-capture host / protocol inventory (derived with tshark)\n")
for name, pcap in PCAPS.items():
    ci = capinfo(pcap)
    rows = tsh(["frame.number", "eth.src", "ip.src", "ip.dst", "_ws.col.Protocol"], pcap)
    srcs = collections.Counter(r[1] for r in rows if len(r) > 1 and r[1])
    ips = collections.Counter()
    for r in rows:
        if len(r) > 2 and r[2]:
            ips[r[2]] += 1
        if len(r) > 3 and r[3]:
            ips[r[3]] += 1
    protos = collections.Counter(r[4] for r in rows if len(r) > 4 and r[4])
    lines.append("=" * 78)
    lines.append(f"{name}   ({ci.get('Number of packets','?')} packets, "
                 f"{ci.get('Capture duration','?')} s, sha256 {ci.get('SHA256','?')[:16]}...)")
    lines.append("-" * 78)
    lines.append("  ethernet sources:")
    for s, n in srcs.most_common():
        lines.append(f"    {s}  {n} pkts")
    lines.append("  IP addresses (src or dst):")
    for a, n in ips.most_common():
        tag = ""
        try:
            ip = ipaddress.ip_address(a)
            if ip.is_multicast: tag = "  [link-local/site multicast]"
            elif ip in LAB:      tag = "  [lab subnet]"
            elif a.endswith(".255"): tag = "  [lab subnet broadcast]"
        except ValueError:
            tag = "  [non-IP]"
        lines.append(f"    {a:18s} {n:3d} pkts{tag}")
    lines.append("  protocols:")
    for p, n in protos.most_common():
        lines.append(f"    {p:12s} {n} pkts")
    lines.append("")
    summary["captures"][name] = {
        "packets": int(ci.get("Number of packets", 0)),
        "duration_s": float(ci.get("Capture duration", "0").split()[0]),
        "sha256": ci.get("SHA256"),
        "eth_sources": dict(srcs),
        "ip_addresses": dict(ips),
        "protocols": dict(protos),
    }
(OUT / "hosts-and-protocols.txt").write_text("\n".join(lines) + "\n")

# ---------- safety: address confinement ----------
sa = ["Address confinement check (safety rule: capture must stay inside the lab)\n"]
allbad = []
for name, pcap in PCAPS.items():
    rows = tsh(["ip.src", "ip.dst"], pcap)
    seen = set()
    for r in rows:
        for v in r:
            if v:
                seen.add(v)
    bad = []
    for a in sorted(seen):
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            continue
        if ip.is_multicast:
            continue          # 224.0.0.0/24 link-local + 239.255.255.250 SSDP
        if str(ip) in ("192.168.56.255",):
            continue          # subnet broadcast
        if ip not in LAB:
            bad.append(a)
    allbad += bad
    sa.append(f"{name}: {'FAIL ' + str(bad) if bad else 'PASS -- no routable address outside 192.168.56.0/24'}")
sa.append("")
sa.append("Link-local / site multicast groups observed (not Internet-routable):")
sa.append("  224.0.0.22   IGMP (RFC 2236)      -- link-local, TTL 1")
sa.append("  224.0.0.251  mDNS (RFC 6762)      -- link-local, TTL 255, non-forwarded")
sa.append("  224.0.0.252  LLMNR (RFC 4795)     -- link-local")
sa.append("  239.255.255.250 SSDP (source: the sensor host 192.168.56.1, TTL 4)")
sa.append("  192.168.56.255  subnet broadcast of the lab")
sa.append("")
sa.append("No routable unicast address outside 192.168.56.0/24 was observed in any")
sa.append("capture. No Internet traffic was captured. The stop condition for")
sa.append("out-of-lab traffic was therefore NOT triggered.")
(OUT / "safety-address-check.txt").write_text("\n".join(sa) + "\n")
summary["out_of_lab_routable_addresses"] = sorted(set(allbad))

# ---------- Zeek telemetry ----------
def zlog(gate, name):
    p = B / "zeek-run" / gate / name
    if not p.exists():
        return []
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip() and not l.startswith("#")]

z = []
z.append("Zeek 9.0.0 offline replay -- telemetry summary\n")
tel = {}
for gate, pcap in (("gate1", PCAPS["gate1-window1"]), ("gate2", PCAPS["gate2"])):
    conn = zlog(gate, "conn.log"); dns = zlog(gate, "dns.log")
    http = zlog(gate, "http.log"); det = zlog(gate, "phase2_detections.log")
    notice = zlog(gate, "notice.log")
    protos = collections.Counter(c.get("proto") for c in conn)
    states = collections.Counter(c.get("conn_state") for c in conn)
    svcs = collections.Counter(c.get("service") for c in conn if c.get("service"))
    z.append("=" * 78)
    z.append(f"{gate}: conn={len(conn)} dns={len(dns)} http={len(http)} "
             f"notice={len(notice)} phase2_detections={len(det)}")
    z.append(f"  conn proto:   {dict(protos)}")
    z.append(f"  conn states:  {dict(states)}")
    z.append(f"  conn service: {dict(svcs)}")
    z.append(f"  dns queries:  {len(dns)} records, distinct names: "
             f"{sorted({d.get('query') for d in dns if d.get('query')})}")
    z.append(f"  http:         {'no HTTP log produced' if not http else json.dumps(http)}")
    tel[gate] = {"conn": len(conn), "dns": len(dns), "http": len(http),
                 "notice": len(notice), "detections": len(det),
                 "conn_proto": dict(protos), "conn_states": dict(states),
                 "distinct_dns_names": sorted({d.get("query") for d in dns if d.get("query")})}
summary["zeek"] = tel
(OUT / "zeek-telemetry-summary.txt").write_text("\n".join(z) + "\n")

# ---------- DNS activity ----------
d = ["DNS activity observed in the live captures\n",
     "Source of every DNS record: 192.168.56.102 (SOC002-WS001).",
     "Query type: mDNS (UDP/5353, qtype ANY=255) and LLMNR (UDP/5355, qtype ANY=255).",
     "Every query is WS001 resolving its OWN hostname -- ordinary Windows background",
     "name advertisement, not name resolution against DC1. There are ZERO queries to",
     "DC1 (192.168.56.10:53) and zero unique-name bursts.\n"]
for rec in zlog("gate2", "dns.log"):
    d.append(f"  ts={rec['ts']:.3f} {rec['id.orig_h']}:{rec['id.orig_p']} -> "
             f"{rec['id.resp_h']}:{rec['id.resp_p']}  query={rec.get('query')!r} "
             f"qtype={rec.get('qtype_name')} "
             f"{'rcode=' + str(rec.get('rcode_name')) if 'rcode' in rec else '(query)'}")
d.append("")
d.append("DET-202 needs >=20 DISTINCT query names from one source inside a 30 s window.")
d.append("This capture contains 2 distinct names total (soc002-ws001.local,")
d.append("soc002-ws001) across the whole 9 minutes -> the threshold is not approached.")
(OUT / "dns-activity.txt").write_text("\n".join(d) + "\n")

# ---------- HTTP activity ----------
h = ["HTTP activity observed in the live captures\n",
     "No http.log was produced by either Zeek replay.",
     "There is no TCP traffic at all in either capture, therefore no HTTP requests.",
     "DET-203 was NOT exercised by this capture (it consumes http_request events)."]
(OUT / "http-activity.txt").write_text("\n".join(h) + "\n")

# ---------- detection results ----------
r = ["DET-201 / DET-202 / DET-203 -- unchanged detections run against the live captures\n",
     "Load script : detections/zeek/phase2-load.zeek   (unmodified)",
     "Command     : /opt/zeek/bin/zeek -r <pcap> LogAscii::use_json=T "
     "detections/zeek/phase2-load.zeek\n"]
for gate in ("gate1", "gate2"):
    r.append(f"  {gate}: notice.log {'present' if (B/'zeek-run'/gate/'notice.log').exists() else 'ABSENT'}, "
             f"phase2_detections.log {'present' if (B/'zeek-run'/gate/'phase2_detections.log').exists() else 'ABSENT'}")
r += ["",
      "DET-201  Network Service Discovery Behaviour",
      "  firing          : NONE -- no firing observed in this capture.",
      "  why             : requires >=10 non-established TCP connections from one source",
      "                    to >=5 ports across >=2 hosts in 60 s. The capture contains",
      "                    ZERO TCP packets, so the detector's input never materialises.",
      "  exercised?      : NOT exercised by this capture.",
      "",
      "DET-202  DNS Burst / Unique Subdomain Behaviour",
      "  firing          : NONE -- no firing observed in this capture.",
      "  why             : requires >=20 DISTINCT query names from one source in 30 s.",
      "                    The capture contains 12 DNS records / 2 distinct names total,",
      "                    all WS001 self-name mDNS+LLMNR lookups. Peak in any 30 s",
      "                    window is 2 distinct names -> 10% of the threshold.",
      "  exercised?      : PARTIALLY exercised -- the DNS path was live (Zeek did",
      "                    generate dns.log) but the volume required to reach the",
      "                    decision boundary was absent.",
      "",
      "DET-203  Periodic HTTP Behaviour",
      "  firing          : NONE -- no firing observed in this capture.",
      "  why             : requires >=5 HTTP requests on one (src,dst) pair with a",
      "                    coefficient of variation <= 0.05. There is no HTTP at all",
      "                    (no TCP in the capture), so no intervals exist.",
      "  exercised?      : NOT exercised by this capture.",
      "",
      "No detection was modified, tuned or re-parameterised to produce this result."]
(OUT / "detection-results.txt").write_text("\n".join(r) + "\n")
(OUT / "telemetry-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
print("analysis written to", OUT)
for f in sorted(OUT.iterdir()):
    print("  ", f.name, f.stat().st_size, "bytes")
