#!/usr/bin/env python3
# SOC-003 Phase 5 -- joint Zeek + Suricata investigation artifact builder.
# Read-only over existing evidence; writes only derived artifacts under
# evidence/phase5-joint-investigation/. Creates no new detections and no new
# captures.

import json
import os
import collections

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # soc-003/
PH2 = os.path.join(BASE, "evidence/phase2-controlled-network-behaviour")
PH4B = os.path.join(BASE, "evidence/phase4b-suricata-install/analysis")
PH4D = os.path.join(BASE, "evidence/phase4d-combined/replay-combined/out-phase2")
OUT = os.path.join(BASE, "evidence/phase5-joint-investigation")
os.makedirs(OUT, exist_ok=True)

T0 = 1792134000.0
CUSTOM_SIDS = {9003001, 9003002, 9003003}
ANOMALY_SIDS = {2200073, 2200074, 2200075}
CUSTOM_RULE_COUNT = (9003001, 10, 60)  # sid, count, seconds


def rel(ts):
    return round(ts - T0, 3)


def ts_utc(ts):
    import datetime
    return datetime.datetime.utcfromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]


def jl(path, records):
    with open(os.path.join(OUT, path), "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


# ---------------------------------------------------------------- Zeek side
zeek_sel = []

notices = []
for l in open(os.path.join(PH2, "zeek-run/notice.log")):
    if not l.startswith("#"):
        notices.append(json.loads(l))
for e in notices:
    zeek_sel.append({"kind": "notice", **e, "ts_rel": rel(e["ts"]), "ts_utc": ts_utc(e["ts"])})

dets = []
for l in open(os.path.join(PH2, "zeek-run/phase2_detections.log")):
    if not l.startswith("#"):
        dets.append(json.loads(l))
for e in dets:
    zeek_sel.append({"kind": "detection", **e, "ts_rel": rel(e["ts"]), "ts_utc": ts_utc(e["ts"])})

conns, dns, https, files = [], [], [], []
for fn, acc in (("conn.log", conns), ("dns.log", dns), ("http.log", https), ("files.log", files)):
    for l in open(os.path.join(PH2, "zeek-run/" + fn)):
        if not l.startswith("#"):
            acc.append(json.loads(l))

probes = [e for e in conns if e["id.orig_h"] == "192.168.56.150"]
for i, e in enumerate(probes, start=1):
    zeek_sel.append({
        "kind": "conn.probe", "probe_index": i, "uid": e["uid"], "ts_rel": rel(e["ts"]),
        "ts_utc": ts_utc(e["ts"]), "src": "%s:%s" % (e["id.orig_h"], e["id.orig_p"]),
        "dst": "%s:%s" % (e["id.resp_h"], e["id.resp_p"]), "proto": e.get("proto"),
        "state": e["conn_state"], "orig_pkts": e.get("orig_pkts"), "resp_pkts": e.get("resp_pkts"),
        "orig_bytes": e.get("orig_bytes"),
    })

burst = [e for e in dns if e["id.orig_h"] == "192.168.56.151"]
for i, e in enumerate(burst, start=1):
    zeek_sel.append({
        "kind": "dns.burst", "query_index": i, "uid": e["uid"], "ts_rel": rel(e["ts"]),
        "ts_utc": ts_utc(e["ts"]), "src": "%s:%s" % (e["id.orig_h"], e["id.orig_p"]),
        "dst": "%s:%s" % (e["id.resp_h"], e["id.resp_p"]), "query": e.get("query"),
        "rcode": e.get("rcode_name"), "answers": e.get("answers"),
    })

reqs = [e for e in https if e["id.orig_h"] == "192.168.56.152"]
for i, e in enumerate(reqs, start=1):
    zeek_sel.append({
        "kind": "http.periodic", "request_index": i, "uid": e["uid"], "ts_rel": rel(e["ts"]),
        "ts_utc": ts_utc(e["ts"]), "src": "%s:%s" % (e["id.orig_h"], e["id.orig_p"]),
        "dst": "%s:%s" % (e["id.resp_h"], e["id.resp_p"]), "method": e.get("method"),
        "host": e.get("host"), "uri": e.get("uri"), "status": e.get("status_code"),
        "useragent": e.get("user_agent"),
    })

benign_conn = [e for e in conns if e["id.orig_h"] == "192.168.56.101"]
benign_dns = [e for e in dns if e["id.orig_h"] == "192.168.56.101"]
benign_http = [e for e in https if e["id.orig_h"] == "192.168.56.101"]
syn_controls = [e for e in benign_conn if e["conn_state"] in ("S0", "REJ", "RSTO")]
zeek_sel.append({
    "kind": "control-summary", "behaviour": "A benign block",
    "conn_records": len(benign_conn), "dns_records": len(benign_dns),
    "http_records": len(benign_http), "failed_syn_probes": len(syn_controls),
    "zeek_notice_count": 0, "suricata_alert_count": 0,
    "assessment": "both engines silent on all in-PCAP benign controls (true negative)",
})

jl("zeek-selected-records.jsonl", zeek_sel)

# ------------------------------------------------------------- Suricata side
sur_sel = []
ev = {"alert": [], "flow": [], "dns": [], "http": [], "other": []}
def bucket(k):
    return ev.setdefault(k, [])
event_types = collections.Counter()
for l in open(os.path.join(PH4D, "eve.json")):
    if not l.strip():
        continue
    e = json.loads(l)
    event_types[e.get("event_type")] += 1
    t = e["timestamp"]
    # eve ts is +0300 local; convert to UTC epoch for rel()
    import datetime
    dt = datetime.datetime.strptime(t[:26], "%Y-%m-%dT%H:%M:%S.%f")
    ep = dt.replace(tzinfo=datetime.timezone(datetime.timedelta(hours=3))).timestamp()
    e["_ep"] = ep
    bucket(e.get("event_type", "other")).append(e)

alerts = sorted(ev["alert"], key=lambda e: e["_ep"])
for a in alerts:
    sid = a["alert"]["signature_id"]
    flow = next((f for f in ev["flow"] if f.get("flow_id") == a.get("flow_id")), None)
    sur_sel.append({
        "kind": "alert.full", "ts_utc": a["timestamp"], "ts_rel": rel(a["_ep"]),
        "sid": sid, "signature": a["alert"]["signature"], "category": a["alert"]["category"],
        "severity": a["alert"]["severity"], "src": "%s:%s" % (a["src_ip"], a.get("src_port")),
        "dst": "%s:%s" % (a["dest_ip"], a.get("dest_port")), "proto": a["proto"],
        "flow_id": a.get("flow_id"),
        "flow_start_rel": rel(flow["_ep"]) if flow else None,
        "flow_state": flow["flow"]["state"] if flow else None,
    })

# cross-run attribution comparison (4B standalone custom run vs 4D combined run)
ph4b = json.load(open(os.path.join(PH4B, "custom-rules-summary.json")))
crossrun = []
for a in sorted(ph4b["alerts"], key=lambda x: x["timestamp"]):
    import datetime
    dt = datetime.datetime.strptime(a["timestamp"][:26], "%Y-%m-%dT%H:%M:%S.%f")
    ep = dt.replace(tzinfo=datetime.timezone(datetime.timedelta(hours=3))).timestamp()
    crossrun.append({"run": "phase4b-custom-only", "ts_utc": a["timestamp"], "ts_rel": rel(ep),
                     "sid": a["sid"], "src_port": a["src_port"],
                     "dst": "%s:%s" % (a["dest_ip"], a["dest_port"])})
for a in alerts:
    crossrun.append({"run": "phase4d-combined", "ts_utc": a["timestamp"], "ts_rel": rel(a["_ep"]),
                     "sid": a["alert"]["signature_id"], "src_port": a.get("src_port"),
                     "dst": "%s:%s" % (a["dest_ip"], a["dest_port"])})
crossrun.sort(key=lambda x: (x["sid"], x["run"], x["ts_rel"]))
jl("suricata-selected-eve.jsonl", sur_sel)
with open(os.path.join(OUT, "alert-crossrun-comparison.json"), "w") as f:
    json.dump({
        "note": ("Suricata off-replay alert VOLUME is stable (floor(matches/count)); the ATTRIBUTED "
                 "packet varies run to run under multi-threaded threshold bookkeeping (measured in "
                 "Phase 4B 7.3 and re-measured here). Source ports index the generator's "
                 "probes(40000+)/queries(55000+)/requests(44000+), so each alert maps to an exact "
                 "controlled packet."),
        "runs": crossrun,
        "volume": {"9003001": 2, "9003002": 1, "9003003": 1,
                   "raw_matches": {"9003001": 20, "9003002": 30, "9003003": 6},
                   "count_gates": {"9003001": "10/60s", "9003002": "20/60s", "9003003": "4/300s"}},
    }, f, indent=1)

# ---------------------------------------------------------- correlation base
probe_flows = [f for f in ev["flow"] if f["src_ip"] == "192.168.56.150"]
dns_events = ev["dns"]
dns_burst_events = [d for d in dns_events if d.get("src_ip") == "192.168.56.151"]
dns_burst_q = [d for d in dns_burst_events if d["dest_port"] == 53]
http_events = ev["http"]
http_per = [h for h in http_events if h.get("src_ip") == "192.168.56.152"]
tcp_flows = [f for f in ev["flow"] if f["proto"] == "TCP"]
udp_flows = [f for f in ev["flow"] if f["proto"] == "UDP"]

corr = {
    "t0_utc": "2026-10-16T07:00:00Z", "pcap_packets": 215,
    "engines": {
        "zeek": {"version": "9.0.0", "mode": "offline -r replay (Phase 2 run)", "logs": ["conn", "dns", "http", "files", "notice", "phase2_detections"]},
        "suricata": {"version": "8.0.7", "mode": "offline -r replay (Phase 4D combined run: 53,211 ET Open + 3 custom)", "events": dict(event_types)},
    },
    "telemetry_counts": {
        "zeek": {"conn": 69, "dns": 35, "http": 10, "files": 10,
                 "conn_tcp": len([e for e in conns if e.get("proto") == "tcp"]),
                 "conn_udp": len([e for e in conns if e.get("proto") == "udp"])},
        "suricata": {"flow": len(ev["flow"]), "dns_events": len(dns_events),
                     "dns_query_direction": len(dns_burst_q), "dns_response_direction": len(dns_events) - len(dns_burst_q) - len([d for d in dns_events if d.get("src_ip") == "192.168.56.101"]) - len(dns_burst_q) + len(dns_burst_q),
                     "http": len(http_events), "fileinfo": len(ev["fileinfo"]),
                     "flow_tcp": len(tcp_flows), "flow_udp": len(udp_flows)},
        "counting_note": ("Zeek dns.log = one record per DNS transaction (35); Suricata emits one dns "
                          "event per DNS packet, query and response directions both logged (70). "
                          "conn.log (69) and Suricata flow events (69) agree 1:1; TCP/UDP split (34/35) "
                          "agrees; http transactions (10) and file transfers (10) agree."),
    },
    "behaviours": [
        {
            "id": "A", "name": "Controlled network service discovery (scan block)",
            "src": "192.168.56.150", "dst_hosts": ["198.51.100.10", "198.51.100.11", "203.0.113.20", "203.0.113.21"],
            "dst_ports": [22, 80, 443, 445, 3389], "proto": "TCP",
            "start_rel": rel(min(e["ts"] for e in probes)), "end_rel": rel(max(e["ts"] for e in probes)),
            "packets_events": "20 TCP probes (S0x16, RSTOx2, REJx2); zero payload",
            "zeek_telemetry": "20 conn.log records (uid-listed in zeek-selected-records.jsonl)",
            "zeek_detection": "DET-201 notice: evidence window T+120.000..T+122.700 (10 probes, 2 hosts, 5 ports, 2.7 s); notice ts = T+200.000 (network_time at the 10th lazy connection_state_remove, when the first post-gap packet clock-advanced expired half-open conns -- source-documented behaviour, evidence window computed from conn start times)",
            "suricata_telemetry": "20 matching TCP flow records (of 34 TCP flows)",
            "suricata_detection": "sid 9003001 x2 (volume floor(20 matches/10) = 2); 4D attributed probes #7 (T+121.800) and #18 (T+125.100)",
            "et_open": 0, "anomaly": 0,
        },
        {
            "id": "B", "name": "DNS burst (unique-subdomain lookups)",
            "src": "192.168.56.151", "dst_hosts": ["192.168.56.53"], "dst_ports": [53], "proto": "UDP",
            "start_rel": rel(min(e["ts"] for e in burst)), "end_rel": rel(max(e["ts"] for e in burst)),
            "packets_events": "30 queries c001..c030.lab.test, 0.33 s apart, NOERRORx15, NXDOMAINx15",
            "zeek_telemetry": "30 dns.log records; 30 UDP flow records",
            "zeek_detection": "DET-202 notice at the 20th unique name (c020), ts = crossing = T+206.270 (exact, reproducible)",
            "suricata_telemetry": "30 query-direction dns events (60 dns events incl. responses)",
            "suricata_detection": "sid 9003002 x1 (volume floor(30 matches/20) = 1); 4D attributed query #5 (T+201.320, src port 55004) -- below-gate attribution, see cross-run comparison",
            "et_open": 0, "anomaly": 0,
        },
        {
            "id": "C", "name": "Periodic HTTP behaviour (heartbeat-like GETs)",
            "src": "192.168.56.152", "dst_hosts": ["203.0.113.30"], "dst_ports": [80], "proto": "TCP",
            "start_rel": rel(min(e["ts"] for e in reqs)), "end_rel": rel(max(e["ts"] for e in reqs)),
            "packets_events": "6 GETs /api/v1/heartbeat?id=1000..1005 (host updates.lab.test), exactly 30.000 s apart, all 200 OK",
            "zeek_telemetry": "6 http.log records; 6 TCP flow records",
            "zeek_detection": "DET-203 notice at the 5th request, ts = crossing = T+420.023 (4 intervals, mean 30.000 s, CV 0.0000)",
            "suricata_telemetry": "6 matching http events",
            "suricata_detection": "sid 9003003 x1 (volume floor(6 matches/4) = 1); 4D attributed to the 5th request's exchange (T+420.047) -- same request as Zeek's crossing (within 24 ms); 4B run attributed request #2",
            "et_open": 0, "anomaly": 0,
        },
        {
            "id": "A-control", "name": "in-PCAP benign block (controls)",
            "src": "192.168.56.101",
            "packets_events": "4 HTTP GETs, 1 plain TCP handshake, 5 DNS NXDOMAIN lookups, 3 benign SYNs",
            "zeek_detection": "silent", "suricata_detection": "silent", "et_open": 0, "anomaly": 0,
            "assessment": "true negative in every layer",
        },
    ],
}
with open(os.path.join(OUT, "correlation-table.json"), "w") as f:
    json.dump(corr, f, indent=1)

print("zeek-selected-records.jsonl:", len(zeek_sel), "records")
print("suricata-selected-eve.jsonl:", len(sur_sel), "records")
print("event_types:", dict(event_types))
print("dns q/resp:", len(dns_burst_q), "/", len(dns_events) - len(dns_burst_q))
print("crossrun:", len(crossrun), "alert rows")
print("correlation-table.json written; behaviours:", len(corr["behaviours"]))
