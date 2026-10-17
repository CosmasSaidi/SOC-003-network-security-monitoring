#!/usr/bin/env python3
"""
SOC-003 Phase 2 -- telemetry analysis and detection validation.

Reads the preserved Zeek logs for the Phase 2 PCAP and derives, from the data
alone:

  * conn/dns/http telemetry summaries
  * per-source behaviour breakdown
  * inter-arrival interval statistics for repeated HTTP requests
  * detection validation against a declared ground-truth model
  * simple detection metrics

Everything is computed from the artifacts; nothing is asserted by hand.
Stdlib only.
"""

import json
import math
import pathlib
import sys

BASE = pathlib.Path("/home/saidi/soc-lab/soc-003/evidence/phase2-controlled-network-behaviour")
ZEEK = BASE / "zeek-run"
OUT = BASE / "analysis"

# ---------------------------------------------------------------------------
# Declared ground-truth model for THIS bounded synthetic capture.
# (Not an assertion about the real world -- it is what the generator injected.)
# ---------------------------------------------------------------------------
GROUND_TRUTH = {
    "192.168.56.150": {
        "behaviour": "controlled network service discovery (multi-host / multi-port TCP probing)",
        "kind": "suspicious",
        "detection": "DET-201",
    },
    "192.168.56.151": {
        "behaviour": "controlled DNS burst (unique subdomains under .lab.test)",
        "kind": "suspicious",
        "detection": "DET-202",
    },
    "192.168.56.152": {
        "behaviour": "periodic HTTP (fixed 30 s interval)",
        "kind": "suspicious",
        "detection": "DET-203",
    },
    "192.168.56.101": {
        "behaviour": "benign baseline + three deliberately sub-threshold control patterns",
        "kind": "benign-control",
        "detection": None,
    },
}


def load(name):
    path = ZEEK / name
    rows = []
    if not path.exists():
        return rows
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rows.append(json.loads(line))
    return rows


def ports_by_state(conns):
    out = {}
    for r in conns:
        out.setdefault(r["conn_state"], []).append(r["id.resp_p"])
    return {k: sorted(v) for k, v in sorted(out.items())}


def intervals(times):
    ts = sorted(times)
    return [round(ts[i + 1] - ts[i], 6) for i in range(len(ts) - 1)]


def stats(iv):
    if not iv:
        return {"n": 0, "mean": None, "stdev": None, "cv": None}
    n = len(iv)
    mean = sum(iv) / n
    var = sum((x - mean) ** 2 for x in iv) / n
    sd = math.sqrt(var)
    cv = (sd / mean) if mean else 0.0
    return {"n": n, "mean": round(mean, 6), "stdev": round(sd, 9), "cv": round(cv, 6)}


def main():
    conns = load("conn.log")
    dns = load("dns.log")
    http = load("http.log")
    notices = load("notice.log")
    dets = load("phase2_detections.log")

    OUT.mkdir(parents=True, exist_ok=True)

    # ---------------- conn summary ----------------
    by_src = {}
    for r in conns:
        by_src.setdefault(r["id.orig_h"], []).append(r)

    conn_summary = {}
    for src, rows in sorted(by_src.items()):
        states = {}
        for r in rows:
            states[r["conn_state"]] = states.get(r["conn_state"], 0) + 1
        conn_summary[src] = {
            "records": len(rows),
            "states": dict(sorted(states.items())),
            "distinct_dst_hosts": sorted({r["id.resp_h"] for r in rows}),
            "distinct_dst_ports": sorted({r["id.resp_p"] for r in rows}),
            "protocols": sorted({r["proto"] for r in rows}),
        }

    # ---------------- scan behaviour ----------------
    scan_src = "192.168.56.150"
    scan_rows = by_src.get(scan_src, [])
    failed = [r for r in scan_rows if r["conn_state"] in ("S0", "REJ", "RSTO", "RSTR", "S1", "OTH")]
    answered = [r for r in scan_rows if r["conn_state"] not in ("S0", "REJ", "RSTO", "RSTR", "S1", "OTH")]
    scan = {
        "source": scan_src,
        "total_connection_records": len(scan_rows),
        "failed_or_non_established": len(failed),
        "established_normally": len(answered),
        "distinct_dst_hosts": sorted({r["id.resp_h"] for r in scan_rows}),
        "distinct_dst_ports": sorted({r["id.resp_p"] for r in scan_rows}),
        "state_counts": dict(sorted({s: sum(1 for r in scan_rows if r["conn_state"] == s)
                                     for s in {r["conn_state"] for r in scan_rows}}.items())),
        "per_destination": {
            h: ports_by_state([r for r in scan_rows if r["id.resp_h"] == h])
            for h in sorted({r["id.resp_h"] for r in scan_rows})
        },
        "first_probe_ts": min(r["ts"] for r in scan_rows),
        "last_probe_start_ts": max(r["ts"] for r in scan_rows),
        "probe_span_seconds": round(max(r["ts"] for r in scan_rows) - min(r["ts"] for r in scan_rows), 6),
        "unanswered_syn_attempts": sum(1 for r in scan_rows if r["conn_state"] == "S0"),
        "refused_attempts": sum(1 for r in scan_rows if r["conn_state"] == "REJ"),
    }

    # ---------------- dns ----------------
    dns_by_src = {}
    for r in dns:
        dns_by_src.setdefault(r["id.orig_h"], []).append(r)
    dns_summary = {}
    for src, rows in sorted(dns_by_src.items()):
        q = [r["query"] for r in rows if r.get("query")]
        ts = sorted(r["ts"] for r in rows)
        dns_summary[src] = {
            "log_records": len(rows),
            "queries": len(q),
            "unique_qnames": len(set(q)),
            "rcodes": dict(sorted({str(r.get("rcode_name")): sum(1 for x in rows if x.get("rcode_name") == r.get("rcode_name")) for r in rows}.items())),
            "first_ts": ts[0], "last_ts": ts[-1],
            "span_seconds": round(ts[-1] - ts[0], 6),
            "queries_per_second": round(len(q) / (ts[-1] - ts[0]), 6) if len(ts) > 1 and ts[-1] > ts[0] else None,
            "sample_qnames": sorted(set(q))[:5],
        }

    # ---------------- http periodicity ----------------
    http_pairs = {}
    for r in http:
        http_pairs.setdefault((r["id.orig_h"], r["id.resp_h"]), []).append(r)
    periodicity = {}
    for (src, dst), rows in sorted(http_pairs.items()):
        ts = sorted(r["ts"] for r in rows)
        iv = intervals(ts)
        periodicity[f"{src} -> {dst}"] = {
            "requests": len(rows),
            "uri_paths": [r["uri"] for r in sorted(rows, key=lambda x: x["ts"])],
            "hosts": sorted({r["host"] for r in rows}),
            "user_agents": sorted({r["user_agent"] for r in rows}),
            "timestamps": ts,
            "intervals": iv,
            "interval_stats": stats(iv),
        }

    # ---------------- detections ----------------
    fired = {}
    for d in dets:
        fired.setdefault(d["det_id"], []).append(d)

    # ---------------- validation ----------------
    validation = []
    tp = fp = 0
    for src, truth in sorted(GROUND_TRUTH.items()):
        det_id = truth["detection"]
        src_dets = [d for d in dets if d["src"] == src]
        hit = [d for d in src_dets if det_id is not None and d["det_id"] == det_id]
        any_hit = bool(src_dets)
        if truth["kind"] == "suspicious":
            if hit:
                tp += 1
                verdict = "TRUE POSITIVE"
            else:
                verdict = "FALSE NEGATIVE"
        else:
            if any_hit:
                fp += 1
                verdict = "FALSE POSITIVE"
            else:
                verdict = "TRUE NEGATIVE (no detection raised)"
        validation.append({
            "src": src, "kind": truth["kind"], "behaviour": truth["behaviour"],
            "expected_detection": det_id, "detections_raised": [d["det_id"] for d in src_dets],
            "verdict": verdict,
        })

    injected = sum(1 for v in GROUND_TRUTH.values() if v["kind"] == "suspicious")
    metrics = {
        "dataset": "phase2-controlled-network-behaviour.pcap (single bounded synthetic capture)",
        "ground_truth_model": GROUND_TRUTH,
        "injected_suspicious_behaviours": injected,
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives_measurable": False,
        "notes": [
            "TP/FP are counted against the declared ground-truth model of this one synthetic capture.",
            "FN cannot be measured here: no ground-truth-positive behaviour was constructed that evades",
            "detection. The sub-threshold control on 192.168.56.101 is an EXPECTED non-detection",
            "(threshold sensitivity check) and is deliberately NOT counted as a false negative.",
        ],
        "detection_coverage": round(tp / injected, 4) if injected else None,
        "precision_on_this_dataset": round(tp / (tp + fp), 4) if (tp + fp) else None,
        "per_detection": {},
    }
    for det_id in ("DET-201", "DET-202", "DET-203"):
        hits = fired.get(det_id, [])
        metrics["per_detection"][det_id] = {
            "fired": bool(hits),
            "count": len(hits),
            "sources": sorted({h["src"] for h in hits}),
        }

    summary = {
        "pcap": "phase2-controlled-network-behaviour.pcap",
        "zeek_version": "9.0.0",
        "totals": {
            "conn_records": len(conns), "dns_records": len(dns),
            "http_records": len(http), "notice_records": len(notices),
            "detection_records": len(dets),
        },
        "conn_by_source": conn_summary,
        "service_discovery_observations": scan,
        "dns_by_source": dns_summary,
        "http_periodicity": periodicity,
        "detections": {k: [{"ts": d["ts"], "src": d["src"], "evidence": d["evidence"]} for d in v] for k, v in fired.items()},
        "validation": validation,
        "metrics": metrics,
    }

    (OUT / "telemetry-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=False) + "\n")
    (OUT / "detection-metrics.json").write_text(json.dumps(metrics, indent=2) + "\n")

    # ---------------- human-readable reports ----------------
    def w(name, text):
        (OUT / name).write_text(text)

    L = []
    L.append("SOC-003 Phase 2 -- conn.log analysis (Zeek 9.0.0, offline replay)")
    L.append("=" * 72)
    L.append(f"total conn records : {len(conns)}")
    L.append("")
    L.append("Per source:")
    for src, info in conn_summary.items():
        L.append(f"  {src}")
        L.append(f"    records        : {info['records']}")
        L.append(f"    protocols      : {', '.join(info['protocols'])}")
        L.append(f"    conn states    : {info['states']}")
        L.append(f"    dst hosts      : {', '.join(info['distinct_dst_hosts'])}")
        L.append(f"    dst ports      : {', '.join(str(p) for p in info['distinct_dst_ports'])}")
        L.append("")
    L.append("Service-discovery source detail:")
    L.append(json.dumps(scan, indent=2))
    w("conn-analysis.txt", "\n".join(L) + "\n")

    L = ["SOC-003 Phase 2 -- dns.log analysis", "=" * 72, ""]
    L.append(json.dumps(dns_summary, indent=2))
    w("dns-analysis.txt", "\n".join(L) + "\n")

    L = ["SOC-003 Phase 2 -- http.log analysis", "=" * 72, ""]
    L.append(json.dumps({k: {kk: vv for kk, vv in v.items() if kk != "timestamps"} for k, v in periodicity.items()}, indent=2))
    w("http-analysis.txt", "\n".join(L) + "\n")

    L = ["SOC-003 Phase 2 -- HTTP inter-arrival / periodicity analysis", "=" * 72, ""]
    for pair, info in periodicity.items():
        st = info["interval_stats"]
        L.append(f"{pair}")
        L.append(f"  requests        : {info['requests']}")
        L.append(f"  intervals (s)   : {info['intervals']}")
        L.append(f"  mean interval   : {st['mean']}")
        L.append(f"  population stdev: {st['stdev']}")
        L.append(f"  coefficient var : {st['cv']}")
        L.append(f"  DET-203 gate    : >=4 intervals, mean in [5,600]s, CV <= 0.05 -> "
                 f"{'PASS' if (st['n'] >= 4 and st['mean'] is not None and 5 <= st['mean'] <= 600 and st['cv'] <= 0.05) else 'no fire'}")
        L.append("")
    w("periodicity-analysis.txt", "\n".join(L) + "\n")

    L = ["SOC-003 Phase 2 -- detection validation", "=" * 72, ""]
    L.append("Ground-truth model for this bounded synthetic capture:")
    for v in validation:
        L.append(f"  {v['src']:16s} [{v['kind']}] expected={v['expected_detection']} "
                 f"raised={v['detections_raised']} -> {v['verdict']}")
    L.append("")
    L.append("Detection output present in notice.log:")
    for d in notices:
        L.append(f"  {d['ts']}  {d['note']}  src={d['src']}  -- {d['msg']}")
    L.append("")
    L.append(f"true positives  : {tp}")
    L.append(f"false positives : {fp}")
    L.append("false negatives : NOT MEASURABLE with this dataset (see detection-metrics.json notes)")
    L.append("")
    L.append("Benign-control assertions checked programmatically:")
    benign_src = "192.168.56.101"
    L.append(f"  - no DET-201 for {benign_src}: "
             f"{'CONFIRMED' if not [d for d in dets if d['src'] == benign_src and d['det_id'] == 'DET-201'] else 'FAILED'}")
    L.append(f"  - no DET-202 for {benign_src}: "
             f"{'CONFIRMED' if not [d for d in dets if d['src'] == benign_src and d['det_id'] == 'DET-202'] else 'FAILED'}")
    L.append(f"  - no DET-203 for {benign_src}: "
             f"{'CONFIRMED' if not [d for d in dets if d['src'] == benign_src and d['det_id'] == 'DET-203'] else 'FAILED'}")
    L.append(f"  - benign client made {conn_summary.get(benign_src, {}).get('records', 0)} TCP/UDP connections "
             f"including {conn_summary.get(benign_src, {}).get('states', {}).get('S0', 0)} unanswered SYNs "
             f"and {dns_summary.get(benign_src, {}).get('unique_qnames', 0)} unique DNS names")
    w("detection-validation.txt", "\n".join(L) + "\n")

    print(f"wrote analysis artifacts to {OUT}")
    print(f"  conn={len(conns)} dns={len(dns)} http={len(http)} notices={len(notices)} detections={len(dets)}")
    print(f"  TP={tp} FP={fp} coverage={metrics['detection_coverage']} precision={metrics['precision_on_this_dataset']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
