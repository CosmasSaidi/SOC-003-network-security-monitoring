#!/usr/bin/env python3
# SOC-003 Phase 4C Step 3 -- summarize the managed-ET-Open replays and emit
# the analysis JSONs + comparison used by PHASE4C_REPORT.md.
#
# Inputs (evidence produced by scripts/phase4c_step3_run.sh replays):
#   evidence/phase4c-ruleset/replay-et-open/out-managed-et-open
#   evidence/phase4c-ruleset/negative-controls/out-*
#
# Read-only on the replay outputs; writes only under analysis/.

import json
import os
import collections

BASE = os.path.join(os.path.dirname(__file__),
                    "../evidence/phase4c-ruleset")

REPLAYS = [
    ("phase2", "replay-et-open/out-managed-et-open",
     "replay-et-open/phase2-managed", "phase2-et-open-replay"),
    ("phase1-baseline", "negative-controls/out-phase1-baseline",
     "negative-controls/run-phase1-baseline", "negative-control-phase1-baseline"),
    ("phase3b-benign-ad", "negative-controls/out-phase3b-benign-ad",
     "negative-controls/run-phase3b-benign-ad", "negative-control-phase3b-benign-ad"),
    ("phase3d-ws001-dc1", "negative-controls/out-phase3d-ws001-dc1",
     "negative-controls/run-phase3d-ws001-dc1", "negative-control-phase3d-ws001-dc1"),
]


def read_kv(path):
    d = {}
    with open(path) as f:
        for line in f:
            if "=" in line:
                k, v = line.strip().split("=", 1)
                try:
                    d[k] = int(v)
                except ValueError:
                    try:
                        d[k] = float(v)
                    except ValueError:
                        d[k] = v
    return d


def summarize(out_dir, run_prefix):
    s = {"out_dir": os.path.abspath(os.path.join(BASE, out_dir))}
    files = {}
    for fn in sorted(os.listdir(os.path.join(BASE, out_dir))):
        files[fn] = {"bytes": os.path.getsize(os.path.join(BASE, out_dir, fn))}
    s["files"] = files

    event_types = collections.Counter()
    alerts = []
    flows = 0
    flows_app = collections.Counter()
    flows_proto = collections.Counter()
    counters = {}

    with open(os.path.join(BASE, out_dir, "eve.json")) as f:
        for line in f:
            if not line.strip():
                continue
            e = json.loads(line)
            t = e.get("event_type")
            event_types[t] += 1
            if t == "alert":
                a = e["alert"]
                alerts.append({
                    "timestamp": e.get("timestamp"),
                    "sid": a["signature_id"],
                    "rev": a.get("signature_rev"),
                    "signature": a["signature"],
                    "category": a.get("category"),
                    "severity": a.get("severity"),
                    "src_ip": e.get("src_ip"),
                    "src_port": e.get("src_port"),
                    "dest_ip": e.get("dest_ip"),
                    "dest_port": e.get("dest_port"),
                    "proto": e.get("proto"),
                    "app_proto": e.get("app_proto"),
                    "action": a.get("action"),
                })
            elif t == "flow":
                flows += 1
                flows_app[str(e.get("app_proto"))] += 1
                flows_proto[str(e.get("proto"))] += 1
            elif t == "stats":
                try:
                    counters = dict(e["stats"]["counters"]["detect.alert"].items()) \
                        if isinstance(e["stats"]["counters"].get("detect.alert"), dict) else {}
                except Exception:
                    counters = {}

    alerts_by_sid = collections.Counter()
    for a in alerts:
        alerts_by_sid[str(a["sid"])] += 1

    s["alerts"] = alerts
    s["event_types"] = dict(event_types)
    s["flows"] = {"total": flows}
    s["flows_by_app_proto"] = dict(flows_app)
    s["flows_by_proto"] = dict(flows_proto)
    s["alert_count"] = len(alerts)
    s["alerts_by_sid"] = dict(alerts_by_sid)

    # counters from suricata.log
    log_path = os.path.join(BASE, out_dir, "suricata.log")
    counters = {}
    with open(log_path) as f:
        for line in f:
            if "rules successfully loaded" in line:
                counters["rules_loaded"] = int(line.split(".")[0].split()[-1].split(",")[0]) if False else None
    # simpler direct parse
    counters = {}
    with open(log_path) as f:
        for line in f:
            if "rules successfully loaded" in line:
                for part in line.split():
                    pass
    with open(log_path) as f:
        for line in f:
            if "rules successfully loaded" in line:
                # "1 rule files processed. 53211 rules successfully loaded, 0 rules failed, 0 rules skipped"
                txt = line.split("Info: detect: ")[1]
                counters["rule_files_processed"] = int(txt.split(" rule files")[0])
                counters["rules_loaded"] = int(txt.split(". ")[1].split(" rules successfully")[0])
                counters["rules_failed"] = int(txt.split("loaded, ")[1].split(" rules failed")[0])
                counters["rules_skipped"] = int(txt.split("failed, ")[1].split(" rules skipped")[0])
            elif "pcap: read 1 file" in line:
                counters["pcap_files"] = 1
                counters["pcap_packets"] = int(line.split("read 1 file, ")[1].split(" packets")[0])
                counters["pcap_bytes"] = int(line.split("packets, ")[1].split(" bytes")[0])
            elif "Alerts: " in line:
                counters["alerts"] = int(line.split("Alerts: ")[1])
    s["counters"] = counters

    # run metadata
    run = {}
    tp = os.path.join(BASE, run_prefix + ".time.txt")
    ep = os.path.join(BASE, run_prefix + ".exit.txt")
    if os.path.exists(tp):
        run.update(read_kv(tp))
    if os.path.exists(ep):
        run.update(read_kv(ep))
    s["run"] = run
    return s


def main():
    out = {}
    for key, out_dir, run_prefix, fname in REPLAYS:
        s = summarize(out_dir, run_prefix)
        path = os.path.join(BASE, "analysis", fname + ".json")
        with open(path, "w") as f:
            json.dump(s, f, indent=1)
        print(f"{fname}.json: alerts={s['alert_count']} sids={s['alerts_by_sid']} "
              f"pkts={s['counters'].get('pcap_packets')} rules_loaded={s['counters'].get('rules_loaded')} "
              f"run={s['run']}")

    # ---- Step 5: structured Phase 4B vs 4C comparison ----
    comparison = {
        "baseline_phase": "4B",
        "phase4b": {
            "stock_packaged_rules": {
                "rules_loaded": 0,
                "note": "packaged config had no vendor ruleset; /var/lib/suricata/rules/suricata.rules absent",
                "alerts_phase2": 0,
            },
            "packaged_protocol_event_rulefiles": {
                "rules_loaded": 445,
                "alerts_phase2": 0,
            },
            "custom_soc003_rules": {
                "rules_loaded": 3,
                "sids": [9003001, 9003002, 9003003],
                "alerts_phase2": 4,
                "true_positives": 4,
                "false_positives": 0,
                "unique_behaviours_detected": 3,
                "recall_against_injected_behaviours": "3/3",
                "per_sid": {"9003001": 2, "9003002": 1, "9003003": 1},
            },
            "negative_controls_alerts": {
                "phase1-baseline": 0,
                "phase3b-benign-ad": 0,
                "phase3d-guest-capture": 0,
            },
        },
        "phase4c_step3": {
            "managed_et_open_ruleset": {
                "rules_total": 69171,
                "rules_enabled": 53211,
                "rules_failed": 0,
                "rules_skipped": 0,
                "source": "et/open (Proofpoint) via suricata-update 1.3.8",
            },
            "alerts_phase2": 0,
            "alerts_by_sid_phase2": {},
            "negative_controls_alerts": {
                "phase1-baseline": 0,
                "phase3b-benign-ad": 0,
                "phase3d-ws001-dc1": 544,
            },
            "phase3d_alert_sids": {
                "2200073": 272,
                "2200074": 260,
                "2200075": 12,
            },
            "phase3d_alert_origin": (
                "Suricata-provided packet-anomaly rules (decoder-events.rules, "
                "sids 2200000-2200999 range) merged into the managed suricata.rules "
                "by suricata-update -- not ET Open vendor signatures"
            ),
            "phase3d_alert_assessment": "incidental match (capture artifact: sender-side checksum offload, benign WS001<->DC1 traffic)",
        },
        "same_behaviours_detected": {
            "phase2_block_b_syn_probes": {"phase4b_custom": True, "phase4c_et_open": False},
            "phase2_block_c_dns_burst": {"phase4b_custom": True, "phase4c_et_open": False},
            "phase2_block_d_http_heartbeat": {"phase4b_custom": True, "phase4c_et_open": False},
        },
        "conclusion": (
            "The managed ET Open ruleset produced 0 alerts on the Phase 2 PCAP, so it "
            "detected none of the three injected behaviours in this controlled evidence; "
            "the only firing rules anywhere in the matrix are three Suricata-distributed "
            "checksum-anomaly rules on one benign control (544 incidental alerts from "
            "invalid-checksum packets created by sender-side checksum offload in the guest "
            "capture path)."
        ),
    }
    with open(os.path.join(BASE, "analysis", "comparison-phase4b.json"), "w") as f:
        json.dump(comparison, f, indent=1)
    print("comparison-phase4b.json written")


if __name__ == "__main__":
    main()
