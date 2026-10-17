#!/usr/bin/env python3
# SOC-003 Phase 4D -- structured summaries for the combined-ruleset replays
# and the tuning demonstration. Read-only on replay outputs; writes only
# under evidence/phase4d-combined/analysis/.

import json
import os
import collections

BASE = os.path.join(os.path.dirname(__file__), "../evidence/phase4d-combined")

RUNS = [
    # (key, out_dir, run_prefix)
    ("phase2-combined", "replay-combined/out-phase2", "replay-combined/phase2-combined"),
    ("phase1-baseline-combined", "negative-controls/out-phase1-baseline", "negative-controls/nc-phase1"),
    ("phase3b-combined", "negative-controls/out-phase3b", "negative-controls/nc-phase3b"),
    ("phase3d-combined", "negative-controls/out-phase3d", "negative-controls/nc-phase3d"),
    ("phase3d-tuned", "tuning/out-tuned-3d", "tuning/tuned-3d"),
    ("phase2-tuned", "tuning/out-tuned-phase2", "tuning/tuned-phase2"),
]

CUSTOM_SIDS = {9003001, 9003002, 9003003}
ANOMALY_SIDS = {2200073, 2200074, 2200075}


def read_kv(path):
    d = {}
    with open(path) as f:
        for line in f:
            if "=" in line:
                k, v = line.strip().split("=", 1)
                try:
                    d[k] = int(v)
                except ValueError:
                    d[k] = v
    return d


def parse_suricata_log(path):
    counters = {}
    with open(path) as f:
        for line in f:
            if "rules successfully loaded" in line:
                txt = line.split("Info: detect: ")[1]
                counters["rule_files_processed"] = int(txt.split(" rule files")[0])
                counters["rules_loaded"] = int(txt.split(". ")[1].split(" rules successfully")[0])
                counters["rules_failed"] = int(txt.split("loaded, ")[1].split(" rules failed")[0])
                counters["rules_skipped"] = int(txt.split("failed, ")[1].split(" rules skipped")[0])
            elif "Threshold config parsed" in line:
                counters["threshold_rules"] = int(line.split(": ")[-1].split(" rule(s)")[0])
            elif "pcap: read 1 file" in line:
                counters["pcap_files"] = 1
                counters["pcap_packets"] = int(line.split("read 1 file, ")[1].split(" packets")[0])
                counters["pcap_bytes"] = int(line.split("packets, ")[1].split(" bytes")[0])
            elif "Alerts: " in line:
                counters["alerts"] = int(line.split("Alerts: ")[1])
    return counters


def summarize(key, out_dir, run_prefix):
    s = {"key": key, "out_dir": os.path.abspath(os.path.join(BASE, out_dir))}
    files = {fn: {"bytes": os.path.getsize(os.path.join(BASE, out_dir, fn))}
             for fn in sorted(os.listdir(os.path.join(BASE, out_dir)))}
    s["files"] = files

    event_types = collections.Counter()
    alerts = []
    flows = 0
    flows_app = collections.Counter()
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
                    "signature": a["signature"],
                    "category": a.get("category"),
                    "severity": a.get("severity"),
                    "src_ip": e.get("src_ip"), "src_port": e.get("src_port"),
                    "dest_ip": e.get("dest_ip"), "dest_port": e.get("dest_port"),
                    "proto": e.get("proto"),
                })
            elif t == "flow":
                flows += 1
                flows_app[str(e.get("app_proto"))] += 1
    alerts_by_sid = collections.Counter()
    for a in alerts:
        alerts_by_sid[str(a["sid"])] += 1

    vendor = [a for a in alerts if a["sid"] not in CUSTOM_SIDS | ANOMALY_SIDS]
    custom = [a for a in alerts if a["sid"] in CUSTOM_SIDS]
    anomaly = [a for a in alerts if a["sid"] in ANOMALY_SIDS]

    s["event_types"] = dict(event_types)
    s["flows"] = {"total": flows, "by_app_proto": dict(flows_app)}
    s["alert_count"] = len(alerts)
    s["alerts_by_sid"] = dict(alerts_by_sid)
    s["layer_breakdown"] = {
        "et_open_vendor": len(vendor),
        "soc003_custom": len(custom),
        "suricata_provided_anomaly": len(anomaly),
    }
    s["counters"] = parse_suricata_log(os.path.join(BASE, out_dir, "suricata.log"))
    s["run"] = read_kv(os.path.join(BASE, run_prefix + ".exit.txt")) | read_kv(os.path.join(BASE, run_prefix + ".time.txt"))
    s["unique_dest_pairs"] = sorted({"%s:%s->%s:%s" % (a["src_ip"], a["src_port"], a["dest_ip"], a["dest_port"]) for a in alerts})[:20]
    return s


def main():
    out = {}
    for key, out_dir, run_prefix in RUNS:
        s = summarize(key, out_dir, run_prefix)
        out[key] = s
        path = os.path.join(BASE, "analysis", "run-%s.json" % key)
        with open(path, "w") as f:
            json.dump(s, f, indent=1)
        print("%-26s alerts=%-4d vendor=%-3d custom=%-3d anomaly=%-3d pkts=%-4s rules=%s thr=%s run=%s" % (
            key, s["alert_count"], s["layer_breakdown"]["et_open_vendor"],
            s["layer_breakdown"]["soc003_custom"], s["layer_breakdown"]["suricata_provided_anomaly"],
            s["counters"].get("pcap_packets"), s["counters"].get("rules_loaded"),
            s["counters"].get("threshold_rules"), s["run"].get("exit")))

    matrix = {
        "ruleset": "combined (managed ET Open 53,211 via rule-files + 3 SOC-003 custom via -s)",
        "columns": ["pcap", "packets", "vendor_alerts", "custom_alerts", "anomaly_alerts", "total_alerts"],
        "rows": [
            {"pcap": "A phase1-synthetic-baseline.pcap", "packets": out["phase1-baseline-combined"]["counters"]["pcap_packets"], **out["phase1-baseline-combined"]["layer_breakdown"], "total_alerts": out["phase1-baseline-combined"]["alert_count"], "assessment": "clean"},
            {"pcap": "B phase3b-benign-ad.pcap", "packets": out["phase3b-combined"]["counters"]["pcap_packets"], **out["phase3b-combined"]["layer_breakdown"], "total_alerts": out["phase3b-combined"]["alert_count"], "assessment": "clean"},
            {"pcap": "C ws001-dc1-guest-capture.pcapng", "packets": out["phase3d-combined"]["counters"]["pcap_packets"], **out["phase3d-combined"]["layer_breakdown"], "total_alerts": out["phase3d-combined"]["alert_count"], "assessment": "544 incidental checksum anomaly alerts (capture artifact, benign traffic; measured cause)"},
            {"pcap": "D phase2 in-PCAP benign blocks", "packets": "within phase2 run (215 total)", "et_open_vendor": 0, "soc003_custom": 0, "suricata_provided_anomaly": 0, "total_alerts": 0, "assessment": "correct silence"},
        ],
        "phase2": {
            "packets": out["phase2-combined"]["counters"]["pcap_packets"], **out["phase2-combined"]["layer_breakdown"],
            "total_alerts": out["phase2-combined"]["alert_count"],
            "custom_sids": out["phase2-combined"]["alerts_by_sid"],
        },
        "tunedeffect": {
            "phase3d_untuned": out["phase3d-combined"]["alert_count"],
            "phase3d_tuned": out["phase3d-tuned"]["alert_count"],
            "phase2_tuned_total": out["phase2-tuned"]["alert_count"],
            "phase2_tuned_custom": out["phase2-tuned"]["layer_breakdown"]["soc003_custom"],
            "tuned_sids_fired": out["phase3d-tuned"]["alerts_by_sid"],
        },
    }
    with open(os.path.join(BASE, "analysis", "combined-matrix.json"), "w") as f:
        json.dump(matrix, f, indent=1)
    print("combined-matrix.json written")


if __name__ == "__main__":
    main()
