#!/usr/bin/env python3
"""SOC-003 Phase 4B -- offline summary of a Suricata replay output directory.

Reads an output directory produced by an isolated `suricata ... -l <dir>` run and
emits a deterministic JSON summary (event types, flows, protocol detection,
alerts, capture counters, warnings/errors). Read-only with respect to Suricata;
writes only the JSON file requested on the command line.

Usage: phase4b_analyze.py <out_dir> [json_out]
"""
import collections
import json
import os
import re
import sys


def summarize(out_dir):
    summary = {"out_dir": os.path.abspath(out_dir), "files": {}, "alerts": []}
    for name in ("eve.json", "fast.log", "stats.log", "suricata.log"):
        path = os.path.join(out_dir, name)
        if os.path.exists(path):
            summary["files"][name] = {"bytes": os.path.getsize(path)}

    eve = os.path.join(out_dir, "eve.json")
    events = collections.Counter()
    flows = collections.Counter()
    app_proto = collections.Counter()
    flow_proto = collections.Counter()
    if os.path.exists(eve):
        with open(eve) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                ev = json.loads(line)
                etype = ev.get("event_type")
                events[etype] += 1
                if etype == "flow":
                    flows["total"] += 1
                    app_proto[str(ev.get("app_proto"))] += 1
                    flow_proto[ev.get("proto")] += 1
                elif etype == "alert":
                    alert = ev.get("alert", {})
                    summary["alerts"].append({
                        "timestamp": ev.get("timestamp"),
                        "sid": alert.get("signature_id"),
                        "rev": alert.get("rev"),
                        "signature": alert.get("signature"),
                        "category": alert.get("category"),
                        "severity": alert.get("severity"),
                        "src_ip": ev.get("src_ip"),
                        "src_port": ev.get("src_port"),
                        "dest_ip": ev.get("dest_ip"),
                        "dest_port": ev.get("dest_port"),
                        "proto": ev.get("proto"),
                        "action": alert.get("action"),
                    })
    summary["event_types"] = dict(sorted(events.items()))
    summary["flows"] = dict(flows)
    summary["flows_by_app_proto"] = dict(sorted(app_proto.items()))
    summary["flows_by_proto"] = dict(sorted(flow_proto.items()))
    summary["alert_count"] = len(summary["alerts"])
    summary["alerts_by_sid"] = dict(sorted(
        collections.Counter(str(a["sid"]) for a in summary["alerts"]).items()))

    log = os.path.join(out_dir, "suricata.log")
    counters = {}
    warnings, errors, notices, infos = [], [], [], []
    if os.path.exists(log):
        with open(log) as fh:
            for line in fh:
                line = line.rstrip("\n")
                m = re.search(r"Info: counters: Alerts: (\d+)", line)
                if m:
                    counters["alerts"] = int(m.group(1))
                m = re.search(r"read (\d+) file, (\d+) packets, (\d+) bytes", line)
                if m:
                    counters["pcap_files"], counters["pcap_packets"], counters["pcap_bytes"] = (
                        int(m.group(1)), int(m.group(2)), int(m.group(3)))
                m = re.search(r"(\d+) rule files processed\. (\d+) rules successfully loaded, "
                              r"(\d+) rules failed, (\d+) rules skipped", line)
                if m:
                    counters["rule_files_processed"] = int(m.group(1))
                    counters["rules_loaded"] = int(m.group(2))
                    counters["rules_failed"] = int(m.group(3))
                    counters["rules_skipped"] = int(m.group(4))
                for level, bucket in (("Warning", warnings), ("Error", errors),
                                      ("Notice", notices), ("Info", infos)):
                    marker = f" {level}: "
                    idx = line.find(marker)
                    if idx != -1:
                        bucket.append(line[idx + len(marker):])
                        break
    summary["counters"] = counters
    summary["warnings"] = sorted(set(warnings))
    summary["errors"] = sorted(set(errors))
    return summary


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    summary = summarize(sys.argv[1])
    text = json.dumps(summary, indent=2, sort_keys=False)
    if len(sys.argv) > 2:
        with open(sys.argv[2], "w") as fh:
            fh.write(text + "\n")
        print(f"wrote {sys.argv[2]}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
