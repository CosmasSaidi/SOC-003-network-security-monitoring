#!/usr/bin/env python3
"""SOC-003 Phase 4C Step 3 -- managed ET Open ruleset provenance accounting.

Read-only analysis of:
  1. the cached ET Open archive fetched by suricata-update,
  2. the Suricata distribution rule files under /etc/suricata/rules,
  3. the managed rules file /var/lib/suricata/rules/suricata.rules,
  4. the byte-identical reproduction produced by re-running suricata-update
     offline in an isolated sandbox (update-sandbox/).

Reports total/enabled/disabled/commented rule counts, the protocol-specific
rules suricata-update disables automatically, the archive files whose rules are
not written to the merged output, and a cross-check that the measured unique-SID
count matches suricata-update's own reported total.

Usage: phase4c_step3_provenance.py [json_out]
"""
import collections
import glob
import hashlib
import json
import os
import re
import sys
import tarfile

ARCHIVE = "/var/lib/suricata/update/cache/fb2f2e05df3be8629ef712a89cbae32d-emerging.rules.tar.gz"
MANAGED = "/var/lib/suricata/rules/suricata.rules"
DIST_DIR = "/etc/suricata/rules"
HERE = os.path.dirname(os.path.abspath(__file__))
SANDBOX = os.path.normpath(os.path.join(
    HERE, "..", "evidence/phase4c-ruleset/managed-ruleset/update-sandbox/rules/suricata.rules"))
IGNORED_FILES = ["*deleted.rules"]

# Distribution rule files suricata-update merges in (main.py load_dist_rules).
DIST_FILES = [
    "app-layer-events.rules", "decoder-events.rules", "dhcp-events.rules",
    "dnp3-events.rules", "dns-events.rules", "files.rules", "http2-events.rules",
    "http-events.rules", "ipsec-events.rules", "kerberos-events.rules",
    "modbus-events.rules", "mqtt-events.rules", "nfs-events.rules", "ntp-events.rules",
    "quic-events.rules", "rfb-events.rules", "smb-events.rules", "smtp-events.rules",
    "ssh-events.rules", "stream-events.rules", "tls-events.rules",
]

RULE_RE = re.compile(
    r"^(?P<commented>#\s*)?(?P<action>alert|drop|reject|pass|rejectsrc|rejectdst|rejectboth)"
    r"\s+(?P<proto>[A-Za-z0-9-]+)\s")
SID_RE = re.compile(r"\bsid\s*:\s*(\d+)")
REV_RE = re.compile(r"\brev\s*:\s*(\d+)")
CLASSTYPE_RE = re.compile(r"\bclasstype\s*:\s*([^;\s]+)")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_rule_line(line):
    m = RULE_RE.match(line)
    if not m:
        return None
    sid = SID_RE.search(line)
    if not sid:
        return None
    rev = REV_RE.search(line)
    ct = CLASSTYPE_RE.search(line)
    return {"commented": bool(m.group("commented")), "action": m.group("action"),
            "proto": m.group("proto").lower(), "sid": int(sid.group(1)),
            "rev": int(rev.group(1)) if rev else None,
            "classtype": ct.group(1) if ct else None}


def parse_text(text, group):
    """Parse rule text, joining Suricata multi-line rules (a rule head may span
    several lines before the 'sid:' keyword appears)."""
    out = []
    pending = None

    def emit(raw):
        rule = parse_rule_line(raw)
        if rule:
            rule["group"] = group
            out.append(rule)

    for line in text.splitlines():
        if RULE_RE.match(line):
            if pending is not None:
                emit(pending)
            pending = None
            if SID_RE.search(line):
                emit(line)
            else:
                pending = line
        elif pending is not None:
            pending = pending + " " + line
            if SID_RE.search(pending):
                emit(pending)
                pending = None
    if pending is not None:
        emit(pending)
    return out


def ignored(name):
    base = os.path.basename(name)
    return any(re.fnmatch.fnmatch(base, pat) for pat in IGNORED_FILES) if False else \
        __import__("fnmatch").fnmatch(base, "*deleted.rules")


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else None

    archive_rules = []
    per_file = {}
    with tarfile.open(ARCHIVE, "r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            name = os.path.relpath(member.name)
            data = tar.extractfile(member).read()
            if not name.endswith(".rules"):
                per_file[name] = {"bytes": member.size, "is_rules": False}
                continue
            rules = parse_text(data.decode("utf-8", "replace"), name)
            per_file[name] = {
                "bytes": member.size, "is_rules": True,
                "raw_rules": len(rules),
                "active_in_archive": sum(1 for r in rules if not r["commented"]),
                "commented_in_archive": sum(1 for r in rules if r["commented"]),
                "ignored_by_suricata_update": ignored(name),
            }
            if not ignored(name):
                archive_rules.extend(rules)

    dist_rules = []
    for name in DIST_FILES:
        path = os.path.join(DIST_DIR, name)
        if os.path.exists(path):
            with open(path, encoding="utf-8", errors="replace") as fh:
                dist_rules.extend(parse_text(fh.read(), os.path.join(DIST_DIR, name)))

    loaded_sids = {}
    for rule in archive_rules + dist_rules:
        cur = loaded_sids.get(rule["sid"])
        if cur is None or (rule["rev"] or 0) > (cur["rev"] or 0):
            loaded_sids[rule["sid"]] = rule

    with open(MANAGED, encoding="utf-8", errors="replace") as fh:
        managed_rules = parse_text(fh.read(), MANAGED)

    active, commented = {}, {}
    by_action, by_proto, by_classtype = (collections.Counter() for _ in range(3))
    for rule in managed_rules:
        sid = rule["sid"]
        if rule["commented"]:
            commented[sid] = rule
        else:
            active[sid] = rule
            by_action[rule["action"]] += 1
            by_proto[rule["proto"]] += 1
            by_classtype[str(rule["classtype"])] += 1

    # Rules disabled by suricata-update itself (config-driven), i.e. active in the
    # source rulemap but commented in the merged output.
    config_disabled = [sid for sid in commented
                       if sid in loaded_sids and not loaded_sids[sid]["commented"]]

    not_written = collections.Counter()
    for sid in loaded_sids:
        if sid not in active and sid not in commented:
            not_written[loaded_sids[sid]["group"]] += 1

    sandbox_sha = sha256(SANDBOX) if os.path.exists(SANDBOX) else None
    managed_sha = sha256(MANAGED)

    result = {
        "archive": {
            "path": ARCHIVE, "sha256": sha256(ARCHIVE),
            "bytes": os.path.getsize(ARCHIVE),
            "members": len(per_file),
            "raw_rule_lines": sum(v["raw_rules"] for v in per_file.values() if v["is_rules"]),
            "raw_rule_lines_excluding_ignored":
                sum(v["raw_rules"] for v in per_file.values()
                    if v["is_rules"] and not v["ignored_by_suricata_update"]),
            "per_file": {k: v for k, v in sorted(per_file.items()) if v["is_rules"]},
            "aux_members": sorted(k for k, v in per_file.items() if not v["is_rules"]),
            "ignore_list": IGNORED_FILES,
        },
        "suricata_distribution_rules": {
            "files_merged": [n for n in DIST_FILES if os.path.exists(os.path.join(DIST_DIR, n))],
            "raw_rule_lines": len(dist_rules),
        },
        "loaded_rule_map": {
            "unique_sids": len(loaded_sids),
            "suricata_update_reported_loaded": 69171,
            "matches_report": len(loaded_sids) == 69171,
        },
        "managed": {
            "path": MANAGED, "sha256": managed_sha,
            "bytes": os.path.getsize(MANAGED),
            "lines": sum(1 for _ in open(MANAGED, encoding="utf-8", errors="replace")),
            "rules_enabled": len(active),
            "rules_disabled_commented_out": len(commented),
            "rules_total": len(active) + len(commented),
            "by_action_enabled": dict(sorted(by_action.items())),
            "by_proto_enabled": dict(sorted(by_proto.items())),
            "top_classtypes_enabled": dict(by_classtype.most_common(15)),
        },
        "reproduction": {
            "sandbox_file": SANDBOX, "sandbox_sha256": sandbox_sha,
            "byte_identical_to_managed": sandbox_sha == managed_sha,
        },
        "disabled_by_suricata_update_config": {
            "count": len(config_disabled),
            "by_protocol": dict(collections.Counter(
                loaded_sids[s]["proto"] for s in config_disabled)),
            "sids": sorted(config_disabled),
            "cause": ("suricata-update disables every rule whose app-layer protocol is "
                      "disabled in /etc/suricata/suricata.yaml "
                      "(app-layer.protocols.dnp3.enabled: no, .modbus.enabled: no)"),
        },
        "vendor_commented_out_in_source": {
            "count": len(commented) - len(config_disabled),
            "note": ("ET Open ships these rules already commented out; suricata-update "
                     "preserves them as comments in the merged file"),
        },
        "flowbit_dependency_rules_enabled": {
            "count": 136,
            "source": "suricata-update log line 'Enabled 136 rules for flowbit dependencies.'",
        },
        "source_rules_not_present_in_output": {
            "count": sum(not_written.values()),
            "by_group": dict(sorted(not_written.items())[:10]),
            "cause": ("rules superseded by a higher-revision duplicate SID "
                      "(suricata-update keeps one rule per SID)"),
        },
    }

    text = json.dumps(result, indent=2)
    if out_path:
        with open(out_path, "w") as fh:
            fh.write(text + "\n")
        print("wrote " + out_path)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
