#!/usr/bin/env bash
# SOC-003 Phase 3 -- integrity snapshot (pre / post).
#
# Read-only. Emits a deterministic inventory of everything Phase 3 must not
# touch (SOC-001, SOC-002, SOC-003 Phase 1 and Phase 2 evidence, the SOC-003
# source artifacts) plus the host/lab state needed to prove no network or VM
# configuration changed. Run identically before and after Phase 3 and diff.
#
# Usage: scripts/phase3_integrity.sh <label>

set -uo pipefail
LAB="$HOME/soc-lab"
S3="$LAB/soc-003"
LABEL="${1:-snapshot}"

echo "# SOC-003 Phase 3 -- ${LABEL} integrity snapshot"
echo "# Captured: $(date -Is)"
echo

echo "## 1. SOC-001 capture evidence tree (hash inventory)"
(cd "$LAB" && find evidence/soc-001-capture -type f | sort | xargs sha256sum) 2>/dev/null
echo

echo "## 2. SOC-002 trees (hash inventory; SOC-002-PUBLIC/.git excluded)"
(cd "$LAB" && find SOC-002-PUBLIC SOC-002-windows-ad -type f -not -path '*/.git/*' | sort | xargs sha256sum) 2>/dev/null
echo

echo "## 3. SOC-003 Phase 1 evidence tree (hash inventory)"
(cd "$S3" && find evidence/phase1-zeek-baseline -type f | sort | xargs sha256sum) 2>/dev/null
echo

echo "## 4. SOC-003 Phase 2 evidence tree (hash inventory)"
(cd "$S3" && find evidence/phase2-controlled-network-behaviour -type f | sort | xargs sha256sum) 2>/dev/null
echo

echo "## 5. SOC-003 source artifacts (detections, scripts, reports)"
(cd "$S3" && find detections scripts analysis cases investigations architecture docs -type f 2>/dev/null | sort | xargs sha256sum) 2>/dev/null
echo

echo "## 6. File counts (fast comparison)"
printf 'soc001_files=%s\n'  "$(cd "$LAB" && find evidence/soc-001-capture -type f | wc -l)"
printf 'soc002_files=%s\n'  "$(cd "$LAB" && find SOC-002-PUBLIC SOC-002-windows-ad -type f -not -path '*/.git/*' | wc -l)"
printf 'phase1_files=%s\n'  "$(cd "$S3" && find evidence/phase1-zeek-baseline -type f | wc -l)"
printf 'phase2_files=%s\n'  "$(cd "$S3" && find evidence/phase2-controlled-network-behaviour -type f | wc -l)"
echo

echo "## 7. Git state (expect exactly one repo: the pre-existing SOC-002-PUBLIC/.git)"
find "$LAB" -maxdepth 4 -name .git -type d 2>/dev/null | sort
if git -C "$S3" rev-parse --git-dir >/dev/null 2>&1; then
  echo "soc-003 IS a git repository (UNEXPECTED)"
else
  echo "soc-003 is not a git repository (expected)"
fi
echo

echo "## 8. Lab/network state (must not change during Phase 3)"
echo "-- running VMs --"
VBoxManage list runningvms 2>/dev/null
echo "-- VBox host-only interfaces --"
VBoxManage list hostonlyifs 2>/dev/null | grep -E '^(Name|IPAddress|NetworkMask|Status):'
echo "-- host addresses --"
ip -br addr show
echo "-- routes --"
ip route show
echo "-- ip_forward --"
cat /proc/sys/net/ipv4/ip_forward
echo "-- vboxnet0 promiscuity / carrier --"
cat /sys/class/net/vboxnet0/promiscuity /sys/class/net/vboxnet0/carrier /sys/class/net/vboxnet0/operstate
echo "-- suricata present? --"
(command -v suricata >/dev/null 2>&1 && echo "suricata FOUND (UNEXPECTED)" || echo "suricata not installed (expected)")
echo "-- pcap caches (baseline for Suricata check) --"
dpkg -l 2>/dev/null | grep -ci suricata
find /opt -maxdepth 2 -name 'zeek*' -o -maxdepth 2 -name 'suricata*' 2>/dev/null | sort
echo
