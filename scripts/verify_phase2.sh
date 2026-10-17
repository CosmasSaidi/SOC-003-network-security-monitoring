#!/usr/bin/env bash
# SOC-003 Phase 2 -- end-to-end verification.
#
# Non-destructive: the PCAP is regenerated into a temporary directory and Zeek is
# replayed into a temporary directory. Nothing inside the evidence bundle is
# modified. Writes a report to stdout (or to $1).
#
# Usage: scripts/verify_phase2.sh [output-file]

set -uo pipefail

S3="$HOME/soc-lab/soc-003"
LAB="$HOME/soc-lab"
B="$S3/evidence/phase2-controlled-network-behaviour"
TMP="$(mktemp -d)"
# Zeek writes its logs into the current working directory, so runs happen
# inside $TMP to guarantee nothing outside the temp dir is ever touched.
cleanup() { python3 -c 'import shutil,sys; shutil.rmtree(sys.argv[1], ignore_errors=True)' "$TMP"; }

exec > >(tee "${1:-/dev/stdout}") 2>&1

pass=0; fail=0
ck() { if [ "$2" = "$3" ]; then echo "  [PASS] $1 ($2)"; pass=$((pass+1)); else echo "  [FAIL] $1 (got '$2', expected '$3')"; fail=$((fail+1)); fi; }

echo "SOC-003 Phase 2 -- end-to-end verification"
echo "Run at: $(date -Is)"
echo "Host  : $(uname -srm)"
echo

echo "### 1. PCAP reproducibility (fresh generation vs preserved artifact)"
python3 "$S3/scripts/gen_phase2_synthetic_pcap.py" "$TMP/fresh.pcap" >/dev/null
FRESH=$(sha256sum "$TMP/fresh.pcap" | cut -d' ' -f1)
KEEP=$(sha256sum "$B/phase2-controlled-network-behaviour.pcap" | cut -d' ' -f1)
ck "regenerated PCAP == preserved PCAP" "$FRESH" "$KEEP"
ck "PCAP matches documented hash" "$KEEP" "c63484f083f409c3dd58e01064bac9c0ae2e52a5bffa3dbad05aff6f04201780"
echo

echo "### 2. Zeek 9 offline processing exits successfully"
( cd "$TMP" && /opt/zeek/bin/zeek -r "$B/phase2-controlled-network-behaviour.pcap" LogAscii::use_json=T \
    "$S3/detections/zeek/phase2-load.zeek" > "$TMP/out.txt" 2> "$TMP/err.txt" )
RC=$?
ck "zeek exit code" "$RC" "0"
ck "zeek stderr bytes (empty)" "$(wc -c < "$TMP/err.txt" | tr -d ' ')" "0"
echo "  zeek version: $(/opt/zeek/bin/zeek --version)"
echo

echo "### 3. All three detections execute and fire on their intended source"
for d in DET-201 DET-202 DET-203; do
  n=$(grep -c "\"det_id\":\"$d\"" "$TMP/phase2_detections.log" 2>/dev/null || echo 0)
  ck "$d produced exactly 1 record" "$n" "1"
done
ck "detection records total" "$(grep -c '"det_id"' "$TMP/phase2_detections.log")" "3"
ck "notice records total" "$(grep -c '"note"' "$TMP/notice.log")" "3"
echo

echo "### 4. Benign control does not trigger any detection"
ck "DET-201 src" "$(python3 -c "
import json;print(','.join(sorted({json.loads(l)['src'] for l in open('$TMP/phase2_detections.log') if l.strip() and not l.startswith('#') if json.loads(l)['det_id']=='DET-201'})))")" "192.168.56.150"
ck "DET-202 src" "$(python3 -c "
import json;print(','.join(sorted({json.loads(l)['src'] for l in open('$TMP/phase2_detections.log') if l.strip() and not l.startswith('#') if json.loads(l)['det_id']=='DET-202'})))")" "192.168.56.151"
ck "DET-203 src" "$(python3 -c "
import json;print(','.join(sorted({json.loads(l)['src'] for l in open('$TMP/phase2_detections.log') if l.strip() and not l.startswith('#') if json.loads(l)['det_id']=='DET-203'})))")" "192.168.56.152"
ck "detections attributed to benign client 192.168.56.101" "$(python3 -c "
import json;print(sum(1 for l in open('$TMP/phase2_detections.log') if l.strip() and not l.startswith('#') if json.loads(l)['src']=='192.168.56.101'))")" "0"
echo

echo "### 5. Detection output reproducible (byte-identical to preserved bundle)"
ck "notice.log byte-identical"   "$(sha256sum < "$TMP/notice.log" | cut -d' ' -f1)" "$(sha256sum < "$B/zeek-run/notice.log" | cut -d' ' -f1)"
ck "phase2_detections.log byte-identical" "$(sha256sum < "$TMP/phase2_detections.log" | cut -d' ' -f1)" "$(sha256sum < "$B/zeek-run/phase2_detections.log" | cut -d' ' -f1)"
echo

echo "### 6. Evidence hash inventory"
if [ -f "$B/hashes/SHA256SUMS.txt" ]; then
  tot=$(cd "$B/hashes" && sha256sum -c SHA256SUMS.txt 2>/dev/null | grep -c ': OK')
  bad=$(cd "$B/hashes" && sha256sum -c SHA256SUMS.txt 2>/dev/null | grep -c 'FAILED')
  ck "inventory files verified OK" "$bad" "0"
  echo "  files covered: $tot"
fi
echo

echo "### 7. SOC-001 / SOC-002 / Phase 1 unchanged (vs pre-Phase-2 baseline)"
python3 - <<'PY'
import re, pathlib
b = pathlib.Path.home()/"soc-lab/soc-003/evidence/phase2-controlled-network-behaviour/integrity"
def h(p): return {m.group(2): m.group(1) for m in re.finditer(r'^([0-9a-f]{64})  (.*)$', p.read_text(), re.M)}
pre, post = h(b/'pre-phase2-baseline.txt'), h(b/'post-phase2-integrity-check.txt')
chg = [k for k in pre if k in post and pre[k] != post[k]]
print(f"  [{'PASS' if not chg else 'FAIL'}] pre={len(pre)} post={len(post)} changed={len(chg)}")
PY
echo

echo "### 8. No Git repository, no commit, no push"
if git -C "$S3" rev-parse --git-dir >/dev/null 2>&1; then
  echo "  [FAIL] soc-003 IS a git repository"
else
  echo "  [PASS] soc-003 is not a git repository"
fi
echo "  .git dirs under ~/soc-lab (expect only the pre-existing SOC-002-PUBLIC/.git):"
find "$LAB" -maxdepth 4 -name .git -type d 2>/dev/null | sed 's/^/    /'
echo

echo "### 9. No credential values in the Phase 2 artifacts"
hits=$(grep -rniE 'BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-|password[[:space:]]*[=:][[:space:]]*[^[:space:]]+' "$B" 2>/dev/null | grep -vc 'Binary file')
ck "credential-value pattern matches" "${hits:-0}" "0"
echo

echo "=========================================================================="
echo "RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ] && echo "PHASE 2 VERIFICATION: PASS" || echo "PHASE 2 VERIFICATION: FAIL"
echo
echo "Note: the hash-inventory check in step 6 runs against the SHA256SUMS.txt"
echo "generated before this record was written. This record is itself covered by"
echo "the regenerated inventory. See analysis/final-verification.txt."
cleanup
exit "$fail"
