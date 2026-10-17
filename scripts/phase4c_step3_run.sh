#!/usr/bin/env bash
# SOC-003 Phase 4C Step 3 -- run one offline Suricata invocation and record
# stdout, stderr, exit code, wall-clock duration and peak RSS.
#
# Usage: phase4c_step3_run.sh <label> -- <command...>
# Writes <label>.out.txt, <label>.err.txt, <label>.exit.txt, <label>.time.txt,
# <label>.rss.txt next to each other in the caller's working directory.
set -u

label="$1"
shift
[ "${1:-}" = "--" ] && shift

out="${label}.out.txt"
err="${label}.err.txt"

start=$(date +%s.%N)
"$@" >"$out" 2>"$err" &
pid=$!
peak=0
while kill -0 "$pid" 2>/dev/null; do
    if [ -r "/proc/$pid/status" ]; then
        rss=$(awk '/^VmHWM:/ {print $2}' "/proc/$pid/status" 2>/dev/null)
        [ -n "${rss:-}" ] && [ "$rss" -gt "$peak" ] 2>/dev/null && peak=$rss
    fi
    sleep 0.3
done
wait "$pid"
rc=$?
end=$(date +%s.%N)

printf 'exit=%s\n' "$rc" > "${label}.exit.txt"
awk -v a="$start" -v b="$end" -v p="$peak" 'BEGIN {printf "wall_seconds=%.3f\npeak_rss_kb=%s\n", b-a, p}' > "${label}.time.txt"
printf 'peaked RSS (VmHWM) = %s kB\n' "$peak" > "${label}.rss.txt"
echo "$label: exit=$rc peak_rss_kb=$peak"
exit 0
