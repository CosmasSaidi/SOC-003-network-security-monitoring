# SOC-003 — Lab-only checksum-anomaly tuning (Phase 4D)

**Artifact:** `soc003-lab-anomaly-thresholds.conf` (threshold config, 3 entries)
**Status:** prepared, syntax-validated and demo-replayed — **NOT deployed**. No
`/etc/suricata` file, no `/etc/suricata/suricata.yaml` field and no managed ET
Open ruleset byte was changed. The alert behaviour of the sensor is unchanged
unless an operator explicitly passes the flag below.

## What is tuned

Suricata's own packet-anomaly rules (Suricata-provided `decoder-events.rules`,
*not* ET Open vendor rules) are rate-limited per source:

```
threshold gen_id 1, sig_id 2200073, type limit, track by_src, count 1, seconds 3600
threshold gen_id 1, sig_id 2200074, type limit, track by_src, count 1, seconds 3600
threshold gen_id 1, sig_id 2200075, type limit, track by_src, count 1, seconds 3600
```

* 2200073 `SURICATA IPv4 invalid checksum`
* 2200074 `SURICATA TCPv4 invalid checksum`
* 2200075 `SURICATA UDPv4 invalid checksum`

## Why (measured evidence)

Replays of the benign Phase 3D `WS001↔DC1` capture fired 544 alerts from these
rules (272 packets × 2 rules), all in the guest→host direction, while zero
alerts came from any other layer. Three independent methods (tshark, RFC-1071
recomputation, checksum-fix replay experiment) established that the packets
genuinely carry invalid IPv4 + transport checksums — produced by sender-side
TX checksum offload in the Windows guest's virtual NIC (VirtualBox capture
path) — i.e. a benign collection artifact, not detected attack behaviour and
not a vendor false positive. Evidence:
`../evidence/phase4c-ruleset/analysis/alert-analysis-phase3d-checksums.md`,
`../evidence/phase4c-ruleset/analysis/checksum-experiment/`,
`../evidence/phase4d-combined/analysis/checksum-anomaly-tuning.md`.

## Exact scope

`gen_id 1`, sig_ids 2200073/2200074/2200075 only; `track by_src`; first alert
per source per rule per 3600 s window retained, later duplicates suppressed.

## Measured effect (Phase 4D demonstration)

| Search | Untuned | Tuned (via `--set threshold-file`) |
| --- | --- | --- |
| Phase 3D benign guest capture | 544 alerts | **3 alerts** (one per SID) |
| Phase 2 replay detections | 4 custom alerts | **4 custom alerts** (unchanged) |

## What visibility is lost

Per-packet anomaly counts within each 1-hour per-source window. The first
anomaly per source per rule still alerts, so persistence of the artifact stays
visible. Fine-grained per-packet checksum statistics are available from the
capture itself (tshark/capinfos) — and alert counts were already unsuitable as
event counts (Phase 4B measured threshold sampling semantics).

## Why lab-specific

The artifact is caused by this lab's VirtualBox guest offload path. A sensor on
a production span/TAP without TX-offload artifacts would gain nothing from the
rate limit and could, in principle, delay visibility of genuine packet
tampering floods. This config is therefore **not** recommended for production.

## How to enable (lab only, per-run, no persistent change)

```bash
suricata -c /etc/suricata/suricata.yaml -s soc003-lab.rules \
  --set threshold-file=$HOME/soc-lab/soc-003/detections/suricata/soc003-lab-anomaly-thresholds.conf \
  -r <pcap> -l <outdir>          # offline replay only; never -i / AF_PACKET / IPS
```

Engine confirms: log line `Threshold config parsed: 3 rule(s) found`.

**Suricata 8 syntax caveat (measured in Phase 4D validation):** entries must
NOT end with `;` — a trailing semicolon makes the threshold file fail to parse
(`pcre2_match parse error`, engine exits 1).

## How to reverse

Do not pass `--set threshold-file=…` (or delete this file). Because nothing was
written into any persistent config, reversal is complete by omission — there is
no deployed state to undo.

---
Author: saidi (hand-written for SOC-003 Phase 4D; see also `README.md` for the
Phase 4B lab rules this directory documents).
