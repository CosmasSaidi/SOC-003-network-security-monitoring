# CASE-501 — Joint Zeek + Suricata Network Investigation

| Field | Value |
| --- | --- |
| Case ID | **CASE-501** (joint investigation; correlated with prior artifacts CASE-201, INV-201) |
| Classification | Controlled laboratory exercise — **controlled simulated behaviour**, NOT a real compromise |
| Investigator | saidi |
| Opened / closed | 2026-10-17 (Phase 5) |
| Primary evidence | `phase2-controlled-network-behaviour.pcap` (SHA-256 `c63484f0…1780`, 215 packets, PCAP T0 = 2026-10-16T07:00:00Z) |
| Investigation layers | Zeek 9.0.0 (offline replay), Suricata 8.0.7 (offline replay, combined 53,214-rule ruleset), packet-level evidence |
| Verdict | All activity identified and correlated is **synthetic lab traffic injected by the SOC-003/lab operator into a deterministic capture**. No real-world compromise is present or claimed. |
| Status | CLOSED as validated lab exercise (see §15/§16) |

---

## 1. Case objective

Correlate, on one capture, what two independent network engines observed about
the same controlled behaviours — Zeek telemetry → Zeek behavioural detection;
Suricata telemetry → Suricata custom detection; vendor/anomaly layers — and
produce one evidence-backed investigation file (timeline, correlation,
ATT&CK assessment, gaps). This is a detection-layer validation exercise, not a
live incident response.

## 2. Evidence sources

* **PCAP:** `…/evidence/phase2-controlled-network-behaviour/phase2-controlled-network-behaviour.pcap` — hash verified this phase.
* **Zeek:** Phase 2 offline run logs (conn/dns/http/files/notice/`phase2_detections.log`) in `…/evidence/phase2…/zeek-run/`; detection sources `detections/zeek/det-201…203.zeek`.
* **Suricata:** Phase 4D combined replay (`evidence/phase4d-combined/replay-combined/out-phase2/eve.json|fast.log|stats.log`); Phase 4B custom-only run (`evidence/phase4b-suricata-install/analysis/custom-rules-summary.json`) used for cross-run attribution comparison; custom rules `detections/suricata/soc003-lab.rules`.
* **Context evidence (referenced, not re-measured):** Phase 4C/4D checksum-anomaly analysis; Phase 4D scan-silence diagnosis; Phase 2 investigation extracts (`…/investigation/timeline.txt`, conn/dns/http extracts).
* **Ground truth:** PCAP generator `scripts/gen_phase2_synthetic_pcap.py` parameters; Phase 2 report §6/§7.

## 3. Timeline (T0 = 2026-10-16T07:00:00Z; full version: `evidence/phase5-joint-investigation/normalized-timeline.md`)

| T+ (s) | Event |
| --- | --- |
| 0.1–95.8 | Block A — benign activity (4 HTTP GETs, 1 plain TCP, 5 DNS NXDOMAIN, 3 benign SYNs) — **no detection anywhere** |
| 120.0–125.7 | Block B(in) — **controlled network service discovery**: 20 zero-payload TCP SYNs from `192.168.56.150` → 4 hosts × 5 ports (22/80/443/445/3389); states S0×16 / RSTO×2 / REJ×2 |
| 121.8 / 125.1 | Suricata 9003001 alerts ×2 (4D attributed probes #7/#18; 4B attributed #18/#20) |
| 200.0 | Zeek DET-201 notice logged (10-probe evidence window T+120.0→122.7; logging deferred to the first post-gap packet by lazy connection removal — source-documented) |
| 200.0–209.57 | Block C — **DNS burst**: 30 queries `c001…c030.lab.test` from `192.168.56.151` → `192.168.56.53:53`, 0.33 s apart, NOERROR×15 / NXDOMAIN×15 |
| 201.32 | Suricata 9003002 alert ×1 (4D attributed query #5 — below-gate bookkeeping attribute; 4B run: query #23) |
| 206.27 | Zeek DET-202 notice at the 20th unique name (`c020.lab.test`) — exact crossing |
| 300.02–450.07 | Block D — **periodic HTTP**: 6 GETs `/api/v1/heartbeat?id=1000…1005` from `192.168.56.152` → `203.0.113.30:80` (`Host: updates.lab.test`), exactly 30.000 s apart, all 200 OK |
| 330.05 | Suricata 9003003 alert (4B run attributed request #2) |
| 420.02 | Zeek DET-203 notice at request #5 (4 intervals, mean 30.000 s, CV 0.0000) |
| 420.05 | Suricata 9003003 alert (4D run) — same 5th-request exchange, 24 ms later packet |

## 4. Network entities

| Entity | Role (lab context) | Traffic |
| --- | --- | --- |
| `192.168.56.150` | Lab "scanner" actor | 20 failed TCP probes (2.7 s evidence window) |
| `192.168.56.151` | Lab "DNS burst" actor | 30 unique lookups in 9.57 s |
| `192.168.56.152` | Lab "heartbeat" actor | 6 periodic GETs, 30.000 s cadence |
| `192.168.56.101` | Benign client (block A) | correct silence from both engines |
| `198.51.100.10/.11`, `203.0.113.20/.21` | Scan targets (TEST-NET) | SYN/SYN-ACK/RST |
| `192.168.56.53` | Lab DNS resolver | 30 burst + 5 benign lookups |
| `203.0.113.30` | "updates" HTTP endpoint (TEST-NET) | 6× 200 OK |
| `198.51.100.20`, other TEST-NET | Benign HTTP targets | 200 OK |

All actors are documentation/synthetic-range addresses in a VirtualBox
host-only lab; none are real systems.

## 5. Detection summary

| Detection | Engine | Behaviour | Count | Timestamp of record | Attribution quality |
| --- | --- | --- | --- | --- | --- |
| DET-201 | Zeek | A | 1 | notice @T+200.0; evidence window from conn start times (exact) | reproducible (double-run verified Phase 2) |
| DET-202 | Zeek | B | 1 | @T+206.270 (20th unique name) | reproducible |
| DET-203 | Zeek | C | 1 | @T+420.023 (5th request) | reproducible |
| 9003001 | Suricata custom | A | 2 (floor 20/10) | attribution varies run-to-run | volume stable |
| 9003002 | Suricata custom | B | 1 (floor 30/20) | attribution varies (#23 vs #5) | volume stable |
| 9003003 | Suricata custom | C | 1 (floor 6/4) | attribution varies (#2 vs #5) | volume stable |
| ET Open vendor | Suricata managed set | all | **0** | — | — |
| anomaly rules | Suricata built-in | all | **0** | — | — |

## 6. Zeek evidence (selected, full extracts in `zeek-selected-records.jsonl`)

* **Detection notices:** 3 notice.log records + 3 `phase2_detections.log` records (fields: window, hosts, ports, attempts, CV, sample names).
* **Behaviour A telemetry:** 20 conn records (uid/times/states/packet counts, zero payload bytes).
* **Behaviour B telemetry:** 30 dns records (qname/qtype/rcode/answers) — 15 NOERROR with `192.168.56.90` answers, 15 NXDOMAIN; 30 UDP conns.
* **Behaviour C telemetry:** 6 http records (method/host/uri/status, fixed UA `soc-lab-synthetic-agent/2.0`), exact 30.000 s spacing.
* **Controls:** block A benign records detected as normal traffic; DET counters silent on them.

## 7. Suricata evidence (selected, full alerts in `suricata-selected-eve.jsonl`)

* **4 alerts** (combined run): 9003001×2 (Classification: Detection of a Network Scan, sev 3), 9003002×1 (Misc activity, sev 3), 9003003×1 (Potential Corporate Privacy Violation, sev 1) — each cloning the Zeek finding's behavioural criteria.
* **Telemetry:** 69 flows (TCP 34 / UDP 35 — 1:1 with `conn.log`), 70 dns events (30 burst query-direction), 10 http events, 10 fileinfo events.
* **Cross-run table:** `alert-crossrun-comparison.json` (4B vs 4D: volumes 2/1/1 identical; attributed packets differ — engine bookkeeping, not event time).

## 8. Correlation analysis

Full table: `correlation-table.md`. Correlated by source/dest/port/timestamps/
protocol/request-query characteristics.

**Explicit counting-difference notes.**
1. DNS telemetry granularity: Zeek 1 record/transaction (35) vs Suricata 1
   event/packet (70, incl. response direction). conn/flow agree 1:1 (69; TCP
   34/UDP 35 both).
2. Detection counts differ (1 Zeek notice vs N Suricata threshold-sampler
   alerts: 2/1/1) because the rules use different units (once-per-window vs
   every-count-th-match); volume = floor(matches÷count).
3. Attribution: Zeek's stream-order detections are exact and reproducible;
   the removal-based DET-201 window uses connection start times (exact);
   Suricata threshold attribution under multi-threaded processing varies per
   run — measured in Phase 4B §7.3 and re-measured here (8 alert rows,
   `alert-crossrun-comparison.json`), e.g. 9003002 attributed to query #5 in
   4D although the earliest gate-satisfying instant is query #20 (T+206.270).
   **Timeline of record = Zeek timestamps; Suricata alert timestamps are
   bookkeeping artefacts.** No exact one-to-one event mapping is claimed.

## 9. Behaviour-by-behaviour findings (Step 4)

### 9.1 DET-201 / SID 9003001 — controlled network service discovery
* **What happened:** a lab actor sent 20 zero-payload TCP SYNs to 4 hosts × 5
  administration-relevant ports in 5.7 s; the lab answered 2 ports (80/443 on
  `198.51.100.10`) with SYN-ACK→scanner-RST, 2 port-22 probes with RST
  (REJ), and left 16 unanswered (S0).
* **Zeek saw:** all 20 attempts with full conn telemetry; DET-201 crossed its
  ≥10-probe / ≥5-port / ≥2-host / 60 s gates 10 probes in (T+122.7).
* **Suricata saw:** the same 20 packets (flow telemetry 1:1); 9003001's
  count-10/60 s sampler produced 2 alerts.
* **ET Open saw:** the same packets — 0 vendor alerts (scan-silence diagnosis,
  Phase 4D: inbound-oriented rules + an unmet outbound per-port count gate).
* **Not seen by either:** payload identity or intent (there is none by
  design); no tool looked at host-side state.
* **Justified conclusion:** the traffic *is* network-service-discovery
  behaviour on the wire (T1046, validated for this capture); both local
  engines detected it; vendor silence is a measured ruleset property, not
  proof of coverage.

### 9.2 DET-202 / SID 9003002 — DNS burst
* **What happened:** 30 lookups of sequentially numbered names
  `c001…c030.lab.test` at 0.33 s from one source to the lab resolver;
  half answered, half NXDOMAIN.
* **Zeek saw:** one dns.log record per transaction; DET-202 crossed at the
  20th unique name (T+206.27) — the earliest gate-satisfying instant.
* **Suricata saw:** 60 dns events (query+response directions); 9003002
  (content `lab.test` + 20/60 s) fired once by volume; attributed packet is a
  bookkeeping artefact of threshold processing (#23 in the 4B run, #5 in 4D).
* **ET Open saw:** 0 alerts (13,912 enabled dns rules did not react — no
  rule-specific diagnosis performed; observed-silent only).
* **Not seen by either:** any evidence of what a real attacker's DNS would add
  (tunnelling payloads, DGA structure, resolver-trust behaviour) — none exists.
* **Justified conclusion:** high-volume/unique-name DNS burst, detected by
  both; C2/DGA mappings remain NOT SUPPORTED; recon mapping remains candidate.

### 9.3 DET-203 / SID 9003003 — periodic HTTP
* **What happened:** 6 GETs to one endpoint at exactly 30.000 s intervals
  (CV 0.000 by construction), benign-looking JSON heartbeat, all 200 OK.
* **Zeek saw:** one http.log record per request; DET-203 crossed at the 5th
  request (4 intervals, CV 0.0000, T+420.023).
* **Suricata saw:** 6 http events; 9003003 (flow:established + uri match +
  4/300 s) fired once; in the 4D run its alert packet is in the same
  5th-request exchange (24 ms apart from Zeek's notice) — an exact
  cross-engine anchor; 4B attributed request #2 instead.
* **Neither saw:** C2 indicators — no tasking, no response-shaped payload
  variation, no reputation/pivot. Periodicity is a *shape* held by many benign
  systems.
* **Justified conclusion:** periodic/beacon-like HTTP behaviour detected by
  both; mapping stops at "periodic behaviour worth a look" (Phase 2 §3 — not
  promoted to C2).

## 10. ATT&CK assessment (joint, not broadened)

Preserved verbatim statuses from Phase 2 `analysis/ATTACK_ASSESSMENT.md`
(§1–4); full reasoning there. Summary:

| Behaviour | Technique | Status (unchanged) |
| --- | --- | --- |
| A scan | **T1046 Network Service Discovery** (TA0007) | **VALIDATED** — now with dual-engine confirmation |
| B DNS burst | T1590.002 (TA0043) | Candidate — insufficient evidence |
| B DNS burst | T1071.004 / T1568.002 (TA0011) | **NOT SUPPORTED** |
| C periodic HTTP | T1071.001 / T1102 (TA0011) | Candidate — insufficient evidence |
| Benign block A | — | No technique |

**CONFIRMED/VALIDATED vs CANDIDATE vs NOT SUPPORTED separation is strict:**
dual-engine agreement validates detections, and T1046's mapping — it does not
add intent evidence, and no candidate was promoted. C2, exfiltration,
compromise, persistence, lateral movement, malware execution, credential
access: unclaimed.

## 11. Detection gaps (observed only; full file: `detection-gap-analysis.md`)

1. Three behaviours covered by **both** engines (custom): Zeek-only/Suricata-only: none.
2. **Vendor layer: telemetry without detection** for all three behaviours.
3. **Anomaly layer: telemetry-relevant only for transport validity** — silent here by design.
4. Attribution/volume semantics differences (see §8) are documented gaps in
   *how alert fields should be read*, not missing behaviours.
5. Zeek detection notices are single-event reproducible; Suricata's are not —
   an instrumentation-behaviour gap between engines worth remembering in
   future joint triage.

## 12. False-positive / noise observations

* **0 false positives** by both engines on the benign block
  (in-capture, reproducible) — custom and ET Open and anomaly layers all silent.
* Suricata behaviour-A fires **2 alerts for 1 behaviour** (sampling),
  harmless here, relevant for SIEM aggregation.
* Cross-capture context (referenced): the benign Phase 3D guest capture fires
  544 checksum anomaly alerts from the VirtualBox offload artifact —
  classified in 4C/4D as expected collection noise, with an opt-in
  lab-only rate-limit artifact available. No effect on this case's PCAP.

## 13. Analyst conclusion

On this capture, the two engines independently produced mutually consistent,
fully-correlated findings for all three lab-defined behavioural shapes, with
single per-behaviour anchors from Zeek (exact timestamps, reproducible) and
sampler alerts from Suricata (stable volume). Telemetry stacks agree 1:1
where granularity matches, and counting differences are fully explained. The
controlled-lab ATT&CK reading is unchanged: T1046 validated; recon/C2
distinctions preserved. Vendor coverage of these specific shapes was not
demonstrated (0 alerts; one diagnosed driver: directionality), which is a
measured data point about *this snapshot on this traffic*, not a capability
verdict about ET Open.

## 14. Limitations

1. Single 215-packet deterministic capture; behaviours and benign controls
   are synthetic and well-parameterized.
2. Suricata observations come from offline replay with multi-threaded
   thresholding — attribution artefacts are replay-engine properties whose
   live-capture behaviour was NOT tested (out of scope).
3. ET Open snapshot is time-bound (2026-10-17 02:10 +0300); rules evolve.
4. Content-engineered rules (9003002's `lab.test` content) are lab-anchored
   by design; they are not portable claims.
5. No host-side, user-side, or process evidence existed in this case; joint
   scope is network-only.
6. "Blocked" IDS method was used nowhere; no remediation was tested.

## 15. Case status

CLOSED — exercise validated. All three controlled simulated behaviours were
reconstructed from PCAP→telemetry→detection→correlation with evidence-backed
findings and reproduced alert/notice artefacts. No further action items;
follow-ups live in the phase reports (e.g., Phase 4D tuning decision).

## 16. Evidence integrity

* Input PCAP hash re-verified `c63484f0…1780` ✓ (INTEGRITY_VERIFICATION.txt §1).
* **510 manifest entries, 0 failures** across Phases 1–4D manifests
  (INTEGRITY_VERIFICATION.txt §2) — includes the Phase 4D self-check (83): 4D
  evidence untouched by Phase 5.
* Config/state: `suricata.yaml` and managed rules hashes unchanged; `dpkg -V`
  clean; service inactive/disabled; SOC-001/SOC-002/Zeek untouched (§4–5).
* Case artifacts hashed: `evidence/phase5-joint-investigation/SHA256SUMS.txt`
  (9 files, self-verified).

*Language note: this document deliberately describes all activity as
"<controlled simulated behaviour>"; nothing herein asserts a real compromise.*
