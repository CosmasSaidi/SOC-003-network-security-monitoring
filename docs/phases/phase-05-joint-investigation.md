# SOC-003 — Phase 5 Report: Joint Zeek + Suricata Investigation & Case Packaging

**Phase:** 5 — PCAP → Zeek telemetry/detection → Suricata telemetry/detection → correlation → investigation → ATT&CK → case documentation
**Status:** **PASS** (see §17)
**Executed:** 2026-10-17 (~11:10–11:40 EAT, Africa/Nairobi)
**Host:** Kali GNU/Linux Rolling 2025.4 (sensor); Zeek 9.0.0, Suricata 8.0.7, tshark/capinfos 4.6.0
**Operator:** saidi (uid 1000)
**Mode:** Offline PCAP analysis only. No `-i`, AF_PACKET, NFQUEUE, IPS/inline; `suricata.service` not started (verified inactive/disabled, 0 processes, §15); no firewall/routing/VirtualBox/VM/AD/DNS/WEF/Sysmon/Zeek change; `/etc/suricata/suricata.yaml` and the managed ET Open ruleset unchanged (hash-verified); Phase 2 PCAP not regenerated (hash-verified); no new detections or rules; no Git repo/commit; sole human authorship — no AI/agent attribution.

---

## 1. Objective

Create one evidence-backed investigation correlating, on the same Phase 2 PCAP:
(a) Zeek telemetry + detections, (b) Suricata (custom + managed + anomaly)
telemetry + detections, (c) packet-level evidence — then package it as a case
(CASE-501), with a joint ATT&CK assessment and gap analysis. **No new detections
were created.**

## 2. Evidence sources

Reused — nothing regenerated, nothing advanced over replay:

| Source | Artifact | Verified |
| --- | --- | --- |
| Primary input PCAP | `evidence/phase2-controlled-network-behaviour/phase2-controlled-network-behaviour.pcap` | SHA-256 `c63484f0…1780` ✓ (this phase §15) |
| Zeek telemetry + detections (Phase 2 offline run) | `…/zeek-run/{conn,dns,http,files,notice,phase2_detections}.log` | prior manifests + re-read |
| Zeek detection sources | `detections/zeek/det-201/202/203…zeek` | hashed this phase |
| Suricata combined run (Phase 4D) | `evidence/phase4d-combined/replay-combined/out-phase2/eve.json|fast.log|stats.log` | 4D manifest re-verified (83 OK) |
| Suricata custom-only run (Phase 4B) | `evidence/phase4b-suricata-install/analysis/custom-rules-summary.json` | 4B manifest re-verified (114 OK) |
| Custom rules | `detections/suricata/soc003-lab.rules` (sids 9003001–3) | hash unchanged |
| Phase 2 ground truth | `PHASE2_REPORT.md` (§4/§7/§6), generator source, `analysis/ATTACK_ASSESSMENT.md` | read + cross-checked |
| Context (referenced, not re-measured) | 4C checksum analysis, 4D scan-silence + tuning artifacts | 4D manifest re-verified |

## 3. Investigation methodology

1. Read prior reports/evidence; verify input hashes.
2. Extract selected records from both engines onto one timeline
   (`scripts/phase5_build.py`; deterministic extraction from existing logs —
   63 Zeek records, 4 Suricata alert records, 8 cross-run alert rows).
3. Correlate on 5-tuple + timestamps + protocol + application
   characteristics; state counting-semantics differences explicitly.
4. Investigate each behaviour (what each engine saw / did not see).
5. Joint ATT&CK assessment preserving Phase 2 statuses verbatim.
6. Gap analysis from observed evidence only; integrity sweep; case packaging.

## 4. Activity reconstruction (all three controlled behaviours)

`evidence/phase5-joint-investigation/normalized-timeline.md` (T0 =
2026-10-16T07:00:00Z, 215 packets):

| Behaviour | Time (rel) | Actor → target | Detail | Packets/events |
| --- | --- | --- | --- | --- |
| A — controlled network service discovery | T+120.000–125.700 | `192.168.56.150` → 4 TEST-NET hosts × ports 22/80/443/445/3389 | 20 zero-payload TCP SYNs; conn states S0×16 / RSTO×2 / REJ×2 | 20 conn/flow records |
| B — DNS burst | T+200.000–209.570 | `192.168.56.151` → `192.168.56.53:53` | 30 unique names `c001…c030.lab.test`, 0.33 s cadence, NOERROR×15 / NXDOMAIN×15 | 30 dns transactions |
| C — periodic HTTP | T+300.023–450.069 | `192.168.56.152` → `203.0.113.30:80` | 6 GETs `/api/v1/heartbeat?id=1000…1005` (`Host: updates.lab.test`, UA `soc-lab-synthetic-agent/2.0`), exactly 30.000 s apart, all 200 OK, JSON heartbeat body | 6 http transactions |
| A-control (in-PCAP benign) | T+0.100–95.800 | `192.168.56.101` | 4 HTTP, 5 DNS NXDOMAIN, 1 plain TCP, 3 benign SYNs | 13 conn, 5 dns, 4 http records |

Every field above is present in the captured data; none invented.

## 5. Zeek findings

* **3 detections, one per behaviour** (notice.log + `phase2_detections.log`,
  full record content in `zeek-selected-records.jsonl`):
  * **DET-201** (A): evidence window T+120.000→122.700 — 10 failed probes,
    2 hosts, 5 ports, 2.700 s. Notice logged at network_time T+200.000 (the
    10th lazy `connection_state_remove`, clock-advanced by the first post-gap
    packet — behaviour documented in the detection source). Gate: ≥10 fails,
    ≥5 ports, ≥2 hosts, 60 s.
  * **DET-202** (B): crossed at the **20th unique name** (`c020.lab.test`),
    notice ts = T+206.270 — the earliest instant a 20-unique-name/30 s gate can
    be satisfied. Reproducible (Phase 2 §6: notice + detection logs
    byte-identical across independent replays).
  * **DET-203** (C): crossed at the **5th request** (4 intervals, mean
    30.000 s, CV 0.0000), ts = T+420.023.
* **Telemetry:** 69 conn records (TCP 34 / UDP 35), 35 dns records, 10 http
  records, 10 files records; benign block A fully logged with zero findings.
* **What Zeek did not produce:** no vendor/intel findings, no payload
  attribution beyond its logs, no alert duplication (one notice per behaviour).

## 6. Suricata findings

* **Custom layer — 4 alerts combined (2+1+1), volumes identical to the 4B
  custom-only run**:
  | sid | behaviour | alerts (volume) | gate | matches |
  | --- | --- | --- | --- | --- |
  | 9003001 | A | **2** | count 10 / 60 s | 20 |
  | 9003002 | B | **1** | count 20 / 60 s | 30 |
  | 9003003 | C | **1** | count 4 / 300 s | 6 |
* **Managed ET Open layer: 0 alerts** on this PCAP; **anomaly layer: 0** —
  consistent with Phase 4C/4D (anomaly rules respond to packet-validity, not
  behaviour).
* **Telemetry:** 69 flow events (TCP 34 / UDP 35), 70 dns events (30 burst
  query-direction + 30 burst response-direction + 10 benign = 60+10; 35
  transactions ≡), 10 http events, 10 fileinfo events.
* **What Suricata did not produce:** exact crossing-event timestamps for
  thresholded rules — the attributed packet varies run-to-run (measured,
  `alert-crossrun-comparison.json`: 9003001 attributed to probes #18/#20 in
  4B vs #7/#18 in 4D; 9003002 query #23 vs query #5; 9003003 request #2 vs
  #5) — while the total per-run volume is stable.

## 7. Cross-tool correlation

Full table: `evidence/phase5-joint-investigation/correlation-table.md` (+ JSON).
**All three behaviours correlate** across both engines on the same source,
destinations, ports, protocol, cadence and content characteristics of the same
packets.

**Counting/attribution differences, explicitly (no 1:1 event requirement):**

1. **Telemetry granularity:** conn/flow 69 ≡ 69 (TCP 34/UDP 35 both);
   http 10 ≡ 10; files 10 ≡ 10; dns: 35 Zeek transaction-records vs 70
   Suricata packet-level events (query + response). Different models, same data.
2. **Detection units:** Zeek = once-per-window notice (3 total); Suricata =
   threshold sampler with volume floor(matches÷count) = 2/1/1 (4 total). Both
   are correct in their own units.
3. **Timestamps:** Zeek stream-order crossings are exact and reproducible;
   Zeek's removal-based DET-201 window uses connection start times (exact);
   Suricata threshold attribution under multi-threaded replay is
   non-reproducible (measured twice — 4B and 4D). **Timeline of record =
   Zeek**; Suricata alert timestamps are treated as bookkeeping artefacts.
   Example: the earliest instantaneous state that satisfies 9003002's count-20
   gate is query #20 (T+206.270), yet in the 4D run the alert packet is query
   #5 (T+201.320) — impossible as an event time, correct as an alert volume of
   floor(30/20)=1.
4. **Exact anchor point:** behaviour C in the 4D replay: both engines
   anchored to the **same 5th request** (Zeek T+420.023 vs Suricata
   T+420.047, 24 ms).

## 8. Behaviour-by-behaviour investigation

Condensed here; full narrative in `cases/CASE-501-joint-network-investigation.md` §9:

| | DET-201 / 9003001 | DET-202 / 9003002 | DET-203 / 9003003 |
| --- | --- | --- | --- |
| **What happened** | 20 failed TCP probes, 4 hosts × 5 ports, 5.7 s | 30 unique sequential DNS names in 9.57 s | 6 HTTP GETs, exact 30.000 s cadence, 10 s of clock over 450 s |
| **What Zeek saw** | full conn-level picture incl. per-probe states; crossed at probe #10 | per-transaction DNS incl. rcodes/answers; crossed at 20th unique name | per-request HTTP incl. UA/host/uri/status; crossed at request #5 on CV 0.0000 |
| **What Suricata saw** | same 20 flows (1:1 with conn.log), 2 sampler alerts | 60 dns events (30 queries ≡ Zeek's names), 1 alert | 6 http events, 1 alert anchored (4D) to the same 5th request |
| **What each did NOT see** | intent/tool identity (none exists); ET Open: still 0 on the same packets | root resolver trust, tunnelling proof (none exists) | C2 tasking/pivot (none exists) |
| **Justified conclusion** | network-service-discovery behaviour on the wire — **T1046 validated**, dual-engine | high-volume unique-name DNS burst — both detected; C2/DGA not supported; recon candidate | periodic/beacon-like HTTP — both detected; periodicity alone → candidate only |

## 9. ATT&CK assessment (joint; statuses preserved, none broadened)

`evidence/phase5-joint-investigation/attck-joint-assessment.md` keeps Phase 2
`analysis/ATTACK_ASSESSMENT.md` as authoritative. Joint-status table:

* **CONFIRMED / VALIDATED:** `T1046 Network Service Discovery` (TA0007) —
  evidence *is* the technique's behaviour, this capture only. Phase 5 adds
  dual-engine detection agreement; it does **not** widen the claim.
* **CANDIDATE:** `T1590.002` (TA0043, DNS burst),
  `T1071.001` + `T1102` (TA0011, periodic HTTP) — insufficient evidence for
  validated mapping; original reasons preserved.
* **NOT SUPPORTED:** `T1071.004`, `T1568.002` (TA0011) — no C2 indicators in
  either engine's telemetry.
* Benign block A: no technique.
* **Not promoted by dual-engine agreement anywhere.** C2, exfiltration,
  compromise, persistence, lateral movement, malware execution, credential
  access: unclaimed.

## 10. Detection coverage (evidence from this phase only)

| Layer | A (scan) | B (DNS burst) | C (periodic HTTP) | Benign control |
| --- | --- | --- | --- | --- |
| Zeek behavioural detections | ✅ DET-201 | ✅ DET-202 | ✅ DET-203 | correct silence |
| Suricata custom | ✅ 9003001 ×2 | ✅ 9003002 | ✅ 9003003 | correct silence |
| Suricata managed ET Open | ✗ (diagnosed: inbound-oriented rules; Phase 4D) | ✗ (undifferentiated silence) | ✗ (undifferentiated silence) | correct silence |
| Suricata anomaly rules | ✗ (by design) | ✗ | ✗ | correct silence |

3 of 3 behaviours detected by both local engines; vendor/anomaly contribution
on this PCAP: none (measured result, phase-scoped).

## 11. Detection gaps (`evidence/phase5-joint-investigation/detection-gap-analysis.md`)

1. **Detected by both:** 3/3 behaviours.
2. **Zeek only / Suricata only:** none.
3. **Telemetry visible, no detection:** all three behaviours in the ET Open
   vendor layer and the anomaly layer (measured 0 + 0); benign block A
   correctly generates telemetry without detection.
4. **Not represented in either layer:** none of the exercised behaviours.
5. **Instrumentation gaps (properties, not behaviours):** Suricata threshold
   attribution non-reproducibility; alert-volume duplication (behaviour A
   yields 2 alerts for 1 behaviour); Zeek notice timestamp for removal-based
   detections lags its evidence window (lazy removal, source-documented).
6. Vendor silence for B and C is **not diagnosed per-rule** (recorded as
   observed-silent only) — no manufactured gap and no vendor-coverage claim in
   either direction.

## 12. False-positive/noise observations

* **0 FP** from Zeek (3/3 exact, controls silent) and **0 FP** from Suricata
  custom and ET Open on blocks A–D including in-PCAP benign controls.
* Noise properties observed: sampler duplication (2 alerts for behaviour A);
  attributed-packet variability; DET-201 notice-at-removal-time artefact —
  all explained with references; none alter conclusions.
* Cross-capture context (referenced from 4C/4D, not re-measured): benign guest
  capture checksum anomaly = 544 alerts (expected collection noise; optional
  lab-only rate-limit artifact 544→3, not deployed).

## 13. Analyst conclusion

The joint lens validated cleanly: on one capture, two independent engines —
different architectures, different rule systems — produced mutually
consistent, fully-correlated findings for all three controlled simulated
behaviours, agreed on entity/port/protocol/cadence, and stayed silent on
controls. Telemetry stacks agree 1:1 wherever modelling granularity matches;
every counting difference was measured and explained rather than assumed.
The conservative ATT&CK reading stands: T1046 validated (dual-engine), C2
mappings unsupported, shape-only candidates unpromoted. This is a controlled
lab result; no real-world compromise existed or is claimed.

## 14. Limitations

1. One 215-packet deterministic capture; richness of behaviour is by design.
2. Suricata observations are offline-replay semantics (multi-threaded
   thresholding); live behaviour was deliberately not tested (prohibited).
3. ET Open is a time-bound snapshot (2026-10-17 02:10 +0300); silence on B/C
   was not diagnosed per-rule (out of optional scope); silence on A was
   diagnosed in Phase 4D for this snapshot.
4. `9003002`'s content anchor (`lab.test`) is lab-scoped by design.
5. No host/user/process evidence existed; scope is network-only, IPv4-only.
6. Cross-run Suricata comparison is between two hand-run replays (4B, 4D) —
   statistically small; attribution *variability* is evidenced, its exact
   mechanism (worker races) is not instrumented.

## 15. Integrity verification (`evidence/phase5-joint-investigation/INTEGRITY_VERIFICATION.txt`)

* Input PCAP re-verified: `c63484f0…1780` ✓.
* **510 manifest entries, 0 failures** across **all** prior phases
  (Phase 1 + zeek-output, Phase 2, Phase 3, 3B, 3C, 3D, 4B 114, 4C 114,
  4D 83 self-check) — Phase 5 regenerated nothing inside them.
* Config/managed-set hashes unchanged (`suricata.yaml` `6b5fd573…`,
  `suricata.rules` `1988785c…`); `dpkg -V` clean; service
  **inactive/disabled**, 0 processes.
* Zeek 9.0.0 untouched; SOC-001 (0 modified), SOC-002-PUBLIC (git clean,
  HEAD `ba479eb` 2026-10-15, no new commits), SOC-002-windows-ad (0).
* Phase 5 artifacts hashed: `evidence/phase5-joint-investigation/SHA256SUMS.txt`
  (9 derived files; self-verified 9/9 OK).
* Write claim: scoped to the checks above **only** — no system-wide
  zero-write claim is made (per instruction), and the case/report/manifest
  files were created as documented deliverables.

## 16. Explicit non-claims

* No actual compromise, no real C2, no beacon adjudication beyond lab shape.
* No generic network-scan, DNS-burst or beaconing detection capability for any
  layer; each finding is three lab rules matched to three synthetic shapes.
* No production detection effectiveness; no threat-intelligence
  effectiveness; no comprehensive ET Open coverage (nor its absence).
* No live capture, inline/IPS, or deployment behaviour of any engine.
* No promotion/broadening of any ATT&CK mapping; no zero-system-wide-write
  claim. Sole human authorship preserved — no AI/agent attribution.

## 17. Final status

**PHASE 5 STATUS: PASS** — the joint Zeek + Suricata investigation
successfully reconstructed all three controlled behaviours with
evidence-backed correlation (3/3 detected by both; telemetry 1:1 where
granularities match; all counting differences explained), produced a complete
case package (CASE-501), a joint ATT&CK assessment that preserved every
Phase 2 status distinction, and an observed-only gap analysis; integrity of
all prior work re-verified with zero failures.

**Exact numbers:** behaviours reconstructed 3/3 (plus 1 benign control);
Zeek notices 3; Suricata custom alerts 4 (2/1/1); ET Open 0; anomaly 0;
false positives 0; manifest entries verified 510 (0 failures); Phase 5
evidence hashes 9/9.

## 18. Recommended next phase

None started — **STOP after Phase 5, per scope.** Phase 6 has not been
defined. Candidate future directions (operator's decision, none begun):
(a) settings-level analysis of SOC-001/Zeek ⇄ SOC-002 endpoint evidence
joining (requires VM tools and new captured data — operator approval +
defined scope required), (b) coverage extension of the lab rule set to new
deterministic shapes, (c) report consolidation/handover documentation. No
live-capture, IPS/inline or production work is recommended without an
explicit operator-approved plan and risk review.
