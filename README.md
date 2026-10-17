# SOC-003 — Network Security Monitoring & Investigation

A controlled SOC lab project demonstrating network telemetry, behavioural detection, and cross-engine correlation using Zeek and Suricata.

**Technical investigation and validation are complete through Phase 5.**

## 1. Overview

SOC-003 extends prior Windows/AD telemetry work (SOC-002) by adding host-side network visibility and detection engineering. The project implements and validates conservative behavioural detections, documents evidence, and performs joint Zeek + Suricata investigation in an isolated VirtualBox host-only lab.

## 2. Objective

Create a clean, professional cybersecurity portfolio project that documents completed technical work (Phases 0–5), preserves evidence with integrity, and communicates findings and limitations without over-claiming capability.

## 3. Architecture

The lab operates on an isolated host-only segment (`vboxnet0`, `192.168.56.0/24`) with Kali as the NSM sensor and two Windows guests (DC1, WS001). Key architecture points:
- **Sensor (Kali):** Zeek 9.0.0 for network telemetry; Suricata 8.0.7 for passive IDS (offline validation; service never started)
- **Windows lab:** DC1 (`192.168.56.10`), WS001 (`192.168.56.102`)
- **Capture model:** Host-side `vboxnet0` for host-involved/broadcast traffic. Due to VirtualBox host-only semantics, guest↔guest unicast requires guest-side capture (WS001 pktmon) — documented and validated (Phase 3C/3D)
- **Safety:** No IPS/inline, no routing/NAT changes, `wlan0` excluded, bounded captures

See [architecture/ARCHITECTURE.md](architecture/ARCHITECTURE.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (consolidated view in handover/project docs).

## 4. Investigation Pipeline

1. **Generate/collect evidence** (PCAPs, Zeek/Suricata telemetry)
2. **Extract behavioural signals** from telemetry
3. **Apply conservative detection logic** (behavioural, not signature-heavy)
4. **Validate against controlled traffic** (true/false positive measurement)
5. **Correlate across engines** (accounting for semantics: threshold sampling, attribution, timing)
6. **Map to ATT&CK conservatively** (validated/candidate/not-supported)
7. **Document case/investigation with evidence links**

## 5. Technologies

- **Zeek 9.0.0** — network telemetry and behavioural detections
- **Suricata 8.0.7** — passive IDS (custom rules + managed ET Open snapshot)
- **tshark/capinfos/dumpcap** — packet analysis and validation
- **pktmon (Windows)** — guest-side capture for unicast validation
- **VirtualBox** — isolated lab environment

## 6. Detection Engineering

Detections focus on observable behavioural patterns under lab-calibrated thresholds. Thresholds are **evidence-scoped** (not production-calibrated). Key principles:
- Require breadth + fan-out (e.g. multi-port + multi-host) to reduce trivial triggers
- Prefer conservative ATT&CK mapping (promote only when evidence supports the named behaviour)
- Explicitly document threshold semantics and limitations
- No new detections created during consolidation

## 7. Zeek Detections

- **DET-201** — Network service discovery (multi-host/multi-port failed TCP probes). Window 60s, ≥10 attempts, ≥5 ports, ≥2 hosts. **T1046 validated** (this capture).
- **DET-202** — DNS burst (unique qnames). Window 60s, ≥20 unique names. **Candidate/recon** only; DNS C2/DGA **not supported** by evidence.
- **DET-203** — Periodic HTTP (heartbeat path). Window 300s, fires at ≥5th request; periodicity tracked (CV). **Candidate** only; periodicity alone does **not** establish C2.

## 8. Suricata Detections

Custom lab rules (SID 9003001–9003003), aligned conceptually to Zeek detections:

- **SID 9003001** — Network service discovery analogue (TCP SYN probes to lab port set; threshold count 10/60s). Produces volume-stable alerts (floor(matches/count)); alert attribution may vary between replay runs.
- **SID 9003002** — DNS burst analogue (DNS queries containing `lab.test`; threshold count 20/60s). Volume-stable; attribution may vary; content is lab-anchored.
- **SID 9003003** — Periodic HTTP analogue (GET to `/api/v1/heartbeat`; threshold count 4/300s). Volume-stable; attribution may vary.

**Threshold semantics (important):** Suricata threshold alert counts are **not** equivalent to event counts. The packet attributed to an alert can vary between replay runs (measured 4B vs 4D); volume (floor(matches/count)) is stable. Zeek notices are treated as canonical for event timing in joint correlation.

Managed ET Open ruleset (snapshot 2026-10-17 02:10 +0300, 53,211 enabled) was evaluated offline; it produced 0 alerts on the controlled Phase 2 behaviours (evidence-scoped finding; see limitations).

## 9. Controlled Behaviours

- **Behaviour A: Network Service Discovery** — 20 failed TCP SYN probes from single source to 4 hosts × 5 ports (~6s). Both engines detected; **T1046 validated**.
- **Behaviour B: DNS Burst** — 30 unique DNS lookups (`c001…c030.lab.test`) in ~9.57s. Both engines detected. No C2/DGA indicators (sequential numbering is generator artefact).
- **Behaviour C: Periodic HTTP** — 6 HTTP GETs to `/api/v1/heartbeat` at exactly 30.000s intervals (CV 0). Both engines detected. Periodicity alone does **not** establish C2.

**Benign control:** Included in Phase 2; 0 false positives from custom/behavioural detections on measured controls.

## 10. Joint Zeek + Suricata Investigation

Phase 5 correlated both engines on the same PCAP (CASE-501). Key findings:
- **Telemetry agreement:** conn/flow 1:1 where granularity matches; DNS granularity differs (Zeek transaction vs Suricata query+response events) — documented.
- **Detection consistency:** All three behaviours detected by both engines
- **Attribution semantics:** Suricata threshold attribution varies between replay runs (bookkeeping artefact); Zeek timestamps treated as canonical
- **No cross-engine contradiction:** Differences explained by engine models/semantics, not evidence

## 11. ATT&CK Mapping

- **VALIDATED:** `T1046` Network Service Discovery (TA0007)
- **CANDIDATE:** `T1590.002` (DNS recon, TA0043), `T1071.001` (Web protocols, TA0011), `T1102` (Web service, TA0011)
- **NOT SUPPORTED:** `T1071.004` (DNS C2, TA0011), `T1568.002` (DGA, TA0011)

Dual-engine agreement validates detections; it does **not** promote candidates. No C2/exfiltration/persistence/lateral movement/malware execution/credential access claimed.

## 12. Suricata Managed Ruleset Findings

- **Snapshot:** ET Open for Suricata 8.0.7 (2026-10-17 02:10 +0300), 69,171 rules total; 53,211 enabled
- **Result on Phase 2 behaviours:** **0 alerts** from managed ET Open ruleset (measured offline)
- **Diagnosis (evidence-scoped):** Of 33 enabled TCP scan-classification rules, 32 were inbound-oriented relative to `$EXTERNAL_NET → $HOME_NET` while the controlled scan was outbound (`$HOME_NET → ...`); the remaining relevant outbound rule required higher threshold than the controlled probes. This explains observed silence for this specific case — **do not** generalise to "ET Open cannot detect scans".
- **Anomaly layer:** Decoder checksum anomalies observed only on benign guest-side capture (VirtualBox offload) — benign, documented with opt-in lab-only threshold config available (not deployed)

## 13. Detection Tuning

- Custom rules are lab-calibrated and intentionally narrow
- Anomaly threshold tuning artifact prepared: `detections/suricata/soc003-lab-anomaly-thresholds.conf` (opt-in, lab-only) — demonstrated to reduce guest-capture noise from 544 to 3 without affecting custom detections; **not deployed system-wide**
- Tuning rationale and scope documented in `detections/suricata/TUNING.md`

## 14. Evidence & Integrity

All evidence is preserved with SHA256 manifests. Primary locations:
- Phase reports: `PHASE*.md` (16 reports covering phases 0.2–5)
- Evidence: `evidence/phase{1,2,3b,3c,3d,4b,4c,4d,5}-*/` with manifests
- Detections: `detections/{zeek,suricata}/`
- Cases/Investigations: `cases/`, `investigations/`
- Analysis/docs: `analysis/`, `architecture/`, `docs/`

Consolidation artifacts: `docs/*`, `SOC003_HANDOVER.md`, `evidence/consolidation/*`

Integrity verified across manifests (including Phase 4D and Phase 5). No existing evidence/configs/rulesets were modified during consolidation.

## 15. Key Findings

- **Cross-engine validation:** 3/3 controlled behaviours detected by both Zeek and Suricata custom rules with 0 FP on measured controls
- **Conservative mapping:** T1046 validated; DNS-C2/DGA and generic C2 claims explicitly not supported
- **Visibility constraint identified and resolved:** Host-side guest↔guest unicast limitation diagnosed (Phase 3C), guest-side capture validated (Phase 3D)
- **Engine semantics documented:** Threshold sampling, attribution variability, timing differences — essential for correct joint interpretation
- **ET Open behaviour characterised:** Evidence-scoped silence on these behaviours with documented rationale; not over-generalised

## 16. Limitations

- **Synthetic/controlled scope:** Behaviours parameterised for lab validation; single primary capture focus limits broad FP claims
- **Lab-calibrated:** Thresholds not production-generalised
- **Architecture-dependent:** Guest-side capture required for WS001↔DC1 unicast on this VirtualBox topology
- **Threshold attribution:** Suricata threshold alerts have non-deterministic attribution across replay runs (volume stable); use Zeek for canonical timing
- **ET Open snapshot-specific:** Findings reflect snapshot 2026-10-17 02:10 +0300; rules evolve
- **Offline-only Suricata:** No live deployment/IPS validation
- **No generic claims:** No broad scan/DNS-C2/C2 coverage claimed

## 17. Project Status

**COMPLETE through Phase 5.** Technical work, validation, correlation, and consolidation documentation are complete. No Phase 6 work initiated. Git initialization/publishing not performed (operator decision).

See [docs/PROJECT_MAP.md](docs/PROJECT_MAP.md) for phase-by-phase details and [SOC003_HANDOVER.md](SOC003_HANDOVER.md) for complete handover information.
