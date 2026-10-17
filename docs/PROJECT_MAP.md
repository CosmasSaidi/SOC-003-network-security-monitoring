# SOC-003 — Project Map (Completed through Phase 5)

This document maps each completed phase to its objective, major work, primary evidence, result, and important limitations.

## Phase 1 — Zeek Baseline

- **Phase number:** 1
- **Objective:** Establish Zeek baseline and verify sensor visibility using synthetic PCAPs.
- **Major work:**
  - PCAP generation and validation
  - Zeek installation/verification
  - Offline replay through Zeek
  - Baseline telemetry capture
- **Primary evidence:** `evidence/phase1-zeek-baseline/` (PCAP, Zeek logs, verification artifacts, SHA256SUMS)
- **Result:** PASS
- **Important limitation:** Baseline established using synthetic traffic, not live lab traffic. No Suricata involved.

## Phase 1.1 — Zeek Installation Route Validation

- **Phase number:** 1.1
- **Objective:** Validate safe installation route for Zeek 9.0.0.
- **Major work:** Installation path validation, pre-install state capture, verification.
- **Primary evidence:** `PHASE1_1_INSTALL_ROUTE_REPORT.md`, `evidence/phase1-zeek-baseline/`
- **Result:** PASS
- **Important limitation:** Read-only validation; no system changes beyond recorded state.

## Phase 1.2 — Zeek Installation & Offline Replay

- **Phase number:** 1.2
- **Objective:** Install Zeek 9.0.0 and validate with offline PCAP replay.
- **Major work:** Zeek installation, replay validation, telemetry verification.
- **Primary evidence:** `PHASE1_2_REPORT.md`, `evidence/phase1-zeek-baseline/zeek-output/`
- **Result:** PASS
- **Important limitation:** Offline-only; no live capture.

## Phase 2 — Controlled Network Detection Engineering

- **Phase number:** 2
- **Objective:** Design, implement, and validate three Zeek behavioural detections against controlled synthetic traffic.
- **Major work:**
  - Developed DET-201 (network service discovery), DET-202 (DNS burst), DET-203 (periodic HTTP)
  - Generated controlled PCAP with three behaviours + benign control
  - Validated detections (3/3 true positives, 0 false positives)
  - Investigation (INV-201) and case (CASE-201) documentation
  - Conservative ATT&CK assessment
- **Primary evidence:** `evidence/phase2-controlled-network-behaviour/` (PCAP, Zeek logs, detections, manifests, SHA256SUMS), `PHASE2_REPORT.md`, `detections/zeek/`, `cases/CASE-201-network-service-discovery.md`
- **Result:** PASS
- **Important limitation:** Synthetic PCAP only; behaviours parameterised for lab validation. No C2 established. Suricata not installed.

## Phase 3 — Live Lab Validation (Preflight/Gate)

- **Phase number:** 3
- **Objective:** Validate Zeek detections against genuine benign lab traffic on `vboxnet0`.
- **Major work:** Bounded live captures, verification of sensor visibility, replay through Zeek with unmodified detections.
- **Primary evidence:** `PHASE3_REPORT.md`, `PHASE3_PREFLIGHT_REPORT.md`, `evidence/phase3-live-benign/` (as referenced), associated manifests.
- **Result:** PARTIAL/BLOCKED (visibility constraint determined). No WS001↔DC1 unicast observed from host capture point.
- **Important limitation:** Host-side `vboxnet0` capture could not observe guest-to-guest unicast frames; only broadcasts and host-involved traffic were visible.

## Phase 3B — Benign AD/DNS Validation

- **Phase number:** 3B
- **Objective:** Attempt live benign AD/DNS validation from host sensor position.
- **Major work:** Live benign capture attempts, analysis of captured traffic, verification of detection behaviour.
- **Primary evidence:** `PHASE3B_REPORT.md`, `evidence/phase3b-benign-ad-validation/`
- **Result:** PARTIAL/BLOCKED (intermediate capture attempt; subsequent resolution via 3C/3D).
- **Important limitation:** The initial host-side capture path did **not** provide expected guest-to-guest unicast visibility. This limitation was diagnosed and resolved later (Phase 3C/3D). It should not be mischaracterised as an independent final failure.

## Phase 3C — Capture-Path Diagnosis

- **Phase number:** 3C
- **Objective:** Diagnose why WS001↔DC1 unicast was not visible from host-side `vboxnet0` capture.
- **Major work:** Read-only inspection (WS001/DC1 states), 9 bounded captures with promiscuous mode verified, correlation with WEF activity, conclusive root-cause determination.
- **Primary evidence:** `PHASE3C_PREFLIGHT_REPORT.md`, `evidence/phase3c-preflight/` (9 PCAPs, WS001/DC1 state, Kali state, manifests)
- **Result:** PASS (diagnosis complete). Goal of capturing WS001↔DC1 from host position BLOCKED by structural VirtualBox host-only behaviour.
- **Important limitation:** On VirtualBox host-only `vboxnet0`, guest↔guest unicast frames are not delivered to the host interface; host-involved + broadcast/multicast only. No configuration changes made (read-only).

## Phase 3D — Guest-Side Live Capture Validation

- **Phase number:** 3D
- **Objective:** Prove WS001↔DC1 unicast traffic can be captured from guest side (WS001 pktmon) and replayed through Zeek.
- **Major work:** WS001 pktmon capture (712 packets, 0 drops, filtered to WS001↔DC1), ETL→pcapng conversion, offline Zeek replay, temporal correlation (clock offset −1.83s), integrity verification.
- **Primary evidence:** `PHASE3D_REPORT.md`, `evidence/phase3d-guest-capture/` (pcapng, ETL, Zeek logs, manifests)
- **Result:** PASS
- **Important limitation:** Guest-side capture changes capture point (architecture awareness required). Detections (DET-201/202/203) not exercised by this benign live traffic; no detection tuning. Checksum-offload artefacts observed (benign).

## Phase 4A — Suricata Installation Route

- **Phase number:** 4A
- **Objective:** Read-only reconnaissance for safe Suricata installation route on Kali 2025.4.
- **Major work:** Package state verification, repo candidate identification (Suricata 1:8.0.7-1), reachability checks, documented safe route.
- **Primary evidence:** `PHASE4A_INSTALL_ROUTE_REPORT.md`
- **Result:** PASS
- **Important limitation:** Read-only; no installation performed. No vendor ruleset present.

## Phase 4B — Suricata Installation + Custom Detection

- **Phase number:** 4B
- **Objective:** Install Suricata 8.0.7 and validate custom lab rules against Phase 2 PCAP (offline).
- **Major work:** Installation validation, config validation, offline replay with custom rules (SID 9003001–9003003), negative controls, telemetry comparison with Zeek.
- **Primary evidence:** `PHASE4B_REPORT.md`, `detections/suricata/soc003-lab.rules`, `evidence/phase4b-suricata-install/`
- **Result:** PASS (installation + custom validation). Vendor stock rules blocked by absent ruleset (documented).
- **Important limitation:** Offline-only (no `-i`, no service start). Custom rules are lab-scoped and deterministic; not generalised.

## Phase 4C — Managed ET Open Ruleset Replay

- **Phase number:** 4C
- **Objective:** Acquire managed ET Open ruleset via `suricata-update` and replay against evidence.
- **Major work:** Read-only recon, controlled acquisition (ET Open for Suricata 8.0.7), replay against Phase 2 PCAP and controls, checksum-anomaly diagnosis, comparison with custom-only baseline.
- **Primary evidence:** `PHASE4C_RECON_REPORT.md`, `PHASE4C_REPORT.md`, `evidence/phase4c-ruleset/`
- **Result:** PASS
- **Important limitation:** ET Open produced 0 alerts on Phase 2 behaviours (measured). Checksum anomalies observed only on guest-capture control (benign, due to VirtualBox offload). No IPS/live deployment.

## Phase 4D — Combined Ruleset + Anomaly Tuning

- **Phase number:** 4D
- **Objective:** Replay combined (ET Open + custom + anomaly) and make conservative tuning decision.
- **Major work:** Combined replay validation (53214 loaded rules), negative controls, anomaly investigation, prepared opt-in lab-only threshold config (`soc003-lab-anomaly-thresholds.conf`), documented scan-silence findings.
- **Primary evidence:** `PHASE4D_REPORT.md`, `detections/suricata/soc003-lab-anomaly-thresholds.conf`, `detections/suricata/TUNING.md`, `evidence/phase4d-combined/`
- **Result:** PASS
- **Important limitation:** Vendor ruleset silent on controlled behaviours (32/33 TCP scan-classification rules inbound-oriented relative to $EXTERNAL_NET→$HOME_NET; remaining outbound rule required higher threshold than controlled probes). This is evidence-scoped, not a general claim about ET Open.

## Phase 5 — Joint Zeek + Suricata Investigation

- **Phase number:** 5
- **Objective:** Correlate Zeek and Suricata findings on same PCAP, package as CASE-501 with joint ATT&CK assessment and gaps.
- **Major work:** Normalised timeline, cross-engine correlation (accounting for threshold attribution semantics), joint ATT&CK (preserving validated/candidate/not-supported), gap analysis, case packaging.
- **Primary evidence:** `PHASE5_REPORT.md`, `cases/CASE-501-joint-network-investigation.md`, `evidence/phase5-joint-investigation/`
- **Result:** PASS
- **Important limitation:** Suricata threshold alert attribution varies between replay runs (measured 4B vs 4D); Zeek timestamps are treated as canonical for event timing. No new detections created.
