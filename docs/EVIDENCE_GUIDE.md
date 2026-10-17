# SOC-003 — Evidence Guide

Guide for locating evidence; do not duplicate large files.

## Phase Reports
- `PHASE0_2_REPORT.md`, `PHASE1_REPORT.md`, `PHASE1_1_INSTALL_ROUTE_REPORT.md`, `PHASE1_2_REPORT.md`
- `PHASE2_REPORT.md`
- `PHASE3_PREFLIGHT_REPORT.md`, `PHASE3_REPORT.md`, `PHASE3B_REPORT.md`, `PHASE3C_PREFLIGHT_REPORT.md`, `PHASE3D_REPORT.md`
- `PHASE4A_INSTALL_ROUTE_REPORT.md`, `PHASE4B_REPORT.md`, `PHASE4C_RECON_REPORT.md`, `PHASE4C_REPORT.md`, `PHASE4D_REPORT.md`
- `PHASE5_REPORT.md`

## Architecture
- `architecture/ARCHITECTURE.md`

## PCAPs
- Phase 1 baseline: `evidence/phase1-zeek-baseline/phase1-synthetic-baseline.pcap`
- Phase 2 controlled: `evidence/phase2-controlled-network-behaviour/phase2-controlled-network-behaviour.pcap` (primary PCAP, SHA256 verified)
- Phase 3C: `evidence/phase3c-preflight/captures/*.pcap` (9 captures)
- Phase 3D: `evidence/phase3d-guest-capture/ws001/ws001-dc1-guest-capture.pcapng`

## Zeek Logs
- Phase 1: `evidence/phase1-zeek-baseline/zeek-output/{conn,dns,http,files,packet_filter}.log`
- Phase 2: `evidence/phase2-controlled-network-behaviour/zeek-run/{conn,dns,http,files,notice,phase2_detections}.log`
- Phase 3D: `evidence/phase3d-guest-capture/zeek-run/base/` and `with-detections/`

## Zeek Detections
- Source: `detections/zeek/det-201-service-discovery.zeek`, `det-202-dns-burst.zeek`, `det-203-periodic-http.zeek`, `det-common.zeek`, `phase2-load.zeek`
- Detection records (Phase 2): `evidence/phase2-controlled-network-behaviour/detections/detection-records.ndjson`

## Suricata Detections & Rules
- Custom rules: `detections/suricata/soc003-lab.rules` (SID 9003001–9003003)
- Tuning: `detections/suricata/soc003-lab-anomaly-thresholds.conf`, `detections/suricata/TUNING.md`
- Readmes: `detections/suricata/README.md`, `detections/README.md`

## Suricata Evidence
- Phase 4B: `evidence/phase4b-suricata-install/`
- Phase 4C: `evidence/phase4c-ruleset/`
- Phase 4D: `evidence/phase4d-combined/replay-combined/out-phase2/` (EVE/fast/stats)
- Phase 5: `evidence/phase5-joint-investigation/suricata-selected-eve.jsonl`, `alert-crossrun-comparison.json`

## Investigations, Cases, ATT&CK
- Investigations: `investigations/INV-201-network-service-discovery.md`
- Cases: `cases/CASE-201-network-service-discovery.md`, `cases/CASE-501-joint-network-investigation.md`
- ATT&CK assessments: `analysis/ATTACK_ASSESSMENT.md`, `evidence/phase5-joint-investigation/attck-joint-assessment.md`

## Tuning & Analysis
- `detections/suricata/TUNING.md`, `detections/suricata/README.md`
- Phase 5 correlation: `evidence/phase5-joint-investigation/correlation-table.md`, `normalized-timeline.md`, `detection-gap-analysis.md`

## Integrity Manifests
- Phase 1: `evidence/phase1-zeek-baseline/SHA256SUMS.txt`, `evidence/phase1-zeek-baseline/zeek-output/SHA256SUMS.txt`
- Phase 2: `evidence/phase2-controlled-network-behaviour/hashes/SHA256SUMS.txt`, `manifest.json`
- Phase 3B: `evidence/phase3b-benign-ad-validation/hashes/SHA256SUMS.txt`
- Phase 3C: `evidence/phase3c-preflight/captures/SHA256SUMS.txt`
- Phase 3D: `evidence/phase3d-guest-capture/SHA256SUMS.txt`
- Phase 4B: manifests under `evidence/phase4b-suricata-install/`
- Phase 4C/4D: manifests under respective evidence dirs
- Phase 5: `evidence/phase5-joint-investigation/SHA256SUMS.txt`
- Consolidation: `evidence/consolidation/` (to be populated/updated)
