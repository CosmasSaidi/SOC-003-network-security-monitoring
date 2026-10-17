# SOC-003 — CONSOLIDATION & HANDOVER

## 1. Project Identity

- **Project:** SOC-003 — Network Security Monitoring & Investigation
- **Status:** Technical investigation and validation complete through **Phase 5**
- **Lab scope:** Isolated VirtualBox host-only network `vboxnet0` / `192.168.56.0/24`
- **Sensor:** Kali GNU/Linux Rolling 2025.4 (Zeek 9.0.0, Suricata 8.0.7)
- **Windows lab:** DC1 `192.168.56.10`, WS001 `192.168.56.102` (unchanged)
- **Author:** Sole human author (user). No AI-agent/bot/co-author attribution.

## 2. Final Architecture

- **Topology:** Host-only isolated segment; no third VM; no Wi-Fi bridge; no routing/NAT changes
- **Capture model:** Host-side `vboxnet0` for host-involved/broadcast; **guest-side pktmon (WS001)** required for validated WS001↔DC1 unicast (structural VirtualBox limitation)
- **Telemetry:** Zeek (conn/dns/http/files/notice/phase2_detections) — structured network telemetry
- **Detection:** Suricata (passive IDS only). Custom lab rules SID 9003001–9003003 + managed ET Open (53,211 enabled, snapshot 2026-10-17 02:10 +0300) + Suricata-provided decoder/anomaly rules. **No IPS/inline mode; suricata.service never started.**
- **Safety:** Offline PCAP replay for Suricata validation; bounded captures; `wlan0` explicitly out of scope

Key points (evidence-scoped):
- Guest↔guest unicast not visible from host `vboxnet0` (Phase 3C); resolved via guest-side capture (Phase 3D)
- Checksum-offload artefacts observed on guest capture (benign; opt-in lab-only threshold config prepared, not deployed)

## 3. Completed Phases

1.0.2, 1, 1.1, 1.2 (Zeek baseline) — PASS
2 (Controlled detection engineering: DET-201/202/203, INV-201, CASE-201) — PASS
3 (Live validation preflight) — PARTIAL/BLOCKED (visibility constraint identified)
3B (Benign AD/DNS validation attempt) — PARTIAL/BLOCKED (resolved via 3C/3D)
3C (Capture-path diagnosis) — PASS (root cause determined; host capture of WS001↔DC1 blocked)
3D (Guest-side capture validation) — PASS
4A (Suricata install route recon) — PASS
4B (Suricata install + custom rules validation) — PASS
4C (Managed ET Open acquisition/replay) — PASS
4D (Combined + anomaly tuning decision) — PASS
5 (Joint Zeek+Suricata investigation, CASE-501) — PASS

Technical investigation complete through Phase 5.

## 4. Detection Catalogue

### Zeek
- **DET-201** (network service discovery): 60s window, ≥10 failed attempts, ≥5 ports, ≥2 hosts. Validated true positive (fired at 10th probe). ATT&CK **T1046 VALIDATED** (this capture).
- **DET-202** (DNS burst): ≥20 unique qnames in 60s. Validated true positive (crossed at 20th unique). ATT&CK candidates only; **T1071.004/T1568.002 NOT SUPPORTED**.
- **DET-203** (periodic HTTP): ≥5 requests to `/api/v1/heartbeat` in 300s, tracks periodicity. Validated true positive; ATT&CK candidates only (periodicity alone insufficient for C2).

### Suricata (custom, lab-scoped)
- **SID 9003001** (scan analogue): threshold count 10/60s on TCP SYN to specific ports (dsize:0). Volume-stable (2 alerts for 20 probes); **threshold sampling semantics** — alert counts != event counts; attribution varies between replay runs.
- **SID 9003002** (DNS burst analogue): threshold count 20/60s on DNS queries with `lab.test`. Volume-stable (1 alert for 30 queries); attribution varies between replay runs; content lab-anchored.
- **SID 9003003** (periodic HTTP analogue): threshold count 4/300s on GET to `/api/v1/heartbeat`. Volume-stable (1 alert for 6 requests); attribution varies between replay runs.

Vendor/anomaly: ET Open silent on controlled behaviours (measured Phase 4C/4D); decoder checksum anomalies observed only on benign guest capture (Phase 3D) — benign, documented.

## 5. Investigation Catalogue
- **INV-201** (Phase 2): Investigation of DET-201 behaviour; feeds CASE-201
- **CASE-201** (Phase 2): Formal case for T1046-validated behaviour
- **CASE-501** (Phase 5): Joint Zeek+Suricata correlation with timeline, cross-engine semantics, joint ATT&CK, gaps

## 6. ATT&CK Summary
**VALIDATED:** T1046 (Network Service Discovery)
**CANDIDATE:** T1590.002 (DNS recon), T1071.001 (Web protocols), T1102 (Web service)
**NOT SUPPORTED:** T1071.004 (DNS C2), T1568.002 (DGA)

Dual-engine agreement validates detections; does not promote candidates. DNS burst alone ≠ DNS C2; periodic HTTP alone ≠ C2. No C2/exfil/persistence/lateral/malware/credential access claimed.

## 7. Major Findings
- All three controlled behaviours detected by both Zeek and Suricata custom rules (3/3 TP, 0 FP on measured controls)
- T1046 validated with dual-engine confirmation
- ET Open (53,211 enabled) produced 0 alerts on Phase 2 behaviours (evidence-scoped; directionality/thresholds diagnosed)
- Host `vboxnet0` cannot observe guest↔guest unicast (VirtualBox host-only) — resolved via guest-side pktmon
- Suricata threshold attribution non-deterministic across replay runs (volume stable) — Zeek timestamps canonical
- Checksum offload benign artefacts on guest capture (documented)

## 8. Known Limitations
- Synthetic PCAPs; single primary capture focus
- Lab-calibrated thresholds (not production-generalised)
- ET Open silence on these behaviours is evidence-scoped (do not over-generalise)
- Offline-only Suricata validation; no IPS/live deployment
- Guest-side capture changes architecture point
- Threshold semantics differ between engines (documented)

## 9. Evidence Structure
Primary locations: `evidence/phase{1,2,3b,3c,3d,4b,4c,4d,5}-*/`, `detections/{zeek,suricata}/`, `cases/`, `investigations/`, `analysis/`, `architecture/`, `docs/`. See `docs/EVIDENCE_GUIDE.md` for details. All manifests include SHA256.

## 10. Public-Safety Review
- Scanned public-facing docs for obvious secrets/keys/tokens; **none found** in README, docs/*.md, handover
- `/home/saidi` paths appear in internal evidence/commands (not public-facing documents) — public-facing consolidation docs use neutral/relative context where appropriate
- No credentials, API keys, or private network secrets exposed in consolidation documents
- Original evidence preserved; no blind mass deletion

## 11. Authorship Review
- No Claude/ChatGPT/OpenAI/Codex/Kilo/GLM/AI-agent/bot/co-author attribution present
- Sole human author (user). Git not initialized; no git config modified.

## 12. Git / Publication Readiness
**READY for Git initialization** (pending operator decision to commit/push). Criteria satisfied:
- Documentation complete (README updated, PROJECT_MAP, DETECTION_CATALOGUE, INVESTIGATION_CATALOGUE, ATTACK_SUMMARY, ARCHITECTURE reviewed, LIMITATIONS_AND_BLIND_SPOTS, EVIDENCE_GUIDE, handover)
- Evidence organized with manifests; integrity checks documented
- Public safety acceptable; no secrets in public-facing docs
- Authorship correct
- No broken internal references detected in created docs (relative paths used)
- No Phase 6 references; no unfinished work
- Structural consistency: Phase 3 progression (3B→3C→3D) accurately described
- All safety constraints honored

**DO NOT** initialize Git, commit, add remotes, push, or publish as part of this consolidation action.

## 13. Recommended Publication Sequence
1. Review handover + docs with operator
2. (Optional, operator decision) `git init` in `soc-003` (if desired) — **not performed here**
3. Stage appropriate files (exclude large transient artifacts as desired per repo policy)
4. Commit with clear message when explicitly requested
5. Add remote/push only if explicitly requested
6. Publish only if explicitly authorized
