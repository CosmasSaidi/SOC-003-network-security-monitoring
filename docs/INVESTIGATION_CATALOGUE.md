# SOC-003 — Investigation Catalogue

This catalogue documents investigations and cases completed in SOC-003.

## INV-201 — Network Service Discovery Investigation

- **ID:** INV-201
- **Title:** Network Service Discovery Investigation
- **Location:** `investigations/INV-201-network-service-discovery.md`
- **Purpose:** Detailed investigation of DET-201 behaviour (controlled scan)
- **Demonstrates:** Telemetry extraction, threshold validation, evidence linking, timeline reconstruction
- **Key elements:** Conn log analysis, detection rationale, evidence artifacts, limitations
- **Relationship to case:** Feeds into CASE-201

## CASE-201 — Network Service Discovery Case

- **ID:** CASE-201
- **Title:** CASE-201 — Network Service Discovery (DET-201)
- **Location:** `cases/CASE-201-network-service-discovery.md`
- **Purpose:** Formal SOC-style case documentation for the validated T1046 behaviour
- **Demonstrates:** Case structure (summary, evidence, timeline, findings, ATT&CK mapping, conclusion)
- **ATT&CK:** T1046 validated for this capture
- **Relationship to Phase 2:** Primary case from Phase 2 work

## CASE-501 — Joint Zeek + Suricata Investigation

- **ID:** CASE-501
- **Title:** CASE-501 — Joint Zeek + Suricata Network Investigation
- **Location:** `cases/CASE-501-joint-network-investigation.md`
- **Purpose:** Correlate both engines on same PCAP; document counting semantics, attribution differences, joint findings
- **Demonstrates:**
  - Cross-engine correlation (conn/flow agreement, DNS granularity differences)
  - Threshold sampling semantics (alert volume vs event counts, run-to-run attribution)
  - Canonical timing (Zeek timestamps treated as authoritative for event timing)
  - Joint ATT&CK assessment preserving validated/candidate/not-supported distinctions
  - Gap analysis (vendor layer silence on controlled behaviours)
- **Key distinction:** Detection vs investigation vs case documentation vs ATT&CK assessment are explicitly preserved
- **ATT&CK:** T1046 validated (dual-engine confirmation); candidates/not-supported preserved from Phase 2
