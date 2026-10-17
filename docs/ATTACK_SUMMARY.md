# SOC-003 — ATT&CK Summary

Conservative mapping preserving Phase 2 assessment. No candidate techniques were promoted to validated.

## VALIDATED
- **T1046 — Network Service Discovery** (TA0007)
  - Evidence: 20 failed TCP SYN attempts from single source across 4 hosts × 5 ports in ~6s; no application-layer follow-through
  - Validation: DET-201 (Zeek) + SID 9003001 (Suricata custom) both fired; dual-engine agreement confirms detection, not intent
  - Scope: Validated for this controlled capture only. Does not establish broader intrusion chain.

## CANDIDATE (insufficient evidence for validation)
- **T1590.002 — Gather Victim Network Information: DNS** (TA0043)
  - Evidence: 30 unique lookups `c001…c030.lab.test` in ~9.57s (DET-202/SID 9003002)
  - Rationale: Consistent with DNS reconnaissance, but no AXFR/zone walking/reverse lookups/subdomain brute-force dictionary evidence; uniqueness alone insufficient
- **T1071.001 — Application Layer Protocol: Web Protocols** (TA0011)
  - Evidence: 6 periodic GETs to `/api/v1/heartbeat` at exactly 30.000s (DET-203/SID 9003003), all 200 OK, benign JSON
  - Rationale: HTTP medium true, but C2 requires tasking/variation/pivot/implant evidence — not present
- **T1102 — Web Service** (TA0011)
  - Evidence: Same periodic HTTP behaviour
  - Rationale: Insufficient evidence of external web service used as C2 channel

## NOT SUPPORTED
- **T1071.004 — Application Layer Protocol: DNS** (TA0011)
  - Rationale: No DNS C2 indicators (uniform tiny queries, simple lookup pattern, no tunnelling/long-lived DNS channel)
- **T1568.002 — Dynamic Resolution: Domain Generation Algorithms** (TA0011)
  - Rationale: Sequentially numbered names (`c001…c030`) are generator artefact, not DGA; no C2 traffic present

## Important Notes
- DNS burst alone does **not** establish DNS application-layer protocol (C2) technique
- Periodic HTTP alone does **not** establish C2; beacon shape shared by benign health checks/telemetry
- Dual-engine agreement validates detections; it does **not** promote candidates to validated or prove adversary intent
- No C2, exfiltration, compromise, persistence, lateral movement, malware execution, or credential access techniques are claimed
