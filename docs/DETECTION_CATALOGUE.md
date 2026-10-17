# SOC-003 — Detection Catalogue

This catalogue documents the detections implemented/validated in SOC-003. No new detection logic is introduced in consolidation.

## Zeek Detections

### DET-201 — Network Service Discovery
- **Engine:** Zeek (connection_state_remove)
- **Purpose:** Detect bounded multi-host/multi-port failed TCP connection attempts from a single source (host/service enumeration behaviour)
- **Telemetry source:** `conn.log` (Zeek Conn)
- **Detection logic / behavioural condition:**
  - Track failed TCP probes from a source (states: S0, S1, REJ, RSTO, RSTR, OTH)
  - Window: 60s; requires ≥10 attempts, ≥5 distinct destination ports, ≥2 distinct destination hosts
  - Fire once per window; stay quiet for remainder of window
- **Validation method:** Controlled synthetic PCAP (Phase 2) replayed offline through Zeek; benign control included
- **Observed result:** True positive on controlled scan (20 probes, 4 hosts, 5 ports, ~6s). Fired at 10th probe; notice logged at T+200.0 in Phase 2 timeline (removal-based windowing).
- **False-positive result (measured):** 0 false positives on in-PCAP benign block (block A). Not measured broadly against live production traffic.
- **ATT&CK relationship:** T1046 (Network Service Discovery) — **VALIDATED** for this capture
- **Limitations:**
  - Lab-calibrated thresholds; pacing/low-and-slow could evade
  - Does not identify intent/tooling
  - Removal-based timing affects notice timestamp (documented in source)
  - Synthetic-only validation context

### DET-202 — DNS Burst
- **Engine:** Zeek
- **Purpose:** Detect high-volume unique DNS lookups from a single source in a short window
- **Telemetry source:** `dns.log`
- **Detection logic / behavioural condition:**
  - Track unique qnames per source within window (60s)
  - Fire when ≥20 unique names observed
- **Validation method:** Controlled synthetic PCAP (Phase 2) replayed offline; 30 unique names `c001…c030.lab.test` in ~9.57s
- **Observed result:** True positive; crossed at 20th unique name (`c020.lab.test`) at ~T+206.27
- **False-positive result (measured):** 0 false positives on benign control (Phase 2)
- **ATT&CK relationship:** T1590.002 candidate (recon); T1071.004/T1568.002 **NOT SUPPORTED** (no C2/DGA evidence)
- **Limitations:** Uniqueness alone insufficient for recon attribution; sequential numbering is generator artefact; content-based (`lab.test`) is lab-anchored

### DET-203 — Periodic HTTP
- **Engine:** Zeek
- **Purpose:** Detect repeated requests to a heartbeat path with stable periodicity
- **Telemetry source:** `http.log`
- **Detection logic / behavioural condition:**
  - Track repeated GETs to `/api/v1/heartbeat` from same source (300s window)
  - Fire at ≥5th request; record interval statistics (mean/CV)
- **Validation method:** Controlled synthetic PCAP (Phase 2); 6 requests at exactly 30.000s intervals (CV 0.000)
- **Observed result:** True positive; fired at 5th request (T+420.023)
- **False-positive result (measured):** 0 false positives on benign control
- **ATT&CK relationship:** T1071.001/T1102 candidate (web protocols/C2); **not validated** (periodicity alone insufficient)
- **Limitations:** Beacon shape shared by benign health checks/telemetry; no tasking/variation evidence; exact periodicity is lab construction

## Suricata Detections (Custom Lab Rules)

### SID 9003001 — Network Service Discovery (analogue)
- **Engine:** Suricata (threshold)
- **Purpose:** Lab-scoped analogue to DET-201 for controlled scan behaviour
- **Telemetry source:** Packet/flow (SYN, dsize:0, ports [22,80,443,445,3389])
- **Detection logic / behavioural condition:**
  - `alert tcp $HOME_NET any -> $EXTERNAL_NET [22,80,443,445,3389] (flags:S; dsize:0; flow:stateless; threshold:type threshold, track by_src, count 10, seconds 60; ...)`
- **Validation method:** Phase 2 PCAP replay (offline), negative controls (Phase 4B, 4D)
- **Observed result:** Fired on controlled behaviour (volume floor(20/10)=2 alerts). Stable volume across replay runs.
- **False-positive result (measured):** 0 false positives on all negative controls
- **ATT&CK relationship:** Aligned to T1046 (lab analogue); evidence-scoped
- **Limitations:**
  - **Threshold sampling semantics:** alert counts ≠ event counts; attributed packet varies between replay runs (measured 4B vs 4D: attributed different probe numbers). Treat alert timestamp as bookkeeping; volume is stable.
  - Directionality: outbound scan from $HOME_NET to $EXTERNAL_NET (lab topology)
  - Lab-anchored port set; not generalised

### SID 9003002 — DNS Burst (analogue)
- **Engine:** Suricata (threshold)
- **Purpose:** Lab-scoped analogue to DET-202 (high-volume DNS lookups)
- **Telemetry source:** DNS (dns.query; content:"lab.test")
- **Detection logic / behavioural condition:**
  - `alert dns $HOME_NET any -> any 53 (dns.query; content:"lab.test"; nocase; threshold:type threshold, track by_src, count 20, seconds 60; ...)`
- **Validation method:** Phase 2 PCAP replay, negative controls
- **Observed result:** Fired once (floor(30/20)=1). Attributed packet varied between replay runs (query #23 in 4B vs #5 in 4D) while gate satisfaction is at query #20.
- **False-positive result (measured):** 0 false positives
- **ATT&CK relationship:** Aligned conceptually to DNS burst behaviour; C2/DGA not supported by evidence
- **Limitations:** Content `lab.test` is lab-anchored; threshold attribution non-deterministic across replay runs; telemetry granularity differs from Zeek (query+response events)

### SID 9003003 — Periodic HTTP (analogue)
- **Engine:** Suricata (threshold)
- **Purpose:** Lab-scoped analogue to DET-203 (repeated heartbeat requests)
- **Telemetry source:** HTTP (flow:established,to_server; http.method GET; http.uri contains `/api/v1/heartbeat`)
- **Detection logic / behavioural condition:**
  - `threshold:type threshold, track by_src, count 4, seconds 300`
- **Validation method:** Phase 2 PCAP replay, negative controls
- **Observed result:** Fired once (floor(6/4)=1). Attributed to 5th-request exchange in 4D (24ms from Zeek DET-203), attributed to request #2 in 4B.
- **False-positive result (measured):** 0 false positives
- **ATT&CK relationship:** Periodic behaviour analogue; not validated as C2
- **Limitations:** Threshold semantics (attribution varies), lab-anchored URI/path
