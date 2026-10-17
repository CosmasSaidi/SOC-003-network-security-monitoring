# SOC-003 — Network Security Monitoring & Investigation

SOC-003 demonstrates building an isolated network security monitoring lab, engineering behavioural detections with Zeek and Suricata, and investigating controlled network activity with structured evidence.

## What I Built

- **Isolated lab environment:** VirtualBox host-only network (192.168.56.0/24) with Kali sensor and Windows VMs (DC1, WS001)
- **Network telemetry:** Zeek 9.0.0 for structured connection, DNS, and HTTP logs
- **Passive detection:** Suricata 8.0.7 with custom lab rules and managed ET Open ruleset evaluation
- **Evidence-based investigation:** PCAP analysis, cross-engine correlation, and conservative ATT&CK mapping
- **Detection engineering:** Behavioural detections for service discovery, DNS burst, and periodic HTTP patterns

## Architecture

```
Kali (Sensor) ── Zeek + Suricata
                │
            host-only (vboxnet0)
                │
            ┌───┴───┐
           DC1    WS001
       (Win Server) (Win 10)
```

**Note:** VirtualBox host-only networking prevents guest-to-guest unicast visibility from the host; guest-side pktmon capture validated the WS001↔DC1 traffic path.

## Detection & Investigation

Three controlled behaviours were engineered and validated:

1. **Network service discovery** (multi-host/multi-port failed TCP probes) — detected by both engines
2. **DNS burst** (high-volume unique DNS lookups) — detected by both engines  
3. **Periodic HTTP activity** (scheduled heartbeat requests) — detected by both engines

Cross-engine correlation accounted for Suricata threshold semantics (volume-stable, with run-to-run attribution differences) and treated Zeek timestamps as canonical.

## Key Findings

- **T1046 Network Service Discovery** was validated for the controlled capture
- DNS burst alone was not treated as proof of DNS C2; DGA indicators were not present
- Periodic HTTP alone was not treated as proof of C2 (shared by benign health checks)
- VirtualBox guest-to-guest visibility limitation identified and resolved via guest-side capture
- Suricata threshold/alert attribution behaviour documented; volume (floor(matches/count)) is stable
- ET Open ruleset evaluation on these specific behaviours treated as evidence-scoped observation

## Tools

- Zeek 9.0.0, Suricata 8.0.7
- Wireshark/tshark, capinfos, dumpcap
- Windows pktmon
- Python, shell scripting
- VirtualBox

## Repository Guide

- [`detections/`](detections/) — Zeek and Suricata detection logic
- [`docs/cases/`](docs/cases/) — Formal investigation cases
- [`docs/investigations/`](docs/investigations/) — Investigation writeups
- [`evidence/`](evidence/) — PCAPs, telemetry, manifests (with SHA256 verification)
- [`docs/`](docs/) — Architecture, detection docs, findings, phase reports
- [`scripts/`](scripts/) — Analysis and validation helpers

## Evidence

Core validation artifacts: Phase 1 baseline, Phase 2 controlled PCAP, Phase 3D guest-side capture. Integrity verified via SHA256SUMS/manifests.

## Limitations

Controlled/synthetic traffic, lab-calibrated thresholds, offline Suricata validation, architecture-specific capture behaviour. No production detection coverage claimed.

**Status:** Completed through Phase 5
