# CASE-201 — Network Service Discovery Behaviour (controlled lab)

| Field | Value |
| --- | --- |
| Case ID | `CASE-201` |
| Investigation | `INV-201` — `../investigations/INV-201-network-service-discovery.md` |
| Status | **Closed** |
| Classification | Controlled synthetic behaviour — no real-world impact |
| Detection | `DET-201` (Zeek native) |
| ATT&CK | `T1046` Network Service Discovery — **validated mapping** (see `../analysis/ATTACK_ASSESSMENT.md`) |
| Evidence bundle | `../evidence/phase2-controlled-network-behaviour/` |
| Source | `192.168.56.150` |
| Destinations | `198.51.100.10`, `198.51.100.11`, `203.0.113.20`, `203.0.113.21` (RFC 5737) |
| Ports | `22, 80, 443, 445, 3389` (TCP) |
| Window | `2026-10-16 07:02:00` – `07:02:06 UTC` (6.0 s) |
| Outcome | Behaviour characterised; detection validated; ATT&CK mapped conservatively; limitations recorded |

## Summary

One synthetic source probed four synthetic destinations across five TCP ports in
six seconds — 20 connection attempts, 16 unanswered, 2 refused, 2 answered and
immediately reset — with no DNS, no HTTP and no payload of any kind. `DET-201`
fired at the 10th probe.

## Verdict

Network service discovery behaviour, **confirmed as present in this controlled
capture**. It is not evidence of compromise, malware, C2, lateral movement,
persistence or data exfiltration, and none of those are claimed.

## Status log

| Time (UTC) | Event |
| --- | --- |
| `07:02:00.000` | Probe burst begins |
| `07:02:02.700` | `DET-201` raised (10 attempts / 2 hosts / 5 ports / 2.7 s) |
| `07:02:06.000` | Probe burst ends (20 attempts total) |
| — | Offline investigation performed; case closed |
