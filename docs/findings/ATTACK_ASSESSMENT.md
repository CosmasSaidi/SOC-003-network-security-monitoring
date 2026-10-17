# SOC-003 Phase 2 — ATT&CK Assessment

Conservative mapping of the Phase 2 controlled behaviours to MITRE ATT&CK
(Enterprise). The rule applied throughout: **a technique is only mapped as
validated when the captured evidence actually demonstrates the behaviour named
by the technique.** Where a technique is merely *plausible*, it is recorded as a
**candidate** and the reason the evidence is insufficient is stated explicitly.

Nothing here is a claim about a real adversary. The data is synthetic.

---

## 1. Controlled network service discovery → **T1046 Network Service Discovery**

**Status: VALIDATED MAPPING** (for this controlled capture).

| Field | Value |
| --- | --- |
| Technique | `T1046` — Network Service Discovery |
| Tactic | Discovery (`TA0007`) |
| Evidence | 20 non-established TCP connection attempts from `192.168.56.150` across 4 hosts and 5 ports in 6.0 s; no payload; no protocol follow-through |

**Why the evidence supports it.** T1046 is defined as adversaries attempting to
get a listing of services running on remote hosts, including attempts to access
them, characterised by execution on a *single host* and *network connection
attempts* to remote services. The capture shows exactly that shape: one source,
connection attempts only, breadth across services and hosts, bounded in time,
with no application-layer interaction.

**Why it is "validated" and not just "candidate".** The observable behaviour
(name-level enumeration of remote services by connection attempt) *is* the
technique. No additional evidence is required to establish that this behaviour —
network service discovery — occurred.

**What this mapping does NOT claim.**
- It does not identify the tool, the operator, or the intent.
- It does not claim the technique succeeded in producing a usable service
  inventory (the "open" ports are simulated).
- It does not claim this was part of a larger intrusion chain. No preceding
  access, no following exploitation, no lateral movement, no persistence.
- It is validated **against this synthetic capture**, not against production
  traffic. The detection that supports it is uncalibrated for real networks.

**Difficulty/other notes.** The technique is typically low "detection
difficulty" in ATT&CK terms when done noisily; a paced, low-and-slow version
(which this capture is *not*) would sit below the DET-201 thresholds.

---

## 2. Controlled DNS burst → **candidate only, not validated**

Observed: 30 distinct query names under `lab.test` from `192.168.56.151` in
9.57 s (`DET-202`).

| Candidate technique | Verdict | Reasoning |
| --- | --- | --- |
| `T1590.002` — Gather Victim Network Information: DNS (Reconnaissance, `TA0043`) | **Candidate — not validated** | A burst of unique lookups is *consistent with* DNS-based reconnaissance, but the queries are to a single synthetic resolver for synthetic names, with no evidence of target enumeration (no AXFR, no reverse lookups, no zone walking, no subdomain brute-force dictionary). Uniqueness alone does not establish reconnaissance. |
| `T1071.004` — Application Layer Protocol: DNS (Command and Control, `TA0011`) | **NOT supported** | Requires evidence of C2 over DNS. There is none: payload sizes are uniform and tiny (queries ~34 B), the query/response pattern is a simple one-shot lookup per name, and there is no long-lived or periodic DNS channel, no TXT/records abuse, no tunnelling indicators. |
| `T1568.002` — Dynamic Resolution: Domain Generation Algorithms (Command and Control) | **NOT supported** | DGA requires algorithmically generated names used to locate C2 (typically many over long periods, with DGA-like string structure, followed by resolution attempts and C2 traffic). This is a single 9.57 s burst of sequentially numbered names (`c001`…`c030`) under one domain. Sequential numbering is a *generator* artefact, not a DGA signature, and there is no C2 traffic. |

**Conclusion.** The DNS burst is recorded as an anomaly worth investigating and
**no C2-related technique is mapped**. The correct description is
"high-volume / unique-subdomain DNS burst", nothing stronger.

---

## 3. Periodic HTTP → **candidate only, not validated**

Observed: 6 HTTP requests from `192.168.56.152` to `203.0.113.30` at exactly
30.000 s intervals (mean 30.000 s, population stdev 0.000000 s, CV 0.00000)
(`DET-203`).

| Candidate technique | Verdict | Reasoning |
| --- | --- | --- |
| `T1071.001` — Application Layer Protocol: Web Protocols (Command and Control, `TA0011`) | **Candidate — not validated** | The traffic is HTTP, so "web protocols" is trivially true of the medium. The technique is about using web protocols *for C2*, which the evidence does not show: both endpoints are documentation-range/synthetic addresses, the payload is a fixed benign-looking JSON heartbeat, there is no tasking, no response-varying instruction, no payload delivery, and no follow-on activity after any request. |
| `T1102` — Web Service (Command and Control) | **Candidate — not validated** | Same reasoning: no evidence of an external web service being used as a C2 channel. |
| Beaconing / `TA0011` generally | **Insufficient evidence** | See below. |

**Why periodicity alone is insufficient.** Regularity is a *shape*, not a
verdict. Health checks, telemetry agents, RSS/API pollers, NTP-over-HTTP and
monitoring probes are all periodic by design. Establishing C2 from network
metadata alone would require corroboration that this capture does not contain —
for example: a destination with no legitimate business purpose and poor
reputation, non-benign payload or tasking structure, jitter designed to evade
thresholds, an unusual user agent, host-side evidence of an implant, or
communication that continues and varies in response to input. None of these are
present.

**Conclusion.** The correct description is "periodic / beacon-like HTTP
behaviour". **No C2 technique is mapped.**

---

## 4. Summary table

| Behaviour | Technique | Tactic | Status |
| --- | --- | --- | --- |
| Controlled network service discovery | `T1046` Network Service Discovery | Discovery | **Validated (this capture)** |
| Controlled DNS burst | `T1590.002` Gather Victim Network Information: DNS | Reconnaissance | Candidate — insufficient evidence |
| Controlled DNS burst | `T1071.004` Application Layer Protocol: DNS | Command and Control | Not supported |
| Controlled DNS burst | `T1568.002` Dynamic Resolution: DGA | Command and Control | Not supported |
| Periodic HTTP | `T1071.001` Application Layer Protocol: Web Protocols | Command and Control | Candidate — insufficient evidence |
| Periodic HTTP | `T1102` Web Service | Command and Control | Candidate — insufficient evidence |
| Benign baseline | — | — | No technique. Normal DNS, HTTP and TCP. |

**Techniques deliberately not claimed anywhere in this phase:** C2, data
exfiltration, compromise, persistence, lateral movement, malware execution,
credential access.
