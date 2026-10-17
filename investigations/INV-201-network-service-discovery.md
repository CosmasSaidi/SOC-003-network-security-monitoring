# INV-201 / CASE-201 — Network Service Discovery Behaviour

| Field | Value |
| --- | --- |
| Case ID | `CASE-201` / investigation `INV-201` |
| Status | Closed — behaviour characterised, ATT&CK mapping assessed, limitations recorded |
| Severity | Low–Medium (controlled lab exercise; no production impact) |
| Detection | `DET-201` (Zeek notice `Phase2Det::DET_201_Service_Discovery`) |
| Detection time (network) | `2026-10-16 07:03:20 UTC` (PCAP-relative `T0+120.0 s` … `T0+126.0 s`) |
| Analyst | SOC lab operator (`saidi`) — offline analysis of a synthetic capture |
| Data | `phase2-controlled-network-behaviour.pcap` (SHA256 `c63484f0…17 80`) |
| Verdict | Controlled, synthetic network service discovery behaviour. **Not** a real compromise, not real malware, not real C2. |

> **Scope statement.** This is an offline, lab-only exercise against a
> deterministic synthetic PCAP. No live traffic was generated, no real host was
> contacted, and no Windows VM (DC1 / WS001) was touched. Everything below
> describes synthetic packets.

---

## 1. What happened?

Between `T0+120.000 s` and `T0+126.000 s` of the capture, a single synthetic
source (`192.168.56.150`) initiated **20 TCP connection attempts** across
**4 destination hosts** and **5 destination ports** at a deliberate, fixed
300 ms cadence.

The connections were short-lived probes. None of them carried application data.
Sixteen received no reply at all, two were actively refused, and two completed a
TCP handshake and were immediately reset by the prober. The shape and timing are
characteristic of host/service enumeration: one source, breadth across ports and
hosts, a tightly bounded window, and no follow-on protocol interaction.

`DET-201` fired at `T0+122.700 s`, on the 10th probe, when the source had
covered 2 hosts and 5 ports in 2.7 s.

## 2. When did it happen?

| Item | Value |
| --- | --- |
| First probe | `T0+120.000 s` = `2026-10-16 07:02:00 UTC` |
| Detection fired | `T0+122.700 s` = `2026-10-16 07:02:02.7 UTC` |
| Last probe | `T0+126.000 s` = `2026-10-16 07:02:06 UTC` |
| Duration of probe burst | `6.000 s` (threshold crossing at `2.700 s`) |
| Probe cadence | exactly `0.300 s` between consecutive probes |

The PCAP base time is `T0 = 1792134000.0` = `2026-10-16 07:00:00 UTC`.

## 3. Which source initiated the behaviour?

`192.168.56.150` — a synthetic source address in the lab host-only range
(`192.168.56.0/24`, RFC 1918). It created **20** connection records and **no**
other activity: no DNS queries, no HTTP requests, no successful application
sessions. Source ports were `40000`–`40019`, one per probe.

This address is distinct from the benign client (`192.168.56.101`), the DNS
burst source (`192.168.56.151`) and the periodic-HTTP source
(`192.168.56.152`), so attribution between behaviours is unambiguous *within
this synthetic capture*. In a real environment, `192.168.56.150` would be the
address to locate.

## 4. Which destinations were contacted?

| Destination | Note |
| --- | --- |
| `198.51.100.10` | RFC 5737 TEST-NET-2 — never routable |
| `198.51.100.11` | RFC 5737 TEST-NET-2 — never routable |
| `203.0.113.20` | RFC 5737 TEST-NET-3 — never routable |
| `203.0.113.21` | RFC 5737 TEST-NET-3 — never routable |

All four are documentation ranges. They are not real hosts and were never
contacted on the wire — the packets exist only inside the PCAP file.

## 5. Which ports were targeted?

`22/tcp` (SSH), `80/tcp` (HTTP), `443/tcp` (HTTPS), `445/tcp` (SMB),
`3389/tcp` (RDP) — each attempted once per destination host, 5 x 4 = 20 probes.

This is a small, hand-picked "common services" set rather than a full 1–65535
sweep, and it is identical for every host, which is consistent with a
list-driven probe rather than an adaptive scan.

## 6. Which connections succeeded, and which were unanswered?

| Outcome | `conn_state` | Count | Meaning |
| --- | --- | --- | --- |
| Unanswered | `S0` | 16 | SYN sent, no reply (silently dropped / filtered) |
| Refused | `REJ` | 2 | SYN answered with RST — port closed |
| Handshake completed, then reset by prober | `RSTO` | 2 | Port appeared open; prober immediately reset |

Per destination:

| Destination | `RSTO` (answered) | `REJ` (refused) | `S0` (unanswered) |
| --- | --- | --- | --- |
| `198.51.100.10` | 80, 443 | — | 22, 445, 3389 |
| `198.51.100.11` | — | 443 | 22, 80, 445, 3389 |
| `203.0.113.20` | — | 22 | 80, 443, 445, 3389 |
| `203.0.113.21` | — | — | 22, 80, 443, 445, 3389 |

**What "succeeded" means here.** Two probes completed the TCP three-way
handshake, i.e. the prober *inferred* those two ports as open. This is a
simulated result: no service existed behind them and no application data was
exchanged. The prober's RST immediately after the SYN-ACK (`history` `ShR`) is
itself consistent with an automated sweep that has no interest in the service.

**No connection carried payload.** Total bytes are 54 B (probe) / 54 B (RST) /
108 B (the 3-packet `RSTO`), i.e. headers only.

## 7. What DNS activity occurred around the same time?

**None from the probing source.** `192.168.56.150` produced zero DNS queries in
the whole capture. There is therefore no evidence in this data of the prober
resolving names before probing — the targets were addressed by literal IP, which
is itself a mild indicator of a synthetic or list-driven sweep rather than a
resolver-driven one.

For broader context, the capture does contain a separate DNS burst from a
**different** source (`192.168.56.151`) beginning at `T0+200.000 s`, i.e. 74 s
**after** the probe burst ended. It is a distinct behaviour on a distinct host
(`DET-202`); the temporal gap and the different source mean it should not be
presented as part of the same activity.

## 8. What HTTP activity occurred around the same time?

**None from the probing source.** `192.168.56.150` made no HTTP requests; the
20 probes produced no `http.log` entries.

Nearest HTTP in the capture: the benign client issued `GET /status` at
`T0+33.923 s` (86 s before the probes), and the periodic-HTTP source
(`192.168.56.152`, a different host) began at `T0+300.023 s` (174 s after the
probes ended). Nothing HTTP-shaped accompanies the probe burst.

## 9. What evidence supports the detection?

1. **`conn.log` — 20 records for `192.168.56.150`, all non-established**
   (`S0` x16, `REJ` x2, `RSTO` x2); zero `SF`.
   Extract: `evidence/phase2-controlled-network-behaviour/investigation/conn-extract-service-discovery.txt`
2. **Breadth and fan-out in one window** — 5 distinct destination ports and
   4 distinct destination hosts, all within 6.0 s.
3. **No protocol follow-through** — no payload, no `http.log`, no `dns.log`,
   no `files.log` entries for this source (nothing was transferred).
4. **Detection output** — notice + structured record:
   `notice.log`, `phase2_detections.log`
   (`evidence/.../investigation/detection-extract.txt`).
   > `DET-201 network service discovery behaviour: 10 failed TCP probes from 192.168.56.150 to 2 hosts / 5 ports in 2.7s`
5. **The detection decision is reproducible** — re-running Zeek over the same
   PCAP reproduces `notice.log` and `phase2_detections.log` byte-for-byte.

## 10. What benign activity was present?

Deliberately, so that the detection could be validated against a control:

- `192.168.56.101` normal DNS query/response (`www.example.test` -> `198.51.100.20`).
- `192.168.56.101` normal HTTP request/response (`GET /index.html` -> `200 OK`).
- `192.168.56.101` normal payload-free TCP connection (`:49153 -> 198.51.100.20:8080`, `SF`).
- **Incidental benign-normal traffic:** 3 further HTTP requests at irregular
  intervals (`/health`, `/version`, `/status`).
- **Sub-threshold controls** (present specifically to test threshold
  sensitivity, and *not* counted as false negatives):
  - 3 unanswered SYNs from `192.168.56.101` to one host across 3 ports
    (DET-201 needs >= 10 attempts, >= 5 ports **and** >= 2 hosts — not met);
  - 4 low-rate DNS lookups spread over 45 s (DET-202 needs 20 distinct names
    in 30 s — not met);
  - 4 HTTP requests to one destination at intervals `[19.9, 1.4, 12.5] s`,
    CV `0.6748` (DET-203 needs >= 5 requests with CV <= 0.05 — not met).

**No detection fired for `192.168.56.101`.** This is the true-negative control
and it is verified programmatically in
`evidence/.../analysis/detection-validation.txt`.

## 11. Why is this behaviour suspicious *in this controlled scenario*?

- Network service discovery from a single host is, by itself, frequently benign.
  What makes it worth an analyst's time is the combination: **unusual source**,
  **breadth across hosts and ports**, **tight cadence**, and **zero
  protocol follow-through**.
- The probe cadence was *exactly* 300 ms — machine-regular, not human-paced.
- The identical 5-port set was applied to every host, with no adaptation to the
  responses (ports that answered and ports that were refused were both
  abandoned immediately).
- The source had no other role in the capture: it did not resolve names, did not
  authenticate, did not fetch anything. It existed only to enumerate.
- In this lab, `192.168.56.150` is a synthetic address with no legitimate
  business function, and the targets are documentation ranges that no legitimate
  client would contact.

## 12. What cannot be concluded from the available evidence?

- **No compromise.** Nothing in this data shows access, exploitation, or
  authenticated activity. The prober never got beyond a TCP handshake.
- **No malware and no tooling attribution.** The traffic shape is consistent
  with many tools (`nmap`, a custom script, an inventory scanner). Packet
  metadata cannot identify the tool, let alone the actor.
- **No C2, no exfiltration.** No payload, no beaconing, no outbound data volume.
- **No lateral movement or persistence.** Not observed, not inferable.
- **No claim about real-world intent.** This is a synthetic capture built to
  contain this behaviour; "suspicious" here means "matches a detection
  signature", not "an adversary did this".
- **Nothing about the Windows VMs.** DC1 and WS001 were never involved; their
  logs would be needed for any host-side correlation and were deliberately not
  touched in this phase.
- **The two "open" ports are simulated.** They prove the prober *inferred*
  openness; they say nothing about any real service.
- **Single-source, single-capture limitations.** These detections have been
  validated on exactly one bounded dataset. Precision/recall on real traffic is
  unknown and the thresholds are uncalibrated against production baselines.

## 13. Timeline

See `evidence/phase2-controlled-network-behaviour/investigation/timeline.txt`
for the full capture timeline. The case-relevant portion:

| Offset | Actor | Event |
| --- | --- | --- |
| `T0+120.000` | `192.168.56.150` | First probe: SYN -> `198.51.100.10:22` (`S0`) |
| `T0+120.300` | `192.168.56.150` | SYN -> `198.51.100.10:80` -> SYN-ACK -> RST (`RSTO`) |
| `T0+120.600` | `192.168.56.150` | SYN -> `198.51.100.10:443` -> SYN-ACK -> RST (`RSTO`) |
| `T0+120.900` … `T0+121.200` | `192.168.56.150` | SYN -> `:445`, `:3389` (`S0`) |
| `T0+121.500` … `T0+122.100` | `192.168.56.150` | Probing `198.51.100.11` ports 22, 80 (`S0`), 443 (`REJ`) |
| `T0+122.400` … `T0+122.700` | `192.168.56.150` | Ports 445 (`S0`), 3389 (`S0`) |
| **`T0+122.700`** | **DET-201** | **Threshold crossed (10 attempts, 2 hosts, 5 ports, 2.7 s) — notice raised** |
| `T0+123.000` … `T0+126.000` | `192.168.56.150` | Remaining 10 probes against `203.0.113.20`, `203.0.113.21` |
| `T0+200.000` … `T0+209.570` | `192.168.56.151` | *(separate behaviour)* DNS burst — `DET-202` |

## 14. Evidence references

All paths relative to
`~/soc-lab/soc-003/evidence/phase2-controlled-network-behaviour/`.

| Artifact | Path | SHA256 |
| --- | --- | --- |
| Input PCAP | `phase2-controlled-network-behaviour.pcap` | `c63484f0…1780` (full value in `hashes/SHA256SUMS.txt`) |
| Raw `conn.log` | `zeek-run/conn.log` | see `zeek-run/zeek-run-metadata.txt` |
| Raw `dns.log` | `zeek-run/dns.log` | see `zeek-run/zeek-run-metadata.txt` |
| Raw `http.log` | `zeek-run/http.log` | see `zeek-run/zeek-run-metadata.txt` |
| Raw `notice.log` | `zeek-run/notice.log` | see `zeek-run/zeek-run-metadata.txt` |
| Structured detections | `zeek-run/phase2_detections.log` | see `zeek-run/zeek-run-metadata.txt` |
| Case conn extract | `investigation/conn-extract-service-discovery.txt` | in `hashes/SHA256SUMS.txt` |
| Case DNS extract | `investigation/dns-extract-all.txt` | in `hashes/SHA256SUMS.txt` |
| Case HTTP extract | `investigation/http-extract-all.txt` | in `hashes/SHA256SUMS.txt` |
| Case detection extract | `investigation/detection-extract.txt` | in `hashes/SHA256SUMS.txt` |
| Case timeline | `investigation/timeline.txt` | in `hashes/SHA256SUMS.txt` |
| Validation output | `analysis/detection-validation.txt` | in `hashes/SHA256SUMS.txt` |
| Metrics | `analysis/detection-metrics.json` | in `hashes/SHA256SUMS.txt` |

## 15. Recommendations (lab-scoped)

- Keep `conn_state`-based enumeration detection, but consider adding a **UDP**
  and a **`SF`-completing** scan variant; both are current blind spots.
- If this were production, the next step would be host-side correlation on
  `192.168.56.150` (process, user, parent process) — out of scope for this
  offline phase, and no such telemetry exists in this capture.
- Do not tune these thresholds on a single synthetic capture. Baseline against
  real traffic before deployment; the thresholds here are demonstrably
  separating *this* data, which is not the same as being correct generally.
