# SOC-003 — Phase 2 Report

**Phase:** 2 — Controlled suspicious network behaviour → PCAP → Zeek telemetry →
detection → investigation → ATT&CK assessment → limitations
**Status: PASS**
**Executed:** 2026-10-16 (local ~13:26–13:35 EAT / 10:26–10:35 UTC)
**Host:** Kali GNU/Linux Rolling 2025.4 (sensor)
**Operator:** saidi (uid 1000)
**Tooling:** Zeek 9.0.0 (`zeek-9.0-core 9.0.0-0`), Scapy 2.6.1, tshark/capinfos 4.6.0, Python 3

Phase 2 was executed **entirely offline**. No packet was transmitted. No
interface was put into promiscuous mode, no live capture was taken, no Windows VM
was started or touched, no network/routing/NAT/firewall/DNS/`ip_forward`
configuration was changed, no package was installed, and no Git repository was
created.

---

## 1. Objective

Demonstrate, end to end, that the SOC-003 network-monitoring pipeline can:

1. distinguish controlled *suspicious-looking* behaviour from benign network
   activity in the same capture;
2. produce Zeek telemetry from an offline PCAP;
3. raise **behavioural** detections (not just log generation or `grep`);
4. validate those detections against a benign control;
5. support a complete SOC-style investigation;
6. map behaviour to MITRE ATT&CK **conservatively** — including saying "not
   supported" where the evidence is insufficient;
7. state its own limitations honestly.

The quality bar: `PCAP → Zeek telemetry → behavioural detection → detection
validation → investigation → evidence → ATT&CK assessment → limitations`.

---

## 2. Scope and safety controls

| Control | State |
| --- | --- |
| Everything offline / lab-only | **Enforced** — packets written to a file with `wrpcap`; no interface ever opened |
| No Internet traffic generated | **Enforced** — all destinations are RFC 1918 / RFC 5737 / RFC 6761 |
| `wlan0` never captured | **Enforced** — no capture performed at all; `-i` never used |
| Windows VMs never attacked/scanned/modified | **Enforced** — DC1/WS001 never contacted, never booted |
| No routing / NAT / firewall / `ip_forward` / DNS / VBox / VM changes | **Enforced** — `sudo` never invoked |
| Suricata not installed | **Enforced** |
| No packages installed | **Enforced** — Zeek 9.0.0 was already installed in Phase 1.2 |
| Python/Scapy used for deterministic generation | **Used** |
| No real malware / no malicious payload execution | **Enforced** — protocol metadata only |
| No Git repo initialised/committed/pushed | **Enforced** |
| SOC-001 / SOC-002 / Phase 1 preserved | **Verified** — see §15 |
| No credentials or secrets in artifacts | **Verified** — see §15 |
| Reserved / synthetic addressing only | **Enforced** |

All file writes were confined to `~/soc-lab/soc-003/`.

---

## 3. Phase 2 architecture

Phase 2 adds no infrastructure. It reuses the Phase 1.2 validated path:

```
  [ deterministic generator ]            [ offline replay ]          [ detection ]              [ analysis ]
  scripts/gen_phase2_synthetic_pcap.py   /opt/zeek/bin/zeek -r       detections/zeek/*.zeek     scripts/analyze_phase2.py
            │                                   │                            │                        │
            ▼                                   ▼                            ▼                        ▼
   phase2-...-behaviour.pcap  ────────►  conn.log / dns.log /      notice.log +               telemetry-summary.json
   SHA256 c63484f0…1780                  http.log / files.log       phase2_detections.log      detection-metrics.json
                                                                                              *-analysis.txt
```

- **Sensor / analyser:** the Kali host, using Zeek 9.0.0 from `/opt/zeek`.
- **Input:** a file, not an interface. In Phase 2 the "sensor" is a PCAP reader;
  this is deliberate — it removes all live-traffic and VM-visibility variables.
- **No live network is involved at any point.**
- Zeek JSON output (`LogAscii::use_json=T`) for machine-readable evidence.

---

## 4. Synthetic traffic design

One deterministic PCAP containing four blocks, separated in time and by source
so that attribution is unambiguous.

| Block | Source | Window (T0+) | Content |
| --- | --- | --- | --- |
| **A** Benign baseline | `192.168.56.101` | `0 – 96 s` | DNS q/r, HTTP req/resp, plain TCP, plus 3 sub-threshold control patterns |
| **B** Controlled network service discovery | `192.168.56.150` | `120 – 126 s` | 20 TCP probes → 4 hosts × 5 ports |
| **C** Controlled DNS burst | `192.168.56.151` | `200 – 209.57 s` | 30 unique `cNNN.lab.test` lookups |
| **D** Periodic HTTP | `192.168.56.152` | `300 – 450 s` | 6 requests at exactly 30.000 s |

`T0 = 1792134000.0` = `2026-10-16 07:00:00 UTC`.

**A — benign baseline.** Normal DNS (`www.example.test` → `198.51.100.20`),
normal HTTP (`GET /index.html` → `200 OK`), and a normal payload-free TCP
connection to `:8080` (`conn_state SF`). Three further patterns exist
specifically as **controls that must not fire**:
- 3 unanswered SYNs to one host / 3 ports (below DET-201 on all three gates);
- 4 low-rate DNS lookups over 45 s (below DET-202);
- 4 HTTP requests to one destination at intervals `[19.9, 1.4, 12.5] s`
  (below DET-203 on the count gate *and* the jitter gate).

**B — network service discovery.** Ports `22, 80, 443, 445, 3389` against
`198.51.100.10`, `198.51.100.11`, `203.0.113.20`, `203.0.113.21`, at a fixed
300 ms cadence. Outcomes: 16 unanswered (`S0`), 2 refused (`REJ`), 2 answered
then reset by the prober (`RSTO`). No payload anywhere. **No real host was
contacted** — all targets are RFC 5737 documentation ranges.

**C — DNS burst.** 30 sequentially numbered names `c001.lab.test` …
`c030.lab.test`, 0.33 s apart, each answered (half `NOERROR A 192.168.56.90`,
half `NXDOMAIN`). Described conservatively as a
*high-volume / unique-subdomain DNS burst*. **Not** labelled DGA, tunnelling or
malicious DNS.

**D — periodic HTTP.** `GET /api/v1/heartbeat?id=<n>` from `192.168.56.152` to
`203.0.113.30:80` at an exact 30.000 s interval, each a short `Connection: close`
exchange. Described as *periodic / beacon-like HTTP behaviour*. **Not** labelled
C2.

---

## 5. PCAP generation methodology

Generator: `scripts/gen_phase2_synthetic_pcap.py` (Scapy 2.6.1, stdlib only).

Determinism is achieved by removing every source of variability:

| Dimension | How it is fixed |
| --- | --- |
| Time | Fixed base epoch `T0`, all packet times expressed as fixed offsets and rounded to 6 dp |
| Addresses | Hard-coded synthetic IPs (no allocation, no random) |
| MACs | Fixed per-host table; one fixed synthetic next-hop MAC for off-link destinations |
| IP IDs | Fixed, explicit per packet |
| TCP sequence numbers | Fixed per connection (`ISN` constants) |
| Source ports | Deterministic (`40000 + index`, etc.) |
| Payloads | Fixed byte strings |
| Ordering | Packets stably sorted by timestamp before writing |
| Randomness | None — no `random`, no `time()` |

Result: 215 packets, 450.093 s span, 19 kB, link type EN10MB, `Strict time
order: True`.

---

## 6. Reproducibility validation

The generator was run twice into two separate files:

```
python3 scripts/gen_phase2_synthetic_pcap.py .../reproducibility/run1.pcap
python3 scripts/gen_phase2_synthetic_pcap.py .../reproducibility/run2.pcap
```

| File | SHA256 |
| --- | --- |
| `reproducibility/run1.pcap` | `c63484f083f409c3dd58e01064bac9c0ae2e52a5bffa3dbad05aff6f04201780` |
| `reproducibility/run2.pcap` | `c63484f083f409c3dd58e01064bac9c0ae2e52a5bffa3dbad05aff6f04201780` |
| `phase2-controlled-network-behaviour.pcap` | `c63484f083f409c3dd58e01064bac9c0ae2e52a5bffa3dbad05aff6f04201780` |

`cmp run1.pcap run2.pcap` → identical. **Byte-for-byte reproducible: YES.**

Two `capinfos`-independent confirmations: `capinfos` reports the same embedded
SHA256, and `tshark` reports the same protocol hierarchy (215 frames: 145 TCP /
70 UDP; 20 HTTP frames; 70 DNS frames).

**Zeek-side reproducibility.** Zeek 9 assigns a random `uid` to every connection
per process, so `conn.log`/`dns.log`/`http.log`/`files.log` differ across replays
in those fields only. Two independent replays were compared: all logs were
identical after stripping `uid`/`fuid`. Critically, **`notice.log` and
`phase2_detections.log` were byte-identical with no normalisation at all.**
`packet_filter.log` records the wall-clock run time and so differs by
construction. This is stated plainly rather than papered over; it is a
limitation of Zeek, not of the capture.

---

## 7. Zeek processing

```
cd ~/soc-lab/soc-003/evidence/phase2-controlled-network-behaviour/zeek-run
/opt/zeek/bin/zeek -r ../phase2-controlled-network-behaviour.pcap \
    LogAscii::use_json=T ../../../detections/zeek/phase2-load.zeek
```

| Item | Result |
| --- | --- |
| Exit code | `0` |
| stderr | empty (0 bytes) — no warnings, no errors |
| stdout | empty (0 bytes) |
| Version | Zeek 9.0.0 |
| Weird log | none produced (no protocol anomalies) |
| JSON | yes (`LogAscii::use_json=T`) |

Logs produced: `conn.log` (69), `dns.log` (35), `http.log` (10), `files.log`
(10), `notice.log` (3), `phase2_detections.log` (3), `packet_filter.log` (1).
All preserved unmodified in `zeek-run/`; per-log hashes in
`zeek-run/zeek-run-metadata.txt`.

---

## 8. Telemetry observed

**Connections (`conn.log`, 69 records).**

| Source | Records | `conn_state` breakdown | Destination ports |
| --- | --- | --- | --- |
| `192.168.56.101` (benign) | 13 | `SF` ×10, `S0` ×3 | 53, 80, 8080, 9000, 9001, 9002 |
| `192.168.56.150` (probe) | 20 | `S0` ×16, `REJ` ×2, `RSTO` ×2 | 22, 80, 443, 445, 3389 |
| `192.168.56.151` (DNS) | 30 | `SF` ×30 (UDP) | 53 |
| `192.168.56.152` (periodic) | 6 | `SF` ×6 | 80 |

**Service-discovery measurement.** 20 attempts across 4 distinct destination
hosts and 5 distinct destination ports, spanning exactly 6.000 s at a 300 ms
cadence. 16 attempts received no reply at all; 2 were refused; 2 completed a
handshake and were immediately reset. Zero bytes of application payload.

**DNS (`dns.log`, 35 records).**

| Source | Queries | Unique names | Span | Rate |
| --- | --- | --- | --- | --- |
| `192.168.56.101` (benign) | 5 | 5 | 70.02 s | 0.071/s |
| `192.168.56.151` (burst) | 30 | 30 | 9.57 s | 3.135/s |

Burst responses: 15 `NOERROR` (A → `192.168.56.90`, TTL 60) and 15 `NXDOMAIN`.
Roughly a 44× difference in unique-name rate between burst and benign control.

**HTTP (`http.log`, 10 records).**

| Pair | Requests | Intervals (s) | Mean | Pop. stdev | CV |
| --- | --- | --- | --- | --- | --- |
| `192.168.56.101 → 198.51.100.20` | 4 | `19.9, 1.4, 12.5` | 11.266667 | 7.602777 | **0.674803** |
| `192.168.56.152 → 203.0.113.30` | 6 | `30.0 ×5` | 30.000000 | 0.000000 | **0.000000** |

**Files (`files.log`, 10 records).** One per HTTP response body
(`text/html` ×1, `text/json` ×9). No file was transferred by the probing or
periodic sources beyond these synthetic response bodies.

---

## 9. DET-201 — Network Service Discovery Behaviour

`detections/zeek/det-201-service-discovery.zeek` · data source `conn.log`
(`connection_state_remove`).

**Logic.** Per source, accumulate TCP connections whose final `conn_state` is
not a normal established session (`S0`, `S1`, `REJ`, `RSTO`, `RSTR`, `OTH`).
Fire once per window when volume, port breadth and host fan-out all pass.

**Thresholds.** window 60 s; attempts ≥ 10; distinct ports ≥ 5; distinct hosts ≥ 2.

**Threshold rationale.** Volume alone is noise (a retry loop against one broken
service reaches 10 attempts easily) — hence the breadth gates. Five ports is
more than any single application retry pattern produces and matches the classic
top-ports enumeration shape. Requiring ≥ 2 hosts prevents single-target retry
storms from firing. 60 s covers a paced scan without aggregating unrelated
connections.

**Result.** Fired once, on `192.168.56.150`, at the 10th probe — 2 hosts and 5
ports in 2.7 s.

> `DET-201 network service discovery behaviour: 10 failed TCP probes from 192.168.56.150 to 2 hosts / 5 ports in 2.7s`

**Design note discovered during implementation.** The window is measured from
each connection's own `c$start_time`, not `network_time()`. On offline replay
Zeek removes un-established connections lazily, at the next packet after their
inactivity timeout, so `network_time()` collapsed all 20 probes onto the single
instant `T0+200` and produced a 0.0 s window. Using `c$start_time` restored the
real 2.7 s measurement. This is a genuine correctness fix, not a cosmetic one.

---

## 10. DET-202 — DNS Burst / Unique Subdomain Behaviour

`detections/zeek/det-202-dns-burst.zeek` · data source `dns.log` (`dns_request`).

**Logic.** Per source, count **distinct** query names in a rolling window; reset
on window expiry; fire once when the distinct count reaches the threshold.
Repeated lookups of the same name never accumulate — so ordinary repeated
resolution cannot fire it.

**Thresholds.** window 30 s; distinct query names ≥ 20.

**Threshold rationale.** Distinct names, not total volume, is the informative
dimension (a busy resolver can legitimately do thousands of queries a minute).
The synthetic burst reaches 30 distinct names in 9.57 s (~3.1/s); the benign
control reaches 5 distinct names in 70 s (~0.07/s). 20 in 30 s sits well clear of
both.

**Result.** Fired once, on `192.168.56.151`, at the 20th unique name (6.27 s).

> `DET-202 DNS burst: 20 unique query names (20 queries) from 192.168.56.151 in 6.3s`

**Explicitly not claimed:** DGA, DNS tunnelling, malicious DNS.

---

## 11. DET-203 — Periodic HTTP Behaviour

`detections/zeek/det-203-periodic-http.zeek` · data source `http.log`
(`http_request`).

**Logic.** Per `(source, destination)` pair, keep inter-arrival intervals. With
≥ 4 intervals, compute the mean, the population standard deviation and
`CV = stdev / mean`. Fire when the mean is inside the periodic band and `CV` is
within tolerance. Fire once per episode.

**Thresholds.** ≥ 4 intervals (≥ 5 requests); mean interval 5–600 s;
`CV ≤ 0.05` (≤ 5 % relative jitter).

**Threshold rationale.** Four intervals give a meaningfully stable spread
estimate where three do not, and it sits above the benign control's 4 requests
to the same destination. Synthetic jitter is zero, so a strict `CV = 0` would be
useless against real data; 5 % admits mild natural jitter while excluding
human/browsing patterns. Measured separation on this dataset: periodic pair
`CV = 0.000000` vs benign same-pair `CV = 0.674803` — roughly 13× clear of the
tolerance.

**Result.** Fired once, on `192.168.56.152 → 203.0.113.30`, at the 5th request
(4 intervals, mean 30.000 s, stdev 0.000000 s, CV 0.00000).

> `DET-203 periodic HTTP behaviour: 5 requests 192.168.56.152 -> 203.0.113.30, mean interval 30.000s, CV 0.0000`

**Explicitly not claimed:** C2. Periodicity alone is insufficient to establish C2.

---

## 12. Detection validation

Ground-truth model for this bounded capture, and the verdict computed from the
actual `phase2_detections.log` (`analysis/detection-validation.txt`):

| Source | Kind | Expected | Raised | Verdict |
| --- | --- | --- | --- | --- |
| `192.168.56.150` | suspicious | DET-201 | `DET-201` | **TRUE POSITIVE** |
| `192.168.56.151` | suspicious | DET-202 | `DET-202` | **TRUE POSITIVE** |
| `192.168.56.152` | suspicious | DET-203 | `DET-203` | **TRUE POSITIVE** |
| `192.168.56.101` | benign control | none | *(none)* | **TRUE NEGATIVE** |

| Metric | Value |
| --- | --- |
| True positives | **3** |
| False positives | **0** |
| False negatives | **not measurable** with this dataset — see below |
| Detection coverage | **3/3 = 1.0** of injected behaviours |
| Precision (this dataset) | **1.0** |

**Required evidence, per detection:**

1. *Expected suspicious behaviour triggers it* — yes, all three, on the intended
   source only.
2. *Benign control does not trigger it* — verified programmatically: no
   detection has `src = 192.168.56.101`, despite that client producing 13
   connections (including 3 unanswered SYNs), 5 DNS queries and 4 HTTP requests
   to the periodic destination.
3. *Output contains enough context for investigation* — each record carries
   `det_id`, `src`, `dst_hosts`/`dst_ports`/`unique_qnames`/`sample_qnames`,
   `window_start`, `window_seconds`, the measured statistics, and a free-text
   `evidence` string.
4. *Thresholds documented* — §9–§11 and `detections/README.md`.
5. *Known limitations documented* — `limitations.txt` (30 numbered items).

**Honest treatment of false negatives.** FN is **not** measurable here: no
ground-truth-*positive* behaviour was constructed that evades detection. The
sub-threshold controls on `192.168.56.101` deliberately sit below the thresholds
and are **expected** non-detections (a threshold-sensitivity check) — they are
explicitly *not* counted as false negatives, and counting them as such would be
inventing metrics.

---

## 13. Investigation case

`investigations/INV-201-network-service-discovery.md` (full case) and
`cases/CASE-201-network-service-discovery.md` (case record). Status: **Closed**.

Questions answered from evidence:

| Question | Answer |
| --- | --- |
| What happened? | One source made 20 short TCP connection attempts across 4 hosts / 5 ports in 6 s; no payload, no protocol follow-through |
| When? | `07:02:00.000` – `07:02:06.000 UTC`; detection at `07:02:02.700 UTC` |
| Which source? | `192.168.56.150` — and nothing else: no DNS, no HTTP |
| Which destinations? | `198.51.100.10`, `198.51.100.11`, `203.0.113.20`, `203.0.113.21` (RFC 5737) |
| Which ports? | `22, 80, 443, 445, 3389` TCP — identical set for every host |
| Which succeeded? | 2 probes completed a handshake (`RSTO`) — the prober *inferred* those ports open; no service existed and no data flowed |
| Which were unanswered? | 16 (`S0`); 2 further were refused (`REJ`) |
| DNS around the same time? | **None from the prober.** A separate DNS burst on a *different* host (`192.168.56.151`) starts 74 s later |
| HTTP around the same time? | **None from the prober.** Nearest: benign client 86 s before; periodic host 174 s after |
| Evidence supporting the detection? | 20 non-established `conn.log` records, breadth/fan-out in one 6 s window, no protocol follow-through, and the reproducible notice |
| Benign activity present? | Benign client DNS/HTTP/TCP plus three sub-threshold controls — none fired |
| Why suspicious *here*? | Machine-regular 300 ms cadence, identical port set per host, no adaptation, no other role for the source, synthetic targets no legitimate client would contact |
| What cannot be concluded? | No compromise, no malware, no tooling attribution, no C2, no exfiltration, no lateral movement, no persistence, no intent |

Includes: timeline, `conn.log` records, DNS records, HTTP records, detection
output, and evidence references. Extracts under
`evidence/phase2-controlled-network-behaviour/investigation/`.

---

## 14. ATT&CK assessment

Full reasoning: `analysis/ATTACK_ASSESSMENT.md`.

| Behaviour | Technique | Tactic | Status |
| --- | --- | --- | --- |
| Controlled network service discovery | `T1046` Network Service Discovery | Discovery | **Validated (this capture)** |
| Controlled DNS burst | `T1590.002` Gather Victim Network Information: DNS | Reconnaissance | Candidate — insufficient evidence |
| Controlled DNS burst | `T1071.004` Application Layer Protocol: DNS | Command and Control | **Not supported** |
| Controlled DNS burst | `T1568.002` Dynamic Resolution: DGA | Command and Control | **Not supported** |
| Periodic HTTP | `T1071.001` Application Layer Protocol: Web Protocols | Command and Control | Candidate — insufficient evidence |
| Periodic HTTP | `T1102` Web Service | Command and Control | Candidate — insufficient evidence |

- **T1046 is mapped** because the observable behaviour — network connection
  attempts from a single host to enumerate remote services — *is* the technique.
  The mapping does not claim tooling, intent, success, or any surrounding
  intrusion chain.
- **The DNS burst maps to no C2 technique.** 30 sequentially numbered names in
  one 9.57 s burst is not DGA-like (no long-term periodicity, no algorithm-like
  string structure, no C2 follow-on), and there is no tunnelling evidence
  (uniform ~34 B queries, one-shot lookup per name, no TXT abuse).
- **Periodic HTTP maps to no C2 technique.** Periodicity is a shape, not a
  verdict; health checks and telemetry agents are periodic by design.
  Corroborating evidence (payload, destination reputation, host telemetry) is
  absent and is not invented.

---

## 15. Evidence integrity

**Bundle:** `evidence/phase2-controlled-network-behaviour/` — `hashes/SHA256SUMS.txt`
and `hashes/manifest.json` cover every artifact; verify with
`sha256sum -c SHA256SUMS.txt`.

**Key hashes.**

| Artifact | SHA256 |
| --- | --- |
| `phase2-controlled-network-behaviour.pcap` | `c63484f083f409c3dd58e01064bac9c0ae2e52a5bffa3dbad05aff6f04201780` |
| `zeek-run/notice.log` | `da8c8849e52e42cdfa4b7c80d97634bb1c6b9d3bc9704d144fdce680f1be1d7f` |
| `zeek-run/phase2_detections.log` | `f87c972b8b80519801fb85045c61cc1a1d80ea779680fb1b2d3ce78fabfa9410` |
| `scripts/gen_phase2_synthetic_pcap.py` | see `hashes/SHA256SUMS.txt` |

**Non-modification checks** (`integrity/pre-phase2-baseline.txt` vs
`integrity/post-phase2-integrity-check.txt`), all confirmed:

| Check | Result |
| --- | --- |
| SOC-001 capture evidence (18 files) unchanged | **Yes** — all SHA256 identical |
| SOC-002 trees (343 files) unchanged | **Yes** — all SHA256 identical |
| Phase 1 evidence bundle (19 files) unchanged | **Yes** — all SHA256 identical, including `phase1-synthetic-baseline.pcap` `18de8498…6c11` |
| Phase 1 reports + generator unchanged | **Yes** |
| Only `.git` under `~/soc-lab` is the pre-existing `SOC-002-PUBLIC/.git` | **Yes** — clean tree at `ba479eb3…`, no new repo, no commit, no push |
| No file outside `soc-003/` written during Phase 2 | **Yes** (excluding the pre-existing `PHASE2_PROMPT.txt` supplied by the operator) |
| No credentials or secrets in any artifact | **Yes** — scanned for key/password/token/secret patterns and `Authorization`/`PRIVATE KEY` markers; none found |
| No Internet traffic generated | **Yes** — generation is file-only; all destinations are documentation ranges |


**Operational note, disclosed for completeness.** During Phase 2 the verification
script (`scripts/verify_phase2.sh`) initially did not change into its temporary
working directory before invoking Zeek, so Zeek wrote seven log files
(`conn.log`, `dns.log`, `http.log`, `files.log`, `notice.log`,
`phase2_detections.log`, `packet_filter.log`) into `~/soc-lab/` at the top level
instead of into the temp directory. This was detected immediately during the
verification run itself (the run reported failures), the seven stray files were
removed, and the tree was re-checked: no file outside `soc-003/` remains
modified. The script was corrected — it now `cd`s into its temp directory before
replaying Zeek — and the verification re-run passed 17/17. The pre/post integrity
comparison in the table above reflects the corrected, final state.

---

## 16. Limitations

Summarised here; the full numbered list (30 items) is
`evidence/phase2-controlled-network-behaviour/limitations.txt`.

- **Single synthetic capture.** Every detection was validated on exactly one
  215-packet dataset, built with knowledge of the answer. This proves the
  pipeline works end to end; it does **not** prove generalisation, and the
  thresholds are uncalibrated against production traffic.
- **No host-side telemetry.** No process/user/file/registry/Windows-event data.
  Nothing here can be attributed to an actor or process.
- **DET-201** misses: paced scans below 10 attempts/60 s, single-host sweeps,
  distributed scans, UDP discovery, and scans that complete handshakes cleanly.
  Its `OTH` state could over-count mid-stream flows on a busy sensor.
- **DET-202** misses: slow sweeps, single-name query storms (by design), and
  tunnelling with few distinct names but large payloads (no size/entropy
  analysis). Per-source only.
- **DET-203** misses: jitter > 5 %, intervals outside 5–600 s, destination
  rotation, and non-HTTP beaconing. Interval buffer trimmed at 64.
- **Metrics are counts, not performance figures.** TP=3 / FP=0 / coverage=1.0 /
  precision=1.0 describe one capture. False negatives are not measurable here.
- **Zeek UID non-determinism.** `conn/dns/http/files` logs are not byte-identical
  across replays without stripping `uid`/`fuid`; `notice.log` and
  `phase2_detections.log` are byte-identical.
- **No live sensor validation.** Zeek has never been run against a live
  interface in SOC-003; interface/`local_networks` configuration is unvalidated
  for live capture.
- **No Suricata.** Signature-based detection was deliberately not installed.

---

## 17. What this phase proves

1. A deterministic, byte-for-byte reproducible synthetic PCAP containing both
   benign and controlled-suspicious behaviour can be generated offline with
   Scapy.
2. Zeek 9.0.0 processes that PCAP offline, cleanly (exit 0, no warnings), and
   produces correct `conn`/`dns`/`http`/`files` telemetry, including correct
   connection-state classification (`S0`/`REJ`/`RSTO`/`SF`).
3. **Behavioural** detections — written in Zeek's own scripting/logging
   framework, not `grep`/`tshark` heuristics — can be built on that telemetry.
4. Those detections separate the controlled suspicious behaviours from benign
   activity in the **same** capture: 3/3 injected behaviours detected, 0
   detections on the benign control.
5. The detection output carries enough structured context to support a complete
   SOC-style investigation without re-reading raw packets.
6. A conservative ATT&CK mapping is possible, including a validated `T1046`
   where the evidence supports it and explicit "insufficient evidence" where it
   does not.
7. Phase 1, SOC-001 and SOC-002 were preserved intact throughout.

---

## 18. What this phase does NOT prove

1. **No detection of real adversaries.** The behaviours were synthetic and
   known. No evasion, obfuscation, pacing or real tooling was tested.
2. **No production performance.** Precision/recall on real traffic is unknown;
   the thresholds have never been baselined against a real network.
3. **No compromise of anything.** Nothing was accessed, exploited or
   authenticated. No malware exists or was run. No C2, no exfiltration, no
   persistence, no lateral movement — none of these are claimed or evidenced.
4. **No live monitoring capability.** Zeek was never run against an interface;
   the Kali sensor's live network visibility is still unvalidated.
5. **No host-side correlation.** The PCAP alone cannot say which process, user
   or account generated the behaviour.
6. **No IPS/prevention.** Nothing was blocked or dropped; this is detection and
   investigation only.
7. **No claim about DC1 or WS001.** The Windows VMs were never involved.

---

## 19. Next phase recommendation

**Phase 3 (recommended): live lab validation of the Phase 2 pipeline, without
Suricata.**

Suggested scope, in order:

1. **Re-run the Phase 2 detections against a captured live lab event** — start
   one benign lab VM and capture its ordinary DNS/HTTP on `vboxnet0` only, to
   baseline what *normal* looks like on this network and to test whether any of
   the three detections fire on genuinely benign host traffic (i.e. a real false
   positive test). This is the single highest-value gap: all current validation
   uses synthetic data.
2. **Threshold calibration against that baseline** — the Phase 2 thresholds are
   demonstrated to separate one synthetic dataset and nothing more. Record the
   observed real baseline rates and document whether the thresholds move.
3. **Add the two known blind spots to the detection set** — a UDP discovery
   variant and an `SF`-closing ("connect scan") variant for DET-201; a
   response-size/entropy signal for DET-202.
4. **Validate the live sensor path** — Zeek against a real interface on
   `vboxnet0` with the correct `local_networks`, proving that the offline
   pipeline holds up when packets arrive from a NIC. Still no `wlan0`, still no
   Internet traffic, still no VM modification.
5. **Only then consider Suricata** as a second, signature-based layer, reusing
   the PCAP corpus from Phase 2 as its regression fixture.

Do not tune the Phase 2 detections on further synthetic data — that would
compound the calibration problem rather than resolve it.

**Work stops here. Suricata was not installed and Phase 3 was not started.**
