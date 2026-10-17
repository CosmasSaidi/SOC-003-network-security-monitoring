# SOC-003 Phase 2 — Detections

Behavioural, Zeek-native detections for the Phase 2 controlled network
behaviour capture. All three are implemented as Zeek scripts under
`zeek/` and emit both a `Notice` (`notice.log`) and a structured record
(`phase2_detections.log`, JSON).

- Canonical scripts: `detections/zeek/`
- Loader: `detections/zeek/phase2-load.zeek`
- Evidence + validation: `../evidence/phase2-controlled-network-behaviour/`
- Phase report: `../PHASE2_REPORT.md`

Run (offline replay only):

```
cd ~/soc-lab/soc-003/evidence/phase2-controlled-network-behaviour/zeek-run
/opt/zeek/bin/zeek -r ../phase2-controlled-network-behaviour.pcap \
    LogAscii::use_json=T ../../../detections/zeek/phase2-load.zeek
```

---

## DET-201 — Network Service Discovery Behaviour

| Item | Value |
| --- | --- |
| File | `zeek/det-201-service-discovery.zeek` |
| Data source | `conn.log` (`connection_state_remove`) |
| Notice | `Phase2Det::DET_201_Service_Discovery` |
| Tunables | `det201_window`, `det201_min_attempts`, `det201_min_ports`, `det201_min_hosts` |

**Logic.** Per source address, accumulate TCP connections whose final
`conn_state` is *not* a normal established-and-closed session —
`S0` (SYN, no reply), `S1`, `REJ` (RST from responder), `RSTO`/`RSTR`
(handshake completed, then reset), `OTH`. Fire **once per window** when all
three gates pass simultaneously.

**Thresholds.** window `60 s`; attempts `>= 10`; distinct destination ports
`>= 5`; distinct destination hosts `>= 2`.

**Threshold rationale.**
- *Volume (10).* A single failed connection is noise; ten non-established
  attempts to the same target pair is an ordinary retry loop, which is exactly
  why the breadth gates exist as well. 10 is the smallest round number that
  cleanly separates the synthetic probe burst (20 attempts) from the benign
  control (3 unanswered SYNs).
- *Port breadth (5).* Five distinct ports is more than any single application
  retry pattern produces and is the classic "top ports" enumeration shape.
- *Host fan-out (2).* Requires contact with more than one destination, so a
  repeated retry loop against one broken service cannot fire.
- *Window (60 s).* Long enough to cover a paced scan, short enough that
  unrelated connections hours apart do not aggregate.

**Timing note.** The window is measured from the connections' own
`c$start_time`, **not** `network_time()`. On offline replay Zeek removes
un-established connections lazily (at the next packet after their inactivity
timeout), so `network_time()` collapses a whole probe burst onto one instant
and destroys the time dimension. This was observed during development and is
the reason the script uses `c$start_time`.

**Fires on.** `192.168.56.150` — 20 probes to 4 hosts x 5 ports in ~6 s
(threshold crossed at the 10th probe, 2 hosts / 5 ports in 2.7 s).

**Does not fire on.** `192.168.56.101` benign client (3 unanswered SYNs to one
host / 3 ports, and 10 normally-established connections).

**Blind spots.**
- A slow, low-and-slow scan (`< 10` attempts per 60 s) does not fire.
- A single-host port sweep does not fire (host gate).
- A scan spread across many source addresses does not fire (per-source state).
- UDP service discovery is not covered at all.
- Connection-state based: relies on Zeek's state classification; a scan that
  completes full handshakes and closes cleanly (`SF`) is **not** counted as a
  probe attempt.
- `OTH` is included, which in a busy production capture could include
  mid-stream flows picked up by the sensor.

---

## DET-202 — DNS Burst / Unique Subdomain Behaviour

| Item | Value |
| --- | --- |
| File | `zeek/det-202-dns-burst.zeek` |
| Data source | `dns.log` (`dns_request`) |
| Notice | `Phase2Det::DET_202_DNS_Burst` |
| Tunables | `det202_window`, `det202_min_unique_qnames` |

**Logic.** Per source address, count **distinct** query names inside a rolling
window; reset the window when it is exceeded. Fire once per window on reaching
the distinct-name threshold. Repeated lookups of the *same* name never
accumulate, so normal repeated resolution does not fire.

**Thresholds.** window `30 s`; distinct query names `>= 20`.

**Threshold rationale.**
- *Distinct, not total.* Volume alone is noisy — a busy resolver can do
  thousands of queries a minute. Uniqueness is the more informative dimension
  for enumeration/lookup-sweep shapes.
- *20 in 30 s.* The synthetic burst produces 30 distinct names in 9.57 s
  (~3.1 names/s). The benign control produces 5 distinct names spread over
  70 s (0.07 names/s). 20 sits well clear of both, and 30 s is short enough
  that ordinary browsing does not reach 20 *new* names per source in the
  window.
- The threshold is deliberately documented as an **observation**, not a verdict.

**Explicitly not claimed.** This is *not* labelled DGA, DNS tunnelling or
malicious DNS. A burst of unique names is equally consistent with browsing,
CDN long-tail resolution, update checks or an inventory sweep.

**Fires on.** `192.168.56.151` — 30 unique `cNNN.lab.test` names in 9.57 s
(threshold crossed at the 20th unique name, 6.27 s).

**Does not fire on.** `192.168.56.101` benign client (5 DNS queries, 5 unique
names, over 70 s).

**Blind spots.**
- A slow DNS sweep below 20 unique names / 30 s does not fire.
- High-volume queries for the *same* name (e.g. a retry storm) do not fire —
  by design.
- No payload/size analysis. Genuine DNS tunnelling with few distinct names but
  large TXT responses would be missed; that needs a separate, size/entropy-based
  detection.
- Per-source, so a distributed burst across many clients is not covered.
- NXDOMAIN ratio is logged but not used as a gate.

---

## DET-203 — Periodic HTTP Behaviour

| Item | Value |
| --- | --- |
| File | `zeek/det-203-periodic-http.zeek` |
| Data source | `http.log` (`http_request`) |
| Notice | `Phase2Det::DET_203_Periodic_HTTP` |
| Tunables | `det203_min_intervals`, `det203_min_mean`, `det203_max_mean`, `det203_cv_tolerance` |

**Logic.** Per `(source, destination)` pair, record the inter-arrival intervals
between consecutive HTTP requests. Once at least `det203_min_intervals`
intervals exist, compute the mean, the population standard deviation, and the
coefficient of variation `CV = stdev / mean`. Fire when the mean interval is
inside the periodic band **and** `CV` is within tolerance. Fire once per
episode.

**Thresholds.** minimum intervals `4` (i.e. `>= 5` requests); mean interval
`5 s … 600 s`; `CV <= 0.05` (<= 5 % relative jitter).

**Threshold rationale.**
- *5 requests / 4 intervals.* Four intervals give a meaningfully stable spread
  estimate; three (4 requests) does not. This also sits above the benign
  control's 4 requests to the same destination.
- *Tolerance 5 %.* Synthetic data has zero jitter (`CV = 0.0`). Real beaconing
  usually has some jitter, so a hard `CV = 0` would be useless. 5 % admits mild
  natural jitter while excluding human/browsing patterns. Measured contrast on
  this dataset: periodic pair `CV = 0.000000`; benign same-destination HTTP
  `CV = 0.6748` — a ~13x separation against the threshold.
- *Mean band 5 s … 600 s.* Below 5 s is bulk request traffic (e.g. page loads,
  API polling bursts) rather than beacon periodicity. Above 600 s the detection
  cannot be validated within a bounded capture.

**Explicitly not claimed.** This is periodic / beacon-like HTTP behaviour. It
is **not** C2. Periodicity alone is insufficient to establish C2; benign
monitoring agents, health checks and telemetry clients are periodic by design.

**Fires on.** `192.168.56.152 -> 203.0.113.30` — 6 requests at exactly 30.000 s
(threshold crossed at the 5th request: 4 intervals, mean 30.000 s, stdev
0.000000 s, CV 0.00000).

**Does not fire on.** `192.168.56.101 -> 198.51.100.20` — 4 requests with
intervals `[19.9, 1.4, 12.5] s`, CV `0.6748`. It fails the interval-count gate
*and* the CV gate.

**Blind spots.**
- Jittered beaconing above 5 % relative jitter evades the CV gate.
- Intervals outside 5–600 s are not assessed.
- Detection is per `(source, destination)` pair; a beacon that rotates
  destinations will not accumulate intervals on any single pair.
- Separated but "bursty" periodic patterns (e.g. periodic with long gaps) may
  be sliced by the 64-interval trimming.
- Only HTTP. Periodic DNS, TLS or raw TCP beaconing is not covered.
- No payload, URI, or user-agent analysis — no content-based judgement is made.

---

## Common notes

- All three detections emit the same structured record shape
  (`phase2_detections.log`) so investigations and metrics can be derived
  mechanically. The `src` field and `evidence` string carry enough context to
  start an investigation without re-reading raw packets.
- `dst_hosts` / `dst_ports` / `sample_qnames` are emitted as deterministic
  comma-joined strings built from insertion-ordered vectors. Zeek `set`
  iteration order is not stable, and unordered output would break the
  byte-stability of the detection evidence.
- No detection fires on normal DNS or normal HTTP by construction: DET-202
  requires 20 *distinct* names in 30 s, DET-203 requires 4 low-jitter intervals
  between the same pair, and DET-201 requires 10 non-established attempts
  across >= 5 ports and >= 2 hosts.
- All thresholds are declared `&redef` so a site can tune them without editing
  logic.
