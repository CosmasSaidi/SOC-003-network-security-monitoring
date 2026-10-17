# SOC-003 — Phase 4C Report: Managed ET Open Ruleset Replay + Comparison

**Phase:** 4C — Suricata ruleset provenance, acquisition and managed-ruleset replay
**Steps covered:** Step 1 (recon, PASS), Step 2 (acquisition + validation, PASS), **Step 3 (replay + comparison — this report)**
**Status:** **PASS** (see §16)
**Executed:** 2026-10-17, ~02:00–02:25 EAT (Africa/Nairobi); Step 3 analysis completed ~10:30–11:00 EAT
**Host:** Kali GNU/Linux Rolling 2025.4, kernel `6.19.14+kali-amd64` (sensor)
**Operator:** `saidi` (uid 1000)
**Tooling:** Suricata 8.0.7 RELEASE (`1:8.0.7-1`), suricata-update 1.3.8 (`1.3.8-1`), tshark, capinfos
**Mode:** Offline PCAP replay only. No `-i`, no AF_PACKET, no NFQUEUE, no IPS/inline, no service start, no config change, no ruleset change, no `apt`, no Git. All new artifacts under `~/soc-lab/soc-003/`. No AI/agent attribution in any artifact (sole human authorship preserved).

---

## 1. Objective

Determine what the newly managed ET Open ruleset actually detects in the exact
same controlled evidence used in Phase 4B — the deterministic Phase 2 PCAP and
the Phase 4B negative-control captures — and compare the result against the
Phase 4B baselines. No live detection, no IPS, no new rules were created, and
the managed ruleset was not modified in any way.

## 2. Ruleset provenance

| Item | Value |
| --- | --- |
| Engine | `Suricata 8.0.7 RELEASE` (package `suricata 1:8.0.7-1`) |
| Updater | `suricata-update version 1.3.8` (package `suricata-update 1.3.8-1`) |
| Enabled source | `et/open` only (`/var/lib/suricata/update/sources/et-open.yaml`, `checksum: true`) |
| Source index | `https://www.openinfosecfoundation.org/rules/index.yaml` → cached `/var/lib/suricata/update/cache/index.yaml` (16,716 B, index format v1, 29 sources) |
| Feed URL (resolved) | `https://rules.emergingthreats.net/open/suricata-8.0.7/emerging.rules.tar.gz` (version-pinned template) |
| Retrieval timestamp | 2026-10-17 02:10:42 +0300 (index 02:09:28, rules written 02:10:46) |
| Archive | 5,634,046 B, 61 members, 72,191 raw rule lines (68,726 excluding the ignored `*deleted.rules`) |
| Archive SHA-256 | `be54e299c33e65a411eb85224778da50b542150ec899760043225c35d99ab632` |
| Vendor integrity control | MD5 sidecar only (collision-broken; change-detector, not a security control); no SHA-256/PGP sidecar exists upstream (`/…tar.gz.sha256` → HTTP 404). `--fail` was in effect. |
| Provenance caveat | Provenance rests on HTTPS transport to `rules.emergingthreats.net` (nginx, etag `6ad28a79-55f7fe`) plus suricata-update's MD5 advisory check — no cryptographic attestation exists for ET Open. |

Full evidence: `evidence/phase4c-ruleset/managed-ruleset/00–09` and `recon/00–12`.

## 3. Acquisition result

`sudo suricata-update update-sources` → `enable-source et/open` →
`sudo suricata-update --fail --no-reload` (operator-executed, 2026-10-17 ~02:10 EAT)
succeeded: fetched, merged, dependency-enabled, `-T`-tested and wrote
`/var/lib/suricata/rules/suricata.rules` + `classification.config`. A byte-identical
sandbox reproduction of the merge (SHA-256 match, `update-sandbox/rules/suricata.rules`)
confirms the managed file is exactly what suricata-update generates from this
archive — the ruleset has **not** been manually modified.

## 4. Rule counts

| Count | Value |
| --- | --- |
| Rules in managed file (lines) | 69,171 (unique SIDs 69,171) |
| Enabled | 53,211 (53,210 `alert` + 1 `drop`) |
| Disabled (commented by suricata-update config) | 16 — 8 DNP3 + 8 Modbus (app-layer protocols disabled in the packaged `suricata.yaml`) |
| Vendor-commented in source archive | 15,944 |
| Flowbit-dependency rules auto-enabled | 136 |
| Loaded by engine | 53,211 — **0 failed, 0 skipped** (53,216 signatures processed: 1,210 IP-only, 4,548 packet-payload, 47,222 app-layer, 110 decoder-event) |
| Top enabled classes | trojan-activity 10,162 · bad-unknown 7,427 · domain-c2 7,176 · web-application-attack 6,009 · misc-activity 4,711 · command-and-control 3,616 |
| Top enabled protocols | http 22,512 · dns 13,912 · tls 9,796 · tcp 4,154 · http1 1,065 · rdp 118 |

## 5. Configuration validation

* Operator-executed elevated test `sudo suricata -T -c /etc/suricata/suricata.yaml -v`
  (SYSTEM mode, 02:11:22 +0300): **"53211 rules successfully loaded, 0 rules failed,
  0 rules skipped"** → *"Configuration provided was successfully loaded. Exiting."*
  (`managed-ruleset/08_suricata-update-test-log.txt`).
* Unprivileged re-test with the packaged config (literal command): **exit 1** — the
  engine aborts because the root-owned `default-log-dir /var/log/suricata/` is not
  writable by the operator account. Same structural finding as Phase 4B §3.1; this
  is a permission property of the packaged config, not a ruleset defect.
* Same test with a `-l` override into a user-owned directory: **exit 0**, 53,211
  rules loaded, configuration loaded successfully (`config-test/loverride.*`).
* Recurring non-error warnings in user-mode runs: Hyperscan MPM cache folder not
  writable (`/var/lib/suricata/cache/sgh`); unix command socket bind permission
  denied. Neither affects offline detection.
* `dpkg -V suricata suricata-update` → clean (no packaged file modified).
* Suricata remains **inactive and disabled** (service not started; verified again in §14).

## 6. Phase 2 replay methodology

* Input: the existing deterministic Phase 2 PCAP —
  `evidence/phase2-controlled-network-behaviour/phase2-controlled-network-behaviour.pcap`,
  **SHA-256 verified against the Phase 2 record**: `c63484f083f409c3dd58e01064bac9c0ae2e52a5bffa3dbad05aff6f04201780`
  (`c63484f0…1780` ✓). The PCAP was **not** regenerated.
* Command pattern: `suricata -c /etc/suricata/suricata.yaml -r <PCAP> -l <user-owned output dir>`
  (bounded, isolated: `replay-et-open/out-managed-et-open/`). No `-S`, so the
  managed default ruleset (53,211 rules) was the only ruleset — the SOC-003
  custom rules were **not** loaded (verified absent from `suricata.rules`).
* Engine visibility on the PCAP: 215 packets / 16,136 bytes parsed; 69 flows
  (34 TCP, 35 UDP); 35 DNS and 10 HTTP flows fully decoded; no checksum warnings
  (all packet checksums valid in this PCAP); exit 0.
* Captured per run: stdout, stderr, exit code, wall time, peak RSS, EVE, fast.log,
  stats.log, suricata.log.

## 7. ET Open alerts

**The managed ET Open ruleset produced 0 alerts on the Phase 2 PCAP.**
No ET Open vendor signature — scan, DNS, HTTP, TLS, malware, C2 or otherwise —
fired. fast.log is empty (0 bytes); EVE contains only DNS (70), HTTP (10),
fileinfo (10), flow (69) and stats (1) events. There are no SIDs, addresses,
timestamps or classifications to enumerate because no signature fired.

Across the entire four-replay matrix, the only firing rules anywhere are three
**Suricata-provided packet-anomaly rules** (`decoder-events.rules`, merged into
the managed file by suricata-update; **not ET Open vendor signatures**):
2200073 `SURICATA IPv4 invalid checksum` (272), 2200074 `SURICATA TCPv4 invalid
checksum` (260), 2200075 `SURICATA UDPv4 invalid checksum` (12) — all on
negative-control C only (§8). Full analysis:
`evidence/phase4c-ruleset/analysis/alert-analysis-phase3d-checksums.md`.

## 8. Negative-control results

Same benign controls as Phase 4B, replayed with the managed ET Open ruleset,
each in its own output directory:

| Control | Capture | Packets | Alerts | Assessment |
| --- | --- | --- | --- | --- |
| A | Phase 1 synthetic baseline (`phase1-synthetic-baseline.pcap`) | 20 | **0** | clean |
| B | Phase 3B benign AD lab capture (`phase3b-benign-ad.pcap`) | 18 | **0** | clean |
| C | Phase 3D real WS001↔DC1 benign capture (`ws001-dc1-guest-capture.pcapng`) | 712 | **544** | all incidental — see below |
| D | in-PCAP benign blocks (inside the Phase 2 PCAP) | (in §6 run) | **0** | clean (correct silence) |

**Control C — 544 incidental alerts, exact reason measured.** All 544 alerts
originate from WS001 (`192.168.56.102`) → DC1 (`192.168.56.10`) — benign AD/DNS/
NTP/RPC/LDAP service traffic — and none in the reverse direction. Three
independent methods establish the cause:

1. **tshark** (checksum validation on): 272 packets carry invalid IPv4 header checksums.
2. **Independent RFC-1071 recomputation** (`scripts/phase4c_step3_checksum_experiment.py`):
   272 of 710 IPv4 packets have invalid IPv4 checksums, and **every one of them
   also has an invalid TCP (260) or UDP (12) transport checksum**; all 438
   reverse-direction packets are valid.
3. **Fix-and-replay experiment** (`analysis/checksum-experiment/`): replaying 12
   affected packets unchanged fires 24 alerts (2 per packet); replaying the same
   packets with **only the IPv4 checksum corrected** fires 12 (the TCPv4-csum
   alerts persist, the IPv4-csum alerts vanish) — proving the alerts react to
   genuine on-capture checksum properties, independently per layer.

Conclusion: the packets are genuine invalid-checksum packets produced by
**sender-side TCP/IP checksum offload in the WS001 guest's virtual NIC** (a
well-known VirtualBox capture artifact), flagged by packet-anomaly rules on
otherwise benign traffic. **Classification (conservative): incidental match** —
not a true positive against any Phase 2 behaviour, not malicious-content
evidence, and operationally false-positive noise for this capture path.

## 9. Comparison with Phase 4B

Same evidence, different rulesets (structured data: `analysis/comparison-phase4b.json`,
`analysis/comparison-phase4b.md`):

| Ruleset | Rules | Phase 2 alerts | TP | FP | Controls A/B/C/D |
| --- | --- | --- | --- | --- | --- |
| 4B packaged config (no vendor ruleset) | 0 | 0 | — | — | — |
| 4B packaged protocol event rule files | 445 | 0 | — | — | — |
| 4B SOC-003 custom rules (sids 9003001–3) | 3 | **4** | **4** | **0** | 0/0/0/0 (correct silence) |
| **4C managed ET Open ruleset** | 53,211 | **0** | 0 | 0 | 0/0/**544**/0 |

Findings:

* **No ET Open rule fired on the Phase 2 PCAP**, so none of the three injected
  behaviours (empty-SYN probe block, DNS burst block, periodic HTTP heartbeat
  block) was detected by the managed ruleset in this evidence. The three custom
  rules detect all three (Phase 4B ground truth). The firing sets of the two
  phases are disjoint (9003001–3 vs 2200073–5).
* The managed ruleset contains large relevant categories (286 enabled
  `emerging-scan` rules, 13,912 DNS, 22,512 HTTP), yet stayed silent here. Why
  (thresholds, flow-state requirements, HOME_NET direction constraints) cannot
  be determined from a silent run — recorded as *unable to determine*, not as a
  coverage assertion in either direction.
* The 544 Control-C alerts did not appear in Phase 4B because no 4B run loaded
  the packet-anomaly rules; they are a property of the managed ruleset's
  bundled anomaly layer, not of ET Open vendor content.
* Both systems together are complementary on this evidence: the lab rules catch
  the injected lab behaviours; the managed ruleset's only signal is transport
  anomalies the lab rules do not model.

## 10. Detection coverage actually demonstrated

On this exact evidence set, the managed ET Open ruleset demonstrates:

1. **Loads and evaluates correctly**: 53,211 rules, 0 failed/skipped, full
   app-layer decoding of DNS/HTTP in the replay, deterministic 0-alert verdict.
2. **Zero coverage of the three injected Phase 2 behaviours** in this evidence.
3. **Zero alerts on controls A, B and D** (20 + 18 packets + Phase 2 benign blocks).
4. One incidental anomaly signal type (checksum) on control C only.

Nothing beyond this list is claimed. Coverage on other traffic patterns
(real-world scans, real DNS bursts, malware C2, TLS, exploit kits) was **not**
tested and is **not** claimed.

## 11. False-positive observations

* **544 false-positive-noise alerts** on benign Control C from the three
  checksum-anomaly rules (cause measured: guest-side checksum offload artifact;
  classification: incidental match). At replay scale (712 packets) this is
  ~0.76 alerts/packet affected — operationally material noise if such a capture
  path were monitored, entirely absent on the other three captures.
* The alerts are `Priority: 3` / `Generic Protocol Command Decode` and would be
  noise-tier in a triage queue. No config change or ruleset disablement was
  made in this phase (out of scope); the finding is recorded for Phase 4D.
* No ET Open vendor signature produced any false positive on any control
  (zero vendor alerts anywhere in the matrix).

## 12. Resource observations

Detail: `analysis/resource-observations.md`. Summary:

| Run | Wall (s) | Engine pcap time (s) | Peak RSS |
| --- | --- | --- | --- |
| Phase 2 replay | 31.381 | 0.106 | 531,904 kB (≈ 519 MiB) |
| Control A | 31.069 | 0.089 | 564,448 kB |
| Control B | 31.376 | 0.081 | 523,168 kB |
| Control C | 34.777 | 0.147 | 529,740 kB |

Wall time is dominated by loading 53,211 rules (~21 s); actual packet
processing is ≤ 0.15 s per capture. Peak RSS ≈ 0.5 GiB regardless of capture
size — vs ≈ 70 MB with the 3-rule Phase 4B set (≈ 7–8× resident-cost increase).
Thread model `RX:1 W:4 FM:1 FR:1` on 4 cores; IDS mode. No prolonged benchmark
was run. Output footprint of the new evidence tree ≈ 1.3 MB.

## 13. Limitations

1. **Evidence scope**: four deterministic captures (215/20/18/712 packets). They
   exercise only a narrow slice of the 53,211-rule ruleset; silence elsewhere is
   untested.
2. **ET Open snapshot**: one fetch (02:10:42 +0300, SHA-256 recorded). Feeds
   change continuously; results are snapshot-specific.
3. **No cryptographic provenance** for ET Open (MD5-only sidecar; see §2).
4. **Unprivileged replay constraints**: Hyperscan cache and unix command socket
   warnings recur; MPM state is rebuilt per run. These do not affect alert
   correctness but make timing less comparable to a privileged/live run.
5. **Scan/DNS silence cause not diagnosed**: why no `emerging-scan`/DNS rule
   fired on the injected blocks is *unable to determine* without controlled
   single-rule experiments (possible future work; not done in this phase).
6. **Checksum-offload diagnosis**: measured at packet level (three independent
   methods) but the lab has no second capture path on the same traffic for a
   differential proof of the offload hypothesis; hence the conservative
   "incidental match" classification.
7. **Offline only**: no live/IPS/inline behaviour, performance or drop-policy
   conclusions of any kind.
8. **`threshold`-type rules**: 53,211 rules include thresholded signatures;
   Phase 4B's measured "sample, not count" semantics and non-reproducible
   triggering packet apply to any future thresholded ET Open alerts.

## 14. Integrity verification

`evidence/phase4c-ruleset/INTEGRITY_VERIFICATION.txt` (method identical to Phase 4B):

| Check | Result |
| --- | --- |
| Phase 1/2/3/3B/3C/3D SHA-256 manifests (`sha256sum -c`, 7 manifests) | **199 entries, 0 failures** |
| Phase 2 PCAP SHA-256 vs Phase 2 record | match (`c63484f0…1780`) |
| SOC-001 evidence tree | 0 files modified since 2026-10-17 00:00 |
| SOC-002 public repo (`SOC-002-PUBLIC`) | git status clean; HEAD `ba479eb` unchanged; reflog 1 entry (no new commits) |
| SOC-002-windows-ad tree | 0 files modified |
| Zeek installation (`/opt/zeek`) | 0 files modified; version 9.0.0 |
| `/etc/suricata/suricata.yaml` | unchanged — SHA-256 `6b5fd573…` equals the Phase 4C recon and post-acquisition records |
| Managed ruleset not manually modified | `suricata.rules` SHA-256 `1988785c…` unchanged; byte-identical sandbox reproduction exists |
| `classification.config`, archive, index.yaml, et-open.yaml | all unchanged vs Step 1/2 records |
| `dpkg -V suricata suricata-update` | clean |
| `suricata.service` | inactive, disabled, 0 processes |
| `/var/log/suricata/` | only 3 root-owned test-mode files from the operator's 02:11 elevated `-T` (Step 2); no Step 3 replay wrote there (all used `-l` overrides) |
| New evidence hashed | `evidence/phase4c-ruleset/SHA256SUMS.txt` — 114 files, self-verified OK |

No zero-system-wide-writes claim is made beyond what was measured above.

## 15. Explicit non-claims

* Not claimed: **generic network-scan detection**, **generic DNS-burst detection**,
  **generic C2/beacon detection**, or **threat-intelligence coverage** by ET Open.
  No ET Open signature fired anywhere in the matrix; the only firing rules are
  Suricata's own checksum-anomaly rules.
* Not claimed: **production effectiveness**, live-capture suitability, IPS/inline
  behaviour, drop-policy correctness, or any performance characteristic of live
  traffic.
* Not claimed: ET Open superiority or inferiority vs. the custom rules in
  general — only their measured behaviour on these four captures.
* Not claimed: the scan-category silence has a specific cause (undetermined).
* Not claimed: zero system-wide writes — only the specific checks in §14.
* Not claimed: any change to SOC-001/SOC-002/Zeek/AD/DNS/WEF/Sysmon/VirtualBox/
  firewall/routing — verified unchanged (§14).
* No AI/agent attribution anywhere; sole human authorship preserved.

## 16. Final status

**PHASE 4C STEP 3 STATUS: PASS**

Every objective of Step 3 was validated with measured evidence: the exact Phase 2
PCAP (hash-verified) and all available Phase 4B negative controls were replayed
offline under the managed ET Open ruleset (53,211 rules, 0 failed/skipped, exit 0
per run); results were analyzed per-alert, compared against Phase 4B, and the
integrity of all prior phases and adjacent projects was re-verified with zero
failures. The headline result — **0 ET Open alerts on the Phase 2 PCAP (no
coverage of the injected behaviours), 544 incidental checksum-anomaly alerts on
one benign control, 0 alerts on the other controls** — is a measured finding,
reported as such, not a validation gap. This closes the capability gap that made
Phase 4B PARTIAL: the vendor ruleset now exists, validates and has a measured
replay profile.

**Deliverables**

| Path | Content |
| --- | --- |
| `evidence/phase4c-ruleset/managed-ruleset/00–09` | Step 1 provenance (versions, source index, retrieval metadata, hashes, rule counts, archive listing, config pointers, `-T` logs, enabled sources) |
| `evidence/phase4c-ruleset/managed-ruleset/config-test/*` | Step 2 configuration-test evidence (literal + `-l`-override) |
| `evidence/phase4c-ruleset/managed-ruleset/update-sandbox/*` | Byte-identical merge reproduction |
| `evidence/phase4c-ruleset/replay-et-open/*` | Step 3 Phase 2 replay: run logs (out/err/exit/time/rss) + `out-managed-et-open/` (eve, fast, stats, suricata.log) |
| `evidence/phase4c-ruleset/negative-controls/*` | Step 4 three control replays + input hashes |
| `evidence/phase4c-ruleset/analysis/replay-et-open-phase2-summary.json` | Phase 2 replay summary (0 alerts, counts) |
| `evidence/phase4c-ruleset/analysis/phase2-et-open-replay.json`, `negative-control-*.json` | Per-replay structured summaries |
| `evidence/phase4c-ruleset/analysis/comparison-phase4b.md` + `.json` | Step 5 structured comparison |
| `evidence/phase4c-ruleset/analysis/alert-analysis-phase3d-checksums.md` | Step 6 per-alert analysis + incidental classification |
| `evidence/phase4c-ruleset/analysis/checksum-experiment/*` | Step 6 fix-and-replay experiment (subsets, 3-rule file, run evidence) |
| `scripts/phase4c_step3_checksum_experiment.py`, `scripts/phase4c_step3_analyze.py` | Analysis tooling (read-only on evidence) |
| `evidence/phase4c-ruleset/analysis/resource-observations.md` | Step 7 resource measurements |
| `evidence/phase4c-ruleset/INTEGRITY_VERIFICATION.txt` | Step 8 prior-work verification |
| `evidence/phase4c-ruleset/SHA256SUMS.txt` | Step 8 new-evidence hashes (114 files) |
| `PHASE4C_REPORT.md` | This report |

**Numbers at a glance**

* ET Open alerts on Phase 2 PCAP: **0**
* SIDs that fired on Phase 2 PCAP: **none**
* Negative controls: A **0**, B **0**, C **544** (all incidental, sids 2200073/74/75), D **0**
* TP/FP: Phase 2 — 0 TP / 0 FP (no alerts); Control C — 0 TP, 544 incidental FP-noise alerts; ET Open vendor signatures — 0 alerts anywhere
* Phase 4B comparison: 4B custom 4 TP / 0 FP (recall 3/3) vs 4C ET Open 0 alerts; disjoint firing sets
* Integrity: 199/199 prior manifest entries OK; all recorded hashes unchanged

**Recommended next phase:** **Phase 4D — combined ruleset replay + anomaly-tuning decision**, i.e.
(a) re-run the same matrix with the managed ET Open ruleset **plus** the SOC-003
custom rules loaded together (both `-S` and a merged user-owned rules file, without
modifying the managed ruleset), (b) make and document the checksum-anomaly FP
decision for this lab (keep as-is, or scope a future disable.conf / checksum-checks
change — *decision only, no config change in the field*), and (c) optionally run
controlled single-rule experiments to diagnose why no `emerging-scan` rule fired on
the Block-B SYN probes. Live/IPS deployment and Phase 5 remain out of scope.
