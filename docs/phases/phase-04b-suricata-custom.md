# SOC-003 — Phase 4B Report

**Phase:** 4B — Suricata installation validation & controlled offline PCAP replay
**Status:** **PARTIAL** (see §12; installation and custom-rule validation PASS, stock-rule detection is blocked by the absent vendor ruleset)
**Executed:** 2026-10-17, ~01:37–01:50 EAT (Africa/Nairobi)
**Host:** Kali GNU/Linux Rolling 2025.4, kernel `6.19.14+kali-amd64` (sensor)
**Operator:** `saidi` (uid 1000)
**Tooling:** Suricata 8.0.7 RELEASE, suricata-update 1.3.8, tshark/capinfos 4.6.0, Python 3.13
**Mode:** OFFLINE validation only. No interface opened, no packet captured, no VM/network/service configuration changed, no `sudo` used.

---

## 0. The seven required distinctions (read this first)

| # | Question | Answer |
| --- | --- | --- |
| 1 | Did Suricata install successfully? | **Yes.** `suricata 1:8.0.7-1` and `suricata-update 1.3.8-1` are installed, `dpkg -V` reports no modified packaged file, binaries and `/etc/suricata` tree are present and coherent (§2). |
| 2 | Configuration validation result | **The packaged configuration is syntactically valid but its test run fails (exit 1) solely because the vendor ruleset is absent.** `rule-files: suricata.rules` resolves under `default-rule-path: /var/lib/suricata/rules`, which is empty. Control runs with an existing and with an empty rule file both return 0 (§3). |
| 3 | Stock-rule replay result | **Completed, and it detected nothing.** With the packaged configuration exactly as shipped, 0 rules are loaded (`Warning: No rule files match the pattern …`) and 0 alerts are produced. With the only rules the package actually ships locally (410 protocol-anomaly rules from `/etc/suricata/rules/*.rules`) still 0 alerts — expected, the synthetic traffic is well-formed (§5, §6). |
| 4 | Custom-rule result | **3 narrow lab rules created and validated:** sid 9003001/9003002/9003003 each fired on the corresponding Phase 2 behaviour, with 0 false positives across four benign controls (§7). |
| 5 | What was actually detected | The three deterministic Phase 2 behaviours — repeated empty TCP SYN probes, a high-volume DNS burst, repeated `/api/v1/heartbeat` GETs — **but only via hand-written, lab-scoped local rules.** |
| 6 | What was NOT detected | Nothing was detected by the stock/packaged rulesets (because the ET Open ruleset is not installed and the shipped protocol-anomaly rules correctly stay silent on well-formed traffic). No protocol-anomaly, decoder-event or malformed-packet alert of any kind fired. |
| 7 | What cannot yet be claimed | That Suricata detects scanning, DNS tunnelling/DGA or beaconing in general; that the vendor ruleset works here; that IDS/live-mode, AF_PACKET/NFQUEUE, inline/IPS, or host-performance behaviour is validated; that these rules are anything other than lab artefacts (§11). |

---

## 1. Scope and safety controls

| Control | State |
| --- | --- |
| Offline only — `-r <pcap>` replay, never `-i` | **Enforced.** Every Suricata invocation used `-r`; the string `-i`/AF_PACKET/NFQUEUE/inline was never used. |
| No packet capture | **Enforced.** No capture tool run; no interface put into promiscuous mode. |
| No packet transmitted | **Enforced.** All input is a file; nothing was sent. |
| No vboxnet0 involvement | **Enforced.** vboxnet0 was never referenced by any command. |
| No firewall / routing / `ip_forward` / VirtualBox networking change | **Enforced.** No `iptables`/`nft`/`sysctl`/`VBoxManage modify*` command was issued. (`VBoxManage list runningvms` is the only VirtualBox command, read-only.) |
| SOC-002 VMs not started or modified | **Enforced.** Both VMs were already running since Phase 3D (13:48/13:50 on 2026-10-16); nothing was done to them. See §9. |
| Zeek installation/configuration/detections untouched | **Verified.** 0 files under `/opt/zeek` modified; `detections/zeek/*` still verify against the Phase 2/3 manifests. |
| `/etc/suricata` not modified | **Enforced.** Package conffiles unchanged (`dpkg -V` clean). Rules were supplied per-run with `-S`; no config was ever edited, and none was improvised to silence a warning. |
| Service not started | **Enforced.** `suricata.service` remains `inactive`/`disabled`; `pgrep suricata` → no process. |
| No packages installed / no APT changes | **Enforced.** No `apt`/`dpkg`/`pip` invocation; no sources touched; no autoremove/full-upgrade. |
| No Git repository or commit created | **Enforced.** No `git init/add/commit/push` anywhere; SOC-002-PUBLIC untouched (`git status` clean). |
| All artifacts under `~/soc-lab/soc-003/` | **Enforced**, with trivial documented exceptions (§9.3). |
| No secrets/credentials/PII | **Verified.** All addresses are RFC 1918/5737/6761 lab values already published in Phase 2. |
| Sole human authorship | **Preserved.** No AI/bot attribution, co-author trailers, contributor credits or metadata were added anywhere. |
| `sudo` | **Not used and not available** (no passwordless `sudo`). All validation ran unprivileged; the two operations that would need root (writing `/var/log/suricata`, `suricata-update` fetching rules) were deliberately not attempted. |

---

## 2. Installation validation (Objective A)

Evidence: `evidence/phase4b-suricata-install/install-validation/01…04`.

| Probe | Result |
| --- | --- |
| `suricata -V` | `This is Suricata version 8.0.7 RELEASE` |
| `suricata --build-info` | 8.0.7 RELEASE; `Detection enabled: yes`; AF_PACKET/AF_XDP/DPDK/eBPF/XDP, NFQueue/NFLOG, Rust (rustc 1.95.0), Hyperscan, JA3/JA4, Landlock, systemd support; `Install suricata-update: no, not bundled` |
| `suricata-update --version` | `suricata-update version 1.3.8` |
| Binaries | `/usr/bin/suricata`, `/usr/bin/suricata-update`, `/usr/bin/suricatasc` |
| `dpkg -l` | `suricata 1:8.0.7-1 amd64` — `ii` (install ok installed); `suricata-update 1.3.8-1 amd64` — `ii` |
| `dpkg -V suricata suricata-update` | no output, exit 0 → **no packaged file modified** |
| `/etc/suricata/` | exists: `suricata.yaml` (94 378 B), `classification.config`, `reference.config`, `threshold.config`, `rules/` |
| `/etc/suricata/rules/` | 30 files, **only protocol event/conformance rules** (`*-events.rules`, `files.rules`); no `suricata.rules` |
| Config pointers | `default-rule-path: /var/lib/suricata/rules`; `rule-files: [suricata.rules]`; `default-log-dir: /var/log/suricata/` |
| Service | `inactive (dead)`, `disabled`, preset `disabled`; no `suricata` process; `suricata.socket` inactive |
| Runtime dirs | `/var/log/suricata` exists and is **empty**; `/var/lib/suricata/rules` exists and is **empty** |
| Rule source | `/etc/suricata/update.yaml` absent; `/var/lib/suricata/update` absent; no `suricata-update` timer → `suricata-update` was never initialised and **no ruleset has ever been fetched** |

**Internal consistency:** the package is self-consistent, with three benign packaging wrinkles:

1. **Event rules vs. disabled app-layer detection.** 23 of the shipped `*-events.rules` signatures cannot load because their protocols are disabled in the shipped config (`app-layer.protocols.{dnp3,modbus,pgsql,enip}.enabled: no`): dnp3 8, modbus 8, pgsql 5, enip 2. This is a Kali/Debian packaging artefact, not a fault of this installation, and it is harmless for our traffic (none of those protocols appear).
2. **`systemd` unit notice** — `PIDFile=` still points at the legacy `/var/run/suricata/suricata.pid`; systemd rewrites it to `/run/...` at load time. Cosmetic.
3. **`/var/log/suricata` exists but is empty**, because the service has never run.

---

## 3. Configuration validation (Objective B)

### 3.1 The exact prescribed command, as the operator

```
$ suricata -T -c /etc/suricata/suricata.yaml     # (unprivileged)
Warning: debug: error opening file /var/log/suricata//suricata.log: Permission denied
i: suricata: This is Suricata version 8.0.7 RELEASE running in SYSTEM mode
E: suricata: The logging directory "/var/log/suricata/" supplied by /etc/suricata/suricata.yaml (default-log-dir) is not writable. Shutting down the engine
exit=1
```

This is an **environment/permission** failure (the systemd unit runs as root; the packager's keep-empty log dir is root-owned and this session has no `sudo`), not a configuration error.

### 3.2 Same command with a runtime log-dir override (`-l`, no config edit)

```
$ suricata -T -c /etc/suricata/suricata.yaml -l <bundle>/config-test/logs
i: suricata: This is Suricata version 8.0.7 RELEASE running in SYSTEM mode
W: detect: No rule files match the pattern /var/lib/suricata/rules/suricata.rules
exit=1
```

`suricata.log` ends immediately after that warning — no `E:` line, and no `Configuration provided was successfully loaded` notice. **Suricata 8.0.7 `-T` returns 1 when a `rule-files` entry resolves to no file, emitting only a `W:` line.**

### 3.3 Isolating the cause (read-only controls)

| Control run | Purpose | Result |
| --- | --- | --- |
| `-S /etc/suricata/rules/dns-events.rules` | prove the config itself loads when a rule file exists | **exit 0**, `11 rules successfully loaded`, `Configuration provided was successfully loaded. Exiting.` |
| `-S <empty file>` | prove 0 rules is not itself fatal | **exit 0**, `W: 1 rule files specified, but no rules were loaded!`, `Configuration provided was successfully loaded.` |
| (packaged) `rule-files: suricata.rules` missing | the actual packaged state | **exit 1** |

### 3.4 Warnings vs. errors (packaged-config test, §3.2)

* **Errors (E:)** — none from the config parser.
* **Warnings (W:)**:
  * `No rule files match the pattern /var/lib/suricata/rules/suricata.rules` ← the substantive finding
  * `1 rule files specified, but no rules were loaded!` (replay mode)
  * `mpm-hs: Failed to create Hyperscan cache folder … (/var/lib/suricata/cache/sgh)` — unprivileged session, no cache written
  * `unix-manager: … bind(/var/run/suricata/suricata-command.socket) error: Permission denied` / `Unable to create unix command socket` — replay does not need the control socket

No warning was silenced and no configuration was modified.

### 3.5 Verdict and stop condition

`suricata -T` fails for exactly one reason: **the packaged ruleset has not been downloaded/generated.** Per the phase instruction, this sub-step was documented and **stopped** rather than improvised — no rule was fabricated into `/etc`, no config was edited, and no `suricata-update` run (which needs root and would fetch network content) was attempted.

---

## 4. Rule-source state

`suricata-update` is installed but **uninitialised**: no `/etc/suricata/update.yaml`, no `/var/lib/suricata/update/`, no index/sources, no timer, no `suricata.rules`. Therefore the *only* rules available on this sensor without further installation or network fetch are the 30 local `*-events.rules` files in `/etc/suricata/rules/`. **Suricata on this host currently has no detection content beyond protocol-anomaly conformance rules.**

---

## 5. Offline replay (Objective C)

Input (unchanged, verified): `evidence/phase2-controlled-network-behaviour/phase2-controlled-network-behaviour.pcap`
SHA256 `c63484f083f409c3dd58e01064bac9c0ae2e52a5bffa3dbad05aff6f04201780` (215 packets, EN10MB, 16 136 payload bytes). It was **not** regenerated.

All replays used the packaged configuration and an isolated `-l` directory under `evidence/phase4b-suricata-install/`, so `/var/log/suricata` was never written to (still empty, mtime unchanged).

| # | Rules supplied | Command (abridged) | Exit | Rules loaded | Packets | Alerts |
| --- | --- | --- | --- | --- | --- | --- |
| R1 | none (packaged `rule-files` as shipped) | `suricata -c /etc/suricata/suricata.yaml -r <PCAP> -l out-packaged` | 0 | **0** | 215 | **0** |
| R2 | packaged event rules (concat copy of `/etc/suricata/rules/*.rules`) | `… -S packaged-event-rules.concat.rules -r <PCAP> -l out-packaged-rulefiles` | 0 | **410** (23 failed — §2.1) | 215 | **0** |
| R3 | SOC-003 lab rules | `… -S detections/suricata/soc003-lab.rules -r <PCAP> -l out-custom-rules` | 0 | **3** | 215 | **4** |

R1 is the literal requested stock replay; R2 is the strongest available "packaged ruleset" datapoint on this host; R3 is §7. Note R1/R2 use `-c /etc/suricata/suricata.yaml` unmodified; no `-i`, no socket, no live interface.

---

## 6. Output analysis (Objective D)

Machine-readable summaries: `evidence/phase4b-suricata-install/analysis/*.json` (produced by `scripts/phase4b_analyze.py`).

### 6.1 R1 — packaged config, no rules (`out-packaged`)

* `eve.json` 86 012 B, `fast.log` **0 B**, `stats.log` 4 837 B.
* Event types: `flow` 69, `dns` 70, `http` 10, `fileinfo` 10, `stats` 1.
* Flow inventory: 69 flows — 35 UDP / 34 TCP; `app_proto` = `dns` 35, `http` 10, null 24 → **protocol detection works** (DNS and HTTP correctly identified; the 24 null are the plain/closed TCP probe and shutdown flows).
* Decoder counters: `decoder.pkts` 215, `decoder.bytes` 16 136, `decoder.ipv4` 215, `decoder.ethernet` 215, `decoder.tcp` 145, `decoder.udp` 70, `tcp.syn` 34, `tcp.synack` 13, `tcp.rst` 4.
* Alerts: **0** (both the EVE `alert` array and the `counters: Alerts: 0` line).
* Warnings: the four listed in §3.4. Errors: none.
* **Interpretation:** the pipeline (decode → flow → app-layer → EVE/stats/fast output) is healthy; the detection layer is empty because zero rules are loaded. *This replay proves plumbing, not detection.*

### 6.2 R2 — packaged event rules (`out-packaged-rulefiles`)

* 410 rules loaded, 23 failed to parse (§2.1), 228 inspect application layer, 110 are decoder-event only.
* `fast.log` **0 B**; `counters: Alerts: 0`.
* **Interpretation:** the packaged conformance rules stay silent on this PCAP, as expected — the synthetic traffic is well-formed and contains no DNS/HTTP/TCP protocol violations, and none of the affected protocols (dnp3/modbus/pgsql/enip) are present. No coverage of the lab behaviours is possible with packaged content.

### 6.3 R3 — SOC-003 lab rules (`out-custom-rules`)

`fast.log` (verbatim, file order):

```
10/16/2026-10:02:05.100000  [**] [1:9003001:1] SOC-003 LAB DET-201 network service discovery - repeated empty SYN probes [**] {TCP} 192.168.56.150:40017 -> 203.0.113.21:443
10/16/2026-10:03:27.260000  [**] [1:9003002:1] SOC-003 LAB DET-202 DNS burst - high-volume lookups from a single lab host [**] {UDP} 192.168.56.151:55022 -> 192.168.56.53:53
10/16/2026-10:05:30.047000  [**] [1:9003003:1] SOC-003 LAB DET-203 periodic HTTP - repeated heartbeat path requests [**] {TCP} 192.168.56.152:44001 -> 203.0.113.30:80
10/16/2026-10:02:05.700000  [**] [1:9003001:1] SOC-003 LAB DET-201 network service discovery - repeated empty SYN probes [**] {TCP} 192.168.56.150:40019 -> 203.0.113.21:3389
```

Alert totals: **4** (`9003001` ×2, `9003002` ×1, `9003003` ×1). Exit 0; 215/215 packets; 3/3 rules. Alerts are `action: allowed` (IDS, not blocking). No errors.

### 6.4 The synthetic PCAP — is the stock ruleset "right" to stay silent?

Yes for the packaged content available: nothing in the capture is malformed, so protocol-anomaly rules *should* be silent, and there is no community/ET ruleset installed to test behavioural coverage against. Per the phase instruction this is recorded as a **legitimate negative result**, not papered over: **Suricata with its packaged ruleset detects nothing in the Phase 2 PCAP.**

---

## 7. Controlled custom detection validation (Objective E)

### 7.1 Design

Created `detections/suricata/soc003-lab.rules` (3 rules, sid 9003001–9003003) + `detections/suricata/README.md`. `/etc/suricata` was **not** modified; the rules are loaded per-run with `-S`. Each rule mirrors the count/port/path gate of a Phase 2 Zeek detection (DET-201/202/203) so results compare directly to existing ground truth:

| sid | Analogue | Behavioural trigger | Threshold |
| --- | --- | --- | --- |
| 9003001 | DET-201 | `flags:S; dsize:0` from `$HOME_NET` → `$EXTERNAL_NET` ports `22/80/443/445/3389` | 10 / 60 s, `track by_src` |
| 9003002 | DET-202 | `dns.query` containing `lab.test`, `flow:to_server` | 20 / 60 s, `track by_src` |
| 9003003 | DET-203 | `http.method GET` + `http.uri /api/v1/heartbeat` | 4 / 300 s, `track by_src` |

`$HOME_NET`/`$EXTERNAL_NET` are the **packaged defaults** (RFC 1918 vs `!HOME_NET`); the Phase 2 lab addresses fall inside them correctly, so no variable override was needed.

### 7.2 Expected vs. observed (Phase 2 ground truth)

| Behaviour (ground truth) | Rule | Expected | Observed | TP/FP |
| --- | --- | --- | --- | --- |
| Block B — 20 empty SYN probes, `192.168.56.150` → 4 hosts × 5 ports, 0.3 s apart | 9003001 | ≥1 alert from `.150` | 2 alerts | **TP** |
| Block C — 30 DNS queries, `192.168.56.151` → `192.168.56.53`, ~9.6 s | 9003002 | ≥1 alert from `.151` | 1 alert | **TP** |
| Block D — 6 `GET /api/v1/heartbeat` from `192.168.56.152`, 30.000 s apart | 9003003 | ≥1 alert from `.152` | 1 alert | **TP** |
| Block A control — 3 SYNs / 1 host / 3 ports from `.101` | 9003001 | no alert | none | correct silence |
| Block A control — 5 DNS queries from `.101` over 45 s | 9003002 | no alert | none | correct silence |
| Block A control — 6 HTTP SYNs from `.152` (below count 10) | 9003001 | no alert | none | correct silence |
| Benign baseline — 3 GETs at irregular intervals from `.101` | 9003003 | no alert | none | correct silence |

Precision on this PCAP: **4 alerts, 4 true positives, 0 false positives**; recall against the three injected behaviours: **3/3**.

### 7.3 `threshold` semantics (measured, not assumed)

`threshold: type threshold` **samples** — it does not emit one alert per match. Isolated offline experiments (`replay-stock/out-th-*`, `out-diag-*`) on the same PCAP with the scan rule:

| `count` | rule matches (tracked source) | alerts | alerts/matches |
| --- | --- | --- | --- |
| 1 | 30 (20 × `.150`, 6 × `.152`, 4 × `.101`) | 30 | 1.00 |
| 2 | 30 | 15 | 0.50 (≈ matches/count) |
| 3 | 30 | 8 | 0.27 |
| 5 | 30 | 5 | 0.17 |
| 10 | 30 | 2 | 0.07 |

Moreover, *which* packet triggers is **not reproducible**: three separate `count: 10` runs alerted on probes `#18/#20`, then `#5/#20`, then `#13/#19`. Alert **volume** is stable (≈ `floor(matches/count)` per tracker); alert **attribution to a specific packet** is not. This is the single most important limitation of the custom rules — alert counts must never be read as event counts, and thresholds must be tuned to "≥1 alert means the gate was crossed", not to a precise count.

### 7.4 Negative controls (false-positive check on other existing evidence)

Same three rules, same packaged config, offline replay of pre-existing captures:

| Control capture | Content | Rule-relevant matches | Alerts |
| --- | --- | --- | --- |
| `phase1-zeek-baseline/phase1-synthetic-baseline.pcap` | 20 pkts / 0.4 s | 1 SYN to rule ports, 1 DNS query | **0** |
| `phase3b-benign-ad-validation/capture/phase3b-benign-ad.pcap` | 18 pkts / 103 s | 0 SYNs to rule ports, 0 DNS queries | **0** |
| `phase3d-guest-capture/ws001/ws001-dc1-guest-capture.pcapng` | 712 pkts / 97.4 s of real benign AD traffic | 0 SYNs to rule ports, 9 DNS queries from `192.168.56.102` (< 20) | **0** |

Honest reading: the last control is the only one with non-trivial traffic (real AD/WEF traffic, 9 DNS queries — genuinely below the 20-query gate), and the others barely exercise the rules. **FP resistance here is mostly structural** (lab port set, `lab.test` domain scope, thresholds well above benign rates) and is **not** evidence of general-purpose FP quality.

### 7.5 Claim discipline

The rules match *this* deterministic traffic with *these* thresholds. Nothing here supports "SOC-003 now detects port scanning, DNS tunnelling, DGA or C2". No vendor signature was involved, no scanning was performed on a real network, and the targets are RFC 5737 documentation addresses.

---

## 8. Resource observations

* Thread model: `RX: 1  W: 4  FM: 1  FR: 1` (4 worker threads) — a synthetic pcap replay, so throughput here says nothing about live performance.
* R3 replay cost: wall **0.252 s** (user 0.196 s, sys 0.055 s), **max RSS ≈ 70 MB** (71 772 kB) — well within the 7.5 GiB host.
* Memory counters (R1 stats): `flow.memuse` ≈ 7.15 MB with `flow.spare` 9700, `tcp.memuse` 2.49 MB, `ippair.memuse` 398 kB, `memcap.pressure` 5 (no memcap exhaustion), `detect.thresholds.cache.memuse` 8 736 B.
* Hyperscan SPM cache could not be created (`/var/lib/suricata/cache/sgh`) in the unprivileged session → the cache warning recurs on every run; no file was written.
* Evidence footprint: **1.6 MB** total, 114 files (`replay-stock` 1.3 MB, `negative-controls` 116 KB, `config-test` 64 KB, `analysis` 36 KB, `install-validation` 28 KB).

---

## 9. Evidence, integrity and hashes (Objective F)

### 9.1 Deliverables

* `PHASE4B_REPORT.md` (this file)
* `evidence/phase4b-suricata-install/` — 114 files: `install-validation/`, `config-test/`, `replay-stock/` (R1, R2, R3, threshold experiments), `negative-controls/`, `analysis/`, `diagnostics/`, `INTEGRITY_VERIFICATION.txt`, `README.md`, `SHA256SUMS.txt`, `hashes/SHA256SUMS.txt`
* `detections/suricata/soc003-lab.rules` + `detections/suricata/README.md`
* `scripts/phase4b_analyze.py` (reproducible analysis)

### 9.2 Key hashes (SHA256)

| Artifact | SHA256 |
| --- | --- |
| Phase 2 PCAP (input, unchanged) | `c63484f083f409c3dd58e01064bac9c0ae2e52a5bffa3dbad05aff6f04201780` |
| `detections/suricata/soc003-lab.rules` | `21448205843126f622886f4929172696884171fd007679fd8cf6c9e6863adb63` |
| `detections/suricata/README.md` | `e7523c28eb05035368dc459d272c37f6eae06f2d5ffab1ffc2d37d1a606cddcc` |
| `scripts/phase4b_analyze.py` | `d38277b29cc4647be0df898e4b713c827772943c33ca547845a64a9dc2f89758` |

Full per-file manifests: `evidence/phase4b-suricata-install/SHA256SUMS.txt` (verify inside the bundle) and `evidence/phase4b-suricata-install/hashes/SHA256SUMS.txt` (anchored at `~/soc-lab/soc-003`, includes this report).

### 9.3 Integrity verification (`INTEGRITY_VERIFICATION.txt`)

| Check | Result |
| --- | --- |
| Phase 1 manifests (`SHA256SUMS.txt`, `zeek-output/SHA256SUMS.txt`) | 3/3 and 8/8 OK |
| Phase 2 manifest | 49/49 OK |
| Phase 3 manifest | 52/52 OK |
| Phase 3B manifest | 35/35 OK |
| Phase 3C manifest | 9/9 OK |
| Phase 3D manifest | 43/43 OK |
| **Total prior manifest entries** | **199 verified, 0 failures** |
| SOC-001 (`~/soc-lab/evidence/soc-001-capture`) | 18 files, 0 modified since 2026-10-17 01:20 |
| SOC-002-PUBLIC | `git status --porcelain` empty; HEAD still `ba479eb` "Initial SOC-002 public portfolio release"; reflog 1 entry |
| SOC-002-windows-ad tree | 0 files modified |
| Zeek (`/opt/zeek`) | 0 files modified since the Phase 1.2 install; still `zeek 9.0.0` |
| Suricata runtime dirs | `/var/log/suricata` empty & mtime unchanged (Sep 15); `/var/lib/suricata/rules` empty |
| `/etc/suricata` | `dpkg -V` clean — no packaged file modified |
| Git repos created | none (only the pre-existing SOC-002-PUBLIC) |

**Out-of-tree effects — identified explicitly.** A whole-filesystem sweep for files written during the Phase 4B window (01:35–01:52) returned **339 files outside `~/soc-lab/soc-003`**. Every one of them is attributable to something other than this phase's lab work, and the full list plus timestamps is in `INTEGRITY_VERIFICATION.txt` (§7, §7b):

1. **01:37:12–01:37:35 — the operator's Suricata package transaction (dpkg).** `/var/lib/dpkg/status`, `/var/lib/dpkg/info/*.list` for the newly installed dependencies, `/var/log/dpkg.log`, `/var/log/apt/{history,term}.log`, `/var/cache/apt/pkgcache.bin`, `/usr/share/applications/*.desktop` (desktop-database trigger), and the `__pycache__/*.pyc` files under `/usr/lib/python3/dist-packages/suricata/` and `/usr/lib/suricata/python/`. These predate my first command (~01:39) and are the operator's install, not Phase 4B.
2. **01:36:37–01:36:46 — apt/swcatalog/command-not-found cache refresh** preceding that install.
3. **01:39:19, 01:46:01, 01:46:13, 01:50:19 — VirtualBox live VM state** (`/home/saidi/VirtualBox VMs/SOC002-*/…`, including `Logs/VBox.log` and the two `Snapshots/*.vdi`). Both SOC-002 VMs have been **running since 2026-10-16 13:48/13:50** (Phase 3D), before this phase; VirtualBox writes live guest disk/log state continuously. The only VirtualBox command issued in Phase 4B was the read-only `VBoxManage list runningvms`.
4. **01:43–01:50 — routine host daemons**: `/var/lib/upower/*` (battery history), `/var/lib/smartmontools/*`, `/var/lib/systemd/{timesync/clock,timers/*}`, `/var/log/audit/audit.log`, `/var/cache/snapd/sections`.

**Writes caused by Phase 4B outside `~/soc-lab/soc-003`: none.** The only scratch files I created on the way were five rule files under `/tmp` for the threshold experiments (§7.3); they were **moved into** `evidence/phase4b-suricata-install/diagnostics/`, so `/tmp` is clean and the diagnostic inputs are preserved as evidence.

---

## 10. Limitations

1. **No vendor ruleset exists on this host**, and it cannot be installed without root/network changes that are out of scope. All behavioural detection results therefore come from hand-written lab rules.
2. `-T` could not be run exactly as root/systemd would (no passwordless `sudo`); the faithful test failed on log-dir permissions, so the substantive configuration test was run with a runtime `-l` override. The config file itself was never modified.
3. **`threshold` sampling** (§7.3): alert counts are not event counts and the triggering packet varies between runs.
4. **Rules are lab-tuned** (port set, `lab.test` scope, `$HOME_NET`→`$EXTERNAL_NET`) — narrow by construction; no generalisation claim is possible.
5. **No interval/jitter modelling** for the periodic HTTP behaviour (Suricata threshold cannot express "30.000 s ± 5 %").
6. **Negative controls are weak**: two of the three contain almost no rule-relevant traffic; a busy production-like capture is not available in SOC-003 offline evidence.
7. **Replay ≠ live**: no interface, no stream reordering, no drops, no timing under load; NFQUEUE/AF_PACKET/inline and IPS behaviour are entirely unvalidated.
8. Everything is measured on a synthetic 215-packet PCAP with RFC 5737 destinations; nothing real was scanned, resolved or contacted.

---

## 11. Claims matrix

| Claim | Supported? |
| --- | --- |
| Suricata 8.0.7 + suricata-update 1.3.8 are correctly installed and self-consistent | **Yes** (§2) |
| Suricata can decode, track flows and identify DNS/HTTP from an offline PCAP here | **Yes** (§6.1) |
| The packaged configuration alone passes `-T` today | **No** — exit 1 because the ruleset is absent (§3) |
| The packaged ruleset detects the Phase 2 behaviours | **No** — 0 alerts in both stock configurations (§6.2, §6.3) |
| Three narrow, documented local rules detect the three Phase 2 behaviours with 0 FP on available controls | **Yes** (§7) |
| Suricata reliably detects Nmap-style scanning / DNS tunnelling / beaconing / C2 on this sensor | **No** |
| The ET Open (or any vendor) ruleset works / was evaluated | **No** — not installed |
| IDS/live capture, AF_PACKET, NFQUEUE, inline/IPS, tuning or performance validated | **No** |
| `/etc/suricata`, Zeek, SOC-001, SOC-002, VMs, network config untouched | **Yes** (§9.3) |

---

## 12. Overall Phase 4B status

**PARTIAL**

**Reason:** the installation is validated (binary, packages, config tree, service state, internal consistency) and the offline replay path works end-to-end, and the controlled custom-rule validation is a clean PASS (3 TPs, 0 FPs, documented limits). However, the prescribed packaged-configuration test **fails (exit 1)** and the stock-rule replay detects **nothing**, because the vendor ruleset (`/var/lib/suricata/rules/suricata.rules`, fed by suricata-update / ET Open) is not present. That is an honest, documented capability gap — not a defect in this phase's execution — but it means stock Suricata detection capability is **not yet demonstrated**, so the phase is PARTIAL rather than PASS.

**Deliverables**

* `~/soc-lab/soc-003/PHASE4B_REPORT.md`
* `~/soc-lab/soc-003/evidence/phase4b-suricata-install/` (incl. `SHA256SUMS.txt`, `hashes/SHA256SUMS.txt`, `INTEGRITY_VERIFICATION.txt`)
* `~/soc-lab/soc-003/detections/suricata/soc003-lab.rules` + `README.md`
* `~/soc-lab/soc-003/scripts/phase4b_analyze.py`

**Next recommended SOC-003 phase:** **Phase 4C — obtain an offline-vetted Suricata ruleset** (e.g. fetch ET Open via `suricata-update` into `/var/lib/suricata/rules` with operator-approved root access, or stage a signed ruleset bundle from removable/offline media), then re-run the *unchanged* Phase 4B replay matrix (packaged config + vendor rules, plus the custom rules for comparison) against the same Phase 2 PCAP and re-test `suricata -T` for a clean exit 0. Phase 5 was not started.
