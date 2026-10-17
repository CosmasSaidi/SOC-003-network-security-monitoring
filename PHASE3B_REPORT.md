# SOC-003 — Phase 3B Report

**Phase:** 3B — real benign AD/DNS validation (bounded live capture on `vboxnet0`)
**Status: PARTIAL / BLOCKED — objective not met (the lab was quiet again)**
**Executed:** 2026-10-16, local 14:36:33 – 14:39:33 EAT (11:36 – 11:39 UTC)
**Host:** Kali GNU/Linux Rolling 2025.4 — the SOC-003 sensor (`192.168.56.1`)
**Operator:** saidi (uid 1000)
**Tooling:** `dumpcap` 4.6.0 (unprivileged), `capinfos`/`tshark` 4.6.0, Zeek 9.0.0

**Status in one line.** A 180-second passive capture of `vboxnet0` recorded
**18 packets**, all of them emitted by `SOC002-WS001` and all of them
broadcast/multicast (SSDP, IGMP, mDNS, LLMNR) — **zero frames from
`SOC002-DC1`, zero TCP, zero HTTP and no DNS query to a DNS server**. The three
unchanged detections were replayed over it: **no detection fired**, `DET-201` and
`DET-203` were **not exercised**, and `DET-202` was **not meaningfully
exercised**. Phase 3B therefore did **not** capture the ordinary operator-driven
AD/DNS traffic it was launched to capture, and reports that honestly rather than
fabricating it.

---

## 1. Objective

Phase 3 established that the Kali sensor *can* see real lab traffic on
`vboxnet0`, but found the lab too quiet to exercise `DET-201` / `DET-202` /
`DET-203`: no WS001↔DC1 traffic, no TCP, no HTTP, no DNS to DC1. Phase 3B was
launched to close that gap by capturing **ordinary operator-generated
Windows/AD/DNS traffic from `SOC002-WS001`** — a real-traffic benign-validation
run, not a sensitivity test and not a threshold-calibration exercise — and to
replay the **existing, unmodified** detections over it.

## 2. Safety controls

| Control | State |
| --- | --- |
| Interface captured | **`vboxnet0` only.** `dumpcap -D` on this host lists 11 capture sources (`wlan0`, `vboxnet0`, `any`, `lo`, `eth0`, `bluetooth0`, `bluetooth-monitor`, `nflog`, `nfqueue`, `dbus-system`, `dbus-session`); the capture used the explicit `-i vboxnet0`, and the resulting PCAP contains **exactly one interface block, named `vboxnet0`**. `wlan0`, `any`, `lo` and every other source were never opened. |
| Capture filter | **`net 192.168.56.0/24`**, recorded by `capinfos` inside the PCAP interface block as `Filter string = net 192.168.56.0/24`. |
| Internet traffic | **None captured, none generated.** Every routable address in the PCAP is inside `192.168.56.0/24`; the only other addresses are link-local/site multicast groups (see §6 and `analysis/safety-address-check.txt`). |
| Out-of-lab stop condition | **Not triggered.** No routable address outside `192.168.56.0/24` was observed. |
| Traffic generation | **None.** The phase is entirely passive — no scan, no probe, no stress, no DNS burst, no periodic HTTP, no beacon simulation, no stimulus of any kind. |
| VM / network / Windows configuration | **Unchanged.** No VM start/stop/snapshot, no `VBoxManage modifyvm`/`setextradata`, no Windows interaction, no firewall/route/`ip_forward`/DNS change. The pre- and post-capture snapshots are byte-identical (§12). |
| Detections | **Unmodified.** `det-201`/`det-202`/`det-203`, `det-common.zeek` and `phase2-load.zeek` are byte-identical to the Phase 2 hash inventory (`sha256sum -c` → 49/49 OK). |
| Threshold tuning | **None.** No `&redef` value was changed before or after seeing the results. |
| SOC-001 / SOC-002 / Phase 1 / Phase 2 | **Untouched.** See §12. |
| Suricata | **Not installed, not started.** `command -v suricata` → not found; `dpkg -l \| grep -c suricata` → 0. Only Zeek is under `/opt`. |
| Packages | **None installed.** Only pre-existing tools were used. |
| Git | **No repository created or initialised.** `git -C soc-003 rev-parse --git-dir` → not a git repository; the only `.git` under `~/soc-lab` is the pre-existing `SOC-002-PUBLIC/.git`. |
| Credentials | **None read, none exposed.** No Windows authentication; no secrets in any artifact. |
| Privilege | **No `sudo`.** The capture used the pre-existing unprivileged `dumpcap` capability; `sudo -n true` on this host fails. |
| Write scope | All writes confined to `~/soc-lab/soc-003/`. A `find` for files under `~/soc-lab` modified during the phase, excluding `soc-003`, returned **nothing** (§12). |

**Resource note.** Both Windows VMs were already running throughout (each
~2 GiB), so the host ran with `MemAvailable` in the ~500 MiB range and ~3.8 GiB
of swap in use. The capture itself is negligible-memory (`dumpcap` RSS ~3 MiB)
and completed with **0 packets dropped**; the host stayed responsive and no OOM
event occurred. Recorded for honesty, as in Phase 3.

## 3. Capture

**Exact command** (see `evidence/phase3b-benign-ad-validation/capture/capture-command.txt`):

```
dumpcap -i vboxnet0 -f 'net 192.168.56.0/24' -a duration:180 -w phase3b-benign-ad.pcap
```

`CAPTURE_READY` was emitted once `dumpcap` had opened the interface and created
the file; the capture then ran to its 180 s bound and **stopped cleanly on its
own** (`dumpcap_exit=0`, `Packets received/dropped on interface 'vboxnet0':
18/0 (...) (100.0%)`).

| Metric | Value |
| --- | --- |
| Interface | `vboxnet0` (only) |
| Filter | `net 192.168.56.0/24` |
| Bounded duration | **180 s** — 14:36:33 → 14:39:33 EAT |
| Packets | **18** |
| Packets dropped | 0 (0.0 %) |
| File size | 2 884 bytes (1 930 bytes on the wire) |
| First packet | 2026-10-16 14:37:42.240731 (69.2 s into the window) |
| Last packet | 2026-10-16 14:39:25.390009 (103.1 s span; then 8.1 s of silence) |
| Average packet size | 107.2 bytes |
| PCAP SHA256 | `addfcd3f32a612e7c729df9dbe1528de25569aa7e99c17f7de0f71c5849276f7` |

Note the shape of the 180 s: the link was **completely silent for the first
69 seconds**, then WS001 emitted three short multicast bursts, then the link went
silent again for the final 8 seconds.

## 4. Hosts

| Host | IP | MAC | Packets | Note |
| --- | --- | --- | --- | --- |
| `SOC002-WS001` | `192.168.56.102` | `08:00:27:81:7a:74` | **18** | the only transmitter in the capture |
| `SOC002-DC1` | `192.168.56.10` | `08:00:27:95:b3:02` | **0** | **absent from the capture entirely** |
| Kali sensor | `192.168.56.1` | `0a:00:27:00:00:00` | 0 | did not source or receive anything |

`192.168.56.102` is the only unicast address present. Every other destination is
a multicast group: `239.255.255.250` (SSDP), `224.0.0.22` (IGMP), `224.0.0.251`
(mDNS) and `224.0.0.252` (LLMNR). No frame was unicast to any lab host, and
**no frame involved the domain controller**.

## 5. Protocols

| Protocol | Packets |
| --- | --- |
| SSDP | 6 |
| IGMPv3 | 6 |
| mDNS | 4 |
| LLMNR | 2 |
| (UDP total) | 12 |
| **TCP** | **0** |
| **ARP / DHCP / IPv6 / ICMP** | **0 (not matched by the filter)** |

All 18 frames are Ethernet → IPv4 → UDP or IGMP. There is no IPv6 packet, no
ARP, no DHCP and no ICMP in the capture.

## 6. Safety: address confinement

Every address in the PCAP, and why it is inside the lab boundary:

| Address | Role |
| --- | --- |
| `192.168.56.102` | SOC002-WS001 — inside `192.168.56.0/24` |
| `224.0.0.22` | IGMP all-hosts group — link-local, TTL 1, not routable |
| `224.0.0.251` | mDNS group (RFC 6762) — link-local, non-forwarded |
| `224.0.0.252` | LLMNR group (RFC 4795) — link-local |
| `239.255.255.250` | SSDP group — administratively scoped |

**Routable unicast addresses outside `192.168.56.0/24`: none.** No Internet
traffic was captured or generated, and the out-of-lab stop condition was not
triggered.

## 7. DNS activity

Zeek produced `dns.log` with **6 records, 2 distinct query names, 1 source**:

| Query name | Count | Transport |
| --- | --- | --- |
| `soc002-ws001.local` | 4 | `udp/5353 -> 224.0.0.251` (mDNS) |
| `soc002-ws001` | 2 | `udp/5355 -> 224.0.0.252` (LLMNR) |

Both names are **WS001 resolving its own hostname** over peer-to-peer multicast
name resolution. This is ordinary Windows background name advertisement, not
name resolution against a DNS server.

- Queries to the DC/DNS server `192.168.56.10:53`: **0**
- Query for the AD domain (`soc002.local`), or any SRV/service lookup: **0**
- Unique-name volume: 2 names in the whole 180 s

**DET-202 needs ≥ 20 distinct query names in 30 s**; the capture reached 2 — 10 %
of the threshold.

## 8. TCP activity

**Zero TCP frames.** No SYN, no handshake, no refused/reset connection, no
session of any kind. The detector `DET-201` consumes TCP connection records from
`conn.log`; with no TCP at all it had **no input to evaluate**, so its silence
tells us nothing about it either way.

## 9. HTTP activity

**No HTTP.** No TCP ⇒ no HTTP-over-TCP, and Zeek produced **no `http.log`**.
`DET-203` consumes `http_request` events, so it was **not exercised**.

One point worth recording, because it looks superficially like a near-miss: the
6 SSDP `M-SEARCH` datagrams are periodically spaced (≈0 s, 3.0 s, 6.0 s) and
could be mistaken for a beacon. They are **not** HTTP-over-TCP, they are not a
DET-203 data source, and DET-203 correctly ignores them. No HTTP-level periodic
behaviour was present.

## 10. AD-related traffic observed

Checked explicitly for the network services a domain-joined Windows client uses,
and for any exchange with the domain controller:

| Signal | Observed |
| --- | --- |
| Any traffic involving `SOC002-DC1` (`192.168.56.10`) | **NONE** |
| DNS to a DNS server (53) | **NONE** |
| Kerberos (88 / 464) | **NONE** |
| LDAP / Global Catalog (389 / 636 / 3268 / 3269) | **NONE** |
| SMB (445) / NetBIOS (139) | **NONE** |
| RPC endpoint mapper (135) | **NONE** |
| NTP (123) | **NONE** |
| WinRM (5985) | **NONE** |
| LLMNR (5355) | present (2 pkts, WS001 self-name) |
| mDNS (5353) | present (4 pkts, WS001 self-name) |
| Windows discovery / SSDP (1900) | present (6 pkts) |

**Conclusion: no AD traffic was observed, benign or otherwise.** WS001 did not
contact the domain controller at all during the window — no logon, no Group
Policy, no directory lookup, no share access and no domain DNS query. The only
traffic is WS001's own local-network chatter.

## 11. Detection results (DET-201 / DET-202 / DET-203, unchanged)

Replay: Zeek 9.0.0, offline, `LogAscii::use_json=T`, loaded via the unmodified
`detections/zeek/phase2-load.zeek`. Output preserved in
`evidence/phase3b-benign-ad-validation/zeek-run/`.

| Detection | Fired? | Exercised? | Why |
| --- | --- | --- | --- |
| **DET-201** Network Service Discovery | **No** | **Not exercised** | Needs ≥ 10 failed TCP attempts, ≥ 5 ports, ≥ 2 hosts in 60 s. The capture has **zero TCP**, so the detector had no input. |
| **DET-202** DNS Burst / Unique Subdomain | **No** | **Not meaningfully exercised** | Needs ≥ 20 distinct query names in 30 s; the capture holds **2** distinct names (both WS001's own, via mDNS/LLMNR). The DNS code path ran, but the volume was nowhere near the decision boundary. |
| **DET-203** Periodic HTTP | **No** | **Not exercised** | Needs ≥ 5 HTTP requests on one `(src,dst)` pair with CV ≤ 0.05. There is **no HTTP and no TCP**, so no request intervals exist. |

Evidence that nothing fired: the replay produced **no `notice.log`** and **no
`phase2_detections.log`**, and `stderr` was empty. Because
`phase2_detections.log` is the structured output stream *only written when a
detection fires* (`detections/zeek/det-common.zeek`), its absence is positive
evidence of a zero-firing run, not merely a missing file.

### Alerts requiring investigation

**None.** No detection fired, so there is no alert to triage, no incident to
raise, and nothing to escalate. The only "events" in the capture are WS001's own
multicast chatter, which is expected Windows background behaviour on an isolated
segment and would not warrant an alert even if a rule had matched it.

### False-positive statement (per the tasking)

No detection fired in this capture. Therefore **there is no firing that could be
assessed as a true or false positive, and no false-positive rate may — or may
not — be claimed from this single capture.** Nothing in this bundle is labelled a
false positive; nothing is labelled a false negative either, because the
behaviours the detections look for simply did not occur.

## 12. Integrity verification

Full checklist in `evidence/phase3b-benign-ad-validation/analysis/final-verification.txt`;
pre/post snapshots and their diff in `integrity/`.

| Check | Result |
| --- | --- |
| SOC-001 unchanged | **PASS** — 0 changed files vs the pre-capture baseline (18 files) |
| SOC-002 unchanged | **PASS** — 0 changed files (332 files; `.git` excluded) |
| Phase 1 unchanged | **PASS** — `sha256sum -c evidence/phase1-zeek-baseline/SHA256SUMS.txt` → 3/3 OK |
| Phase 2 unchanged | **PASS** — `sha256sum -c .../phase2-controlled-network-behaviour/hashes/SHA256SUMS.txt` → **49/49 OK** (includes DET-201/202/203, det-common, phase2-load) |
| Detections unmodified / not tuned | **PASS** — byte-identical to the Phase 2 inventory |
| No Git repository created | **PASS** — `soc-003` is not a git repository |
| No files outside SOC-003 modified | **PASS** — `find ~/soc-lab -newermt '14:36:00' ! -path './soc-003/*'` → empty |
| No Suricata installed | **PASS** — not found; `dpkg` count 0; `/opt` holds only `zeek` |
| No package installed | **PASS** |
| Network / VM configuration unchanged | **PASS** — pre/post snapshots identical (same 2 running VMs, same `ip addr`, same `ip route`, `ip_forward` still 1, no `VBoxManage modify*`) |
| No Internet traffic captured or generated | **PASS** |
| Capture confined to `vboxnet0` + `192.168.56.0/24` | **PASS** — one interface block, filter string recorded |
| No `sudo` used | **PASS** |
| No credentials exposed | **PASS** |

**Pre/post diff:** `changed=0, removed=0, added=1` — the single addition is
`scripts/phase3b_analyze.py`, a new Phase 3B artifact. Nothing that Phase 3B was
required to leave untouched changed.

## 13. SHA256 evidence

Input PCAP:

```
addfcd3f32a612e7c729df9dbe1528de25569aa7e99c17f7de0f71c5849276f7  capture/phase3b-benign-ad.pcap
```

Verify the whole bundle:

```
cd evidence/phase3b-benign-ad-validation/hashes && sha256sum -c SHA256SUMS.txt
```

The bundle also carries `manifest.json` (per-artifact path/sha256/size/role) and
`capture/phase3b-benign-ad.pcap.sha256.txt`.

## 14. Limitations

1. **The lab was quiet again.** 18 packets in 180 s; the segment was silent for
   the first 69 s and the last 8 s. This run did not produce the
   operator-generated AD/DNS traffic it was launched for.
2. **No AD / DNS-server traffic was observed at all** — no DC1 frame, no logon,
   no LDAP/Kerberos/SMB, no DNS query to a DNS server. The objective is unmet.
3. **Two of three detections were not exercised** (DET-201, DET-203 need TCP/HTTP
   that never appeared); DET-202 saw 2 distinct names against a threshold of 20.
4. **One capture proves nothing about rates.** No false-positive/negative rate,
   sensitivity or miss-rate claim is made or implied.
5. **Multicast/IPv4-only blind spot.** The unchanged filter `net
   192.168.56.0/24` does not match IPv6 or non-IP ARP/DHCP frames. WS001 does
   advertise an IPv6 link-local address in its mDNS reply, so some segment
   traffic remains outside this capture by design.
6. **Offline replay, single sensor.** Deterministic and reproducible, but it is
   Zeek's view of the recorded bytes from the Kali host's NIC, not a live
   deployment and not a second vantage point.

The same points are recorded in `analysis/limitations.txt`.

## 15. What this phase proves, and does not prove

**Proves.** That the sensor's visibility of `vboxnet0` is intact and that a
bounded, unprivileged, correctly-filtered capture can be taken and replayed
reproducibly; that the unchanged detections run cleanly under Zeek 9.0.0 and do
**not** fire on WS001's ordinary multicast background chatter; and that the
Phase 3B write scope, and SOC-001/SOC-002/Phase 1/Phase 2 integrity, held.

**Does not prove.** That the detections are validated against real benign AD/DNS
traffic — the traffic never appeared. It also does not prove the detections are
free of false positives on that traffic, because they were never given the
opportunity to fire on it.

## 16. Recommendation for the next run

The blocker is **operational, not technical**: the lab must actually be *used*
during the window. A re-run should secure, in advance, a short scripted-but-real
operator session on WS001 that produces the missing inputs **without** violating
this phase's rules — for example, logging in / unlocking WS001 and running a
handful of *ordinary* interactive actions (open a domain share, resolve a few
internal names, let Group Policy apply), which by itself yields Kerberos/LDAP/
SMB and DNS-to-DC1 traffic. Then repeat this exact capture/replay procedure. Only
after such a capture contains DC1 traffic should any statement about the
detections be made. Do **not** tune thresholds on the strength of this empty
capture.

Whether to widen the capture filter (IPv6/ARP/DHCP) is a separate decision that
changes a safety control and should be made explicitly, not by default.

---

## Appendix A — Evidence map

```
evidence/phase3b-benign-ad-validation/
├── README.md
├── capture/
│   ├── capture-command.txt              exact command, dumpcap -D interface list, timestamps
│   ├── capture-run.log                  dumpcap stdout/stderr (CR-normalised)
│   ├── phase3b-benign-ad.pcap           18 pkts / 180 s
│   ├── phase3b-benign-ad.pcap.sha256.txt
│   ├── pcap-validation-capinfos.txt
│   └── pcap-validation-tshark.txt        protocol hierarchy, endpoints, conversations, packet list
├── zeek-run/
│   ├── conn.log                          3 records (UDP, WS001 -> multicast)
│   ├── dns.log                           6 records (mDNS + LLMNR self-name)
│   ├── packet_filter.log
│   ├── ABSENT-LOGS.txt                   http/notice/reporter/weird/phase2_detections NOT produced, and why
│   ├── zeek-run-metadata.txt
│   └── zeek-run-stdout.txt / zeek-run-stderr.txt   (both empty)
├── analysis/
│   ├── hosts-and-protocols.txt
│   ├── safety-address-check.txt
│   ├── dns-activity.txt
│   ├── tcp-activity.txt
│   ├── http-activity.txt
│   ├── ad-related-traffic.txt
│   ├── detection-results.txt             per-detection fire / no-fire + why
│   ├── zeek-telemetry-summary.txt
│   ├── limitations.txt
│   ├── final-verification.txt
│   └── telemetry-summary.json
├── integrity/
│   ├── pre-phase3b-baseline.txt
│   ├── post-phase3b-integrity-check.txt
│   └── phase3b-integrity-diff.txt
└── hashes/
    ├── SHA256SUMS.txt
    └── manifest.json
```

## Appendix B — Provenance hashes

| Artifact | SHA256 |
| --- | --- |
| `capture/phase3b-benign-ad.pcap` | `addfcd3f32a612e7c729df9dbe1528de25569aa7e99c17f7de0f71c5849276f7` |

`DET-201` / `DET-202` / `DET-203` / `det-common.zeek` / `phase2-load.zeek`
hashes are unchanged from Phase 2 and were verified with
`evidence/phase2-controlled-network-behaviour/hashes/SHA256SUMS.txt` (49/49 OK).

---

**FINAL STATUS: PHASE 3B — PARTIAL / BLOCKED — objective not met.**

Visibility of real lab traffic on `vboxnet0` was confirmed again, the unchanged
detections replayed cleanly over genuinely captured traffic, and **no detection
fired**. But WS001 never contacted DC1 and the capture contained **no AD
traffic, no TCP, no HTTP and no DNS to a DNS server**, so two of the three
detections were not exercised and the third was not meaningfully exercised. The
phase cannot claim to have validated the detections against real benign AD/DNS
traffic. Per the tasking's own rules, no false-positive rate is claimed.

**Work stops here. Suricata was not installed and was not started. No further
phase was begun.**
