# SOC-003 — Phase 3D Report
## Guest-side network capture validation (WS001 pktmon → PCAPNG → Zeek)

**Phase:** 3D — prove that real WS001↔DC1 unicast traffic can be captured from the guest side and turned into a PCAP that Zeek can analyse
**Final status:** **PASS**
**Executed:** 2026-10-17, local 00:06 – 00:14 EAT (UTC 21:06 – 21:14 on 2026-10-16)
**Sensor:** Kali (`192.168.56.1`), existing SOC-003 Zeek 9.0.0 at `/opt/zeek`
**Capture point:** WS001 itself (`SOC002-WS001`, `192.168.56.102`), built-in Windows `pktmon`
**Evidence bundle:** `evidence/phase3d-guest-capture/` (43 files, `SHA256SUMS.txt` verified)
**Write scope:** `evidence/phase3d-guest-capture/**`, this report, and three helper scripts. **Nothing outside `~/soc-lab/soc-003` was created or modified.**

**Status in one line.** A bounded, IP-filtered capture taken *on WS001* captured **712 real WS001↔DC1 unicast packets (97.4 s, 0 drops, 0 packets from any other host, 0 Internet packets)**, converted cleanly to pcapng with the built-in `pktmon etl2pcap`, and replayed through the existing Zeek 9 — which parsed genuine **Kerberos, NTLM, LDAP, DCE/RPC, DNS and NTP** domain traffic. The endpoint-side timeline and the network-side timeline line up once WS001's measured **−1.83 s** clock offset is applied.

---

## 1. Objective

Prove, with evidence, that ordinary unicast traffic between `SOC002-WS001` (192.168.56.102)
and `SOC002-DC1` (192.168.56.10) — the traffic Phase 3C showed exists but that the host
capture point cannot see — **can be captured from the guest side and converted to a PCAP
that the existing Zeek installation will analyse**. This is a *visibility validation*, not
a detection exercise: no detections are to be manufactured, and none were.

## 2. Why host-side `vboxnet0` capture was insufficient

Phase 3C established this with nine bounded captures and did not need repeating:

- `vboxnet0` was provably in promiscuous mode (`IFF_PROMISC` set, `promiscuity 2`) during capture.
- Over ~12 minutes of capture, **every** frame involving the sensor (Kali↔guest unicast) and
  every broadcast/multicast frame from both guests was seen — and **not one** WS001↔DC1 frame was,
  even during a 170 s window in which WS001 opened a *new* TCP connection to DC1:49668 (lsass)
  and DC1's `ForwardedEvents` log ingested WS001-forwarded events.
- Both VMs are `nic1="hostonly"`, `hostonlyadapter1="vboxnet0"`, `nic2..8 = none`; each guest has a
  single NIC and no default gateway.

On this VirtualBox host-only configuration the frames between two guests are delivered to the
other guest and not to the host interface, regardless of promiscuous mode. The host capture point
is therefore structurally unable to see guest↔guest unicast here, which is why a guest-side capture
point is the only viable option. The topology was **not** changed to work around it.

## 3. Guest-side capture methodology

- **Tool:** the built-in Windows 10 `pktmon` (`C:\Windows\System32\PktMon.exe`, `10.0.19041.2913`,
  driver `E1G6032E.sys` component id 9). No third-party capture software was installed.
- **Access:** the pre-existing SOC-002 WinRM (NTLM) read/write management channel from Kali, used
  to run a scripted capture on WS001 and to pull the results back. No credential appears in any
  artifact.
- **Method:** `pktmon start --capture --comp 9 --pkt-size 0` (full packets, single NIC) with two
  `pktmon` filters applied first; traffic was generated only by ordinary domain operations on WS001;
  `pktmon stop`, `pktmon filter remove`, then `pktmon etl2pcap` to produce pcapng.
- **Why ETL, not PCAP, at capture time:** `pktmon start --file-name …` rejects a `.pcap`/`.pcapng`
  name ("Failed to start ETW session: The specified path is invalid"). Its native format is ETL and
  the conversion is a separate step. This was the only blocker encountered, and it is a naming/format
  constraint, not a capability limit — `etl2pcap` produced a valid pcapng on this build.
- **Transfer:** the pcapng, ETL, and run logs were copied to the Kali sensor over the existing
  host-only link (one-shot HTTP receiver bound to `192.168.56.1`). The receiver recomputed SHA256 and
  both the `.pcapng` and `.etl` hashes matched WS001's own values.
- **Cleanup:** filters removed, monitor stopped, and every `soc003-p3d*` temp file deleted from WS001
  (`ws001/ws001-cleanup.txt`: "NO soc003-p3d* FILES REMAIN UNDER C:\Windows\Temp", filters `None`).

Two small scripting notes for the record: `netdom.exe` is not present on this WS001 (RSAT not
installed), so that optional secure-channel query was dropped; and `wecutil gs` was run on the wrong
host (WS001 is a WEF *source*, not a collector — WEC is not running there, and DC1's `Wecsvc`
subscription is the authoritative one). Both are non-findings.

## 4. Exact capture scope

| Item | Value |
| --- | --- |
| Host / adapter | `SOC002-WS001`, "Ethernet", Intel PRO/1000 MT, ifIndex 7, MAC `08:00:27:81:7A:74` |
| Component captured | `9` — the single NIC (no other component selected) |
| Packet size logged | full packet (`--pkt-size 0`) |
| Filter 1 | `ws001-dc1-pair` — IPs **192.168.56.102 AND 192.168.56.10** (packets carrying both) |
| Filter 2 | `ws001-dns-dc1` — UDP port 53 to 192.168.56.10 (WS001's DNS to the DC) |
| Capture window | `2026-10-17T00:06:49.2249573+03:00` → `2026-10-17T00:08:30.2103655+03:00` (~101 s wall, ~97.4 s of traffic) |
| Explicitly out of scope | `wlan0`/uplink, any subnet other than 192.168.56.0/24, any host other than WS001/DC1 |

The two filters are conjunctive with `pktmon`'s "match all conditions" rule, so only WS001↔DC1
traffic can be logged. The scope is confirmed empirically in §5.

## 5. Traffic observed

Capture summary (`capinfos`): **pcapng, link type ether, 712 packets, 97.40668 s**,
earliest `00:06:49.889616`, latest `00:08:27.296296`, average 1374 B/packet.

**Exact scope — nothing else was captured:**

| Check | Result |
| --- | --- |
| Total frames | 712 |
| IPv4 / ARP | 710 / 2 |
| TCP / UDP | 689 / 21 |
| WS001→DC1 frames | 272 |
| DC1→WS001 frames | 438 |
| Frames from/to any other host | **0** |
| Frames outside 192.168.56.0/24 (Internet) | **0** |
| Frames involving the Kali MAC (`0a:00:27:00:00:00`) | **0** |
| Unique source / destination IPs | `192.168.56.102`, `192.168.56.10` (only) |
| DC1 ports contacted by WS001 | TCP 135, 389, 49668, 64213; UDP 53, 123 |

**What the traffic was** (tshark hierarchy and protocol detail):

- **Windows Event Forwarding / WinRM — the dominant flow.** A single long-lived TCP session
  `WS001:5985 ↔ DC1:64213` carried 564 frames / 947 kB of WEF-over-HTTP (`POST /wsman`,
  Kerberos-session-encrypted), pulling WS001's events to DC1 on the subscription's 5 s cadence.
- **Domain secure channel (LSASS/RPC).** WS001 opened RPC connections to DC1's endpoint mapper (135)
  and to the DC's dynamic RPC service (49668, `lsass` EPMAP) at 00:07:08 and 00:07:16 — this is the
  netlogon/secure-channel and LSA RPC path Phase 3C described.
- **DNS.** Resolution queries to the DC1 resolver on 192.168.56.10:53 (see §7): the host's own A
  record, and the `_ldap`/`_kerberos`/`_gc` SRV records.
- **LDAP** to DC1:389 and **NTP** to DC1:123 (three samples from the `w32tm /stripchart` probe).
- **ARP:** one request/reply pair mid-capture confirming L2 address resolution between the two hosts.

This is entirely ordinary, benign domain traffic — no scanning, no probe bursts, no Internet traffic.

## 6. PCAP validation (Kali, tshark/capinfos)

- `capinfos -M` parses the file cleanly: **pcapng**, encapsulation **ether**, one interface,
  **712 packets**, `Strict time order: True`, `Capture application: Packet Monitor`,
  `Capture oper-sys: Windows 10 Pro`, `SHA256 1e677617…92f5` (matches WS001 and the receiver).
- `pktmon etl2pcap` self-reported: **Packets total 712 / Packet drop count 0 / Packets formatted 712**.
- tshark reads the file without warnings and its protocol hierarchy names real protocols
  (http, mime_multipart, dcerpc, epm, drsuapi, ldap, dns, ntp), i.e. the pcapng carries usable
  L2–L7 content, not just counters.
- **No Internet traffic and no out-of-scope host was present** (§5), so the capture is exactly the
  WS001↔DC1 slice the objective called for. Full detail: `kali-analysis/pcap-validation-*.txt`,
  `scope-and-safety.txt`, `pcap-counts-and-safety.txt`.

## 7. Zeek replay results

Replayed with the existing `/opt/zeek/bin/zeek` 9.0.0 — **once with stock scripts and once with the
unchanged Phase 2 detection loader**. No Zeek configuration or detection script was modified.

```
cd evidence/phase3d-guest-capture/zeek-run/base
/opt/zeek/bin/zeek -r ../../ws001/ws001-dc1-guest-capture.pcapng LogAscii::use_json=T
# → exit 0, no warnings

cd ../with-detections
/opt/zeek/bin/zeek -r ../../ws001/ws001-dc1-guest-capture.pcapng LogAscii::use_json=T \
    ../../../../detections/zeek/phase2-load.zeek
# → exit 0, no warnings
```

**Logs produced and what they contain:**

| Log | Content of note |
| --- | --- |
| `conn.log` | 19 records. Services: `dns` ×6, `dce_rpc` ×4, `ntlm,dce_rpc` ×2, `krb,gssapi,dce_rpc` ×2, `ntp` ×3, `-` ×2. Includes the WEF session `DC1:64213 ↔ WS001:5985` (state `OTH`, duration 97.4 s). |
| `dns.log` | `soc002-dc1.soc002.local` A → 192.168.56.10; `_ldap._tcp`, `_kerberos._tcp`, `_gc._tcp` SRV → soc002-dc1.soc002.local; two `windowsupdate` names → `SERVFAIL` (DC resolves within the isolated lab). |
| `kerberos.log` | 2 events, `success: true` (WS001 → DC1:49668, 00:07:08 and 00:07:16). |
| `ntlm.log` | 2 events naming `server_nb_computer_name SOC002-DC1`, `server_dns_computer_name SOC002-DC1.soc002.local`, `server_tree_name soc002.local`. |
| `ldap.log` / `ldap_search.log` | bind `success`; one search returning 1 result. |
| `ntp.log` | 3 events, DC1 stratum 1, version 3. |
| `packet_filter.log` | `ip or not ip` applied successfully (the whole file is in scope). |
| `analyzer.log` | records the one long-lived HTTP/5985 analyser instance — a single WEF/WinRM session reused for the whole window. |
| `weird.log` | 2.8 kB of benign anomalies (e.g. RPC-over-WSMan byte-stream framing) — no security signal. |

**Detection outcome — nothing fired, and nothing was forced:**

- `notice.log` was **not created**; `phase2_detections.log` was **not created**.
- That is the correct result. In the same bounded window the only candidate signals were
  **1** DNS SRV/answer cluster, **8** new TCP connections to DC1 across **4** distinct ports and
  **1** host, and a *regular* 5-second WEF cadence (which is a keep-alive heartbeat, not periodic
  beaconing). DET-201 needs ≥10 non-established attempts across ≥5 ports and ≥2 hosts; DET-202 needs
  a DNS burst; DET-203 needs periodic HTTP to the same pair. None of these live benign patterns
  qualifies — and the detections were deliberately **not** tuned or re-thresholded to make them match.
- **DET-201 / DET-202 / DET-203 remain unexercised by live benign traffic.** Live benign WS001↔DC1
  domain traffic does not produce the behaviours they look for. They continue to be exercised by the
  Phase 2 controlled capture only.

## 8. Endpoint / network correlation findings

The correlation below is supported by evidence; nothing stronger is claimed.

- **Clock relationship (measured, not assumed).** `w32tm /stripchart /computer:192.168.56.10`
  on WS001 reported a stable offset of **−1.829 s** (WS001 − DC1) across three samples
  (00:07:25/27/29). All comparisons below use that ±2 s tolerance. DC1 runs EAT (UTC+03:00), the
  same zone as the sensor, so timestamps are directly comparable.
- **Phase 3C's continuous WEF flow is reproduced live.** On the wire, `WS001:5985 ↔ DC1:64213`
  carries a WEF-over-HTTP conversation for the entire 97.4 s window. On the endpoint side, DC1
  ingested WS001-forwarded events continuously (newest 00:08:36 during the run; 218 events in the
  5 minutes after the capture). This is the same steady WEF conversation Phase 3C inferred from
  `ForwardedEvents` growth — now seen directly on the network.
- **The LSASS/RPC traffic Phase 3C noted is captured.** WS001 opened RPC sessions to DC1's endpoint
  mapper (135) and to DC1:49668 (the `lsass` EPMAP endpoint) at 00:07:08 and again at 00:07:16.
  The wire timestamps sit inside the endpoint-side wave-3 window (`wave3_ts = 00:07:08.26`, wave-4
  `00:07:16.60`), i.e. within the ±2 s tolerance. Zeek decoded these as `dce_rpc`, one of them
  `ntlm,dce_rpc` and one `krb,gssapi,dce_rpc`, and NTLM named the DC explicitly.
- **The endpoint command sequence is visible on the wire at the expected time.** The `nltest`
  secure-channel check (00:06:51) and the `nltest /dsgetdc` discovery (00:07:08) precede the DNS
  SRV lookups Zeek logged at 00:07:00 and the 135/49668/389 RPC connections at 00:07:08–00:07:16;
  the `w32tm /stripchart` probe (00:07:25) is exactly the three NTP exchanges Zeek logged at
  00:07:25, 00:07:27 and 00:07:29.
- **A 60-second hold window shows no fresh short-lived connections** (only the long-lived WEF
  session and a persistent RPC channel remain). That the visible connections in the busy window
  are attributable to named, deliberate endpoint operations (§3) is therefore a fair conclusion,
  not an artefact of unattributed background traffic.
- **Boundary of the claim.** This is **temporal + protocol** correlation between endpoint-side
  operation timestamps and the network-side flow records (Kerberos/NTLM/LDAP/DNS/NTP decoded,
  naming `SOC002-DC1`/`soc002.local`). Deep host attribution — e.g. mapping a specific LSASS PID to
  a specific TCP connection — is **not** claimed; `pktmon` output has no PID, and no host-side EDR
  capture was in scope.

## 9. Limitations

1. **Application-payload blindness.** The WEF/WinRM body is Kerberos-session-encrypted, so its
   contents are not visible; only the envelope (`POST /wsman`, cadence, sizes) is. The RPC traffic
   is likewise seen only as transport plus bound interfaces, not as RPC operations.
2. **`pktmon` on the end host sees the NIC only.** Traffic that never reaches the WS001 NIC
   (loopback, or anything a host firewall would drop before the NIC) is out of scope by design.
3. **No PID / process attribution** in `pktmon` output, so §8's correlation is temporal and protocol
   based (§8, "Boundary of the claim").
4. **`conn.log` under-represents long-lived flows.** Zeek only writes a `conn` row when a connection
   closes or times out, so the full-window WEF session appears as a single `OTH` row (97.4 s) plus
   the analyser logs, rather than per-message flows. This is normal Zeek behaviour, not a capture fault.
5. **Small, short, benign window.** 712 packets / 97 s of deliberately ordinary domain traffic. The
   sample is enough to prove visibility and correlation; it is not a baseline and cannot exercise
   detections that need attack-shaped volume or periodicity.
6. **`with-detections` run is a negative control, not a detection test.** It shows the detections do
   not misfire on live benign traffic; it does not re-validate that they fire on the Phase 2 capture
   (that remains Phase 2's result).
7. **Clock offset is first-order.** Correlation is stated to ±2 s; sub-second ordering between an
   endpoint action and its packet is not asserted.

## 10. Integrity verification

Full run recorded in `evidence/phase3d-guest-capture/integrity/prior-phases-verification.txt`.

| Target | Method | Result |
| --- | --- | --- |
| Phase 1 evidence | `sha256sum -c` over its manifest | 3/3 OK (+ 3/3 OK for `zeek-output`) |
| Phase 2 evidence | `sha256sum -c` over `hashes/SHA256SUMS.txt` | **49/49 OK** |
| Phase 3 evidence | `sha256sum -c` over `hashes/SHA256SUMS.txt` | **52/52 OK** |
| Phase 3B evidence | `sha256sum -c` over `hashes/SHA256SUMS.txt` | **35/35 OK** |
| Phase 3C evidence | `sha256sum -c` over `captures/SHA256SUMS.txt` | **9/9 OK** |
| **Total prior-phase checks** | | **148 OK, 0 FAILED** |
| SOC-001 | `evidence/soc-001-capture/` listing | all artifacts still dated 2026-10-11, untouched |
| SOC-002 | `SOC-002-PUBLIC` `git status --porcelain` | **0 changes**; `HEAD ba479eb3…` unmoved |
| SOC-002 lab config | files under `SOC-002-windows-ad` newer than 2026-10-16 | none (only running-VM runtime logs, rewritten while the VMs are powered on) |
| Zeek installation | `find /opt/zeek -type f -newermt '2026-10-16 13:00'` | **0** — untouched |
| Detection scripts | mtimes under `detections/zeek/` | still 2026-10-16 13:28–13:29 — unchanged |
| Writes outside `soc-003` | `find ~/soc-lab -maxdepth 1 -newermt …` | none (only this task's own prompt files at the top level) |
| Lab health after capture | WS001 pktmon state + DC1 services/WEF | WS001: filters `None`, monitor stopped, no temp files. DC1: NTDS/DNS/Netlogon/W32Time/WinRM/Wecsvc/EventLog all Running; WEF subscription Enabled/Pull; WEF still delivering |

**New Phase 3D evidence hashes:** `evidence/phase3d-guest-capture/SHA256SUMS.txt` — 43 files,
`sha256sum -c` → **43 OK, 0 FAILED**. Key hashes:

- `ws001/ws001-dc1-guest-capture.pcapng` → `1e6776170b67bc7b34ace1b072ef220556eccae7352edb27049963b646d092f5`
- `ws001/ws001-dc1-guest-capture.etl` → `c5f84d71f418d9aec6f22b27053c0c24bf2d92d0b904c18b910d3ea64d7d360c`
- driving script `scripts/phase3d_ws001_capture.ps1` → `9c38dfe096f9a921abdb2fd2981bd97d8c7b700a21e6576dd7606b8c38203d94`

## 11. Final status

## **PASS**

Guest-side capture on WS001 with the built-in `pktmon` captured **712 real WS001↔DC1 unicast
packets** with **0 drops, 0 out-of-scope hosts and 0 Internet traffic**, converted them to a **valid
pcapng** with the built-in `pktmon etl2pcap`, and the **existing Zeek 9** parsed **Kerberos, NTLM,
LDAP, DCE/RPC, DNS and NTP** from it. The network-side flow records temporally match the named
endpoint operations once the measured **−1.83 s** WS001↔DC1 clock offset is applied, reproducing live
the WEF and LSASS/RPC activity Phase 3C had inferred.

The capture validated **network visibility and endpoint↔network correlation**, which was the
objective. It did **not** exercise any detection: **DET-201, DET-202 and DET-203 remain unexercised
by live benign traffic** and were deliberately not tuned or forced to fire. No AD DS, DNS, WEF,
Sysmon, PowerShell-logging or SOC-002 configuration was disturbed; the Windows/AD lab and the Zeek
installation are unchanged; all prior-phase evidence verifies clean.

Work stops here.
