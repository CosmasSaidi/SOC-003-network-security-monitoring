# SOC-003 — Phase 3C Preflight Report
## WS001 ↔ DC1 connectivity preflight (read-only)

**Phase:** 3C — preflight / root-cause of the missing WS001↔DC1 unicast
**Status:** **PHASE 3C PREFLIGHT: PASS** — the cause of the missing unicast *was* determined, with evidence
**Consequence (separate from the preflight status):** the Phase 3 / 3B objective ("capture ordinary WS001↔DC1 domain traffic from `vboxnet0`") is **not achievable from the current sensor position** and is therefore **BLOCKED pending a user decision on capture architecture**
**Executed:** 2026-10-16, local 14:53 – 15:19 EAT (11:53 – 12:19 UTC)
**Host:** Kali GNU/Linux Rolling 2025.4 — the SOC-003 sensor (`192.168.56.1`)
**Tooling:** `dumpcap`/`capinfos`/`tshark` 4.6.0 (unprivileged), `VBoxManage` 7.2.8, the pre-existing WinRM (NTLM) read-only management channel
**Write scope:** this report + `evidence/phase3c-preflight/` only. **No lab configuration was changed.**

**Status in one line.** WS001 **is** exchanging ordinary unicast traffic with DC1 — continuously and observably from the guests — but **the `vboxnet0` capture point cannot see guest↔guest unicast frames at all**. Over 9 read-only captures (~12 minutes of capture) and with the host interface provably in promiscuous mode, every frame involving the sensor (Kali↔WS001/DC1 unicast TCP) and every broadcast/multicast frame from both guests was captured, and **not one frame between WS001 and DC1 was** — including a 170 s window in which WS001 demonstrably opened a *new* TCP connection to DC1 and DC1 demonstrably ingested WS001-forwarded events.

---

## 0. Objective

Determine **why WS001 is not generating / not observably exchanging ordinary unicast traffic with DC1**, following Phase 3 and 3B, which proved `vboxnet0` capture works, showed WS001 and DC1 broadcast traffic, but found:

- no WS001↔DC1 unicast,
- no TCP at all,
- no DNS queries to DC1.

## 0.1 Safety and method (what was and was not done)

| Rule | State |
| --- | --- |
| Read-only | **Complied.** No Windows setting, firewall, DNS, route, adapter, VirtualBox networking, IP address, `ip_forward`, service or VM state was modified. Nothing was installed, restarted, rebooted, initialised in Git, or re-hashed/tuned. |
| Active traffic generation tests | **Not performed.** No ping, no `Test-NetConnection`, no `Resolve-DnsName`, no `nltest`, no scans, no probes. Tests that would require generated traffic are listed in §9 as *not performed*. |
| Capture | **Passive only**, `vboxnet0`, bounded, unprivileged `dumpcap`, 0 packets dropped in every run. Three filter shapes were used (see §3.3) — including a permissive MAC-scoped filter so that nothing from either guest could be filtered away. |
| Management channel | Read-only inspection of WS001/DC1 used the **pre-existing SOC-002 WinRM/NTLM channel** from Kali. This is itself unicast traffic on `vboxnet0` and is disclosed as a known, unavoidable confound: it is what makes host-involved unicast *visible* in the captures (§3.3), and it may itself provoke WS001→DC1 authentication traffic. No credentials were read into any artifact, printed, or stored. |
| Scope of writes | This report and `evidence/phase3c-preflight/`. Nothing under SOC-001 / SOC-002 / Phase 1 / Phase 2 was touched. |
| Integrity of prior phases | Phase 2 evidence re-verified during this phase: `sha256sum -c` over `evidence/phase2-controlled-network-behaviour/hashes/SHA256SUMS.txt` → **49/49 OK** (includes `DET-201`, `DET-202`, `DET-203`, `det-common.zeek`, `phase2-load.zeek`). Prior captures were read, never rewritten. |

**Interpretation rule applied throughout:** no conclusion is drawn from a single failing command. Where a probe failed (for example `Get-NetAdapterStatistics -Name Ethernet`, which returned "No MSFT_NetAdapterStatisticsSettingData objects found" on both hosts), an equivalent read-only method was used instead (`netstat -e`, `Get-CimInstance Win32_PerfRawData_Tcpip_NetworkInterface`).

---

## 1. Observed WS001 state

Source: `evidence/phase3c-preflight/ws001/ws001.out` (read-only WinRM).

| Item | Observed value |
| --- | --- |
| Host / domain | `SOC002-WS001`; `Domain=soc002.local`, `PartOfDomain=True`, `DomainRole=1` (member workstation) |
| Current logon context | Interactive console session is **active**: `quser` → `administrator`, session id 1, state `Active`, logon 16/10/2026 13:51 (one minute after boot); `Win32_ComputerSystem.UserName = SOC002\Administrator`; `explorer.exe` running in session 1. Read-only management access is as `soc002\administrator` (SID `S-1-5-21-..-500`). |
| Adapter | one adapter, `Ethernet`, Intel PRO/1000 MT Desktop Adapter, `Status=Up`, `LinkSpeed=1 Gbps`, `MediaConnectionState=Connected`, `AdminStatus=Up`, ifIndex 7, MAC `08-00-27-81-7A-74` |
| IP configuration | `192.168.56.102/24` **Preferred**, `PrefixOrigin/SuffixOrigin=Dhcp`, `AddressState=Preferred`; lease obtained 16/10/2026 13:50:41, expires 15:00:42; DHCP server `192.168.56.100` (the VirtualBox host-only DHCP server) |
| Default route | **none.** `ipconfig /all` → *Default Gateway . . . :* (blank). `route print -4` shows only `127.0.0.0/8`, `192.168.56.0/24 on-link`, `192.168.56.102/32`, `192.168.56.255/32`, `224.0.0.0/4`, `255.255.255.255/32`. `Get-NetRoute` agrees; no `0.0.0.0/0`. **This is correct and expected for an isolated host-only segment**, and it is irrelevant to DC1 because DC1 is on-link. |
| DNS configuration | DNS server = `192.168.56.10` (DC1), DNS suffix search list `soc002.local`, `RegisterThisConnectionsAddress=True`, `Node Type=Hybrid`, NetBIOS over TCP/IP enabled, DNS Client (`dnscache`) `Running/Automatic` |
| Relevant services | `dnscache` Running, `Netlogon` Running, `lanmanserver` Running, `lanmanworkstation` Running, `WinRM` Running |
| Network profile | `NetworkCategory=DomainAuthenticated`, `DomainAuthenticationKind=Ldap`, `Name=soc002.local`, `IPv4Connectivity=NoTraffic`, `IPv6Connectivity=NoTraffic` |
| Firewall | Domain/Private/Public all `Enabled=True`, default actions `NotConfigured` (no outbound block configured) |
| IPv6 | link-local only (`fe80::73f0:1da1:b17d:98a2`), no global address |
| Uptime | last boot 16/10/2026 13:50:22 |

**Is the adapter actually communicating on `192.168.56.0/24`? Yes** — direct evidence in §5 and §6 (live TCP sessions to DC1, `Reachable` ARP entries for DC1 and Kali, DHCP lease from `192.168.56.100`, DNS/GPO/time-service activity).

---

## 2. Observed DC1 state

Source: `evidence/phase3c-preflight/dc1/dc1.out`, `dcx.out`.

| Item | Observed value |
| --- | --- |
| Host / domain | `SOC002-DC1`; `Domain=soc002.local`, `PartOfDomain=True`, `DomainRole=5` |
| Adapter | one adapter, `Ethernet`, Intel PRO/1000 MT Desktop Adapter, `Status=Up`, `1 Gbps`, `MediaConnectionState=Connected`, ifIndex 5, MAC `08-00-27-95-B3-02` |
| IP configuration | `192.168.56.10/24`, `PrefixOrigin/SuffixOrigin=Manual` (static), no gateway |
| Route | only `127.0.0.0/8`, `192.168.56.0/24 on-link`, own `/32`, `192.168.56.255/32`, `224.0.0.0/4`, `255.255.255.255/32` — no default route |
| DNS configuration | clients = `::1`, `127.0.0.1` (itself) |
| DNS server state | zones `soc002.local` and `_msdcs.soc002.local` (AD-integrated, `Primary`), plus `0/127/255.in-addr.arpa`; A records include `soc002-dc1 → 192.168.56.10`, `SOC002-WS001 → 192.168.56.102`, `@ / DomainDnsZones / ForestDnsZones → 192.168.56.10` |
| Services | `NTDS`, `DNS`, `Netlogon`, `W32Time`, `WinRM` all `Running/Automatic` |
| Neighbor state for WS001 | `192.168.56.102 → 08-00-27-81-7A-74`, **State = Reachable** (ARP-confirmed) |
| Live sessions toward/from WS001 | `TCP 192.168.56.10:49716 → 192.168.56.102:5985 ESTABLISHED PID 828 (svchost.exe — Windows Event Collector)`; listeners `:53` (PID 2144, DNS), `:139`, UDP `:53/:88/:137/:138/:464` |
| WEF (domain-relevant to WS001) | subscription `SOC002-WS001-Security`: `Enabled: true`, `SubscriptionType: CollectorInitiated`, **`DeliveryMode: Pull`**, `DeliveryMaxItems: 1`, `DeliveryMaxLatencyTime: 5000`, **`HeartbeatInterval: 5000`**, `TransportPort: 5985`, source `SOC002-WS001.soc002.local` enabled, target log `ForwardedEvents` |
| WEF delivery reality | `ForwardedEvents` newest entries **15:16:18** (Security 4688, Sysmon 1/3, PowerShell 4104 — i.e. WS001-sourced), **942 events in the 30 minutes** preceding the reading |

**DC1 is healthy, reachable and actively exchanging domain/WEF traffic with WS001.** Note the WEF cadence implied by `DeliveryMode: Pull` with `DeliveryMaxLatencyTime`/`HeartbeatInterval` of 5000 ms: DC1 is expected to poll WS001 over HTTP/5985 on the order of every few seconds, which is a steady, ordinary, on-link unicast conversation.

---

## 3. Observed Kali / `vboxnet0` state

Source: `evidence/phase3c-preflight/kali/kali-state.txt`.

### 3.1 Interface and host state

| Item | Observed value |
| --- | --- |
| `vboxnet0` | `UP`, `192.168.56.1/24`, MAC `0a:00:27:00:00:00`, MTU 1500, `<BROADCAST,MULTICAST,UP,LOWER_UP>` |
| Route | `192.168.56.0/24 dev vboxnet0` (sensor management uplink `wlan0` default route is out of capture scope and was never captured) |
| `ip_forward` | `net.ipv4.ip_forward = 1`, `net.ipv4.conf.vboxnet0.forwarding = 1` (host default). **Not exercised and not a factor:** both guests are on-link, neither guest has a default gateway, and Kali routed nothing for them. Not changed. |
| Neighbour table | `192.168.56.10 STALE (08:00:27:95:b3:02)`, `192.168.56.102 STALE (08:00:27:81:7a:74)`, plus both guests' IPv6 link-locals (STALE) — the sensor has exchanged L2 frames with **both** guests recently |
| Promiscuous mode during capture | **verified:** while `dumpcap` was running, `ip -d link` reported `promiscuity 2` and `/sys/class/net/vboxnet0/flags = 0x1103` (**IFF_PROMISC set**). The interface was **not** the reason VM-to-VM frames were missed. |
| Netdev packet counters | **not usable as a traffic gauge** (see §3.4) |

### 3.2 VirtualBox attachment state

Source: `VBoxManage list runningvms`, `list hostonlyifs`, `list dhcpservers`, `showvminfo --machinereadable`.

| Item | Observed value |
| --- | --- |
| VirtualBox | 7.2.8_Debian |
| Running VMs | `SOC002-DC1`, `SOC002-WS001` — **both running** |
| `vboxnet0` | `IPAddress 192.168.56.1 / 255.255.255.0`, `Status: Up`, `DHCP: Disabled` on the interface object, `MediumType Ethernet`, GUID `effffff9-dae8-4abf-8000-0a0027000000` |
| Host-only DHCP server | enabled: `Dhcpd IP 192.168.56.100`, range `192.168.56.101 – 192.168.56.254` (this is where WS001's `.102` lease comes from; the *server* is a separate object from the `DHCP:` flag above) |
| VM NICs | both VMs: `nic1="hostonly"`, `hostonlyadapter1="vboxnet0"`, `cableconnected1="on"`, MACs `080027817A74` / `08002795B302` — matching the frames seen on the wire. `nic2..nic8 = none`. |
| Per-VM network metrics | not enabled (`VBoxManage metrics query ... Net*` returns nothing). Enabling them would be a state change and was **not** done; it is listed as an option in §10. |

### 3.3 Capture visibility matrix (this phase)

Nine bounded captures, unprivileged `dumpcap -i vboxnet0`, **0 packets dropped in every run**. Full per-capture detail and hashes: `evidence/phase3c-preflight/captures/SHA256SUMS.txt` and `analysis/capture-visibility-matrix.txt`.

| PCAP | Window (EAT) | Filter | Pkts | Frames from/to **DC1** | VM↔VM frames (`any` ethertype) | TCP frames |
| --- | --- | --- | --- | --- | --- | --- |
| `unicast-test-145712` | 14:57:12–14:57:24 | `net 192.168.56.0/24` | 72 | 32 (Kali↔DC1) | **0** | 72 |
| `passive-145836` | 14:58:36–15:01:06 | `net 192.168.56.0/24` | 98 | 0 | **0** | 80 |
| `counter-150136` | 15:01:36–15:03:30 | `net 192.168.56.0/24` | 160 | 80 (Kali↔DC1) | **0** | 160 |
| `counter2-150446` | 15:04:46–15:05:56 | `net 192.168.56.0/24` | 142 | 47 (Kali↔DC1) | **0** | 122 |
| `counter3-150644` | 15:06:44–15:08:14 | `net 192.168.56.0/24` | 175 | 85 (Kali↔DC1) | **0** | 175 |
| `vm2vm-150913` | 15:09:13–15:10:43 | `ether host WS001 or ether host DC1` | **0** | 0 | **0** | 0 |
| `counter4-151057` | 15:10:57–15:11:36 | `ether host WS001 or ether host DC1` | 165 | 80 (Kali↔DC1) | **0** | 165 |
| `twin-151323` | 15:13:23–15:16:29 | `ether host WS001 or ether host DC1` | 112 | **0** | **0** | 80 |
| `promisc-151804` | 15:18:04–15:18:24 | `ether host WS001 or ether host DC1` | **0** | 0 | **0** | 0 |

What the captures **did** contain, in full:

- **Kali↔WS001 and Kali↔DC1 unicast TCP, complete and bidirectional** — e.g. `twin-151323` holds 46 `192.168.56.1 → 192.168.56.102 tcp/5985` frames and 34 `192.168.56.102 → 192.168.56.1` frames, all with Ethernet unicast MACs. **Unicast is manifestly visible to the sensor when the sensor is one of the endpoints.**
- **WS001 broadcast/multicast** — IGMPv3 to `224.0.0.22`, mDNS to `224.0.0.251`, LLMNR to `224.0.0.252`, SSDP to `239.255.255.250`, over both IPv4 and IPv6 (`0x0800`/`0x86dd` observed).
- **Host-sourced broadcast** — the VirtualBox DHCP server (`192.168.56.100`) ARP-probing for `192.168.56.102`.
- **Nothing else. Not one frame from, to, or between the two guests**, under any of the three filter shapes.

### 3.4 The netdev counters cannot be used as a traffic gauge

`/sys/class/net/vboxnet0/statistics/rx_packets` and `rx_bytes` are **persistently 0**, although the same interface demonstrably receives frames (hundreds captured). `tx_packets` moved 25008 → 25026 over ~4 minutes but **did not move at all** across a 15 s window in which 42 host-sourced unicast frames were captured on that interface. Reported for completeness; it means "current packet counters" on the Kali side are **not** a valid measure of lab traffic. Evidence: `kali/kali-state.txt`.

Guest-side counters are also unusable for arithmetic: WS001/DC1 `netstat -e` "Unicast packets" and the WMI per-NIC raw counters disagreed by a **uniform ~4× factor** in the same windows, and their byte/packet ratios implied frame sizes above the 1500-byte MTU. They were therefore used only qualitatively (see §5.3), never as a number.

---

## 4. Evidence of successful / failed resolution

**No live name-resolution probe was run** (it would generate traffic). Resolution was established from cached state and from the DC side.

| Question | Evidence | Verdict |
| --- | --- | --- |
| Is WS001's DNS client pointed at DC1? | `Get-DnsClientServerAddress` → `Ethernet {192.168.56.10}`; `ipconfig /all` → `DNS Servers . . . : 192.168.56.10` | **Yes** |
| Has WS001 successfully resolved the DC name `SOC002-DC1.soc002.local`? | WS001 DNS client cache: `SOC002-DC1.soc002.local type 1 status 0 data 192.168.56.10` (Status 0 = success) | **Yes — a successful query is cached** |
| Can DC1 answer for the domain? | DC1 hosts AD-integrated zones `soc002.local` + `_msdcs.soc002.local` (SRV-capable) with A records for the DC and `SOC002-WS001`; DNS service Running | **Yes (server-side capability proven)** |
| Has WS001 successfully located the domain `soc002.local`? | `Get-NetConnectionProfile` → `NetworkCategory=DomainAuthenticated`, `DomainAuthenticationKind=Ldap` — Windows only classifies the network this way after successful domain DNS discovery + LDAP contact | **Yes, indirectly** |
| Do queries *reach* the DC over the wire *right now*? | Not tested live. A DNS query is unicast WS001→DC1:53 — precisely the class of traffic that §3.3 proves is invisible at the capture point | **Not testable from here without generating traffic** |

No resolution failure was observed anywhere. There is **no evidence of an NXDOMAIN, timeout, or DNS misconfiguration** on WS001 or DC1.

---

## 5. Evidence of successful / failed connectivity

### 5.1 Live, confirmed, bidirectional WS001↔DC1 connectivity

| Evidence | Detail |
| --- | --- |
| WS001 → DC1 TCP, established with data | `192.168.56.102:49771 → 192.168.56.10:49668 ESTABLISHED PID 560 = **lsass.exe**` (LSA/domain secure-channel RPC to DC1), observed at 15:13:28 |
| Connection churn proves *recent* activity | WS001 ephemeral ports to `DC1:49668` advanced `49752/49753/49754` (14:55) → `49768/49769/49770` (15:12) → `49769/49770/49771` (15:13:28) → `49772` (15:16:17), with rolling `TIME_WAIT` entries: **a fresh TCP connection to DC1 is created roughly every 1–2 minutes** |
| DC1 → WS001 TCP, established | `192.168.56.10:49716 → 192.168.56.102:5985 ESTABLISHED PID 828 (svchost — Windows Event Collector)`, present continuously from 14:55 through 15:16 |
| WS001 → DC1 at the application layer | DC1's `ForwardedEvents` received **942 WS001-sourced events in 30 minutes**, newest **15:16:18** (Unix-time WEF pull, per the subscription config) |
| WS001 ← DC1 time service | `w32tm` status: `Source SOC002-DC1.soc002.local`, `Last Successful Sync 16/10/2026 14:42:21`, `Poll Interval 2048s`; Time-Service events 37/35 at 13:50:53 / 13:51:09 record NTP from `192.168.56.10:123` |
| L2 reachability, both directions | WS001's ARP entry for `192.168.56.10` = **Reachable**; DC1's entry for `192.168.56.102` = **Reachable** |
| DC1 ↔ Kali | DC1's WinRM listener answered the sensor's read-only management channel; the full Kali↔DC1 unicast TCP exchange was captured |

### 5.2 "Ability to reach 192.168.56.10" — answered without a probe

WS001 reaches DC1 and DC1 reaches WS001 **as a matter of continuously observed fact** (established TCP sessions in both directions, RPC churn, WEF delivery, NTP synchronisation, mutual `Reachable` neighbour state). A ping would add nothing and was not sent.

### 5.3 What the guest-side counters said (qualitative only)

Over three aligned measurement windows, WS001's and DC1's own NIC counters incremented by hundreds of unicast packets while the simultaneous captures recorded only the Kali-involved frames (e.g. window 15:11:03→15:11:39: captions-side capture saw 45 WS001 frames and 40 DC1 frames; the guests' own counters reported increments several times larger, and WS001's *received* count closely tracked DC1's *transmitted* count in the same window). Because the two counter sources disagreed by a uniform ~4× and implied impossible frame sizes, **no packet rate is stated from them.** They are consistent with — but are not proof of — a continuous WS001↔DC1 unicast conversation, which is independently proven by the WEF delivery, RPC churn and socket state above.

### 5.4 Failures observed (for completeness)

| Probe | Result | Interpretation |
| --- | --- | --- |
| `Get-NetAdapterStatistics -Name Ethernet` (both hosts) | error: no such instance | cmdlet parameter issue, not a network fault — equivalent data obtained via `netstat -e` / WMI |
| `Get-NetAdapterStatistics` on WS001 | empty output | as above; **not** treated as a fault |
| `netstat -e` / WMI per-NIC counters | mutually inconsistent (~4×) | emulated-NIC counter artefact; **not** treated as a fault |
| `vboxnet0` netdev counters | `rx_packets`=0 permanently | driver-level counter artefact; **not** treated as a fault |

**No connectivity failure of any kind was found on WS001 or DC1.**

---

## 6. ARP / neighbour observations

| Host | Entry | State | Note |
| --- | --- | --- | --- |
| WS001 | `192.168.56.10 → 08-00-27-95-B3-02` | **Reachable** (14:55 and again 15:12) | ARP-confirmed within the reachable timer; the entry would decay to `Stale` in the absence of exchange |
| WS001 | `192.168.56.1 → 0A-00-27-00-00-00` | Reachable | the sensor |
| WS001 | `192.168.56.100 → 08-00-27-5E-9C-0A` | Stale | VirtualBox DHCP server (lease 13:50) |
| WS001 | `192.168.56.255`, `255.255.255.255`, `224.0.0.22/.251/.252`, `239.255.255.250` | Permanent | static broadcast/multicast entries, as expected |
| DC1 | `192.168.56.102 → 08-00-27-81-7A-74` | **Reachable** | the workstation |
| DC1 | `192.168.56.1 → 0A-00-27-00-00-00` | Reachable | the sensor |
| Kali | `192.168.56.10`, `192.168.56.102` | Stale (both), plus both link-locals | sensor has exchanged L2 frames with both guests |

**Key observation:** both guests hold *fresh, positively confirmed* neighbour state for each other, which on Windows only happens after successful ARP exchange. Yet **not one ARP frame from either guest** was captured in any of the nine captures — while the *host*'s own ARP probe toward WS001 (`192.168.56.100 → 192.168.56.102`, broadcast) **was** captured in `passive-145836` and in the Phase 3 Gate 2 PCAP. Guest-originated ARP is broadcast, so it would be visible if it were delivered; it is consistent with the guest↔guest invisibility finding and it also means the guests' mutual ARP exchanges happened between capture windows.

---

## 7. Most likely explanation(s)

**Primary — a capture-point limitation, not a traffic problem (strongly supported).**
The VirtualBox host-only switch (`VBoxNetAdp`/`VBoxNetFlt`) forwards guest↔guest frames inside the hypervisor, guest port to guest port. The host's `vboxnet0` receive path is delivered only (a) frames addressed to the host itself and (b) flooded broadcast/multicast. Consequences, all of which match every observation:

1. Kali↔WS001 and Kali↔DC1 unicast ⇒ **visible** (proven: full TCP sessions captured both directions).
2. Guest broadcast/multicast ⇒ **visible** (both VMs' IGMP/mDNS/LLMNR/SSDP; DC1's NetBIOS announcement in Phase 3 Gate 1).
3. WS001↔DC1 unicast (AD/WEF/RPC/DNS/NTP) ⇒ **invisible, always** — the class of traffic that Phase 3 and 3B went looking for.
4. Promiscuous mode is **not** the limiter: the host interface was verified in `IFF_PROMISC` during capture (`promiscuity 2`, flags `0x1103`), and a permissive `ether host WS001 or ether host DC1` filter (any ethertype, any direction) still recorded zero guest↔guest frames.

**Decisive corollary test.** `twin-151323.pcap` (170.7 s, 15:13:23–15:16:29, permissive MAC-scoped filter) captured 112 frames — 80 Kali↔WS001 WinRM frames and 32 WS001 multicast — and **zero frames involving DC1**, while *in the same window*:

- WS001 opened a **new** TCP connection to `192.168.56.10:49668` (lsass): ephemeral port `49771` at 15:13:28 → `49772` at 15:16:17, i.e. a full handshake (and FIN of the predecessor) inside the capture window; and
- DC1's `ForwardedEvents` log ingested WS001-generated events with the newest stamp **15:16:18** (942 in 30 min), which can only arrive over the WS001→DC1 WEF channel.

Traffic provably on the wire, capture provably covering the wire, capture provably permissive — **nothing recorded.** That is not a timing coincidence; it is a visibility boundary.

**Secondary — the Phase 3/3B filter could not have seen everything anyway (minor, additive).** The harness filter `net 192.168.56.0/24` does not match DHCP broadcast traffic sourced from `0.0.0.0`/`255.255.255.255`. Evidence: the VirtualBox DHCP server's ARP probe for `192.168.56.102` **is** in `passive-145836` and in Phase 3 Gate 2, but no DHCP frames are, even though WS001's lease was renewing around 15:00. This explains nothing about WS001↔DC1, but it is a second, independent blind spot in the existing harness.

**Tertiary — genuine sparsity (minor, and now moot).** The lab's guest↔guest unicast is real but low-rate and bursty (WEF pull cadence ≈ seconds, lsass RPC ≈ 1–2 min, NTP ≈ 34 min). Short captures can miss it *by timing*. This was the leading Phase 3B hypothesis and it is **not** sufficient to explain the result — the `twin` capture had certain traffic in-window and still saw none — but it remains true that a 90–180 s capture is a weak sampling instrument.

**Explicitly excluded as causes** (all inspected, all healthy): WS001 IP address/subnet/mask, DNS server configuration, DNS suffix, default-route/on-link routing correctness, adapter state and link speed, domain membership (`PartOfDomain=True`), logon/domain context (`soc002\administrator`), DC1 IP/adapter/route/DNS-zone/service state, VirtualBox NIC attachment (`hostonly`/`vboxnet0`/cable connected), host-only DHCP function, and the sensor interface's promiscuous-mode state.

---

## 8. What can be concluded

1. **WS001 is generating and exchanging ordinary unicast traffic with DC1 right now** — established TCP sessions in both directions (lsass→DC1 RPC, DC1 WEC→WS001:5985), repeated connection churn, WEF event delivery (942 events / 30 min, newest 15:16:18), NTP synchronisation from DC1, and mutually `Reachable` neighbour state. The premise "WS001 is not generating unicast" is **false**.
2. **The reason it was not observed is the capture point.** On this VirtualBox host-only configuration the sensor's `vboxnet0` capture sees (i) frames addressed to the sensor and (ii) flooded broadcast/multicast — and **not** guest↔guest unicast. This is confirmed by ~20 minutes of capture across two phases, three filter shapes, and a 170 s window where guest↔guest traffic is independently proven to have occurred.
3. **Therefore the Phase 3/3B findings are explained and are not lab faults:** "no WS001↔DC1 unicast", "no TCP", and "no DNS to DC1" are all *the same single blind spot* — every one of those flows is guest↔guest unicast. Conversely, the traffic that *was* seen (both VMs' broadcast/multicast, and the host-involved unicast) is exactly what this capture point can see.
4. **The sensor is healthy and correctly configured** for what it can see: unprivileged `dumpcap` works, the interface enters promiscuous mode, the correct host-only segment is attached, 0 drops, and both guests' frame-level presence on the segment is proven.
5. **Self-consistency check that supports the above:** WS001's DHCP-renewal ARP probes from `192.168.56.100` (a *host-owned* address) are captured, while guest↔guest ARP never is — the split is exactly "host or flooded" vs "guest-to-guest".
6. **The Phase 2 detections remain intact and integrity-verified** (49/49 hashes OK, re-checked during this phase); nothing was modified by Phase 3C beyond this report and its evidence folder.

## 9. What cannot be concluded

1. **Nothing about detection validity.** `DET-201`, `DET-202` and `DET-203` are still **not exercised**: the traffic they consume (guest↔guest TCP/DNS/HTTP) is unobservable from this position. Phase 3B's "not exercised" statements stand unchanged.
2. **No false-positive rate, no sensitivity, no precision/recall** — unchanged from Phase 3/3B, and no live alert was produced.
3. **No "current moment" resolution or reachability probe.** `ping`, `Test-NetConnection`, `Resolve-DnsName` and `nltest` were deliberately **not** run (they would require active traffic generation). Current-moment DNS reachability from WS001 to DC1 is therefore *inferred* from cached client state, socket state and DC-side logs, not asserted from a fresh query.
4. **No quantitative packet rates.** Guest NIC counters are mutually inconsistent (~4×) and imply impossible frame sizes; `vboxnet0` netdev counters read 0 for RX. Only qualitative statements are made.
5. **Not proven: the exact internal mechanism.** Whether the host-only switch never mirrors guest↔guest frames, or mirrors them only under some condition not met here, was **not** determined — only that they are not delivered to this capture path in this configuration/build. Nothing was changed to test alternatives.
6. **No claim that guest↔guest capture is impossible in general** — only that it does not work with this harness on this VirtualBox host-only setup, as observed.
7. **Nothing about IPC/other hosts, IPv6-only flows, security posture, patching, or the absence of other AD traffic** (Kerberos/LDAP/SMB volume was not measurable for the same visibility reason).
8. **No inference of failure from any single failed command** — the two cmdlet failures and the counter artefacts in §5.4 are measurement issues, not lab faults.
9. **The SOC-002 forwarding pipeline was observed, not validated** — Phase 3C read WEF configuration and event arrivals; it did not test their correctness or retention.

---

## 10. Minimal safe next action

**Do nothing to the lab.** Phase 3C made no changes and the finding does not indicate a fault that needs fixing. The next action is a **decision**, then a scoped phase:

1. **Adopt the corrected visibility model** for SOC-003: `vboxnet0` = *host-involved unicast + flooded broadcast/multicast only*. Every existing SOC-003 detection plan that assumes "we can watch WS001 talk to DC1" must be re-scoped. (Documentation change only.)
2. **Then choose one of these, in order of preference:**
   - **(A) Zero-change option — observe host-involved flows.** Have the sensor itself originate the benign lab traffic it wants to validate (Kali→WS001 and Kali→DC1: name resolution against DC1, ordinary HTTP to a lab service, ordinary session traffic). It is 100 % observable with today's harness (proven in §3.3) and needs no configuration change — but it is *sensor-initiated* traffic, so it validates detector behaviour on real AD-adjacent flows rather than *ordinary operator-generated* traffic from WS001.
   - **(B) Capture-point change — requires explicit user authorisation, out of scope for a read-only phase.** Options include: guest-side capture on WS001/DC1 with the built-in `pktmon` (no install, but it makes the *guest* the sensor and changes the SOC-003 architecture), or re-attaching the lab to a topology where the sensor is in-path (VirtualBox internal network with a promiscuous sensor NIC, or a mirror/SPAN arrangement). Each is a VirtualBox/VM configuration change and must be approved and documented as an architecture change.
   - **(C) Diagnostic confirmation only — `VBoxManage metrics setup` for the two VMs** to obtain hypervisor-side per-VM NIC counters (requires approval; enables metrics collection, changes no networking). This would *confirm* the volume of guest↔guest traffic independently of the guest OS, but it will not make that traffic capturable.
3. **Do not re-run the Phase 3/3B harness expecting a different result** (§11).
4. **If (A) is chosen later**, the same safety envelope applies: bounded capture, `vboxnet0` only, lab CIDR only, no scans/bursts/beacons, unmodified detections, evidence hashed.

## 11. Whether another live capture is justified

**No — not with the current capture point.** The question is already answered affirmatively and the null result is reproducible by construction: 4 prior PCAPs plus **9 new captures (~12 minutes of capture, three filter shapes, promiscuous mode verified, 0 drops)** produced zero guest↔guest frames, while guest↔guest traffic is independently proven to have occurred inside at least one of those windows. Another capture from the same position can only reproduce the same blind spot and would risk being misread as fresh evidence.

**A further capture *is* justified in exactly two situations:**

- **After the capture point changes** (option B in §10) — then a capture must be re-run to (i) confirm guest↔guest frames are now visible and (ii) re-do the benign AD/DNS validation the detections need. This should be its own authorised phase with a fresh preflight.
- **As a scoped, sensor-initiated validation** (option A in §10) — a bounded capture over traffic the sensor itself generates to WS001/DC1, run only with explicit authorisation for that traffic. This would exercise `DET-201`/`DET-202`/`DET-203` inputs but would **not** satisfy the original "observe WS001↔DC1" goal, and it must be reported as such.

---

## 12. Evidence bundle

`~/soc-lab/soc-003/evidence/phase3c-preflight/`

| Path | Contents |
| --- | --- |
| `README.md` | bundle index, method, hashes |
| `kali/kali-state.txt` | interface, routes, neighbours, counters, promiscuous flags, `VBoxManage` attachment/DHCP state |
| `ws001/` | `ws001.out` (full read-only state capture), `wse.out` (time-service/NETLOGON/GPO events), `wsx.out` (WinRM log, neighbour state, sockets), `C1/C2/Q1/Q2/S1/S2` (counter and socket snapshots) |
| `dc1/` | `dc1.out` (full state), `dcx.out` (WEC subscription, WEC process, WinRM log), `D1/D2/P1/P2/R3/R4` (counter snapshots) |
| `captures/` | the 9 PCAPs + `SHA256SUMS.txt` |
| `analysis/` | `capture-visibility-matrix.txt`, the PowerShell scripts used for read-only inspection |

**Captured PCAP SHA256 (this phase):**

```
cf23e0670cf687a458d3e48a908cb575e75a181f76129781258d97269610e193  counter-150136.pcap
2fa7c0a888fc3fd0ac329981ead8b946122b13b088bf216dfb6534762c9f298c  counter2-150446.pcap
4717377bc3726a2b6f6ecdeddf7d8b2ed773ee4fa0a9c29a7fbbf3cfcdc22bf8  counter3-150644.pcap
2767ccf2732f24659c48c1e82fc5d580eadf6930bc522802da0fb4091e50bab7  counter4-151057.pcap
02e51af6c5a7549eb03381d2fdeed7c94c35c3381649b5d8247c3790a695e80d  passive-145836.pcap
0d3149d9178ad52bc2847a15490000bc86f89bae82616219980a5252b6898b51  twin-151323.pcap
0cbd1e1e3514ed08e0f78a1eb041e2659c5ea800a86a3174271238957c39e8d1  unicast-test-145712.pcap
d7265f514dcad0f3aed83d172670062b30f708fc531209fa38c3a6daba5e5a03  vm2vm-150913.pcap
```
(plus `promisc-151804.pcap`, hashed in `captures/SHA256SUMS.txt`)

## 13. Integrity / no-change confirmation

| Check | Result |
| --- | --- |
| Windows settings / firewall / DNS / routes / adapter | **unchanged** — no write cmdlet was issued on either guest |
| VirtualBox networking, VM state, IP addresses | **unchanged** — all `VBoxManage` calls were `list` / `showvminfo` (read-only); no VM started, stopped, snapshotted or modified |
| `ip_forward` / host networking | **unchanged** (`1` before and after, `vboxnet0` config untouched) |
| Services / reboots / package installs | **none** |
| Zeek detections, Suricata, Phase 2 evidence | **unchanged** — Phase 2 hash inventory re-verified 49/49 OK; Suricata still not installed; no detection logic touched |
| SOC-001 / SOC-002 | **untouched** (read-only reads of phase evidence only) |
| Git | **no repository created or initialised** |
| Credentials | **none exposed** — the management channel read them from the local environment; no secret appears in any artifact |
| Writes | this report + `evidence/phase3c-preflight/` only |

---

## 14. Final status

**PHASE 3C PREFLIGHT: PASS**

The preflight objective — *determine why WS001 is not generating / not observably exchanging ordinary unicast traffic with DC1* — was met, with evidence: **WS001↔DC1 unicast traffic is real and continuous; the `vboxnet0` capture point cannot observe guest↔guest unicast.**

**Consequence for the downstream phase (reported separately, not a Phase 3C failure):** the Phase 3 / 3B goal of capturing ordinary WS001↔DC1 domain traffic from this sensor position is **BLOCKED** until the capture architecture is decided (§10). No live capture is justified before that decision (§11).

**STOP.**
