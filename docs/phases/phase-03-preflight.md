# SOC-003 — Phase 3 Preflight / Reconnaissance Report

**Phase:** 3 (preflight only — reconnaissance, not execution)
**Mode:** READ-ONLY
**Status: PASS (with a mandatory in-phase visibility gate — see §11 and §13)**
**Executed:** 2026-10-16 (local ~13:44–13:46 EAT)
**Host:** Kali GNU/Linux Rolling 2025.4 (sensor, `192.168.56.1`)
**Operator:** saidi (uid 1000)

**What this report is.** A read-only survey of the current state of the lab, to
decide whether Phase 3 can be executed safely and whether its objective (validate
`DET-201` / `DET-202` / `DET-203` against genuinely generated benign traffic from
`SOC002-WS001`) is achievable.

**What was NOT done.** No VM was started, stopped, paused, saved or snapshotted.
No VirtualBox configuration was modified. No Windows configuration was touched.
No firewall, route, `ip_forward`, or DNS setting was changed. No traffic was
captured. Zeek was not run live. No package was installed. Nothing in SOC-001 or
SOC-002 was modified. No credentials were read or reproduced. No Git repository
was created.

---

## 1. Current state (summary)

| Item | State |
| --- | --- |
| `SOC002-DC1` power state | `poweroff` (since `2026-10-15T04:07:36`) |
| `SOC002-WS001` power state | `aborted` (since `2026-10-15T16:17:17`) — unclean prior shutdown |
| Running VMs | none (`VBoxManage list runningvms` empty) |
| `vboxnet0` (VirtualBox view) | Exists, host-only, `Status: Up`, `192.168.56.1/24` |
| `vboxnet0` (Linux/kernel view) | `NO-CARRIER`, `operstate=down`, `carrier=0`, `promiscuity 0` |
| `vboxnet0` counters (this boot) | `rx_packets=0`, `rx_bytes=0` / `tx_packets=24506`, `tx_bytes=2447942` |
| VM NICs | Both `nic1=hostonly` → `vboxnet0`, cable `on`, `82540EM`, `AllowAll` promisc |
| Host interfaces | `lo`, `eth0` (down/no carrier), `wlan0` (`10.16.17.149/19`), `vboxnet0` (`192.168.56.1/24`) |
| `ip_forward` | `1` (pre-existing; **must not be changed**, see risk R2) |
| Zeek | 9.0.0 at `/opt/zeek`, **no file capabilities** → live capture needs root |
| Capture tooling | `dumpcap` **unprivileged-capable** (`cap_net_admin,cap_net_raw=eip`, group `wireshark`) |
| Disk headroom | `106 GiB` free on `/` |
| Memory headroom | `7.5 GiB` total, `2.4 GiB` available; swap `9.5 GiB` free |
| CPU | 4 cores (i5-7300U); **current load average 4.14** (browser-driven) |
| `sudo` | Password required (no passwordless sudo) |
| `soc-003` Git status | Not a Git repository (correct) |

---

## 2. Evidence (raw, as observed)

### 2.1 VM inventory and power state

```
$ VBoxManage list vms
"SOC002-DC1"   {0bddd518-e98a-4b69-bcbc-f531107e994a}
"SOC002-WS001" {f06302bc-796c-40f5-ab9c-7ca7893c199f}

$ VBoxManage list runningvms
(empty)
```

```
SOC002-DC1:   VMState="poweroff" VMStateChangeTime="2026-10-15T04:07:36"
SOC002-WS001: VMState="aborted"  VMStateChangeTime="2026-10-15T16:17:17"
```

`WS001` reporting `aborted` is the state it entered at the end of the SOC-002
session (it was already `aborted` during Phase 0.2). It was **not** caused by this
preflight.

### 2.2 VirtualBox NIC configuration (both VMs)

```
=== SOC002-DC1 ===
memory=2048  cpus=2
nic1="hostonly"  hostonlyadapter1="vboxnet0"  nictype1="82540EM"
macaddress1="08002795B302"  cableconnected1="on"
nic2..nic8="none"

=== SOC002-WS001 ===
memory=2048  cpus=1
nic1="hostonly"  hostonlyadapter1="vboxnet0"  nictype1="82540EM"
macaddress1="080027817A74"  cableconnected1="on"
nic2..nic8="none"
```

Promiscuous policy, read directly from the live `<Hardware>` section of each
`.vbox` definition (`.vbox` mtime `2026-10-16 12:32:47` — unchanged since
Phase 0.2):

```xml
SOC002-DC1.vbox:125   <Adapter slot="0" enabled="true" MACAddress="08002795B302" promiscuousModePolicy="AllowAll" type="82540EM"/>
SOC002-WS001.vbox:155 <Adapter slot="0" enabled="true" MACAddress="080027817A74" promiscuousModePolicy="AllowAll" type="82540EM"/>
```

**Answer to "are both VMs still attached to `vboxnet0`?" — Yes**, at the
configuration level: both have NIC1 bound to `vboxnet0`, cable connected, and the
Phase 0.2 `AllowAll` promiscuous policy is still in place. Attachment is only
"live" once a VM is powered on.

### 2.3 `vboxnet0`

```
$ VBoxManage list hostonlyifs
Name:            vboxnet0
DHCP:            Disabled
IPAddress:       192.168.56.1
NetworkMask:     255.255.255.0
Status:          Up

$ VBoxManage list dhcpservers
NetworkName:    HostInterfaceNetworking-vboxnet0
Dhcpd IP:       192.168.56.100
LowerIPAddress: 192.168.56.101
UpperIPAddress: 192.168.56.254
Enabled:        Yes
```

```
$ ip -d link show vboxnet0
4: vboxnet0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 ... state DOWN
    link/ether 0a:00:27:00:00:00 ... promiscuity 0 allmulti 0

$ cat /sys/class/net/vboxnet0/{carrier,operstate}
0
down

$ cat /sys/class/net/vboxnet0/statistics/{rx_packets,tx_packets,rx_bytes,tx_bytes}
0
24506
0
2447942
```

Note the internal inconsistency in VirtualBox's own reporting: the host-only
interface reports `DHCP: Disabled` while a DHCP server object for the same
network reports `Enabled: Yes`. Both VMs are documented with static addresses
(`DC1 .10`, `WS001 .102`), so DHCP should be irrelevant — but this must be
confirmed from the guest before Phase 3 relies on addressing (see §8).

### 2.4 Kernel/VirtualBox history for `vboxnet0`

```
$ dmesg | grep -i vboxnetflt
[    9.579915] VBoxNetFlt: Successfully started.
[29623.673845] VBoxNetFlt: attached to 'vboxnet0' / 0a:00:27:00:00:00
[ 184402.79 ] vboxnet0: left promiscuous mode
[ 184402.79 ] vboxnetflt: 2503 out of 16547 packets were not sent (directed to host)
[187410.699325] VBoxNetFlt: attached to 'vboxnet0' / 0a:00:27:00:00:00
[ 261468.70 ] vboxnet0: left promiscuous mode
[ 261468.72 ] vboxnetflt: 21878 out of 32340 packets were not sent (directed to host)
```

`uptime` = `up 3 days, 21:54`; last "left promiscuous mode" is `2026-10-15 19:17:22`
— i.e. when the VMs were last powered off. The interface itself was **not**
recreated during this boot (no netdev teardown in the log), which matters for the
interpretation in §4.

### 2.5 Host interfaces and routes

```
$ ip -o addr show
lo         127.0.0.1/8
eth0       (no address; NO-CARRIER, state DOWN)
wlan0      10.16.17.149/19  (management/uplink — OUT OF SCOPE)
vboxnet0   192.168.56.1/24

$ ip route show
default via 10.16.0.1 dev wlan0 proto dhcp src 10.16.17.149 metric 600
10.16.0.0/19 dev wlan0 proto kernel scope link src 10.16.17.149 metric 600
192.168.56.0/24 dev vboxnet0 proto kernel scope link src 192.168.56.1 linkdown

$ cat /proc/sys/net/ipv4/ip_forward
1
```

`$ ip neigh show dev vboxnet0` → empty (no VM has been on the segment this boot
lifetime of the cache).

### 2.6 Zeek and capture permissions

```
/opt/zeek/bin/zeek            -rwxr-xr-x root:root     (NO capabilities, not setuid)
/usr/bin/dumpcap              -rwxr-xr-- root:wireshark cap_net_admin,cap_net_raw=eip
/usr/sbin/tcpdump             (no capabilities → requires root)
$ /opt/zeek/bin/zeek --version   →  zeek version 9.0.0
$ id  →  uid=1000(saidi) ... 27(sudo),121(wireshark), ...  (NOT in the zeek group)
$ getent group zeek  →  zeek:x:982:      (empty group)
$ sudo -n true  →  "sudo: a password is required"
$ dumpcap -D  →  lists vboxnet0 (unprivileged interface enumeration works)
```

Zeek has **no** installation at `/opt/zeek/logs` or `/opt/zeek/spool` and only a
minimal `/opt/zeek/etc/zeek/zeek.conf` — Zeek is used by invoking the binary
directly (the Phase 1.2 / Phase 2 pattern), not via `zeekctl`.

### 2.7 Headroom

```
$ df -h /          →  235G total, 117G used, 106G avail (53%)
$ free -h          →  Mem: 7.5Gi total, 5.2Gi used, 2.3Gi available; Swap: 9Gi total, 2.1Gi used
$ nproc            →  4   (Intel i5-7300U)
$ uptime           →  load average: 4.14, 3.82, 3.56
$ ps --sort=-pcpu  →  brave (100% CPU, 832 MB RSS), brave (21%), gnome-shell, firefox-esr, Isolated Web Co x5
```

The current load is **entirely desktop/agent-driven** (browsers, GNOME, this
Codex session). No VM is running. Two VMs at 2 GiB each = 4 GiB against 2.3 GiB
currently available.

### 2.8 Detection content (read-only inspection)

- `detections/zeek/det-201-service-discovery.zeek` — per-source accumulator over
  `conn.log` / `connection_state_remove`; states `S0,S1,REJ,RSTO,RSTR,OTH`;
  gates `60s`, `≥10` attempts, `≥5` ports, `≥2` hosts; window arithmetic uses
  `c$start_time`.
- `detections/zeek/det-202-dns-burst.zeek` — per-source distinct qname counter
  over `dns.log` / `dns_request`; `30s`, `≥20` unique names.
- `detections/zeek/det-203-periodic-http.zeek` — per `(src,dst)` HTTP interval
  statistics over `http.log` / `http_request`; `≥4` intervals, mean `5–600 s`,
  `CV ≤ 0.05`.
- `detections/zeek/phase2-load.zeek` — single loader for all three + scaffolding.
- `detections/zeek/det-common.zeek` — shared `phase2_detections` JSON log stream.

**No script contains a hard-coded synthetic address, subnet, or capture-specific
assumption.** All three are expressed purely in terms of `c$id$orig_h` /
`c$id$resp_h` / qnames derived from the analysed events, and all thresholds are
`&redef`. They are therefore source-agnostic and are expected to run unmodified
against a live capture.

### 2.9 SOC-002 documentation (read-only cross-check)

- `SOC-002-PUBLIC/README.md`: `DC1 192.168.56.10` = "AD DS + DNS + WEF collector";
  `WS001 192.168.56.102` = "Domain-joined `soc002.local`; Sysmon, PowerShell
  Script Block Logging, Security auditing"; `Kali 192.168.56.1` = operator,
  "Drives the lab over WinRM/NTLM (authorised management channel)".
- `SOC-002-PUBLIC/phase5/evidence/t3d_sysmon3_ws001.txt` and
  `phase7/.../t5b_central_telemetry_dc1_session.txt`: many Sysmon Event ID 3
  records of the form `Source=192.168.56.1:* → Destination=192.168.56.102:5985`
  (`Initiated=false`, i.e. inbound to WS001). This is direct evidence that
  **host ↔ VM traffic is delivered over `vboxnet0` in both directions** when the
  VMs are running.
- A repository-wide search for `gateway` in the SOC-002 corpus returns **no
  hits** — no default-gateway configuration is documented for either guest.
- The `soc002.local` domain implies DC1 serves DNS to WS001 as an ordinary
  domain-joined client (Kerberos/LDAP/SMB/RPC/WinRM/WEF are all normal,
  benign, expected on-segment traffic).

---

## 3. Answers to the twelve reconnaissance questions

| # | Question | Finding |
| --- | --- | --- |
| 1 | Power state of DC1 / WS001 | DC1 `poweroff`; WS001 `aborted`. Neither running. |
| 2 | `vboxnet0` state | Exists, host-only, `192.168.56.1/24`, VirtualBox `Status: Up`, kernel `NO-CARRIER`/`down` (no VM attached), `promiscuity 0`. |
| 3 | VirtualBox NIC config | Both: NIC1 `hostonly`→`vboxnet0`, cable `on`, `82540EM`, `AllowAll` promisc, MACs as recorded. NIC2–8 disabled. |
| 4 | Still attached to `vboxnet0` | Yes (config-level), for both. |
| 5 | Host interfaces / routes | `lo`, `eth0` (down), `wlan0` `10.16.17.149/19` (uplink, out of scope), `vboxnet0` `192.168.56.1/24`; default route via `wlan0`; `192.168.56.0/24` link-down route on `vboxnet0`. |
| 6 | Can the host observe VM↔VM traffic without config changes? | **NOT ESTABLISHED.** Cannot be proven with the VMs down. Indirect evidence exists for host↔VM visibility; VM↔VM visibility is unresolved. A bounded in-phase test is mandatory (§4, §8 step 3). |
| 7 | Can WS001 generate ordinary benign traffic inside the isolated lab? | Yes in principle — a domain-joined Windows 10 client with DC1 present generates DNS, Kerberos, LDAP, SMB, RPC, Netlogon and WinRM traffic on-link by simply booting and logging in. It is **conditional on** WS001 having no usable default gateway (unverified; §8 step 4) and on the user logging in. |
| 8 | Can DC1 provide useful benign services? | Yes — documented as AD DS + DNS for `soc002.local`. DNS in particular is directly relevant to `DET-202`, and AD client chatter is directly relevant to `DET-201`. |
| 9 | Are Zeek capture permissions suitable for bounded live capture? | Zeek itself: **not directly** (no capabilities → live `-i` needs root/sudo password). The installed tooling supports a **fully unprivileged** path instead: `dumpcap` (capable, group `wireshark`, and saidi *is* in `wireshark`) → bounded PCAP → offline Zeek replay. This is the recommended route and needs no sudo. |
| 10 | Disk/RAM/CPU headroom | Disk: ample (106 GiB free). CPU: 4 cores, currently saturated by desktop browsers. RAM: **tight** — 2.3 GiB available vs 4 GiB required by both VMs. |
| 11 | Can Phase 2 detections be replayed against a live capture unmodified? | Yes. All three are source-agnostic Zeek scripts with no synthetic assumptions; the same `phase2-load.zeek` can be pointed at a live-derived PCAP. No modification required or permitted. |
| 12 | What must be done in Phase 3 / what needs the user? | See §8 (procedure), §9 (user actions), §10 (Codex actions). Two user actions: start the two VMs / log in; and free up RAM. Sudo is **not** required if the `dumpcap` path is used. |

---

## 4. The one genuine open question: host visibility of VM↔VM traffic

This is the only finding that can invalidate the Phase 3 objective, so it is
called out separately rather than buried.

**What is known.**

- `vboxnet0` has `rx_packets = 0 / rx_bytes = 0` for the entire current boot,
  even though the VMs ran on 13–15 Oct and SOC-002 evidence proves WinRM
  traffic flowed between Kali and WS001 (`192.168.56.1 → 192.168.56.102:5985`).
- `tx_packets = 24506` on the same interface, so TX accounting works.
- Kernel log shows `VBoxNetFlt: attached to 'vboxnet0'` and `vboxnet0: entered
  promiscuous mode` while VMs run, and a shutdown summary line
  `vboxnetflt: N out of M packets were not sent (directed to host)`.

**Interpretation, stated conservatively.**

- The `rx_packets = 0` counter is **not** reliable evidence of zero visibility.
  The far more likely explanation is that the `VBoxNetAdp` host-only driver
  delivers host-directed frames up the stack without maintaining `rx_packets`
  (RX statistics for this driver are known to be incomplete), because
  host↔VM traffic demonstrably worked during SOC-002 while these counters read
  zero.
- The `vboxnetflt` summary line shows the host-only filter explicitly separates
  "directed to host" frames from the rest, which is consistent with the classic
  VirtualBox host-only behaviour: the host is a **port** on the internal switch,
  not a mirror port, so frames that are neither broadcast/multicast nor
  addressed to the host may never be presented to the host's stack.

**Conclusion: VM↔VM unicast visibility is UNPROVEN.** It must not be assumed.
Phase 3 therefore begins with an explicit, bounded **visibility gate** (§8, step 3)
whose result selects the phase shape. If the gate shows VM↔VM traffic is not
visible, Phase 3 cannot fully satisfy its objective without a configuration change
(adding a third capture VM, or bridging/mirroring), which is outside the SOC-003
scope rules and would require an explicit user decision.

**Why this is a preflight PASS rather than BLOCKED.** The gate is cheap, bounded,
non-destructive, and is itself a legitimate Phase 3 step; and a large part of the
objective (does `DET-201/202/203` fire spuriously on *real* Windows/AD traffic)
is testable on the host-visible subset regardless of the gate result. The
objective would be limited, not impossible; §11 makes the limitation explicit.

---

## 5. Risks

| ID | Risk | Severity | Mitigation |
| --- | --- | --- | --- |
| R1 | VM↔VM unicast may not reach the sensor, so `DET-202`-relevant DNS (WS001→DC1) and much AD chatter may be invisible. | High | Mandatory visibility gate (§8 step 3) before any interpretation; report the limitation explicitly if it fails. |
| R2 | `ip_forward = 1` already on the host. If a guest has a default gateway pointing at `192.168.56.1`, guest "internet" attempts could be forwarded onto `wlan0`, leaking out-of-scope traffic and creating unintended host traffic. | High | Do **not** change `ip_forward` (prohibited). Instead: verify from the guest that no default gateway is configured (§8 step 4) and abort traffic generation if one is; capture **only** on `vboxnet0`, never on `wlan0` or `any`. |
| R3 | `WS001` is `aborted`, i.e. last powered off uncleanly. Booting may prompt for disk check / show an unclean-shutdown notice. | Medium | Expected. Do not snapshot or roll back. If Windows performs an automatic repair, stop and report rather than intervening. |
| R4 | RAM: 2.3 GiB available vs 4 GiB of guest RAM; load average already 4.14/4 cores. | Medium | User closes browsers before Phase 3. Start DC1 first, confirm it is stable, then WS001. Capture stays bounded (no long-running analysis while both VMs run). |
| R5 | Live Zeek capture requires root → sudo password prompt and root-owned log files. | Medium | Avoid entirely: use the unprivileged `dumpcap` → offline Zeek path. If live Zeek is ever wanted, it requires an explicit user decision. |
| R6 | The `AllowAll` promiscuous policy lives in the VMs' live config, **not** in their snapshots (documented in Phase 0.2). A snapshot revert would silently restore `deny`. | Low | Do not revert snapshots in Phase 3; re-verify the policy before starting VMs. |
| R7 | Windows guests will attempt internet-bound activity (CRL/OCSP, Defender signatures, telemetry, time sync). | Medium | Expect repeated failed lookups/timeouts and treat them as benign lab reality, not evidence. Ensure they fail closed on-segment; never capture or route them off-segment. |
| R8 | Zeek assigns random `uid`/`fuid` per run, so live-capture logs are **not** byte-reproducible (unlike Phase 2). | Low | Compare on detection records and field-level content, not on raw log hashes; state this in the Phase 3 report. |
| R9 | Realistic expectation: Phase 3 will likely produce **zero or near-zero** detections, because real Windows/AD traffic is dominated by SMB/Kerberos/LDAP/RPC/DNS, and `DET-203` only covers HTTP/1.x. | Low | This is a valid and valuable result (a benign-traffic false-positive check) provided it is reported as such and not misread as "detections are broken". |
| R10 | `vboxnet0` DHCP reporting is contradictory (`Disabled` vs `Enabled`). | Low | Confirm guest addressing (static vs DHCP) before generating traffic; observe whether the VirtualBox DHCP responder appears on the wire. |
| R11 | Long/unbounded capture fills disk or starves the host. | Low | Hard bounds: ≤ 10 min wall clock, 5-min segments, ~512 MiB ring cap, disk has 106 GiB free. |
| R12 | Scope creep into `wlan0`. | High | Capture filter is `-i vboxnet0` only; a BPF filter `net 192.168.56.0/24` is applied as a second guard; all output confined to `~/soc-lab/soc-003/`. |

---

## 6. Proposed Phase 3 procedure

All steps remain READ-ONLY with respect to VM/VirtualBox/Windows/firewall/route/
DNS configuration. Nothing is installed. Only `~/soc-lab/soc-003/` is written to.

1. **Re-verify preconditions** (Codex): VM states, `vboxnet0` carrier, promisc
   policy, `ip_forward` value, disk/RAM. Record into a Phase 3 working log.
2. **Prepare bounded capture area**: use `captures/` with a ring-bounded
   `dumpcap` invocation (`-b duration:300 -b files:4 -s 0 -w ...`), filter
   `net 192.168.56.0/24`, interface `vboxnet0` only. No capture starts yet.
3. **Visibility gate (mandatory, ~90 s)**: with both VMs up, run a single bounded
   `dumpcap` capture on `vboxnet0` while the user triggers an on-segment ping
   between WS001 and DC1 and between WS001 and Kali. Compare what is observed:
   - WS001↔Kali only visible → host-observed model (reduced Phase 3).
   - WS001↔DC1 also visible → full Phase 3 as designed.
   - Neither visible → stop; report `BLOCKED` with evidence and options.
4. **Confirm no default gateway** on WS001 (read-only `ipconfig /all` equivalent,
   gathered via the existing authorised management channel). If a gateway exists,
   do not generate traffic until the user decides.
5. **Benign traffic generation (user-driven, in-lab only)**: normal WS001 use —
   logon/logoff, DNS resolution of `soc002.local` names, a Windows Update check
   attempt, SMB share access to DC1, `nltest`-style domain queries, a few HTTP
   requests to a local on-segment listener only. No scanning tools, no external
   destinations, no attack traffic.
6. **Bounded capture** (≤ 10 min) with the ring settings above; stop on bounds.
7. **Offline analysis**: replay the resulting PCAP through the **unmodified**
   `detections/zeek/phase2-load.zeek` into a fresh temp directory; extract
   `conn.log`, `dns.log`, `http.log`, `notice.log`, `phase2_detections.log`.
8. **Compare against baseline expectations**: per-detection fire/no-fire, plus a
   field-level review of why. Quantify: detection counts, distinct sources,
   whether `192.168.56.102` (WS001) triggered anything, which of the three gates
   came closest to firing.
9. **Evidence capture** into `evidence/phase3-.../` with SHA256 inventory,
   following the Phase 2 pattern; keep the PCAP short-lived in `captures/` unless
   promoted to evidence.
10. **Write `PHASE3_REPORT.md`** including honest limitations, plus a
    false-positive / unexpected-behaviour assessment for `DET-201/202/203`.
11. **Do not modify the detection scripts.** If tuning is indicated, report it as
    a recommendation for a later phase.

---

## 7. Expected traffic (predictions to be confirmed by observation, never assumed)

| Expected | Detail | Relevant detection |
| --- | --- | --- |
| ARP | WS001/DC1 ARP for each other and for `192.168.56.1` | none |
| DNS → DC1 | `soc002.local` SRV/A lookups, workstation registration, reverse lookups; low volume, mostly *repeated* names | `DET-202` (should not fire — repeated names, low volume) |
| Kerberos/LDAP/RPC | `:88`, `:389`, `:445`, `:135`, `:4966x` between WS001 and DC1 | `DET-201` (should not fire — these are normally established `SF` sessions, and `DET-201` requires *failed* states) |
| SMB | WS001 ↔ DC1 file/print and `SYSVOL`/`NETLOGON` access | none directly |
| WinRM | inbound `:5985` to WS001 from `192.168.56.1` (operator channel) | none |
| WEF | WS001 → DC1 event forwarding | none |
| Failed/latent internet attempts | DC1/WS001 CRL, Defender, telemetry, time sync attempts with no on-segment responder → `S0`-style or immediate `REJ` | `DET-201` (should not fire — low volume, few hosts/ports) |
| HTTP | essentially **only if** deliberately exercised against a local listener | `DET-203` (near-zero expectation otherwise) |

**Honest expectation:** the most likely Phase 3 outcome is **0/3 detections on
genuinely benign lab traffic**, which is the desired result for a
false-positive check — but the outcome must be reported as observed, not assumed.

---

## 8. Capture duration recommendation

- **Total capture window: 10 minutes maximum**, split into two bounded captures:
  a **90-second visibility gate** first, then a **~8-minute traffic-generation
  capture**.
- **Segmenting:** `dumpcap -b duration:300 -b files:4` → ≤ 4 × 5-minute segments,
  hard ring cap (~512 MiB worst case, trivially within the 106 GiB free).
- **Snaplen:** `-s 0` (full frames) for Zeek fidelity; traffic volume is tiny on an
  isolated two-VM segment.
- **Why so short:** the objective is a false-positive check on ordinary traffic,
  not a traffic-volume study; `DET-201` needs only a 60 s window, `DET-202` only
  30 s, and `DET-203` 4 intervals. Ten minutes is generous for all three and keeps
  RAM/CPU/disk risk (R4, R11) negligible.

---

## 9. Exact user action required

1. **Free up memory (before starting VMs).** Close Brave, Firefox and any other
   heavy desktop applications. Currently 2.3 GiB is available against 4 GiB of
   guest RAM; without this, both VMs will swap heavily.
2. **Start `SOC002-DC1`** (VirtualBox GUI or `VBoxManage startvm`), wait for
   Windows Server to finish booting and for the AD DS / DNS service to be healthy,
   and confirm `192.168.56.10` is on `vboxnet0`.
3. **Start `SOC002-WS001`** and let it boot. It was last left `aborted`; expect a
   possible unclean-shutdown notice or disk check. Do **not** revert a snapshot.
4. **Log in to WS001** with a normal domain account and let it settle (a couple of
   minutes) so the ordinary domain client chatter appears.
5. **Tell Codex when both VMs are up and logged in.** Codex then runs the
   visibility gate (§6 step 3) and reports whether the gate passed.
6. **After the gate passes, generate ordinary benign activity for ~5–8 minutes**:
   logon/logoff, normal browsing of Windows network locations, opening a mapped
   share on DC1, running a Windows Update check, `nltest /dsgetdc:soc002.local`
   style queries, a couple of `ping`/`Test-NetConnection` calls between WS001 and
   DC1 — and **only** within `192.168.56.0/24`. When done, tell Codex the window
   has ended.
7. **Sudo:** *not required* if the recommended `dumpcap` → offline Zeek path is
   used (dumpcap is capability-enabled and saidi is in the `wireshark` group). If
   you prefer live Zeek (`zeek -i vboxnet0`), an interactive sudo password will be
   needed and Zeek's logs will be root-owned; this preflight does **not** recommend
   that route.

**No other credential or authentication is required from the user.**

---

## 10. Exact Codex action after that

1. `VBoxManage list runningvms`, `ip -d link show vboxnet0`, `ip route` — confirm
   states and that carrier is now up.
2. Start the bounded gate capture:
   `dumpcap -i vboxnet0 -f "net 192.168.56.0/24" -a duration:90 -s 0 -w captures/phase3-gate.pcapng`
   — nothing else running on `vboxnet0`.
3. Report the gate result honestly, from the actual packet/endpoint content.
4. If the gate passes: run the bounded main capture
   (`dumpcap -i vboxnet0 -f "net 192.168.56.0/24" -a duration:600 -b duration:300 -b files:4 -s 0 -w captures/phase3-<ts>.pcapng`),
   stopping early if the user signals the window has ended.
5. Verify the PCAP (`capinfos`, `tshark -r ... -q -z io,phs`), then replay
   **unmodified** detections offline:
   `cd <tmp> && /opt/zeek/bin/zeek -r <pcap> LogAscii::use_json=T ~/soc-lab/soc-003/detections/zeek/phase2-load.zeek`
6. Extract and summarise: `conn.log`, `dns.log`, `http.log`, `notice.log`,
   `phase2_detections.log`; per-detection fire/no-fire and per-gate analysis;
   false-positive / unexpected-behaviour assessment for `DET-201/202/203`.
7. Store the bounded artifacts under `evidence/phase3-.../` with SHA256 inventory
   and integrity pre/post checks against SOC-001/SOC-002 (Phase 2 pattern).
8. Write `~/soc-lab/soc-003/PHASE3_REPORT.md` and stop. No detection tuning.

---

## 11. Stop conditions

Phase 3 must stop immediately and report (without continuing to capture or
generate traffic) if any of these occur:

1. **Visibility gate fails** — no WS001↔DC1 traffic is visible on `vboxnet0`, and
   the phase cannot meet its objective without a configuration change. Report the
   reduced-scope result and the options; do not change configuration.
2. **Any command would require changing** VirtualBox config, Windows config,
   firewall rules, routes, `ip_forward`, DNS, or would require installing anything.
3. **`wlan0` (or `any`) would be captured**, or a capture filter would not confine
   observation to `192.168.56.0/24`.
4. **Unexpected out-of-lab traffic appears** on the sensor (evidence that guest
   traffic is being forwarded or leaked), or a guest is found to have a working
   default gateway to a non-lab network. Stop generating traffic; report.
5. **A guest shows signs of corruption or an unclean-repair boot** (possible given
   `WS001`'s `aborted` state). Do not intervene; report.
6. **Resource exhaustion** — available RAM falls below ~300 MiB, disk free falls
   below ~5 GiB, or the host becomes unusable. Kill the capture, preserve what
   exists, report.
7. **Any detection fires in a way that suggests synthetic-only tuning** — this is a
   *finding*, not a failure; stop and report it rather than modifying detections.
8. **Any request/instruction to modify SOC-001 or SOC-002**, or to expose
   credentials.

---

## 12. Scope compliance of this preflight

| Rule | Status |
| --- | --- |
| READ ONLY | Complied |
| No VM start/stop/reboot/snapshot | Complied (`list`/`showvminfo`/`snapshot list` only) |
| No VirtualBox configuration change | Complied (no `modifyvm`/`setextradata`) |
| No Windows configuration change | Complied (VMs not running; nothing contacted) |
| No firewall / route / `ip_forward` / DNS change | Complied (read-only inspection) |
| No package installed | Complied |
| No traffic captured | Complied (`dumpcap -D` enumerates interfaces only; no capture opened) |
| No live Zeek | Complied (`--version` only) |
| No Suricata installed | Complied |
| No Git initialised | Complied (`soc-003` is not a Git repository) |
| SOC-001 / SOC-002 unmodified | Complied (SOC-002 files read only) |
| No credentials exposed | Complied (none read, none reproduced) |

---

## 13. Verdict

**PHASE 3 PREFLIGHT: PASS**

**Why PASS.**
- All infrastructure Phase 3 needs is present and healthy: both VMs exist with
  NIC1 correctly bound to `vboxnet0` and the `AllowAll` promiscuous policy intact;
  `vboxnet0` exists at `192.168.56.1/24`; DC1 is a documented AD DS + DNS server;
  WS001 is a domain-joined Windows 10 client.
- The detection content is source-agnostic and can be replayed unchanged against a
  live capture: no hard-coded synthetic addresses, all thresholds `&redef`.
- A **fully unprivileged** capture path exists (`dumpcap` with
  `cap_net_admin,cap_net_raw` + saidi in the `wireshark` group → offline Zeek
  replay), so Phase 3 needs **no sudo password**.
- Headroom is sufficient for the recommended bounded 10-minute capture (disk
  abundant; RAM/CPU adequate provided the user closes desktop browsers first).
- Nothing in the lab was modified, and every remaining action either is read-only
  or is explicitly a user-performed VM start / login.

**Conditions attached to this PASS** (all are ordinary Phase 3 steps, not blockers):
- A **mandatory 90-second visibility gate** must run first, because host
  visibility of WS001↔DC1 traffic is **UNPROVEN** and must not be assumed. If the
  gate fails, Phase 3 continues only in reduced scope and must report that
  limitation rather than claiming VM-to-VM validation.
- The user must start both VMs and log in to WS001; WS001 is in an `aborted`
  state and may need an unclean-boot disk check.
- The user should close desktop browsers first for memory headroom.
- Capture must stay on `vboxnet0` with a `net 192.168.56.0/24` filter, for ≤ 10
  minutes, with bounded rotation — `wlan0` is never captured.
- `ip_forward = 1` and `192.168.56.1`'s default route via `wlan0` are pre-existing
  states that Phase 3 must **not** change; the guest default-gateway check in §6
  step 4 guards against out-of-lab leakage, and any such leakage is a stop
  condition.
- Detection scripts are not modified; any tuning need is reported as a finding.

`STOP — preflight report complete. No Phase 3 execution has been performed.`
