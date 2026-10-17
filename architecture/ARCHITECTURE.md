# SOC-003 — Network Security Monitoring Architecture

Status: Phase 0.2 baseline.
Scope: definition only. No tooling is installed, no capture is running.

## 1. Sensor

| Property | Value |
| --- | --- |
| Sensor host | Kali GNU/Linux Rolling 2025.4 (the lab workstation) |
| Role | Network sensor / NSM analyst platform |
| Capture interface | `vboxnet0` (host-only, `192.168.56.1/24`) |
| Excluded interface | `wlan0` — out of capture scope |
| Hardware budget | 4 vCPU, 7.5 GiB RAM, ~106 GiB free on `/` |

The Kali host is both the **sensor** and the **analysis platform**. It sits on the
lab network as the host side of `vboxnet0`, so all VM-to-VM and host-to-VM traffic
on that segment is visible to it without any identity as a router, gateway, or
inline device.

The sensor is **passive**. It does not forward, route, bridge, or filter traffic
for the lab. It observes.

## 2. Network

| Property | Value |
| --- | --- |
| Virtual network | VirtualBox host-only network `vboxnet0` |
| Subnet | `192.168.56.0/24` |
| Gateway / router | None — there is no gateway in the lab |
| DHCP | Disabled (static addressing) |
| Routing / NAT / bridging | None; no changes are made to any of these |
| Internet access from lab VMs | None by design |

`vboxnet0` is an isolated host-only segment. Traffic on it never leaves the lab
unless it is deliberately moved there by an operator.

### Address plan

| Host | IP | Role |
| --- | --- | --- |
| Kali sensor host | `192.168.56.1` | NSM sensor, analysis platform, host-only network owner |
| `SOC002-WS001` | `192.168.56.102` | Windows 10 Pro endpoint; domain-joined to `soc002.local`; primary detection target |
| `SOC002-DC1` | `192.168.56.10` | Windows Server 2022; AD DS + DNS + WEF collector (`ForwardedEvents`); authentication and name-resolution target |

## 3. Assets

### 3.1 SOC002-DC1

- Windows Server 2022.
- Roles: Active Directory Domain Services, DNS, Windows Event Forwarding collector.
- Network position: NIC1 attached to `vboxnet0` (host-only), static `192.168.56.10`.
- NSM relevance: authoritative source for authentication, Kerberos/LDAP, DNS, and
  group-policy activity on the segment.

### 3.2 SOC002-WS001

- Windows 10 Pro.
- Role: domain-joined user endpoint in `soc002.local`.
- Network position: NIC1 attached to `vboxnet0` (host-only), static `192.168.56.102`.
- NSM relevance: primary host for endpoint-side activity and the most likely source
  of simulated adversary traffic.

There is **no third VM** in this lab.

## 4. Tooling

### 4.1 Zeek — network telemetry

Zeek is the network **telemetry** layer. It converts raw packets into structured,
connection-oriented logs (`conn`, `dns`, `http`, `ssl`, `smb`, `kerberos`, `files`,
and related datasets) suitable for pivoting, aggregation, and hunting.

- Zeek is *not* a signature IDS; it produces the record of what happened.
- Planned role: persistent visibility on `vboxnet0` and the source of truth for
  "what connections existed" during an investigation.

### 4.2 Suricata — IDS / detection

Suricata is the **detection** layer. It evaluates traffic against signatures and
protocol-aware rules and emits alerts.

- Planned mode: **passive IDS only**, reading from `vboxnet0`.
- Suricata is **not** deployed inline; it does not block or modify traffic.
- Planned role: signature-based alerting mapped to ATT&CK techniques, aligned with
  the detections already established in SOC-002.

### 4.3 Wireshark / tshark / dumpcap — packet analysis

The packet-analysis tooling for drill-down when telemetry or an alert needs
packet-level confirmation:

- `wireshark` — GUI dissection and session reconstruction.
- `tshark` — scripted/terminal dissection and field extraction.
- `dumpcap` — capture engine used for bounded, privilege-scoped capture.

Packet capture is used deliberately and briefly, not as an always-on default.

## 5. Data flow

```
SOC002-WS001 (192.168.56.102)
SOC002-DC1   (192.168.56.10)
        |
        |  isolated host-only segment, no gateway
        v
+------------------------------+
| vboxnet0  192.168.56.0/24    |
+------------------------------+
        |
        |  passive observation (no forwarding/routing/NAT/bridging)
        v
Kali sensor (192.168.56.1)
   |-> Zeek      : structured telemetry (conn/dns/http/ssl/...)
   |-> Suricata  : signature alerts (passive IDS, no inline action)
   |-> tshark / dumpcap : bounded PCAP for packet-level confirmation
   `-> Wireshark : manual deep-dive
        |
        v
 investigations/  ->  cases/  ->  evidence/
```

## 6. Strict scope

- **Isolated SOC lab network only.** Monitoring is limited to `vboxnet0` /
  `192.168.56.0/24` and the hosts on it.
- **`wlan0` is explicitly out of capture scope.** The wireless management/uplink
  interface is never a capture device, and no capture filter or configuration may
  reference it. Any capture on `wlan0` would place non-lab traffic in scope and is
  prohibited.
- **No third VM.** The lab is one sensor host plus two VMs, and stays that way.
- **No perimeter changes.** No routing, NAT, bridging, firewall, forwarding
  (`ip_forward`), or DNS changes are part of SOC-003.
- **No inline enforcement.** Suricata remains a passive IDS; there is no IPS,
  no blocking, and no traffic modification.
- **Authorization.** All activity is confined to lab-owned hosts. No external
  targeting, and no credentials or secrets are stored in this repository.

## 7. Resource constraints

The Kali sensor shares one physical workstation with the two lab VMs, so NSM
tooling must not starve the guest VMs or the desktop.

| Constraint | Value |
| --- | --- |
| vCPU available | 4 (shared with both VMs) |
| RAM available | ~3 GiB usable headroom of 7.5 GiB total |
| Disk budget for captures | Bounded subset of ~106 GiB free |
| Concurrent load | 2 Windows VMs plus sensor tooling on one host |

Implications:

- Zeek and Suricata run with modest worker/thread counts and no aggressive
  per-packet logging beyond what the datasets require.
- Capture is bounded by size and duration; long-running unbounded capture is not
  permitted.
- Analysis of large PCAPs is done in slices rather than by loading whole files.

## 8. Bounded PCAP retention

PCAP grows far faster than Zeek or Suricata output, so retention is explicitly
bounded by a **rotate-and-expire** policy:

- PCAP is captured in short, named, time-bounded segments rather than one
  open-ended file.
- A rolling ring of segments is kept with a hard cap on total size; the oldest
  segment is deleted when the cap is reached.
- A separate short max-age policy expires segments even when the size cap has not
  been reached, so quiet lab periods do not accumulate stale data.
- Zeek and Suricata outputs are the durable record; PCAP is a short-lived
  confirmation layer that can be aged out safely.
- Any PCAP that becomes investigation-relevant is copied into `evidence/` and
  hashed **before** it can be aged out by rotation.

Initial retention targets (to be tuned in a later phase, reviewed before enabling
any always-on capture):

| Parameter | Target |
| --- | --- |
| Segment length | 5–15 minutes |
| Ring size cap | ~2 GiB total |
| Max age | 24–72 hours |
| Evidence promotion | Manual, hash-recorded, exempt from rotation |

## 9. Interface policy (current state)

| VM | Adapter | Attachment | Promiscuous policy | MAC |
| --- | --- | --- | --- | --- |
| `SOC002-DC1` | NIC1 | host-only `vboxnet0` | `allow-all` | `08:00:27:95:B3:02` |
| `SOC002-WS001` | NIC1 | host-only `vboxnet0` | `allow-all` | `08:00:27:81:7A:74` |

Both VMs are configured to permit promiscuous-mode traffic on the lab segment so
the sensor-side tooling can observe frames that are not addressed to the guest.
This is a VirtualBox hypervisor-level policy on NIC1 only; it changes no guest
configuration, addressing, adapter type, MAC, DHCP, route, DNS, or cable state.

## 10. Out of scope for SOC-003

- Inline/prevention (IPS) deployment of any kind.
- Routing, NAT, bridging, or gateway behaviour on the sensor.
- Capturing on `wlan0` or any interface carrying non-lab traffic.
- Adding a third VM.
- Changing Kali firewall, `ip_forward`, nftables, routes, or DNS.
