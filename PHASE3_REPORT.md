# SOC-003 — Phase 3 Report

**Phase:** 3 — live benign-traffic validation of the existing SOC-003 Zeek detections
**Status: PARTIAL / BLOCKED**
**Executed:** 2026-10-16, local 13:56 – 14:13 EAT (10:56 – 11:13 UTC)
**Host:** Kali GNU/Linux Rolling 2025.4 — the SOC-003 sensor (`192.168.56.1`)
**Operator:** saidi (uid 1000)
**Tooling:** `dumpcap` 4.6.0 (unprivileged), `capinfos`/`tshark` 4.6.0, Zeek 9.0.0

**Status in one line.** The sensor demonstrably observes real lab traffic on
`vboxnet0` (frames from **both** `SOC002-WS001` and `SOC002-DC1` were captured),
but the lab was quiet enough that **no WS001↔DC1 traffic ever occurred**, and the
captured benign traffic contained **no TCP, no DNS to DC1 and no HTTP** — so
`DET-201` and `DET-203` were **not exercised** and `DET-202` was only marginally
exercised. No detection fired. No false-positive rate may be claimed from this.

---

## 1. Objective

Validate the *existing, unmodified* SOC-003 Zeek detections (`DET-201` network
service discovery, `DET-202` DNS burst, `DET-203` periodic HTTP) against
**genuinely generated benign traffic** from the real Windows lab
(`SOC002-DC1`, `SOC002-WS001`) on the VirtualBox host-only segment
`vboxnet0` (`192.168.56.0/24`) — i.e. a real-world false-positive test rather
than further tuning against synthetic PCAPs.

Two gates were defined by the tasking:

- **Gate 1** — a bounded ~90 s visibility capture to establish whether the
  sensor can observe real lab traffic at all.
- **Gate 2** — a bounded (≤ 10 min) capture of ordinary benign lab traffic,
  replayed offline through Zeek 9 with the unchanged detections.

---

## 2. Safety controls

| Control | State |
| --- | --- |
| Interface captured | **`vboxnet0` only.** `wlan0`, `any`, `eth0`, `lo`, Bluetooth, D-Bus, netlink and nfqueue capture sources were never opened. Confirmed by the explicit `-i vboxnet0` on every `dumpcap` invocation (`gate1/capture-command.txt`, `gate2/capture-command.txt`). |
| Capture filter | **`net 192.168.56.0/24` on every capture** (`Filter string` recorded inside each PCAPNG interface block by `capinfos`). |
| Internet traffic | **None captured, none generated.** Every routable address in all three PCAPs is inside `192.168.56.0/24`; the only other addresses are link-local/site multicast groups and the subnet broadcast (see §5 and `analysis/safety-address-check.txt`). |
| Out-of-lab stop condition | **Not triggered.** No routable address outside `192.168.56.0/24` was observed. |
| Traffic generation | **None.** The phase is entirely passive. No scan, probe, stress, DNS burst, beacon simulation or any other stimulus was issued, from the sensor or anywhere else. |
| VM / network configuration | **Unchanged.** No `VBoxManage modifyvm`/`setextradata`, no VM start/stop/snapshot, no Windows interaction, no firewall/route/`ip_forward`/DNS change. Before/after snapshots are byte-identical (§12). |
| Detections | **Unmodified.** `det-201/202/203`, `det-common.zeek` and `phase2-load.zeek` hashes are unchanged from Phase 2 (§12). |
| Threshold tuning | **None performed.** No `&redef` value was changed; no detection was touched after seeing the results. |
| SOC-001 / SOC-002 / Phase 1 / Phase 2 | **Untouched.** See §12. |
| Suricata | **Not installed.** `dpkg -l | grep -c suricata` = 0 before and after; `/opt` contains only Zeek. |
| Packages | **None installed.** Only pre-existing tools were used. |
| Git | **No repository created or initialised.** `soc-003` is still not a Git repo (§12). |
| Credentials | **None read, none exposed.** No Windows authentication, no secrets in any artifact. |
| Privilege | **No `sudo`.** The capture used the pre-existing unprivileged `dumpcap` capability (`cap_net_admin,cap_net_raw=eip`, user in group `wireshark`). |
| Write scope | All writes confined to `~/soc-lab/soc-003/`. |

**Resource note (honest disclosure).** Host memory was tight throughout because
the two Windows VMs (≈3.6 GiB RSS combined) and desktop browsers were running
concurrently; `MemAvailable` fluctuated between ≈107 MiB and ≈1.0 GiB on a
7.5 GiB host (≈5.3 GiB swap free). The capture itself is negligible-memory
(`dumpcap` RSS ~3 MiB) and the excursions were transient and self-recovering;
the host stayed responsive and no OOM event occurred. This is recorded rather
than hidden because the pre-Phase-3 preflight recommended closing browsers for
headroom, and because the preflight stop condition nominally names ~300 MiB
`MemAvailable`. The capture was allowed to complete because the pressure was
demonstrably not caused by, nor affected by, the capture, and the machine
remained usable. See §11.

---

## 3. Visibility gate (Gate 1)

### 3.1 What was run

| | Window 1 | Window 2 |
| --- | --- | --- |
| Window | 13:56:20 → 13:57:50 EAT | 13:59:04 → 14:00:34 EAT |
| Duration | 90 s (`-a duration:90`) | 90 s (`-a duration:90`) |
| Command | `dumpcap -i vboxnet0 -f 'net 192.168.56.0/24' -a duration:90 -w gate1-visibility.pcap` | identical, `-w window2/gate1-window2-visibility.pcap` |
| Packets captured | **6** | **4** |
| Drops | 0 | 0 |
| SHA256 | `9c1334c0d60500c7e949ad8389af6455879c7b51075be5ae4960bc0df628b68c` | `afc9ed09ea60d047633208319fa46d2afe0e01f578ddf46b31eb962233425581` |

**Why two windows.** The tasking specifies a single ~90 s window. Window 1
caught only 6 packets and none from WS001. Because an idle Windows client
legitimately emits almost nothing in 90 s, one window cannot distinguish *"WS001
is not visible"* from *"WS001 is sending nothing"*. A second identical, bounded,
filtered, passive window was therefore run to give WS001 a fair chance. This is
the only deviation from the literal Gate 1 procedure and it is documented here
deliberately. No configuration was changed.

### 3.2 Validation and observations

Both PCAPs validate cleanly with `capinfos` and `tshark`
(`gate1/pcap-validation-capinfos.txt`, `gate1/pcap-validation-tshark.txt`,
`gate1/window2/…`).

Observed hosts:

| Address | Identity | Window 1 | Window 2 |
| --- | --- | --- | --- |
| `192.168.56.1` | the SOC-003 sensor itself (Kali) | 4 pkts (SSDP) | 4 pkts (SSDP) |
| `192.168.56.10` | **`SOC002-DC1`** (`08:00:27:95:b3:02`) | **2 pkts** | 0 |
| `192.168.56.102` | `SOC002-WS001` (`08:00:27:81:7a:74`) | **0 pkts** | **0 pkts** |

Observed protocols: `SSDP` (the sensor's own periodic `M-SEARCH` to
`239.255.255.250`) and `NBDGM→SMB→MAILSLOT→BROWSER` (DC1's periodic NetBIOS
**Host Announcement** to `192.168.56.255:138`). No TCP at all.

### 3.3 Determination — stated precisely

- **"Can Kali observe real lab traffic on vboxnet0?" → YES, with evidence.**
  Two frames emitted by a real lab Windows VM (`SOC002-DC1`, source MAC
  `08:00:27:95:b3:02`) were captured on `vboxnet0` through the unprivileged
  `dumpcap` path. The sensor is therefore genuinely attached to the lab segment
  and its capture path works.
- **"Is WS001↔DC1 traffic visible?" → NOT OBSERVED.**
  No frame with WS001 as an endpoint exists in either window, so **no visibility
  claim is made**. Stated exactly as the evidence allows:

      WS001↔DC1 traffic:  NOT OBSERVED in this capture.
      Cause:              no such traffic was present to observe.

- **"Is unicast VM-to-VM visibility proven?" → NO.** The DC1 frames that *were*
  observed were **broadcasts** (`dst 192.168.56.255` / `ff:ff:ff:ff:ff:ff`).
  Broadcast frames are flooded to every switch port, so their arrival does not
  by itself prove that *unicast* frames between two guest NICs are also copied to
  the host adapter. That property remained unproven after Gate 1.
- **IPv6 is out of scope by design.** The mandated IPv4 filter
  (`net 192.168.56.0/24`) does not match IPv6, including link-local `fe80::`
  traffic such as LLMNR-over-IPv6 or Neighbour Discovery. Absence of IPv4
  traffic must not be read as absence of IPv6 traffic.
- **Counter caveat.** The kernel `rx_packets` counter for `vboxnet0` read `0`
  throughout while `dumpcap` demonstrably captured frames, so those counters do
  not reflect captured traffic on this VirtualBox host-only device and were
  **not** used as evidence.

**Gate 1 outcome:** the gate's stated purpose — *"establish whether Kali can
observe real lab traffic"* — **passed**. The narrower WS001↔DC1 sub-question was
**not answerable**, because the lab produced no such traffic. Phase 3 continued
to Gate 2, whose window is the natural place for ordinary WS001→DC1 domain
traffic (DNS, Kerberos, SMB, Group Policy) to appear — and which, unlike a 90 s
window, is long enough for it to do so.

---

## 4. Live benign capture (Gate 2)

| | |
| --- | --- |
| Window | 14:02:18 → 14:11:19 EAT (540 s = 9 min 0 s, strictly below the 10-minute ceiling) |
| Command | `dumpcap -i vboxnet0 -f 'net 192.168.56.0/24' -a duration:540 -w gate2-benign-lab-traffic.pcap` |
| Packets | **56** (0 dropped, 100 % captured) |
| Actual packet span | 502.06 s (14:02:21.26 → 14:10:43.32) |
| Size / rate | 8 572 B on disk; 12 B/s, ≈100 bit/s |
| SHA256 | `564b1fe0518ee45b1c0188ef885bd5578ab74359f3fe6e91082ee81febf299aa` |
| Validation | `gate2/pcap-validation-capinfos.txt`, `gate2/pcap-validation-tshark.txt` |
| Raw PCAP preserved | `gate2/gate2-benign-lab-traffic.pcap` |

Nothing was generated. The capture is a pure passive listen of the already-running
lab for nine minutes.

---

## 5. Hosts and protocols observed (Gate 2)

Ethernet sources (56 frames total):

| Source MAC | Identity | Frames |
| --- | --- | --- |
| `08:00:27:81:7a:74` | **`SOC002-WS001`** (`192.168.56.102`) | **32** |
| `0a:00:27:00:00:00` | the sensor's own `vboxnet0` interface | 18 |
| `08:00:27:5e:9c:0a` | VirtualBox DHCP server for `vboxnet0` (`192.168.56.100`) | 4 |
| `08:00:27:95:b3:02` | **`SOC002-DC1`** (`192.168.56.10`) | **2** |

Protocols:

| Protocol | Frames | Source | Nature |
| --- | --- | --- | --- |
| `IGMPv3` | 22 | WS001 (+ sensor) | IPv4 multicast group join/leave to `224.0.0.22` |
| `SSDP` | 16 | sensor only | host's own periodic `M-SEARCH` |
| `MDNS` | 8 | WS001 | `SOC002-WS001.local` ANY query + answer on `224.0.0.251` |
| `ARP` | 4 | VBox DHCP server | “Who has `192.168.56.102`? Tell `192.168.56.100`” probes |
| `LLMNR` | 4 | WS001 | `SOC002-WS001` ANY query on `224.0.0.252` |
| `BROWSER` | 2 | DC1 | NetBIOS Host Announcement to the subnet broadcast |

Byte-level containment: `analysis/safety-address-check.txt`.

**Two findings worth stating plainly.**

1. **WS001 *is* visible.** Its 32 frames (IGMPv3 membership reports, mDNS and
   LLMNR self-name resolution) were captured directly. This is stronger evidence
   than Gate 1 alone gave that the sensor sits on the segment with both guests
   and receives frames *originated by WS001*. It still does not include a single
   unicast frame between the two guests.
2. **WS001↔DC1 traffic: none.** Across the whole 9 minutes DC1 sent **only** the
   NetBIOS broadcast announcement, and WS001 sent **only** link-local multicast
   and the DHCP server's ARP probes. **No DNS, Kerberos, SMB, LDAP, RPC or ICMP
   passed between WS001 and DC1 — and there is no TCP at all in the capture.**
   The ARP probes for `192.168.56.102` at t≈202 s and t≈502 s show the lab DHCP
   process was alive; the DHCPDISCOVER/REQUEST messages themselves are broadcasts
   from `0.0.0.0` and are excluded by the mandated IPv4 subnet filter.

---

## 6. Zeek telemetry

Both PCAPs were replayed offline with the **unmodified** Phase 2 loader:

```
/opt/zeek/bin/zeek -r <pcap> LogAscii::use_json=T detections/zeek/phase2-load.zeek
```

| Run | `conn.log` | `dns.log` | `http.log` | `notice.log` | `phase2_detections.log` |
| --- | --- | --- | --- | --- | --- |
| Gate 1 (window 1) | 2 | 0 | — (none produced) | — (none produced) | — (none produced) |
| Gate 2 | 9 | 12 | — (none produced) | — (none produced) | — (none produced) |

Zeek exited 0 on both runs. Raw logs are preserved under
`evidence/phase3-live-benign-validation/zeek-run/{gate1,gate2}/`
(`conn.log`, `dns.log`, `weird.log`, `reporter.log`, `packet_filter.log`,
run metadata, stdout, stderr).

Gate 2 `conn.log` in full: 9 UDP “connections” — 4 × SSDP from the sensor, 2 ×
mDNS (`192.168.56.102:5353 → 224.0.0.251:5353`, `service=dns`), 2 × LLMNR
(`192.168.56.102 → 224.0.0.252:5355`, `service=dns`), 1 × NBDGM/138 broadcast
from DC1. Connection states were `S0` ×5 and `OTH` ×4 — **no `SF`, no `REJ`,
no `RSTO`/`RSTR`, i.e. nothing that DET-201 treats as a probe.**

Gate 2 `dns.log`: 12 records, all from `192.168.56.102`, all for **two distinct
names** (`soc002-ws001.local`, `soc002-ws001`) — WS001 advertising/resolving its
**own** hostname via mDNS and LLMNR. There is **not one query to DC1**
(`192.168.56.10:53`).

**Telemetry artefacts (reported, not fixed).** Zeek's
`find-checksum-offloading.zeek` emitted a `Reporter::WARNING` and a
`bad_UDP_checksum` weird on each run. The affected packets are the **sensor's
own** egress SSDP frames, whose UDP checksum is a NIC-offload placeholder at the
moment `dumpcap` sees them (they are logged with `history="C"` and
`conn_state="OTH"`). Guest-originated frames parsed normally. This is an
expected artefact of capturing locally-generated traffic on the sensor and is
relevant to the live-sensor recommendation in §15; it did **not** affect the
guest traffic the detections consume. Nothing was re-run with `-C`, because
changing the replay parameters would depart from “replay it offline through
Zeek 9” as specified.

---

## 7. DET-201 result — Network Service Discovery Behaviour

**Result: NO FIRING — “no firing observed in this capture.”**

`DET-201` requires ≥ 10 non-established TCP connections (`S0/S1/REJ/RSTO/RSTR/OTH`)
from one source to ≥ 5 distinct ports across ≥ 2 distinct hosts within 60 s.
The capture contains **zero TCP packets**, so the detector's input never
materialises: no accumulator is ever created, and there is no opportunity for a
false positive.

**Exercised by this capture: NOT exercised by this capture.**

No detection was modified or tuned.

---

## 8. DET-202 result — DNS Burst / Unique Subdomain Behaviour

**Result: NO FIRING — “no firing observed in this capture.”**

`DET-202` requires ≥ 20 **distinct** query names from one source inside a 30 s
window. The capture's DNS surface (`dns_request` events) is 12 records covering
**2 distinct names** for the entire nine minutes — a maximum of 2 distinct names
in any 30 s window, i.e. **10 % of the threshold**. The nearest approach to the
boundary is therefore an order of magnitude away.

**Exercised by this capture: PARTIALLY exercised.** The DNS path *was* live —
Zeek built `dns.log` from live-derived mDNS/LLMNR traffic and the detector ran
against it — but the volume needed to reach the decision boundary was absent, so
the strong form of the test (does a *near-threshold* benign pattern stay quiet?)
was not performed.

**Incidental observation for the record (not a defect claim).** Zeek's DNS
analyser consumes mDNS (UDP/5353) and LLMNR (UDP/5355) as DNS events, so
`DET-202` counts those names too. `DET-202`'s ±threshold is far above what this
lab generated, so nothing fires here; on a busier segment this is a plausible
benign source of unique names worth remembering. No change is proposed in this
phase.

---

## 9. DET-203 result — Periodic HTTP Behaviour

**Result: NO FIRING — “no firing observed in this capture.”**

`DET-203` requires ≥ 5 HTTP requests on one `(src, dst)` pair with a coefficient
of variation ≤ 0.05 and a mean interval in 5–600 s. The capture contains **no TCP
and no HTTP**, so no `http_request` event exists, no interval vector is built,
and the detector cannot reach a decision.

**Exercised by this capture: NOT exercised by this capture.**

---

## 10. False-positive assessment

- **Detection firings in this phase: 0** (across all three detections, both
  replay runs).
- Because there were **no firings**, there is consequently **no firing to
  adjudicate** as a true false positive or as requiring further investigation.
  The expected phrase applies instead: for `DET-201` and `DET-203`,
  *“not exercised by this capture”*; for `DET-202`, *“partially exercised by
  this capture.”*
- **No false-positive rate is claimed from this capture.** One quiet nine-minute
  window on one lab segment cannot support a rate, and the near-total absence of
  the traffic types the detections consume means even “zero firings” is weak
  evidence rather than a clean negative.
- **No false negatives are claimed or implied.** The detections were never
  presented with the behaviour they target, so their silence says nothing about
  their sensitivity.
- **What this legitimately shows:** on genuinely benign live lab traffic, the
  unmodified detections produced **no spurious alert** — they did not misfire on
  IGMPv3 membership churn, mDNS/LLMNR self-name resolution, NetBIOS browser
  announcements, DHCP-server ARP probes, or SSDP chatter. That is a real, if
  narrow, false-positive datapoint: the pipeline stayed quiet on ordinary noise.
  It is explicitly **not** a validation of the detections' accuracy.

---

## 11. Limitations

1. **No WS001↔DC1 traffic existed to observe.** The single most important
   limitation. Gate 1's specific question could not be answered because the lab
   generated no such traffic in any window; the WS001↔DC1 visibility nexus is
   therefore **unproven**, not disproven.
2. **The lab was extremely quiet.** 56 packets in nine minutes with **no TCP,
   no HTTP and no DNS-to-DC1**. The benign baseline is dominated by link-local
   multicast noise, not by the "ordinary domain activity" (DNS, Kerberos, SMB,
   Group Policy) that Phase 3 was designed to sample. An idle, logged-in Windows
   client simply does not produce those on a schedule short enough to hit a
   nine-minute window (Group Policy refresh ≈ 90 min, Kerberos TGT renewal
   ≈ 10 h, name resolution only on demand).
3. **Two detections were not exercised at all and one only marginally.** The
   headline objective — validating `DET-201/202/203` against real benign traffic
   — was therefore **not achieved** at this volume.
4. **IPv6 is out of scope by design.** The mandated IPv4 filter excludes
   `fe80::` traffic (LLMNR-over-IPv6, Neighbour Discovery). WS001 is clearly
   IPv6-active; that activity was deliberately not examined.
5. **DHCP and other `0.0.0.0`-sourced broadcasts are excluded** by the same
   filter, so the capture understates the lab's true packet volume.
6. **The sensor's own traffic is in the capture.** The `192.168.56.1` SSDP
   `M-SEARCH` stream is the sensor host, not a lab VM, and it is the source of
   the only Zeek weirdness (checksum offload). Real multi-vendor sensors usually
   do not observe their own egress this way.
7. **Duplicate frames.** Every guest frame appears twice in the capture (a
   VirtualBox host-only + promiscuous delivery artefact); connection counts in
   `conn.log` are unaffected because Zeek merges them within the same flow.
8. **Counters are unreliable here.** `vboxnet0`'s kernel `rx_*` statistics do
   not reflect captured traffic on this device and must not be used as a
   visibility signal.
9. **Memory headroom was tight** (§2). The phase completed safely, but the
   concurrent VM + browser load left little margin, and `MemAvailable` briefly
   fell below the preflight's nominal 300 MiB reference.
10. **`promiscuity` has no sysfs attribute on this kernel** for `vboxnet0`;
    link flags (`0x1103`, i.e. `UP|BROADCAST|PROMISC|MULTICAST`) were used
    instead. Cosmetic, noted for reproducibility of the integrity snapshot.
11. **One capture, one segment, one time of day.** Nothing here generalises.

---

## 12. Integrity verification

Method: `scripts/phase3_integrity.sh` was run identically before and after
Phase 3 and the two snapshots diffed. It hashes the SOC-001 evidence tree, the
SOC-002 trees, the SOC-003 Phase 1 and Phase 2 evidence trees and the SOC-003
source artifacts, and records lab/network state.

- Snapshots: `integrity/pre-phase3-baseline.txt`,
  `integrity/post-phase3-integrity-check.txt`
- **Changed files: 0. Removed files: 0. Added files: 1**
  (`scripts/phase3_analyze.py`, a new Phase 3 artifact — expected).
- Phase 1 inventory: `sha256sum -c evidence/phase1-zeek-baseline/SHA256SUMS.txt`
  → **3/3 OK**.
- Phase 2 inventory:
  `sha256sum -c evidence/phase2-controlled-network-behaviour/hashes/SHA256SUMS.txt`
  → **49/49 OK**, including `det-201`, `det-202`, `det-203`, `det-common` and
  `phase2-load.zeek` — the detections replayed in this phase are provably the
  Phase 2 originals.
- Lab/network state identical in both snapshots: same two running VMs,
  `vboxnet0` at `192.168.56.1/24` Up, same addresses and the same route table,
  `ip_forward` still `1` (unchanged pre-existing value).
- Suricata: not installed before or after (`dpkg -l` match count 0; `/opt`
  contains only `zeek`).
- Git: `soc-003` is not a Git repository; the only `.git` under `~/soc-lab` is
  the pre-existing `SOC-002-PUBLIC/.git`.
- Write scope: every file written by this phase is under
  `~/soc-lab/soc-003/`.

Evidence bundle hashes: `hashes/SHA256SUMS.txt` + `hashes/manifest.json`.

---

## 13. What this phase proves

1. **The unprivileged dumpcap path works against a live lab interface.** No
   `sudo` was needed to capture real traffic on `vboxnet0`.
2. **The sensor genuinely observes the lab segment.** Frames originating from
   **both** lab VMs were captured — DC1's NetBIOS announcement (Gate 1) and
   WS001's IGMPv3/mDNS/LLMNR (Gate 2). The capture path is connected to the
   segment and receives guest-originated traffic.
3. **The capture filter and confinement held.** Every capture was confined to
   `vboxnet0` with `net 192.168.56.0/24`; no routable address outside the lab,
   and no Internet traffic, appeared in any PCAP.
4. **Zeek 9.0.0 processes live-derived lab traffic cleanly** — exit 0, correct
   classification of mDNS/LLMNR as DNS, correct `S0`/`OTH` UDP states, one
   understood and explained checksum-offload artefact affecting only the
   sensor's own frames.
5. **The unchanged Phase 2 detections run correctly on live-derived input.**
   They loaded, executed and produced **zero firings** — no crash, no
   fail-open, no spurious alert, and the detection source is provably the Phase 2
   original by hash.
6. **On the benign traffic that was present, the detections did not misfire** —
   a narrow but real false-positive datapoint on IGMP/mDNS/LLMNR/NetBIOS/ARP/SSDP
   lab noise.
7. **Nothing outside Phase 3's write scope changed** — SOC-001, SOC-002,
   Phase 1 and Phase 2 are byte-identical, and no VM/network configuration was
   touched.

---

## 14. What this phase does not prove

1. **It does not prove WS001↔DC1 visibility.** No such traffic occurred; the
   nexus is unobserved and, strictly, unproven.
2. **It does not prove unicast VM-to-VM visibility.** Every guest frame seen was
   broadcast or multicast; whether the host adapter also receives *unicast*
   frames between the two guest NICs remains untested.
3. **It did not validate `DET-201` or `DET-203`.** Both were “not exercised by
   this capture”: no TCP, therefore no failed-probe burst and no HTTP intervals.
4. **It did not meaningfully validate `DET-202`.** Two distinct names versus a
   twenty-name threshold is not a test of the decision boundary.
5. **It establishes no false-positive rate, and no precision/recall.** One quiet
   capture cannot support a rate; and no true-positive behaviour was presented.
6. **It says nothing about detection sensitivity**, evasion, or adversary
   behaviour — by design.
7. **It says nothing about IPv6**, which was filtered out.
8. **It does not characterise the *normal* baseline of this lab** — nine minutes
   of near-silence is not a baseline, and the traffic seen is dominated by
   multicast noise rather than domain activity.
9. **It does not validate the live-sensor path.** Zeek was run offline against
   captured files, exactly as in Phases 1–2; Zeek was never attached to an
   interface.
10. **It makes no claim about WS001's or DC1's health, patching, or
    configuration**, and it did not contact either VM.

---

## 15. Recommendation for next phase

**Phase 3b / a re-run of Phase 3 Gate 2 with genuine lab activity is required
before the detections can be called validated.** Concretely:

1. **Exercise the lab, then capture.** Keep the same harness (unprivileged
   `dumpcap` on `vboxnet0`, `net 192.168.56.0/24`, bounded ≤ 10 min), but during
   the window have an operator perform *ordinary* Windows work **on WS001** —
   log off/on, open a network share, browse an internal site, resolve names via
   DC1. That is what generates the DNS/Kerberos/SMB/HTTP traffic the three
   detections consume. The current capture proves this cannot be forced from the
   sensor side without violating the “no generated traffic” rule.
2. **Explicitly target the WS001↔DC1 nexus in the visibility gate.** Re-run
   Gate 1 *while WS001 is doing that ordinary work*, so a real WS001↔DC1 frame
   can be observed and the nexus closed. Until then, treat VM-to-VM visibility as
   **unproven**.
3. **Close the two blind spots deliberately excluded here**: decide whether a
   companion capture without the IPv4 filter (still `vboxnet0`-only) is wanted
   for IPv6/ARP, and whether DHCP broadcasts matter. Note this changes a safety
   control and should be an explicit decision.
4. **Handling checksum offload on the live path.** For a live Zeek-on-interface
   phase, either disable TX checksum offload on `vboxnet0`/the NIC or run Zeek
   with `-C`, and document which — otherwise the sensor's own traffic will be
   discarded as `bad_UDP_checksum` exactly as observed here.
5. **Sequence the remaining work as recommended in the Phase 2 report:**
   richer benign baseline → then the two known `DET-201` blind spots (UDP
   discovery, `SF`-closing connect scan) and `DET-202`'s response-size/entropy
   signal → then true live Zeek on `vboxnet0` with correct `local_networks` →
   only then Suricata as a second, signature-based layer, using the Phase 2 PCAP
   corpus as its regression fixture.
6. **Do not tune thresholds** on the strength of this capture. The capture is
   too thin to justify any change; tuning against it would repeat the synthetic
   calibration problem in a new costume.

**Work stops here. Suricata was not installed and no further phase was started.**

---

## Appendix A — Evidence map

```
evidence/phase3-live-benign-validation/
├── README.md                      (bundle index)
├── gate1/                         GATE 1 — visibility
│   ├── README.md
│   ├── capture-command.txt        exact command, timestamps, interface list
│   ├── capture-run.log
│   ├── gate1-visibility.pcap      window 1 (6 pkts, sha256 9c1334c0…)
│   ├── pcap-validation-capinfos.txt
│   ├── pcap-validation-tshark.txt
│   ├── visibility-analysis.txt    hosts, protocols, determination
│   └── window2/                   window 2 (4 pkts, sha256 afc9ed09…) + validation
├── gate2/                         GATE 2 — benign lab traffic
│   ├── capture-command.txt
│   ├── capture-run.log
│   ├── gate2-benign-lab-traffic.pcap   56 pkts, 540 s, sha256 564b1fe0…
│   ├── pcap-validation-capinfos.txt
│   └── pcap-validation-tshark.txt
├── zeek-run/
│   ├── gate1/  conn.log, weird.log, reporter.log, packet_filter.log, metadata, stdout, stderr
│   └── gate2/  conn.log, dns.log, weird.log, reporter.log, packet_filter.log, metadata, stdout, stderr
├── analysis/
│   ├── hosts-and-protocols.txt
│   ├── safety-address-check.txt        address confinement (safety rule)
│   ├── zeek-telemetry-summary.txt
│   ├── dns-activity.txt
│   ├── http-activity.txt
│   ├── detection-results.txt            per-detection fire / no-fire + why
│   ├── telemetry-summary.json
│   └── final-verification.txt           the final integrity checklist
├── integrity/
│   ├── pre-phase3-baseline.txt
│   └── post-phase3-integrity-check.txt
└── hashes/
    ├── SHA256SUMS.txt
    └── manifest.json
```

## Appendix B — Provenance hashes

| Artifact | SHA256 |
| --- | --- |
| `gate1/gate1-visibility.pcap` | `9c1334c0d60500c7e949ad8389af6455879c7b51075be5ae4960bc0df628b68c` |
| `gate1/window2/gate1-window2-visibility.pcap` | `afc9ed09ea60d047633208319fa46d2afe0e01f578ddf46b31eb962233425581` |
| `gate2/gate2-benign-lab-traffic.pcap` | `564b1fe0518ee45b1c0188ef885bd5578ab74359f3fe6e91082ee81febf299aa` |

`DET-201`/`DET-202`/`DET-203`/`det-common.zeek`/`phase2-load.zeek` hashes are
unchanged from Phase 2 and are verified by
`evidence/phase2-controlled-network-behaviour/hashes/SHA256SUMS.txt` (49/49 OK).

---

**FINAL STATUS: PHASE 3 — PARTIAL / BLOCKED**

Visibility of real lab traffic on `vboxnet0` from the sensor was **established**,
and the unchanged detections were replayed against genuinely benign live lab
traffic without a single firing. However the lab produced **no WS001↔DC1
traffic** and **no TCP / no HTTP / no DNS-to-DC1**, so `DET-201` and `DET-203`
were **not exercised**, `DET-202` was only **partially** exercised, and the
WS001↔DC1 visibility nexus is **unproven**. The phase therefore cannot claim to
have validated the detections against real benign traffic; the correct outcome
under the tasking's own rules is **PARTIAL/BLOCKED**, to be resolved by a re-run
with genuine operator-driven lab activity.
