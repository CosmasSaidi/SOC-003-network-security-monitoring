# SOC-003 — Phase 0.2 Report

Phase: 0.2 — Scaffolding and sensor NIC preparation
Status: COMPLETE
Executed: 2026-10-16 (local 12:33 EAT / 09:33 UTC)
Host: Kali GNU/Linux Rolling 2025.4 (sensor)

This phase is a bounded setup step: create the SOC-003 workspace, document the
architecture, and prepare the two lab VM NICs for passive sensor visibility. No
monitoring software was installed and no capture was performed.

---

## 1. Actions performed

1. Read-only reconnaissance of the lab:
   - Confirmed `vboxnet0` exists as a host-only network on `192.168.56.0/24`, with
     DHCP disabled and Kali at `192.168.56.1`.
   - Confirmed both lab VMs exist (`SOC002-DC1`, `SOC002-WS001`) and that neither
     was running.
   - Confirmed each VM's NIC1 is host-only on `vboxnet0`.
   - Recorded the pre-change promiscuous policy for both NIC1s as `deny`.
   - Confirmed tool availability: `wireshark`, `tshark`, `dumpcap`, `tcpdump`
     present; `zeek` and `suricata` absent.
   - Derived lab addressing from existing SOC-002 documentation (read-only).
2. Created the `~/soc-lab/soc-003/` directory tree (11 subdirectories).
3. Wrote `README.md` and `architecture/ARCHITECTURE.md`.
4. Changed the NIC1 promiscuous policy to `allow-all` on both VMs via VBoxManage,
   while both VMs were powered off.
5. Verified the change with three independent methods (VBoxManage human-readable,
   VBoxManage machine-readable, and the VM's `.vbox` XML definition).
6. Wrote this report.

Nothing else was created, installed, started, or modified.

---

## 2. Exact VirtualBox changes

Both VMs were confirmed **not running** immediately before the change
(`VBoxManage list runningvms` returned empty).

Commands executed (one per VM, verbatim):

```
VBoxManage modifyvm SOC002-DC1   --nicpromisc1 allow-all
VBoxManage modifyvm SOC002-WS001 --nicpromisc1 allow-all
```

Both commands returned exit code `0`.

| VM | Adapter | Setting | Before | After |
| --- | --- | --- | --- | --- |
| `SOC002-DC1` | NIC1 (slot 0) | Promiscuous policy | `deny` (default) | `allow-all` |
| `SOC002-WS001` | NIC1 (slot 0) | Promiscuous policy | `deny` (default) | `allow-all` |

Resulting XML attribute (live machine configuration only):

```xml
<Adapter slot="0" enabled="true" MACAddress="08002795B302" promiscuousModePolicy="AllowAll" type="82540EM"/>
<Adapter slot="0" enabled="true" MACAddress="080027817A74" promiscuousModePolicy="AllowAll" type="82540EM"/>
```

This is a hypervisor-level policy on NIC1 only. It is the sole configuration
change made to either VM.

### Explicitly unchanged

Confirmed by before/after comparison of the full NIC1 attributes:

- Attachment type: `hostonly` (unchanged)
- Attachment target: `vboxnet0` (unchanged)
- MAC address: `08:00:27:95:B3:02` / `08:00:27:81:7A:74` (unchanged)
- Adapter type: `82540EM` (unchanged)
- Cable connected: `on` (unchanged)
- NIC2–NIC8: disabled (unchanged)
- VM memory/CPU: untouched
- Guest IP configuration, DNS, routes, DHCP: untouched
- No adapters were added, removed, or re-ordered

---

## 3. Verification results

Three independent checks, all agreeing.

**a) VBoxManage, human-readable**

```
SOC002-DC1   NIC 1: <MAC: 08002795B302, Attachment: Host-only Interface 'vboxnet0',
             Cable connected: on, Type: 82540EM, Promisc Policy: allow-all>
SOC002-WS001 NIC 1: <MAC: 080027817A74, Attachment: Host-only Interface 'vboxnet0',
             Cable connected: on, Type: 82540EM, Promisc Policy: allow-all>
```

**b) VM definition files** — exactly one `promiscuousModePolicy` attribute per
file, on slot 0 only, in the live `<Hardware>` section:

- `~/VirtualBox VMs/SOC002-DC1/SOC002-DC1.vbox:125` → `promiscuousModePolicy="AllowAll"`
- `~/VirtualBox VMs/SOC002-WS001/SOC002-WS001.vbox:155` → `promiscuousModePolicy="AllowAll"`

**c) Host network unchanged**

```
vboxnet0: DHCP: Disabled, IPAddress: 192.168.56.1, NetworkMask: 255.255.255.0, Status: Up
```

**VM power state at end of phase**

```
SOC002-DC1   VMState="poweroff"
SOC002-WS001 VMState="aborted"
```

Neither VM is running. `SOC002-WS001` reports `aborted`, meaning it was last left
in an unclean power-off state from a previous SOC-002 session; this is its state
on entry to this phase and was not caused by, nor altered by, Phase 0.2.

**Operational note (for a later phase):** both VMs have snapshots. The
promiscuous policy was applied to the live configuration, not to the stored
snapshot configurations. Reverting either VM to its snapshot would restore the
snapshot's `deny` setting, so the policy must be re-checked after any snapshot
revert.

---

## 4. Files created

Directory tree (all new):

```
~/soc-lab/soc-003/
├── README.md
├── PHASE0_2_REPORT.md
├── architecture/     (ARCHITECTURE.md)
├── captures/
├── zeek/
├── suricata/
├── detections/
├── investigations/
├── cases/
├── evidence/
├── analysis/
├── scripts/
└── docs/
```

Documents written:

- `~/soc-lab/soc-003/README.md`
- `~/soc-lab/soc-003/architecture/ARCHITECTURE.md`
- `~/soc-lab/soc-003/PHASE0_2_REPORT.md` (this file)

`ARCHITECTURE.md` documents: Kali as the sensor, `vboxnet0` / `192.168.56.0/24`,
DC1 and WS001 roles and IPs (`192.168.56.10`, `192.168.56.102`), Zeek as network
telemetry, Suricata as passive IDS/detection, Wireshark/tshark as packet-analysis
tooling, the strict isolated-lab scope, `wlan0` as explicitly out of capture
scope, the absence of a third VM, resource constraints, and the bounded PCAP
retention policy.

No files outside `~/soc-lab/soc-003/` were created or modified, with the single
exception of the two VirtualBox `.vbox` machine definitions, which were updated
by `VBoxManage modifyvm` as described above.

---

## 5. Explicit statements

- **No packages were installed.** No `apt`, `pip`, or other package operation was
  run. Zeek and Suricata remain uninstalled; no software was added, upgraded, or
  removed. Task 5 satisfied.
- **No VMs were started.** Neither `SOC002-DC1` nor `SOC002-WS001` was booted,
  resumed, saved, reset, or otherwise transitioned by this phase. Both were
  powered off at the moment of the NIC change and remain off. Task 6 satisfied.
- **No network routing/firewall/DNS changes were made.** Kali's firewall,
  nftables ruleset, `net.ipv4.ip_forward`, routing table, and DNS configuration
  were read for reporting only and were not modified. No routing, NAT, or
  bridging configuration was created or altered, and the `vboxnet0` host-only
  network definition itself is unchanged. Tasks 8 and the phase constraints
  satisfied.
- **No traffic was captured.** Task 7 satisfied (no capture file was created).
- **No Git repository was initialized and no commits were made.** `soc-003/` is
  not a Git repository. Tasks 9 and 10 satisfied.
- **SOC-001 and SOC-002 files were not modified.** Task 11 satisfied. Existing
  SOC-002 documents were read for addressing and context only.
- **`SOC-002-PUBLIC` was not touched.** Task 12 satisfied; it was not read,
  written, or listed in any operation.
- **No credentials or secrets were exposed.** Task 13 satisfied; none were read,
  written, or printed, and none appear in the created files.

---

## 6. Errors encountered

No errors. Both `VBoxManage modifyvm` commands succeeded with exit code 0 and all
verification checks passed on the first attempt.

One benign, pre-existing condition was observed and is recorded for accuracy:

- `VBoxManage` prints `Warning: program compiled against libxml 215 using older
  214`. This is a Debian packaging mismatch in the VBoxManage binary, is emitted
  on every invocation, and has no effect on VirtualBox behaviour or on the
  configuration changes made. No action taken.

Phase 0.2 is complete. Work stops here pending the next phase.
