# SOC-003 — Phase 1.2 Report
## Zeek 9 Installation Validation + Offline PCAP Analysis

**Status: PASS** — Zeek 9.0.0 installation verified; the existing synthetic PCAP
was replayed offline through Zeek and every generated log matches the known
PCAP design with no unexplained anomalies.

---

## 1. Execution context

| Item | Value |
| --- | --- |
| Date/time (start) | 2026-10-16 13:04 EAT |
| Date/time (end)   | 2026-10-16 13:06 EAT |
| Host | `kali` |
| Kernel | `Linux 6.19.14+kali-amd64 x86_64` |
| Working directory for the run | `~/soc-lab/soc-003/evidence/phase1-zeek-baseline/zeek-output` |
| Mode | **Offline PCAP replay only** (`zeek -r`). No `-i`, no live capture. |
| Zeek reinstalled? | **No.** The operator-installed package was used as-is. |

---

## 2. Installation verification

Zeek was already installed by the operator and was **not** reinstalled, upgraded
or reconfigured by this phase. All checks below were read-only. Full command
transcript: `evidence/phase1-zeek-baseline/zeek-install-verification.txt`.

| Check | Command | Result |
| --- | --- | --- |
| Version | `/opt/zeek/bin/zeek --version` | `version 9.0.0` |
| Package | `dpkg-query -W -f='${Package} ${Version} ${Architecture} ${Status}' zeek-9.0-core` | `zeek-9.0-core 9.0.0-0 amd64 install ok installed` |
| Package state | `dpkg-query -s zeek-9.0-core` | `Status: install ok installed` |
| Binary | `ls -l /opt/zeek/bin/zeek` | `-rwxr-xr-x root root 47928040` — exists, executable |
| Binary type | `file /opt/zeek/bin/zeek` | ELF 64-bit LSB PIE executable, x86-64, dynamically linked, stripped |
| Runtime linkage | `ldd /opt/zeek/bin/zeek` | All dependencies resolve; **0** entries `not found` |
| Install path | `/opt/zeek/bin/zeek-config --prefix` | `/opt/zeek` |
| Script path | `/opt/zeek/bin/zeek-config --zeekpath` | `.:/opt/zeek/share/zeek:/opt/zeek/share/zeek/policy:/opt/zeek/share/zeek/site:/opt/zeek/share/zeek/builtin-plugins` |
| Package-owned files | `dpkg-query -L zeek-9.0-core \| wc -l` | 949 files (941 under `/opt/zeek`) |
| Files outside `/opt/zeek` | `dpkg-query -L zeek-9.0-core \| grep -v '^/opt/zeek'` | Only `/usr/share/doc/zeek-9.0-core/*` documentation |

**Package / version / architecture:** `zeek-9.0-core` **9.0.0-0** **amd64** —
state `install ok installed`.

**Runtime linkage detail:** the binary links against the system libraries it
needs and all are present: `libpcap.so.0.8`, `libssl.so.3`, `libcrypto.so.3`,
`libz.so.1`, `libmaxminddb.so.0`, `libkrb5.so.3`, `libzmq.so.5`,
`libstdc++.so.6`, `libgcc_s.so.1`, `libc.so.6` (plus transitive deps).
`libpcap0.8t64`, `libssl3t64`, `libmaxminddb0`, `libzmq5` etc. are declared
package dependencies and are satisfied. No missing libraries, no
`LD_LIBRARY_PATH` override, no environment workaround was required.

**Package source:** installed from
`~/soc-lab/soc-003/packages/zeek-9.0-core_9.0.0-0_amd64.deb` (operator action,
prior to this phase). No APT repository was added or referenced; `/etc/apt/`
contains no Zeek entry.

**Cross-check that nothing under `/opt/zeek` was touched during this phase:**
`find /opt/zeek -type f -newermt '2026-10-16 13:00'` returned nothing; all
package files retain their install-time state. `/opt/zeek/etc/zeek/zeek.conf`
is unmodified.

> The `zeek` binary mtime displays as `Jan 28 2015`; this is the timestamp
> baked into the upstream packaged binary and is not a modification.

---

## 3. Input PCAP (preserved, unmodified)

| Item | Value |
| --- | --- |
| Path | `~/soc-lab/soc-003/evidence/phase1-zeek-baseline/phase1-synthetic-baseline.pcap` |
| SHA256 | `18de849818195361ec7471799f90fab7398009fa777151744124c88f0bc76c11` |
| Size | 1782 bytes |
| Format | libpcap, little-endian, microsecond timestamps, Ethernet, 20 packets |
| Generator | `scripts/gen_phase1_synthetic_pcap.py` (deterministic) |
| mtime | 2026-10-16 12:37:20 +0300 (unchanged) |

The PCAP was **read only**. Its SHA256 after the Zeek run is byte-identical to
the value recorded in Phase 1 (`SHA256SUMS.txt` in the same directory) and to
the value embedded in `pcap-validation-tshark.txt`. The original PCAP was not
modified, copied over, or regenerated.

---

## 4. Exact Zeek command

```
cd ~/soc-lab/soc-003/evidence/phase1-zeek-baseline/zeek-output
/opt/zeek/bin/zeek -r ../phase1-synthetic-baseline.pcap LogAscii::use_json=T
```

- Exit code: **0**
- stderr: **empty** (`zeek-run-stderr.txt`, 0 bytes)
- No working-directory or config adjustment was needed; the default `zeekpath`
  resolved all base scripts because the package installs its script tree at
  `/opt/zeek/share/zeek`. No system configuration, no `ZEEKPATH` export, no
  `local.zeek` edit was required.

---

## 5. Generated logs and event/line counts

Output directory: `~/soc-lab/soc-003/evidence/phase1-zeek-baseline/zeek-output/`

| Log | Lines | Events | Notes |
| --- | --- | --- | --- |
| `conn.log` | 4 | 4 | 1 UDP/DNS flow, 3 TCP flows |
| `dns.log` | 1 | 1 | one query/response pair |
| `http.log` | 1 | 1 | one HTTP request/response transaction |
| `files.log` | 1 | 1 | the HTTP response body (61 bytes, `text/html`) |
| `packet_filter.log` | 1 | 1 | run metadata, not derived from the PCAP |
| **Total** | **8** | — | |

Logs **not** produced (verified absent, not assumed):

- `weird.log` — **not created.** Zeek only writes `weird.log` when at least one
  weird event occurs; the file does not exist in the output directory.
- Also absent: `notice.log`, `ssl.log`, `x509.log`, `ssh.log`, `dhcp.log`,
  `smtp.log`, `ftp.log`, `tunnel.log` — none are expected for this synthetic
  PCAP (no such protocols present).

JSON output mode (`LogAscii::use_json=T`) means one JSON object per event with
no header line; `ts` fields are Unix epoch seconds (UTC).

---

## 6. Network observations (Zeek-derived telemetry)

Base time: PCAP T0 = epoch `1792130400.0` = **2026-10-16 06:00:00 UTC** =
**2026-10-16 09:00:00 EAT**. `t_rel` below is seconds after T0.

### conn.log

| t_rel | Originator | Resp. | Proto | Service | State | Duration | Orig pkts | Resp pkts | History |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0.000 | 192.168.56.101:52000 | 192.168.56.53:53 | udp | dns | SF | 0.021 s | 1 | 1 | `Dd` |
| 0.100 | 192.168.56.101:49152 | 198.51.100.80:80 | tcp | http | SF | 0.072 s | 6 | 5 | `ShADadFf` |
| 0.300 | 192.168.56.101:49153 | 198.51.100.80:8080 | tcp | – | SF | 0.046 s | 4 | 2 | `ShAFf` |
| 0.400 | 192.168.56.101:49154 | 198.51.100.80:8443 | tcp | – | S0 | (none) | 1 | 0 | `S` |

All flows report `local_orig:true` and `local_resp:true`. This is expected, not
evidence of real topology: Zeek's default `Site::private_address_space` includes
`192.168.0.0/16` **and** the RFC 5737 documentation block `198.51.100.0/24`, and
`Site::private_address_space_is_local = T` by default, so both synthetic
endpoints are classified as local.

### dns.log

| Field | Value |
| --- | --- |
| t_rel | 0.000 |
| src → dst | 192.168.56.101:52000 → 192.168.56.53:53 (udp) |
| trans_id | 4660 (`0x1234`) |
| query | `example.test` |
| qtype | `A` (1) |
| rcode | `NOERROR` (0) |
| answers | `198.51.100.80` |
| TTLs | `300` |
| flags | AA=true, RD=true, RA=true |
| rtt | 0.021 s |

### http.log

| Field | Value |
| --- | --- |
| t_rel | 0.123 |
| src → dst | 192.168.56.101:49152 → 198.51.100.80:80 |
| method | `GET` |
| host | `example.test` |
| uri | `/index.html` |
| version | `HTTP/1.1` |
| user_agent | `soc-lab-zeek-baseline/1.0` |
| status | `200 OK` |
| request_body_len | 0 |
| response_body_len | 61 |
| resp_mime_types | `text/html` |

### files.log

| Field | Value |
| --- | --- |
| t_rel | 0.146 |
| source | `HTTP` |
| mime_type | `text/html` |
| seen_bytes / total_bytes | 61 / 61 |
| is_orig | false (server → client response body) |

### packet_filter.log

`{"ts":1792145057.708099,"node":"zeek","filter":"ip or not ip","init":true,"success":true}`

This is the default capture filter Zeek installs at startup; `ts` is the wall
clock of the run (2026-10-16 13:04 EAT), i.e. **not** PCAP-derived data.

---

## 7. Comparison against the known synthetic PCAP

The PCAP design (from `scripts/gen_phase1_synthetic_pcap.py` and the Phase 1
`tshark` baseline) versus what Zeek actually produced:

| # | Known PCAP design | Zeek observation | Verdict |
| --- | --- | --- | --- |
| 1 | DNS query `example.test` A from 192.168.56.101:52000 → 192.168.56.53:53 at +0.000 s | `dns.log`: query `example.test`, A, src .101:52000 → .53:53, t_rel 0.000 | Match |
| 2 | DNS response `example.test` → `198.51.100.80`, TTL 300, at +0.021 s | `dns.log`: answers `198.51.100.80`, TTL 300, NOERROR, AA=true, rtt 0.021 s | Match |
| 3 | HTTP `GET /index.html`, Host `example.test`, UA `soc-lab-zeek-baseline/1.0`, on 192.168.56.101:49152 → 198.51.100.80:80, at +0.123 s | `http.log`: GET `/index.html`, host `example.test`, same UA, t_rel 0.123 | Match |
| 4 | HTTP `200 OK`, `text/html`, 61-byte body, at +0.146 s | `http.log` + `files.log`: 200 OK, `text/html`, 61 bytes | Match |
| 5 | Clean TCP connection 192.168.56.101:49153 → 198.51.100.80:8080 (SYN/SA/A, FA/F, A), from +0.300 s | `conn.log`: tcp SF, 4 orig / 2 resp pkts, history `ShAFf`, t_rel 0.300 | Match |
| 6 | Unanswered TCP SYN 192.168.56.101:49154 → 198.51.100.80:8443, at +0.400 s | `conn.log`: tcp `S0`, orig 1 pkt / resp 0 pkts, history `S`, t_rel 0.400 | Match — unanswered SYN is represented as `S0` |
| 7 | Fixed timestamps | All Zeek `ts` values line up with the fixed T0 + offsets exactly (0.000 / 0.100 / 0.300 / 0.400 s) | Match |
| 8 | Fixed IPs / ports | Originator `192.168.56.101`; responders `198.51.100.80` and `192.168.56.53:53`; ports 49152/49153/49154/52000 → 80/8080/8443/53 | Match |
| 9 | Deterministic sequence values | Confirmed indirectly: Zeek assembled the HTTP transaction (`ShADadFf`) and the 8080 handshake (`ShAFf`) without any gap/retransmit flags | Consistent |

### `conn_state` / `history` interpretation used above

- `SF` — normal connection establishment and teardown (both directions).
- `S0` — connection attempt seen, **no reply** → the unanswered 8443 SYN.
- `history` letters: `S`/`h` = SYN / SYN-ACK, `A/a` = ACK each direction,
  `D/d` = payload each direction, `F/f` = FIN each direction.

### Timestamp fidelity note

Zeek's `conn.log` `duration` is measured to the packet that **closes** the
connection (the responder FIN), so it is slightly shorter than the full
capture span that `tshark` reports:

- HTTP flow: Zeek 0.072 s = responder FIN (+0.172) − initial SYN (+0.100);
  the raw span is 0.093 s (SYN +0.100 → final ACK +0.193).
- TCP/8080 flow: Zeek 0.046 s = responder FIN (+0.346) − SYN (+0.300);
  the raw span is 0.067 s.
- DNS flow: Zeek 0.021 s equals query → response exactly.

This is a definitional difference in how duration is bounded, not missing
packets: the trailing pure-ACK is still counted in `orig_pkts`/`resp_pkts`
(6/5 and 4/2 respectively), confirming Zeek saw every frame.

---

## 8. Weird / anomaly observations

**None.** Zeek created **no `weird.log`**, and no `notice.log`. There are zero
weird events, zero notices, and no analyzer gaps, retransmissions or
protocol-violation tags for this capture. Absence of `weird.log` is a positive
result for a clean synthetic capture, not a missing-file problem — the file is
only written when at least one weird event fires.

---

## 9. Limitations (explicit)

- **Offline PCAP analysis only.** This is a replay of a static capture file via
  `zeek -r`. Nothing was monitored live; no interface was opened (`-i` was not
  used) and no live traffic was captured.
- **No VM-to-VM visibility.** `SOC002-DC1` and `SOC002-WS001` were not started,
  resumed or touched. No claim is made that Zeek observed any real lab host.
- **No Suricata.** Suricata was not installed and is not part of this phase.
- **Not a production deployment.** Zeek ran as a one-shot standalone process in
  a working directory; there is no service, no cluster, no log rotation, no
  `zeekctl` supervision.
- **No malicious activity was detected, because none exists.** This PCAP is
  deterministic, hand-crafted lab traffic. Nothing in these logs should be read
  as a detection, an alert, or an incident.
- **Packet contents vs Zeek telemetry.** The MAC addresses, IP IDs, TCP sequence
  numbers and payloads exist in the PCAP, but Zeek's default logs do not record
  them: `conn.log` carries no L2/MAC fields (the optional
  `policy/protocols/conn/mac-logging` script was not loaded) and no raw
  sequence numbers. Anything not shown above is **not** evidenced by these logs.
- **Earned coverage is narrow.** Only 4 connections, 1 DNS event and 1 HTTP
  transaction exist. This validates the Zeek install/parse/log pipeline; it does
  not exercise anomaly logging, notices, file extraction, TLS, or GeoIP.
- **No data enrichment.** Core package only: no `zkg` packages, no GeoIP
  database, no Community ID.
- **Timestamps are the PCAP's fixed lab times,** not real capture time. The
  replay wall clock was ~13:04 EAT on 2026-10-16.
- **`local_orig`/`local_resp`** are a Zeek default-network-configuration
  artifact (see §6) and must not be read as real network topology.

---

## 10. Evidence paths

Bundle root: `~/soc-lab/soc-003/evidence/phase1-zeek-baseline/`

```
evidence/phase1-zeek-baseline/
├── phase1-synthetic-baseline.pcap            (input, preserved, unmodified)
├── pcap-validation-tshark.txt                (Phase 1 non-Zeek baseline)
├── SHA256SUMS.txt                            (Phase 1 bundle inventory)
├── README.md
├── zeek-install-verification.txt             (NEW — install/linkage transcript)
├── soc001-soc002-integrity-check.txt         (NEW — SOC-001/SOC-002 untouched)
├── pre-install-state/                        (operator pre-install snapshots)
└── zeek-output/                              (NEW — raw Zeek logs, preserved)
    ├── conn.log
    ├── dns.log
    ├── http.log
    ├── files.log
    ├── packet_filter.log
    ├── zeek-run-metadata.txt
    ├── zeek-run-stderr.txt                   (empty — clean run)
    ├── zeek-telemetry-summary.json           (machine-readable, jq-generated)
    └── SHA256SUMS.txt                        (SHA256 of every file above)
```

Raw Zeek logs are preserved unmodified in `zeek-output/`. All analysis was
performed with `jq`; the parsed, normalized form is
`zeek-output/zeek-telemetry-summary.json`.

---

## 11. SHA256 integrity information

`zeek-output/SHA256SUMS.txt` (verify from inside `zeek-output/`):

```
214ad1245e8bbfe06ceb4107b43ba2af484a49d1ba030c43c0aaf33cb630c736  conn.log
dab4ba358753ab329fe2200fc682600eea26c30a20676b867fd05a70194321e6  dns.log
559b89ee3c185a26a6919ea54aec7a4d87f4df0bc594e3317fcdf80d33330411  files.log
af116c715e9b1f281ac2cd2c4c9e2f3bc8f5d06ca030ed7cb588d324e1522995  http.log
7bb7e6fb0421505beb32675ba7c359872454a6c9f7a1110b9734b188187a60d9  packet_filter.log
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  zeek-run-stderr.txt
57cc0d888b15e26645705d183e6a3dc864ef67b3556ef8be1427bfc4427cb70d  zeek-run-metadata.txt
a6ebb4f41f4b7afba02e4bd29caa7f281af5eb63e69bb89ba6950c7e5176c2fd  zeek-telemetry-summary.json
```

`sha256sum -c SHA256SUMS.txt` → all 8 files `OK`.

| Artifact | SHA256 |
| --- | --- |
| `phase1-synthetic-baseline.pcap` (input) | `18de849818195361ec7471799f90fab7398009fa777151744124c88f0bc76c11` |
| `zeek-install-verification.txt` | `c242e9e15f459a3eae3fc9b8c6dc207aa8f526343f7ea4dfe40fec01e1dae7af` |
| `soc001-soc002-integrity-check.txt` | `fd983d0a5140db3cbeb9bd404899965e1f716e68cbedf4412a9c1ae0c74a02dc` |

The empty-file SHA256 `e3b0c442…b855` for `zeek-run-stderr.txt` is the expected
digest of a zero-byte file and confirms the Zeek run emitted no warnings/errors.

---

## 12. SOC-001 / SOC-002 non-modification check

Full detail: `evidence/phase1-zeek-baseline/soc001-soc002-integrity-check.txt`.

- Newest file mtime per sibling tree (SOC-001 = `evidence/soc-001-capture`,
  SOC-002 = `SOC-002-PUBLIC`, `SOC-002-windows-ad`, `soc002-final`,
  `phase4`–`phase10`, `detections`) — the newest is
  `2026-10-15 19:51` (`SOC-002-PUBLIC/.git/logs/...`), i.e. **before** this
  phase began.
- `find ~/soc-lab -path ./soc-003 -prune -o -type f -newermt '2026-10-16 12:55'`
  → **0 files.** Nothing outside `soc-003/` was written during this phase.
- SHA256 values for the SOC-001 capture evidence tree and the SOC-002 top-level
  reports are recorded in the integrity-check file for future comparison.
- `git -C SOC-002-PUBLIC status --porcelain` → empty (working tree clean); the
  only `.git` under `~/soc-lab` is the pre-existing `SOC-002-PUBLIC/.git`.
- No `git init`, no commits, no pushes anywhere.

---

## 13. Constraint compliance

Not done, as required:

- **No Zeek reinstall**, no package install/upgrade/remove, no APT repository
  added, no APT source or key modified (`/etc/apt/` unchanged, no Zeek entry).
- **No system library changes**, no `LD_LIBRARY_PATH`/`ZEEKPATH` override.
- **No `/opt/zeek` changes** — no Zeek config file created or edited.
- **No VM started** — neither Windows VM was powered on or modified.
- **No live capture**; `zeek -i` was not used; no interface was put in
  promiscuous mode; no traffic generated.
- **No networking/firewall/route/DNS/`ip_forward`/VirtualBox changes.**
- **No Suricata** installed or configured.
- **No Git repository initialised; no commits; no pushes.**
- **SOC-001 and SOC-002 untouched** (see §12).
- **No credentials or secrets** read, written or printed.
- No `sudo` command was run during this phase.

File-write scope: this phase wrote only inside `~/soc-lab/soc-003/`.

---

## 14. Rollback method

This phase made **no system-level change**, so no system rollback is required.
The Zeek package itself predates this phase and is the operator's to keep or
remove. To undo this phase's artifacts:

```bash
# 1. Remove the generated Zeek evidence (Phase 1.2 output only)
rm -rf ~/soc-lab/soc-003/evidence/phase1-zeek-baseline/zeek-output
rm -f  ~/soc-lab/soc-003/evidence/phase1-zeek-baseline/zeek-install-verification.txt
rm -f  ~/soc-lab/soc-003/evidence/phase1-zeek-baseline/soc001-soc002-integrity-check.txt
rm -f  ~/soc-lab/soc-003/PHASE1_2_REPORT.md

# 2. Regenerate if needed (deterministic, byte-identical command)
cd ~/soc-lab/soc-003/evidence/phase1-zeek-baseline/zeek-output
/opt/zeek/bin/zeek -r ../phase1-synthetic-baseline.pcap LogAscii::use_json=T
```

Optional, only if the operator wants to remove the Zeek package installed
earlier (this is **not** part of Phase 1.2):

```bash
sudo apt-get remove 'zeek-9.0*'      # package-owned files under /opt/zeek
sudo rm -rf /opt/zeek                # any leftover state (if desired)
```

Rollback is confined to `/opt/zeek` and `~/soc-lab/soc-003/`; it involves no
`/usr`, `/etc`, `/var`, network, VirtualBox or SOC-001/SOC-002 change. The input
PCAP is never removed or rewritten by any step.

---

## 15. Result summary

| Question | Answer |
| --- | --- |
| Zeek installation validated? | **Yes** — 9.0.0, `zeek-9.0-core` 9.0.0-0 amd64, `install ok installed`, `/opt/zeek`, all libs resolve |
| Offline PCAP replay successful? | **Yes** — exit 0, empty stderr |
| Logs produced | `conn.log`, `dns.log`, `http.log`, `files.log`, `packet_filter.log` |
| Total events | 4 conn + 1 dns + 1 http + 1 files = 7 telemetry events (8 lines incl. packet_filter) |
| DNS correct? | **Yes** — `example.test` A → `198.51.100.80`, NOERROR, TTL 300, AA=true |
| HTTP correct? | **Yes** — `GET /index.html` → `200 OK`, `text/html`, 61 bytes |
| TCP/8080 clean connection? | **Yes** — `conn_state SF`, history `ShAFf` |
| TCP/8443 unanswered SYN? | **Yes** — `conn_state S0`, 1 orig pkt / 0 resp pkts |
| Weird/anomalies? | **None** — no `weird.log`, no `notice.log` |
| Any failure? | **None.** No unexpected install/runtime problem occurred. |
| Live monitoring claimed? | **No.** Offline replay only; no VM visibility; no Suricata; no detections. |
