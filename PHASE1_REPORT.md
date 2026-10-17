# SOC-003 — Phase 1 Report

Phase: 1 — Zeek installation and offline validation
Status: **BLOCKED (install) / PARTIAL** — Zeek could not be installed; the
synthetic validation PCAP was produced and validated with a non-Zeek tool.
Executed: 2026-10-16 (local 12:33–12:40 EAT / 09:33–09:40 UTC)
Host: Kali GNU/Linux Rolling 2025.4 (sensor)
Operator: saidi (uid 1000, member of `sudo`)

Phase 1 was to establish a working Zeek network-telemetry pipeline driven from
an offline synthetic PCAP. **No Zeek log exists**, because Zeek cannot be
installed on this host from the existing Kali repository. The blocker is
diagnosed in full below (section 2). No system change was made to work around
it, in line with the Phase 1 stop-condition.

---

## 1. Summary of outcome

| Task | Result |
| --- | --- |
| 1. Install Zeek from existing Kali repo | **BLOCKED** — package unsatisfiable on this system |
| 2. Verify version / path / default policy load | **NOT POSSIBLE** — binary not present |
| 3. Create deterministic synthetic PCAP | **DONE** |
| 4. Run Zeek offline against the PCAP | **NOT POSSIBLE** — Zeek absent |
| 5. Store PCAP/logs under `~/soc-lab/soc-003/` | **PARTIAL** — PCAP stored, no Zeek logs exist |
| 6. Verify conn/dns/http metadata | **PARTIAL** — verified with `tshark` (non-Zeek substitute) |
| 7. SHA256 hashes of artifacts | **DONE** |
| 8. `PHASE1_REPORT.md` | **DONE** (this document) |

No live traffic was captured. No third-party repository was added. Suricata was
not installed. No VM was started or modified. No network, route, firewall, DNS
or sysctl setting was touched.

---

## 2. Installation result and diagnosis

### 2.1 What was attempted

```
sudo apt-get install --no-install-recommends zeek
```

This was **not executed** — the environment requires an interactive `sudo`
password (`sudo -n -l` → `sudo: a password is required`; no askpass helper, no
cached credential, and no passwordless rule applies to user `saidi`). In
addition, a dependency simulation showed the package cannot be installed even
with root. Both facts are recorded here rather than worked around.

### 2.2 The only available package

The single Zeek package offered by the configured repository
(`deb http://http.kali.org/kali kali-rolling main non-free non-free-firmware contrib`)
is stale and unsatisfiable:

```
Package: zeek
Version: 5.1.1-0kali3
Depends: libc6 (>> 2.37), libc6 (<< 2.38), libgcc-s1 (>= 3.0),
         libgoogle-perftools4 (>= 2.10), libkrb5-3 (>= 1.13~alpha1+dfsg),
         libmaxminddb0 (>= 1.0.2), libpcap0.8 (>= 1.7.3),
         libssl3 (>= 3.0.0), libstdc++6 (>= 12), zlib1g (>= 1:1.1.4),
         zeek-common (>= 5.1.1-0kali3)
```

The package binary itself is dated **2023-07-15** and installs `/usr/bin/zeek`.
It predates both the Debian `time_t` (`t64`) library transition and the glibc
2.38 bump, so four of its hard dependencies are now unsatisfiable on this host:

| Dependency required by `zeek` | Status on this system | Blocking? |
| --- | --- | --- |
| `libc6 (>> 2.37)`, `libc6 (<< 2.38)` | installed `libc6 2.42-13` (candidate 2.43-4) | Yes — would require downgrading glibc |
| `libgoogle-perftools4` | not in repo; renamed to `libgoogle-perftools4t64` | Yes |
| `libssl3` | not in repo (candidate `none`); renamed to `libssl3t64` | Yes |
| `libpcap0.8` | not in repo (candidate `none`); renamed to `libpcap0.8t64` | Yes |

`apt-get -s install zeek` fails immediately with:

```
zeek : Depends: libc6 (< 2.38) but 2.42-13 is to be installed
       Depends: libgoogle-perftools4 (>= 2.10)
       Depends: zeek-common (>= 5.1.1-0kali3) but it is not going to be installed
E: Unable to satisfy dependencies.
```

A check of the upstream Kali pool (`http://http.kali.org/kali/pool/main/z/zeek/`)
confirms the repository carries **no newer build** — `5.1.1-0kali3` is the only
version published. There is therefore no install path within the Phase 1
constraint of "use the existing Kali package repository".

### 2.3 Why this stops the phase

The only ways to install Zeek here would be to (a) add a third-party repository,
(b) downgrade `libc6` from 2.42 to 2.37 and substitute/rebuild several renamed
libraries, or (c) build Zeek from source against current libraries. Option (a)
is explicitly forbidden. Options (b) and (c) are broad, high-risk system changes
that the Phase 1 stop-condition forbids ("diagnose it and stop rather than
making broad system changes"). Phase 1 therefore stops at the install step and
this report records the blocker rather than forcing a workaround.

---

## 3. Zeek version and installation path

| Item | Value |
| --- | --- |
| Target version (repo candidate) | `zeek 5.1.1-0kali3` |
| Installed version | **none — not installed** |
| Installed path | **none** (package would place `/usr/bin/zeek`; not present) |
| `which zeek` | not found |
| Default policy/script load test | **not possible — no binary** |

---

## 4. Test PCAP generation method

Generator (deterministic, no randomness):

```
~/soc-lab/soc-003/scripts/gen_phase1_synthetic_pcap.py
```

It uses Scapy (`2.6.1`) to hand-craft 20 Ethernet/IPv4 frames with fixed
timestamps (base `2026-10-16 06:00:00 UTC`), fixed IP IDs, fixed MAC addresses,
fixed TCP sequence numbers and fixed payloads. Re-running it reproduces a
byte-identical file (verified: two runs produced the same SHA256).

All addressing is reserved/placeholder — **no real host, credential, personal
data or captured traffic is involved**:

| Role | Address |
| --- | --- |
| Synthetic client | `192.168.56.101` |
| Synthetic DNS resolver | `192.168.56.53` |
| Web server | `198.51.100.80` (RFC 5737 TEST-NET-2, never routable) |
| DNS QNAME | `example.test` (RFC 6761 reserved `.test` TLD) |

Contents designed to exercise the Phase 1 checks:

- **DNS** query/response for `example.test` A → `198.51.100.80` (UDP/53).
- **HTTP** `GET /index.html` → `HTTP/1.1 200 OK` over TCP/80 with a complete
  handshake and teardown.
- **TCP** a second full connection to TCP/8080 with no payload (clean teardown).
- **TCP** an unanswered `SYN` to TCP/8443 (no reply).

---

## 5. Offline analysis command

The exact command that Phase 1 specifies (from the evidence directory) is:

```
cd ~/soc-lab/soc-003/evidence/phase1-zeek-baseline
zeek -r phase1-synthetic-baseline.pcap
```

**This command was not executed** because Zeek is not installed. It is recorded
here so it can be run verbatim once an install path is available. No Zeek
configuration was created, because there was nothing to configure.

---

## 6. Logs generated

| Log | Expected from this PCAP | Generated? |
| --- | --- | --- |
| `conn.log` | 3 TCP connections (HTTP; plain TCP/8080; unanswered SYN → `S0`) | **No** |
| `dns.log` | 1 query + 1 response for `example.test` | **No** |
| `http.log` | 1 `GET /index.html` + `200 OK` from `example.test` | **No** |

**No Zeek log files were produced.** Any `conn.log`/`dns.log`/`http.log` content
that the pipeline is expected to yield is therefore described (above) as the
*target* schema-to-field mapping, not as observed output.

---

## 7. Substitute validation performed (non-Zeek)

Because Zeek could not run, the PCAP was validated with `capinfos` and `tshark`
to prove it is well-formed and carries the intended metadata. Full output is
preserved at
`~/soc-lab/soc-003/evidence/phase1-zeek-baseline/pcap-validation-tshark.txt`.

Observed:

- File: pcap, Ethernet encapsulation, 20 packets, 1782 bytes, duration 0.400 s,
  strict time order OK.
- Protocol hierarchy: 2 × DNS (UDP), 2 × HTTP (TCP), 18 × TCP.
- TCP conversations:
  - `192.168.56.101:49152 ↔ 198.51.100.80:80` — 11 frames, 888 bytes (HTTP)
  - `192.168.56.101:49153 ↔ 198.51.100.80:8080` — 6 frames, 324 bytes (no payload)
  - `192.168.56.101:49154 ↔ 198.51.100.80:8443` — 1 frame (unanswered SYN)
- DNS: query at `09:00:00.000`, response `A 198.51.100.80` at `09:00:00.021`.
- HTTP: `GET /index.html` (Host `example.test`) at `09:00:00.123`;
  `200 OK` at `09:00:00.146`.

This confirms timestamps, source/destination IPs, ports and protocols are
present and correct. It is a **substitute check, not a Zeek result**.

---

## 8. Limitations of this synthetic test

- **Purely synthetic.** Fixed, hand-crafted packets; no OS stack, no real
  retransmissions, no jitter, no real TLS, no reassembly stress.
- **Single QNAME / single transaction.** One DNS name and one HTTP object only;
  no NXDOMAIN, CNAME chains, TCP DNS, or IPv6.
- **No TLS, no encrypted traffic, no file transfer, no SMTP/SMB.** Nothing to
  test `ssl.log`, `files.log` or protocol breadth.
- **No live network behaviour.** Cannot validate capture performance, NIC
  promiscuous-mode visibility, packet loss, or queuing on the sensor.
- **Not a validation of Zeek.** The whole point of the run — proving Zeek parses
  and logs offline — was not performed, so Zeek's correctness on this host is
  entirely unverified.
- **Timestamp semantics.** Times are fixed UTC; local display will read
  `09:00:00 EAT` (UTC+3).
- **t64/dependency drift is a moving target.** The diagnosis reflects the
  repository state on 2026-10-16; a future Kali rebuild could change it.

---

## 9. SHA256 evidence inventory

Verification: `sha256sum -c evidence/phase1-zeek-baseline/SHA256SUMS.txt`
(run from `~/soc-lab/soc-003`).

```
b0dd85494fa4383bae3bba1c8c8bfe7b372f70443f494ff3ea22ae8004145427  scripts/gen_phase1_synthetic_pcap.py
18de849818195361ec7471799f90fab7398009fa777151744124c88f0bc76c11  evidence/phase1-zeek-baseline/phase1-synthetic-baseline.pcap
fe32083341b32b81aede3d7c6c814b4f05da1bbb434413a306999cf3fe8dbf69  evidence/phase1-zeek-baseline/pcap-validation-tshark.txt
```

The PCAP has no `conn.log`/`dns.log`/`http.log` counterpart to hash because
Zeek did not run.

---

## 10. Statement on live traffic

**No live traffic was captured during Phase 1.** No capture was performed on
`vboxnet0`, on `wlan0`, or on any other interface. `SOC002-DC1` and
`SOC002-WS001` were not started and not modified. The only packet data produced
is the hand-crafted synthetic PCAP described in section 4, which contains no
real hosts, credentials, personal data or corporate traffic.

---

## 11. Constraint compliance

Not done, as required: no third-party repository; no Suricata; no unrelated
package upgrades; no VM start or modification; no `vboxnet0`/`wlan0` capture; no
route, firewall/nftables, DNS or `ip_forward` changes; no `git init`; no
commits; SOC-001/SOC-002/SOC-002-PUBLIC untouched; no credentials or secrets
written.

System modifications made: **none.** The only files created are the artifacts
listed in section 12.

---

## 12. Files created or modified

```
~/soc-lab/soc-003/PHASE1_REPORT.md
~/soc-lab/soc-003/scripts/gen_phase1_synthetic_pcap.py
~/soc-lab/soc-003/evidence/phase1-zeek-baseline/README.md
~/soc-lab/soc-003/evidence/phase1-zeek-baseline/phase1-synthetic-baseline.pcap
~/soc-lab/soc-003/evidence/phase1-zeek-baseline/pcap-validation-tshark.txt
~/soc-lab/soc-003/evidence/phase1-zeek-baseline/SHA256SUMS.txt
```

No pre-existing file was modified.

---

## 13. What is needed to unblock Phase 1

A decision is required from the operator before Phase 1 can complete:

1. **Preferred:** confirm whether a newer Zeek package is acceptable once
   uploaded to this host (e.g., a locally built `.deb` or an official Zeek
   release archive installed by hand) — this avoids third-party repositories but
   is still an out-of-repo install and needs explicit approval.
2. **Or:** accept building Zeek from source against the current toolchain
   (requires root, build dependencies and a compile step).
3. **Or:** defer Zeek and proceed with `tshark`-based offline validation, if a
   Zeek-equivalent pipeline is not essential for the next phase.

Whatever is chosen, an interactive `sudo` password (or a passwordless rule for
the operator) is required to install anything. Synthetic PCAP generation and
hashing are already complete; once Zeek is present, the offline run in section 5
can be executed immediately against the frozen, hashed PCAP.
