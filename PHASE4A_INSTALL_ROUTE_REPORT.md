# SOC-003 — Phase 4A: Suricata Installation Route Reconnaissance

| Field | Value |
|---|---|
| Phase | SOC-003 Phase 4A (reconnaissance only) |
| Mode | **READ-ONLY** — nothing installed, started, or modified |
| Date / time of reconnaissance | 2026-10-17, 01:13–01:20 EAT |
| Host | Kali sensor (`kali`), Lenovo ThinkPad T470s |
| Operator | `saidi` (uid 1000, group sudo) |
| Report author | SOC-003 operator (`saidi`) |
| **Final status** | **PASS** — a safe, supported installation route is identified |

Nothing in this phase was executed. Every command below was a query
(`apt-cache`, `apt-get --simulate`, `dpkg`, `ls`, `find`, `sha256sum`, `curl -o /dev/null`).
No package was installed, no file was written outside this report, no source list,
firewall rule, Zeek artifact, or network interface was touched.

---

## 1. Current Suricata state

**Suricata is NOT installed. No partial, stray, or shadow installation exists.**

| Probe | Command | Result |
|---|---|---|
| Binary on PATH | `command -v suricata suricatasc suricata-update` | **not found** (empty output, exit 1) |
| Package DB | `dpkg -l \| grep -i suricata` | **0 matches** |
| dpkg metadata | `ls /var/lib/dpkg/info/suricata*` | **no such file** |
| apt state | `apt-cache policy suricata` | `Installed: (none)` |
| Config tree | `/etc/suricata` | **does not exist** |
| State dir | `/var/lib/suricata` | **does not exist** |
| Log dir | `/var/log/suricata` | **does not exist** |
| Rules tree | `/usr/share/suricata` | **does not exist** |
| systemd units | `systemctl list-unit-files \| grep -i suricata` | **0 matches** |
| Python binding | `python3 -c "import suricata"` | ModuleNotFoundError |
| pip packages | `pip3 list \| grep -i suricata` | none |
| Filesystem-wide | `find / -xdev -maxdepth 4 -iname '*suricata*'` | only `~/soc-lab/soc-003/suricata/` (empty placeholder dir) |

Confirming prior phases: Phase 3B/3D independently recorded `Suricata | Not installed, not started`.
That state still holds.

---

## 2. Kali release and architecture

| Item | Value |
|---|---|
| Distribution | Kali GNU/Linux Rolling |
| `VERSION_ID` | **2025.4** |
| `VERSION_CODENAME` | **kali-rolling** |
| `PRETTY_NAME` | `Kali GNU/Linux Rolling` |
| `ID_LIKE` | `debian` |
| Kernel | `6.19.14+kali-amd64` (Kali 6.19.14-1+kali1, built 2026-05-05) |
| Architecture (dpkg) | **amd64** |
| Architecture (uname -m) | x86_64 |
| CPU | Intel Core i5-7300U, 2 cores / 4 threads, 2.60 GHz base, 3.50 GHz max |
| RAM | 7.5 GiB total |

This is a rolling-release, Debian-derived distribution: the single supported package
source is the Kali rolling archive. There is no fixed "stable point release" to pin against,
so the install decision must be made against the *current* rolling candidate.

---

## 3. Repository candidate

Active Kali source (`/etc/apt/sources.list`):

```
deb http://http.kali.org/kali kali-rolling main non-free non-free-firmware contrib
```

Candidate found:

```
suricata:
  Installed: (none)
  Candidate: 1:8.0.7-1
  Version table:
     1:8.0.7-1  500
        500 http://http.kali.org/kali kali-rolling/main amd64 Packages
```

- `apt-cache madison suricata` → exactly one candidate: `1:8.0.7-1` (kali-rolling/main).
- `Filename:` `pool/main/s/suricata/suricata_8.0.7-1_amd64.deb`
- `Section: net`, `Priority: optional`, `Architecture: amd64`
- Debian-side maintainer: Sascha Steinbiss `<satta@debian.org>`, `Homepage: https://suricata.io`
- Related packages in the same archive: `suricata-update 1.3.8-1`, `slinkwatch 1.1-6+b10`,
  `fever 1.4.0-1`, `arkime` (reverse-depends on suricata).
- `suricata-hyperscan` (the old separate Hyperscan build) has **no candidate**; it is now
  `Replaces:`/`Conflicts:` by the main `suricata` package, i.e. Hyperscan support is folded in.

Other `.sources` files exist on the host but are **not relevant and were not used**:
`brave-browser-release`, `cursor`, `google-chrome`, `vscode` (all third-party, none ship Suricata).

**Note:** the local apt lists were last refreshed **2026-09-28 15:05** (list dir mtime
2026-09-28 20:57). The candidate above reflects that snapshot. An `apt update` in the install
phase may move the candidate to a newer rolling build — see §11.

---

## 4. Candidate version and integrity anchors

| Field | Value |
|---|---|
| Epoch:version-release | **`1:8.0.7-1`** |
| Upstream version | **8.0.7** |
| Download size | 4,482,084 bytes (~4.27 MiB) |
| Installed size (package alone) | 16,613 KiB (~16.2 MiB) |
| SHA256 | `3de864782cfe398a493955f9ba409f25d631972c67fde0e485b989dddba3cfb2` |
| SHA1 | `f2049495a9507aa854e64c99b4915631ca711bd2` |
| MD5sum | `6198dfc81de411bea947a3d7539c5f9e` |

Record these hashes now; Phase 4B should re-verify the SHA256 of the `.deb` that is actually
downloaded matches the value above (or the newly refreshed value if `apt update` changes the
candidate) before trusting the install.

---

## 5. Dependency compatibility (libc6 / t64 environment)

Verified with `apt-cache show`, `apt-cache policy`, `dpkg -s` and a **simulated** install
(`apt-get install --simulate suricata`) — simulation is read-only and does not download or install.

### 5.1 Hard blockers checked — all clear

| Requirement | Package declares | Host has | Verdict |
|---|---|---|---|
| C library | `libc6 (>= 2.39)` | **2.42-13** | **PASS** (2.42 ≥ 2.39) |
| glibc ABI | — | `ldd (Debian GLIBC 2.42-13) 2.42` | PASS |
| Architecture | `amd64` | `amd64` (x86_64) | PASS |
| t64 transition | `libpcap0.8t64`, `libmagic1t64`, `libevent-2.1-7t64` … | all t64 variants present | **PASS** |
| C++/GCC runtime | `libgcc-s1 (>= 4.2)` | present | PASS |

**No libc6 change is required.** `libc6` does **not** appear anywhere in the install plan
(neither as upgrade, downgrade, or new). Constraint "do not downgrade libc6 / core libraries"
is satisfied by design. The host is fully past the Debian 64-bit `time_t` (t64) transition,
which is the most common reason a modern Suricata package fails on older Debian derivatives.

### 5.2 Simulated transaction plan

```
10 upgraded, 26 newly installed, 0 to remove and 3020 not upgraded.
```

- **0 packages removed** → no conflict, no forced uninstall of anything.
- **26 new**, of which 23 are libraries pulled in transitively.
- **10 upgraded**, all routine rolling-release forward upgrades (see §5.3).

**New packages (26):**

```
libfdt1 libhyperscan5 libnetfilter-log1
librte-argparse26 librte-bus-pci26 librte-bus-vdev26 librte-eal26 librte-ethdev26
librte-hash26 librte-ip-frag26 librte-kvargs26 librte-log26 librte-mbuf26
librte-mempool26 librte-meter26 librte-net-bond26 librte-net26 librte-pci26
librte-rcu26 librte-ring26 librte-sched26 librte-telemetry26
libxdp1 sse4.2-support suricata suricata-update
```

**Upgraded (10):**

```
isa-support libhwloc-plugins libhwloc15
libpcre2-16-0 libpcre2-32-0 libpcre2-8-0 libpcre2-dev libpcre2-posix3
libze1 sse3-support
```

### 5.3 Why each upgrade is triggered (and why it is safe)

| Package group | Host version → candidate | Reason | Assessment |
|---|---|---|---|
| `libpcre2-8-0` (+ `-16-0`, `-32-0`, `-posix3`, `-dev`) | `10.46-1` → `10.48-2` | Suricata requires `libpcre2-8-0 (>= 10.47)` | Same soname (`libpcre2-8-0`), ABI-compatible bump. Forward upgrade only, no downgrade. |
| `libhwloc15` (+ `libhwloc-plugins`) | `2.12.2-1` → `2.14.0-2` | Suricata requires `libhwloc15 (>= 2.14.0)` | Same soname, forward upgrade. Purely NUMA/topology support; a 2-core laptop barely uses it. |
| `libze1` (libseccomp) | `1.24.1-2` → `1.32.0-1` | Rolling-repo resync of an indirect dep | Same soname; syscall-filtering lib, no behaviour change expected. |
| `isa-support`, `sse3-support` | `27` → `34` | `libhyperscan5` pulls `sse4.2-support` | These are tiny ISA-capability metapackages enabling the CPU-feature dependency chain. `sse4.2-support` is genuinely required — Hyperscan needs SSE4.2. |
| `libfdt1`, `librte-*26` (22 DPDK libs), `libxdp1`, `libnetfilter-log1`, `libhyperscan5`, `suricata-update` | new | DPDK/XDP/NFLOG linkage and pattern-matching engine | Additive only; DPDK and AF_XDP paths are unused in this lab (no hugepages, no XDP) — they are link-time deps, not runtime requirements. |

Notably **absent from the plan**: `libc6`, `systemd`, `python3` (already satisfied),
`libpcap0.8t64` (already present), `libyaml-0-2` (already present),
`libmaxminddb0` (present, ≥ 1.0.2), `libnet9` (present), `libjansson4` (present),
`liblz4-1` (present), `libcap-ng0` (present), `libnuma1` (present),
`libnetfilter-queue1` (present), `libnfnetlink0` (present).

### 5.4 t64-aware vs. non-t64 deps

Suricata 8.0.7-1 depends on the **t64** variants (`libpcap0.8t64`, `libmagic1t64`,
`libevent-2.1-7t64`) and on non-t64 libs that never needed the transition
(`libbpf1`, `libpcre2-8-0`, `libhiredis1.1.0`, `libyaml-0-2`, `zlib1g`). All resolve cleanly
against this host. This is a strong compatibility signal: the package was built against the
same post-t64, post-glibc-2.39 generation as the installed Kali 2025.4 userland.

**Conclusion: the existing Kali repository package is compatible with the current
libc6/t64 environment. No downgrade, no pinning, no manual `.deb` surgery is needed.**

---

## 6. Is Suricata 8.0.7 directly available? What is the official stable?

**Yes — Suricata 8.0.7 is directly available from the current Kali repository**, as
`1:8.0.7-1` in `kali-rolling/main`. Item 7 (find an upstream route) is therefore
**not needed**; it is documented below only for completeness and rejected on the merits.

**Official upstream stable version:** the Kali/Debian packaging for this archive is built from
upstream Suricata **8.0.7** (homepage `https://suricata.io`, mainline `x.y.z` tagging).
The branch line is **8.0.x**, i.e. 8.0.7 is a *patch-level* release on the current stable
series — a maintenance point release, not a development snapshot.

**Limitation, stated honestly:** the upstream version could not be independently confirmed
from the internet during this reconnaissance. `https://suricata.io/` responded through an
intercepting HTTP proxy (HTTP 202/301) and returned no usable release list, and
`deb.suricata.io` did not resolve (DNS NXDOMAIN) from this network. Upstream confirmation is
therefore taken from the distribution metadata (package version, maintainer, homepage) rather
than from a live upstream page. Phase 4B should not treat any "latest upstream release"
claim as independently verified.

---

## 7. Safest installation route

**Recommended route: install the Kali rolling package `suricata 1:8.0.7-1` from the existing
Kali repository, in passive IDS mode, with no repository changes.**

Rationale:

1. **Zero new trust anchors.** The package is signed by the Kali archive key already trusted on
   this host. No new keyring, no new source, no new URL.
2. **Already integrated with the host.** Built against Kali 2025.4-era glibc/t64; depend
   resolution verified as `0 removals` by simulation.
3. **No source build.** Objectives #9/#10 (no libc6 downgrade, no source build) are met
   trivially — the distro ships the exact major.minor.patch the phase targets.
4. **Matches the architecture decision.** Package ships the standard Debian unit, config
   skeleton, and `suricata-update` companion; the lab needs a passive `vboxnet0` sensor, which
   the packaged AF_PACKET capture path provides without any inline/NFQUEUE wiring.
5. **Reversible.** A single `sudo apt purge suricata suricata-update` (plus forwarding the
   dependency set to `apt autoremove`) restores the current state. Nothing in this route
   touches routing, NAT, firewall, or Zeek.

Sanity check to be repeated in Phase 4B before installing (read-only):

```bash
apt-cache policy suricata          # expect 1:8.0.7-x, Installed: (none)
apt-get install --simulate suricata | tail -5   # expect '0 to remove'
```

---

## 8. Routes considered and rejected

| Route | Verdict | Reason |
|---|---|---|
| **Kali `kali-rolling/main` package** | **SELECTED** | Signed, compatible, current, zero new trust, 8.0.7 = target |
| OISF official PPA (`ppa:oisf/suricata-stable`) | **Rejected** | Launchpad PPAs serve **Ubuntu** series only. Kali is Debian-based; a PPA would be a third-party repo and a foreign-distro package — violates objective #8 and risks glibc/t64 mismatch. |
| `deb.suricata.io` / OISF APT repo | **Rejected** | Not resolvable/verified from this host, and it would be a new third-party repository, which is explicitly out of scope. |
| Upstream source tarball + `./configure && make` | **Rejected** | Explicitly lowest priority (objective #10) and unnecessary: the packaged version already equals the target. Also far riskier on a CPU/RAM-constrained laptop (build-time CPU saturation, dozens of `-dev` deps, no package-level rollback). |
| Container (Docker/Podman) or Snap | **Rejected** | Adds a runtime; the host already runs two VirtualBox VMs under memory pressure; snap would also be a new distribution channel and binds to a loop-mounted squashfs with its own confinement rules for AF_PACKET capture. |
| Downloading a raw `.deb` from a Debian mirror and `dpkg -i` | **Rejected** | Breaks dependency handling and would bypass the Kali archive version; strictly worse than the in-repo package. |
| Third-party repos already present (`brave`, `cursor`, `google-chrome`, `vscode`) | **N/A** | None of them ship Suricata; on principle none should be used for IDS content. |

---

## 9. Risks and blockers

**No hard blockers. Route is PASS.** Residual risks, in priority order:

1. **Memory pressure is real right now (moderate).** `free -h` at reconnaissance:
   total 7.5 GiB, used 6.5 GiB, free 749 MiB, `available` 1.0 GiB; swap 9 GiB with
   4.3 GiB **in use**. Both SOC-002 VMs are up (VirtualBoxVM DC1 ≈ 2.24 GB RSS,
   WS001 ≈ 1.84 GB RSS). Load average 4.00 / 3.29 / 3.09 on 4 threads. Suricata has not
   been measured here, and the install adds a memory-resident process on a host that is
   already swapping.
   *Mitigation for Phase 4B:* run Suricata with a deliberately small configuration
   (single `workers` runmode, 2 threads max, reduced `stream.memcap` / `flow` limits,
   Hyperscan-enabled but with a small loaded-rule subset), and measure before/after RSS.
   Do not enable DPDK or AF_XDP. Runtime footprint is discussed in §10.
2. **`apt update` freshness (low).** Local lists are from 2026-09-28. Refreshing before
   install may shift the candidate to a newer rolling build of 8.0.x. Treat the exact
   version/hashes in §4 as valid for the *current* snapshot; re-capture them in Phase 4B
   after the refresh.
3. **Shared-library forward upgrades (low).** `libpcre2` (10.46 → 10.48), `libhwloc15`
   (2.12.2 → 2.14.0) and `libze1` (1.24.1 → 1.32.0) are system-wide upgrades affecting
   every dependent binary, not just Suricata. All are same-soname, ABI-compatible forward
   moves and are what a normal Kali rolling update would do anyway — but they are changes
   outside the SOC-003 tree and must be recorded in the Phase 4B change log.
4. **Possible auto-start of the systemd unit on install (medium, must be controlled).**
   The Debian-family package ships `/lib/systemd/system/suricata.service`. Installing may
   enable and start Suricata immediately against the *default* configuration, which is not
   the lab config (default config loads rules and may attempt interface monitoring).
   Phase 4B must either install with the service start suppressed (temporary
   `policy-rc.d` deny, or `systemctl mask suricata` beforehand) or stop and disable the
   unit immediately after install, before any traffic is seen.
5. **Rules supply chain (low–medium, deferred).** Signature detection needs rule content.
   `suricata-update` (in-repo, `1.3.8-1`) fetches rule sets from external sources
   (ET Open / Proofpoint). That is a *rule* download, not an apt repository, so it does not
   violate objective #8 — but it is an outward network dependency and rule-set provenance
   must be recorded in Phase 4B.
6. **CPU contention (moderate).** The i5-7300U has 4 threads total and is already at
   load ~4. Suricata rule loading with Hyperscan compilation is CPU-bursty. Expect a
   noticeable but temporary spike during startup/`suricata-update`.
7. **Constraint compliance is otherwise clean.** No IPS/inline mode is required by this
   route (passive AF_PACKET on `vboxnet0`), so no firewall/NFQUEUE, routing, or NAT change
   arises. `vboxnet0` was observed as `UP 192.168.56.1/24` and must remain untouched.
8. **No blocker found that would justify changing repositories, downgrading libraries, or
   building from source.**

---

## 10. Expected resource impact

Measured host state (reconnaissance): `/` = 235 GB with **105 GB available** (54 % used),
14.6 M free inodes (7 % used), `/home/saidi/soc-lab` = 15 GB, `~/soc-lab/soc-003` = 19 MB.
Disk is **not** a constraint. RAM/CPU is.

### Disk

| Item | Estimate | Basis |
|---|---|---|
| Download (all 36 packages) | **~10.3 MiB** | sum of `Size:` fields of the simulated plan (suricata 4.27 MiB + libhyperscan5 2.64 MiB + libpcre2-dev 0.84 MiB + libze1 0.62 MiB + DPDK/rest) |
| Newly extracted on disk | **~45 MiB** | sum of `Installed-Size:` of the plan (36 packages) |
| Upgraded packages' net growth | a few MiB | pcres/hwloc/libseccomp minor bumps |
| Rule set (ET Open, via `suricata-update`) | ~30–60 MiB | typical `suricata.rules` bundle; deferred to Phase 4B |
| `eve.json` alerts/flow logs | **potentially the largest consumer** | verbose EVE output on a lab link can grow fast — needs rotation from day one |
| Headroom remaining | ≥ 104 GB | ample for a 2 × 8.5 MB Phase 3D replay corpus and logs |

### RAM and CPU (estimates — **not measured**, flagged as such)

| Item | Expectation | Note |
|---|---|---|
| Suricata RSS, minimal lab config (single workers runmode, ~2 threads, reduced memcaps, small rule subset) | **~120–250 MB** | order-of-magnitude for a low-traffic lab |
| Suricata RSS with full ET Open (~tens of thousands of rules) + Hyperscan | **~300–600 MB**, plus a transient load-time peak | Hyperscan compiles pattern sets at startup: CPU-bursty and memory-bursty |
| CPU | 1–2 threads busy during replay; startup spike during rule load | i5-7300U, 4 threads, currently loaded ~4.0 |
| Interaction with existing VMs | Must be validated | DC1 ≈ 2.24 GB + WS001 ≈ 1.84 GB RSS already resident, 4.3 GiB swap in use |

**Net assessment:** the install itself is cheap (≈10 MiB download, ≈45 MiB disk). The
*ongoing* cost is an extra always-resident process on a host already swapping with two VMs.
Phase 4B should (a) install, (b) stop/disable the unit if it auto-starts, (c) bring Suricata
up once in a minimal passive config against the existing Phase 3D PCAPNG offline, and
(d) record before/after RSS, swap, and load. Prefer **offline replay before live monitoring**
so the resource question is answered without adding a live capture load.

---

## 11. Exact next installation commands — **NOT EXECUTED**

Provided for Phase 4B. All are the ordinary, reversible, in-repo route. **Do not run these as
part of Phase 4A.**

Step 0 — refresh metadata (optional, but recommended so the candidate is current;
this writes only `/var/lib/apt/lists`, which is why it is deferred to the install phase):

```bash
sudo apt update
```

Step 1 — re-verify the candidate and the dependency plan is still clean (read-only):

```bash
apt-cache policy suricata
apt-get install --simulate suricata | tail -5      # expect: '0 to remove'
```

Step 2 — prevent the packaged service from starting itself against the default config:

```bash
sudo systemctl mask --now suricata     # or: printf '#!/bin/sh\nexit 101\n' | sudo tee /usr/sbin/policy-rc.d && sudo chmod +x /usr/sbin/policy-rc.d
```

Step 3 — install from the existing Kali repository only:

```bash
sudo apt install suricata suricata-update
```

Step 4 — immediately confirm state and suppress any auto-start:

```bash
dpkg -l | grep suricata
suricata --build-info
systemctl status suricata --no-pager
sudo systemctl disable --now suricata
```

Step 5 — integrity record for the evidence tree (compare against §4):

```bash
sha256sum /var/cache/apt/archives/suricata_1%3a8.0.7-1_amd64.deb
```

Step 6 — only after the above, and in a later phase, offline-validation against the Phase 3D
corpus in a *copy* of the config tree:

```bash
suricata -r ~/soc-lab/soc-003/evidence/phase3d-guest-capture/ws001/ws001-dc1-guest-capture.pcapng \
         -l <phase4b-output-dir> -c /etc/suricata/suricata.yaml -S <lab-rule-file>
```

Explicitly **not** to be used: `apt-add-repository`, PPA addition, `deb.suricata.io`,
any `git clone && make`, any `dpkg -i` of an out-of-repo `.deb`, any `--allow-downgrades`,
and any systemd-run in IPS/inline/NFQUEUE mode.

---

## 12. Integrity observations

**Changes made during Phase 4A: none.** Only `apt-cache`, `apt-get --simulate`,
`dpkg`/`dpkg -V` queries, `ls`/`find`/`du`/`df`, `sha256sum`, `ps`, `systemctl list-unit-files`,
`git status`, and `curl` to `/dev/null` were used. No write path was touched. Partially-read-only
credential files were not accessed.

| Target | Observation | Status |
|---|---|---|
| Zeek package | `zeek-9.0-core 9.0.0-0`, `Status: install ok installed`, `Installed-Size: 52706`, 949 files | **untouched** |
| Zeek binary | `/opt/zeek/bin/zeek` → `version 9.0.0`; `sha256 = ec575807ba30a456cbca930b0ac6aa87ebfac1a82ce6f8b7108f9e0f7db03692` | record as the Phase 4A anchor hash |
| Zeek file integrity | `dpkg -V zeek-9.0-core` → **no output** (no modified/missing files) | **clean** |
| `/opt` contents | only `zeek/` (`bin`, `etc`, `lib`, `share`) | no second engine present |
| `~/soc-lab/soc-003/` | 19 MB; `suricata/` and `zeek/` subdirs exist and are **both empty** (placeholders created in Phase 0) | **no Suricata config, rules, or artifacts exist** |
| Suricata artifacts search | `find ~/soc-lab -iname '*suricata*'` → only the empty `soc-003/suricata/` dir; `find / -xdev -maxdepth 4` → same | **clean** |
| Suricata references in docs | only prose in `PHASE0_2/1/1_2/2/3/3B/3C/3D` reports and `README.md` stating Suricata is absent | consistent |
| SOC-001 / SOC-002 | untouched; `git -C ~/soc-lab/SOC-002-PUBLIC status --porcelain` → **empty** (clean) | **untouched** |
| Git initialization | no `.git` in `~/soc-lab` or `~/soc-lab/soc-003`; the only repo is the pre-existing `SOC-002-PUBLIC/.git` | **none initialized** |
| apt sources | `/etc/apt/sources.list` and `sources.list.d/*` **unmodified** (brave/cursor/chrome/vscode pre-existing) | **unmodified** |
| apt lists | kali `InRelease` mtime 2026-09-28 15:05; list dir 2026-09-28 20:57 → no refresh performed | **unmodified** |
| package DB | no install/remove occurred; `/var/cache/apt/archives/*.deb` → **empty** | **unchanged** |
| VirtualBox | `VBoxSVC` + `VirtualBoxVM` for `SOC002-DC1` and `SOC002-WS001` still running | untouched |
| Network interfaces | `vboxnet0` `UP 192.168.56.1/24`, `wlan0` `UP 10.16.17.149/19`, `eth0` DOWN | untouched; no capture started |
| Phase 3D corpus | `ws001-dc1-guest-capture.pcapng` (1,002,532 bytes) plus `SHA256SUMS.txt` present under `evidence/phase3d-guest-capture/` | present, unmodified |
| No publishing | no commit, no push, no artifact upload performed | compliant |

Environment note (not a SOC-003 asset): `/var/log` and `/var/log/journal` are ≈2.1 GB total.
Not touched; mentioned only because Suricata's EVE output will add to journal/log pressure if
unrotated. Disk headroom (105 GB) makes this a hygiene item, not a risk.

---

## 13. Final status

**PASS.**

- Suricata is **not** installed, and not partially installed.
- Host is **Kali GNU/Linux Rolling 2025.4**, **amd64**, glibc **2.42-13**, past the t64 transition.
- The existing Kali repository offers **`1:8.0.7-1`** — i.e. **Suricata 8.0.7 is directly
  available**, no upstream route required.
- The dependency graph resolves with **0 removals**, **no libc6 change**, and **no downgrade**:
  fully compatible with the current libc6/t64 environment.
- Safest route: **`sudo apt install suricata suricata-update` from the existing Kali
  repository**, in passive IDS mode, with the packaged service suppressed at install time.
- No third-party repository, no PPA, no source build, no core-library downgrade, and no
  change to firewall, routing, NAT, Zeek, SOC-001, or SOC-002 is needed or performed.
- Principal residual risk is **RAM/CPU pressure** (1.0 GiB available, 4.3 GiB swap in use,
  load ≈ 4.0 on 4 threads, two VMs resident) — a configuration and measurement matter for
  Phase 4B, not a blocker to installation.

**Phase 4A stops here. Nothing was installed, started, or modified.**
