# SOC-003 — Phase 1.1: Zeek Installation Route Validation

Phase: 1.1 — Read-only validation of the official Zeek 9 Linux binary route
Status: **COMPLETE (read-only)** — an installable official route is confirmed
Executed: 2026-10-16 12:38–12:46 EAT / 09:38–09:46 UTC
Host: Kali GNU/Linux Rolling 2025.4 (sensor), x86_64 / Debian arch `amd64`
Operator: saidi (uid 1000)
Method: metadata + HTTP inspection only (no install, no repository change)

This report answers the eight questions in the Phase 1.1 task and records the
evidence behind each answer. **No system change was made.** Nothing was
installed, no APT source or key was added, no repository was configured, and no
filesystem path outside `/tmp` was written.

---

## 0. Bottom line

Zeek 9.0.0 is the **current official LTS release** and Zeek publishes amd64
`.deb` binaries for **Debian 13** through the openSUSE Build Service (OBS).
Kali 2025.4 is Debian 13-based, and **all runtime dependencies of the Zeek 9.0
core package are already satisfied on this host.** The packages install entirely
under `/opt/zeek`, so installation is fully isolated and does not require adding
an APT repository: the `.deb` files can be fetched directly and installed with
`apt-get install ./<file>.deb`, letting the existing Kali repo satisfy the
dependencies. **No dependency conflict with the current Kali system is
apparent.**

---

## 1. Official release / version

| Item | Value | Source |
| --- | --- | --- |
| Current LTS release | **Zeek 9.0.0** | zeek.org/get-zeek ("CURRENT LTS RELEASE") |
| Release date | 2026-09-14 | zeek.org/get-zeek; OBS `.deb` `Last-Modified` |
| Previous LTS | Zeek 8.0.10 (2026-08-19) | zeek.org/get-zeek |
| Distribution channel | openSUSE Build Service (OBS), project `security:zeek` | docs.zeek.org install guide; zeek.org |

The Zeek manual states: *"We provide binary packages for a wide range of Linux
distributions via the openSUSE Build Service"* and *"The primary install prefix
for binary packages is `/opt/zeek`."* (docs.zeek.org/en/current/install/install.html)

OBS `security:zeek` publishes these groups (per the official docs): `zeek`
(latest release), `zeek-X.0` (pinned LTS lines), `zeek-nightly`, `zeek-rc`.

---

## 2. Environment confirmed (unchanged)

```
Kali GNU/Linux Rolling 2025.4    (ID=kali, ID_LIKE=debian, VERSION_CODENAME=kali-rolling)
base-files 1:2025.4.0            (/etc/debian_version = kali-rolling -> Debian 13 "trixie" base)
Kernel arch / dpkg arch: x86_64 / amd64
libc6 2.42-13   (Debian GLIBC 2.42)
libstdc++6 16.1.0-1, libgcc-s1 16.1.0-1
Zeek/bro: not installed (which zeek -> not found); /opt/zeek absent
APT sources: deb http://http.kali.org/kali kali-rolling main non-free non-free-firmware contrib
```

The only Zeek in the configured repo is the stale Kali `zeek 5.1.1-0kali3`
(unsatisfiable here; see `PHASE1_REPORT.md`). This report does not use it.

---

## 3. Correct official package for this environment

**Repository target:** `Debian_13` (Kali 2025.4 tracks Debian 13; this is the
closest official build target). Architecture `amd64` (= x86_64).

OBS `security:zeek` build targets available: `Debian_12`, `Debian_13`,
`Debian_Testing`, `xUbuntu_22.04/24.04/26.04`, `Raspbian_*`, `16.0`,
`Fedora_*`, `openSUSE_Tumbleweed`.

**Recommended package (LTS-pinned): `zeek-9.0`** — version `9.0.0-0`.
It is a meta-package that pulls the 9.0 LTS line and pins it, so a future 10.x
release will not silently replace it:

| Sub-package | Role | Arch | `.deb` size | Installed |
| --- | --- | --- | --- | --- |
| `zeek-9.0-core` | Zeek monitor binary + base scripts | amd64 | 13,446,716 B | 52,706 KiB |
| `zeekctl-9.0` | `zeekctl` control shell | amd64 | 3,611,676 B | 12,793 KiB |
| `zeek-9.0-core-dev` | core dev headers | amd64 | 1,692,428 B | 6,636 KiB |
| `zeek-9.0-spicy-dev` | Spicy toolchain | amd64 | 29,805,544 B | 200,868 KiB |
| `zeek-9.0-zkg` | Zeek package manager | all | 704,224 B | 999 KiB |
| `zeek-9.0-client` | cluster management client | all | 674,072 B | 790 KiB |

**Minimal runtime variant: `zeek-9.0-core` alone** (9.0.0-0). This is sufficient
for the SOC-003 offline-PCAP use case (runs `zeek -r <pcap>`, emits
`conn.log`/`dns.log`/`http.log`). Add `zeekctl-9.0` and `zeek-9.0-client` if a
managed/cluster install is wanted later.

**Naming note (important):** OBS also publishes an unversioned `zeek`
meta-package (currently also 9.0.0). That package name is identical to Kali's
`zeek` package, so preferring the versioned `zeek-9.0` avoids any name collision
with the Kali repo.

---

## 4. Exact download URLs

**APT repository (documented route — not used here):**

```
deb https://download.opensuse.org/repositories/security:/zeek/Debian_13/ /
key: https://download.opensuse.org/repositories/security:zeek/Debian_13/Release.key
```

Signing key (verified by fingerprint, read-only):

```
pub  rsa4096 2024-09-23 [SC] [expires: 2026-12-02]
     F9FA 0223 B56B 116C 3637  37EF 5DA5 7BDD 6DD7 85CA
uid  security OBS Project <security@build.opensuse.org>
```

**Direct `.deb` URLs (repo-change-free route):**

```
https://download.opensuse.org/repositories/security:/zeek/Debian_13/amd64/zeek-9.0-core_9.0.0-0_amd64.deb
https://download.opensuse.org/repositories/security:/zeek/Debian_13/amd64/zeek-9.0_9.0.0-0_amd64.deb
https://download.opensuse.org/repositories/security:/zeek/Debian_13/amd64/zeekctl-9.0_9.0.0-0_amd64.deb
https://download.opensuse.org/repositories/security:/zeek/Debian_13/amd64/zeek-9.0-core-dev_9.0.0-0_amd64.deb
https://download.opensuse.org/repositories/security:/zeek/Debian_13/amd64/zeek-9.0-spicy-dev_9.0.0-0_amd64.deb
https://download.opensuse.org/repositories/security:/zeek/Debian_13/all/zeek-9.0-zkg_9.0.0-0_all.deb
https://download.opensuse.org/repositories/security:/zeek/Debian_13/all/zeek-9.0-client_9.0.0-0_all.deb
```

All URLs returned HTTP 200 with `Content-Type: application/x-debian-package`
(HTTP `302` to a mirror then `200`). Metadata hashes from the signed
`Packages` index (`SHA256`):

| File | SHA256 |
| --- | --- |
| `zeek-9.0-core_9.0.0-0_amd64.deb` | `e060962e0cef1adbf354ad058f227f22dc463bcba2c00ce1ab95cd5e27a5e906` |
| `zeek-9.0_9.0.0-0_amd64.deb` | `4949906cade570cc0e984fddae33f172ce02f6423883cdec2493955f9a92dab5` |
| `zeekctl-9.0_9.0.0-0_amd64.deb` | `eab31909e5ab9937bbb9198f151ad1eddacbbe925537b6854a5c979dae68a084` |
| `zeek-9.0-core-dev_9.0.0-0_amd64.deb` | `dd00a8c240b19325120632d7e8eda9d807881b4d0541f71c8037af803edf8b36` |
| `zeek-9.0-spicy-dev_9.0.0-0_amd64.deb` | `c42f100583c1cb41d5a1fcf758ddfb1942c51b9157bd32dd5bdce221f3ccea07` |
| `zeek-9.0-client_9.0.0-0_all.deb` | `5718b7e989c7f1f0bd1e86c5434325cfe4e4ba9e4debbe2bc09f5c3489f2b5cd` |
| `zeek-9.0-zkg_9.0.0-0_all.deb` | `d6a62c2119e57a3a59c9ad70abae1fca32a290a4f3c269298f076daf83088868` |

(These are the index-advertised hashes and should be re-verified with
`sha256sum` after any real download; the signed `InRelease` chains them to the
key above.)

---

## 5. Package format and architecture

| Item | Value |
| --- | --- |
| Format | Debian binary package (`.deb`, format 2.0), control.tar.xz / data xz |
| Architecture | `amd64` (x86_64). `arm64` also published; `all` for zkg/client/btest |
| Version | `9.0.0-0` |
| Build target | OBS `security:zeek` → `Debian_13` (glibc 2.41 base) |
| Install prefix | **`/opt/zeek`** (from `configure --prefix=/opt/zeek`) |

---

## 6. Runtime dependencies

`zeek-9.0-core` (amd64) `Depends` (from the signed Packages index):

```
libpcap0.8, libmaxminddb0 (>= 1.0.2), libzmq5 (>= 4.0.5+dfsg),
libc6 (>= 2.38), libgcc-s1 (>= 3.0), libkrb5-3 (>= 1.6.dfsg.2),
libpcap0.8t64 (>= 1.7.3), libssl3t64 (>= 3.0.0), libstdc++6 (>= 14),
zlib1g (>= 1:1.1.4)
```

`zeekctl-9.0`: `zeek-9.0-core (= 9.0.0-0)`, `python3`.
`zeek-9.0-zkg`: `python3`, `python3-semantic-version`, `python3-git`, plus the
btest/btest-data/core/core-dev/spicy-dev packages.
`zeek-9.0-core-dev` / `zeek-9.0-spicy-dev`: `libpcap-dev`, `libssl-dev`,
`zlib1g-dev`, `libmaxminddb-dev` (+ `libbroker-9.0-dev` for core-dev).

---

## 7. Are the dependencies already installed? (yes — all of them)

Runtime deps of `zeek-9.0-core`, checked with `dpkg-query`:

| Dependency (requires) | Installed on host | Satisfied? |
| --- | --- | --- |
| `libc6 (>= 2.38)` | `2.42-13` | ✅ |
| `libstdc++6 (>= 14)` | `16.1.0-1` | ✅ |
| `libgcc-s1 (>= 3.0)` | `16.1.0-1` | ✅ |
| `zlib1g (>= 1:1.1.4)` | `1:1.3.dfsg+really1.3.1-1+b1` | ✅ |
| `libkrb5-3 (>= 1.6.dfsg.2)` | `1.21.3-5` | ✅ |
| `libmaxminddb0 (>= 1.0.2)` | `1.12.2-1` | ✅ |
| `libzmq5 (>= 4.0.5+dfsg)` | `4.3.5-1+b3` | ✅ |
| `libpcap0.8t64 (>= 1.7.3)` | `1.10.5-2` | ✅ |
| `libssl3t64 (>= 3.0.0)` | `3.6.3-1` | ✅ |
| `libpcap0.8` (no version) | provided by `libpcap0.8t64 1.10.5-2` → `Provides: libpcap0.8 (= 1.10.5-2)` | ✅ |

Notes:

- `libpcap0.8` is not a separate host package (`Candidate: (none)`) because
  Debian 13 moved to the `t64` name. The dependency is met **via the `Provides`
  field** of `libpcap0.8t64`, which is installed. APT/dpkg resolve this
  automatically, so it is not a blocker.
- The same t64 pattern applies to `libssl3` (`libssl3t64 3.6.3-1` →
  `Provides: libssl3 (= 3.6.3-1)`).

**Optional-package deps** (needed only for the full `zeek-9.0` meta): `python3`
installed (`3.13.7-1`). `python3-semantic-version` (candidate `2.10.0-4`),
`python3-git` (candidate `3.1.61-1`), `libpcap-dev` (candidate `1.10.7-1`),
`libmaxminddb-dev` (candidate `1.13.3-1`) are not installed, but all are
available in the configured Kali repo — so even the full meta installs from the
existing sources without a third-party repo.

**Conclusion: a minimal `zeek-9.0-core` install needs zero new packages.**

---

## 8. Installation isolation under `/opt/zeek`

Yes — the official packages are self-contained under **`/opt/zeek`**:

```
/opt/zeek/bin/{zeek,zeek-cut,zeek-config,zeek-archiver,adtrace,zeek-client,zkg,...}
/opt/zeek/etc/zeek/zeek.conf, /opt/zeek/etc/zkg
/opt/zeek/share/zeek/{base,policy,site,builtin-plugins,spicy,zeekygen}
/opt/zeek/lib/zeek/python/...
/opt/zeek/var/lib/zkg
```

No file lands in `/usr/bin`, `/usr/lib`, `/etc`, or `/var`. Because the tree is
confined to `/opt/zeek` and is a Debian package, removal is clean
(`apt-get remove 'zeek-9.0*'` → package-owned files deleted; `rm -rf /opt/zeek`
for any leftover state). Nothing in the SOC-001/SOC-002 trees is touched.

To use it, add `/opt/zeek/bin` to `PATH` (Zeek also ships helpers such as
`zeek-config`/`zeek-path-dev.sh`); no system-wide path edit is forced.

---

## 9. Does installation require adding an APT repository?

**Not necessarily — two routes exist.**

| Route | Changes APT? | Notes |
| --- | --- | --- |
| **A. Official documented route** | **Yes** — writes `/etc/apt/sources.list.d/security:zeek.list` and a key to `/etc/apt/trusted.gpg.d/`, then `apt update` | Matches docs.zeek.org; enables `apt install zeek-9.0` and future updates |
| **B. Direct `.deb` install (no repo)** | **No** — APT sources and keys untouched | `sudo apt-get install ./zeek-9.0-core_9.0.0-0_amd64.deb` (deps come from already-installed packages / existing Kali repo) |

Because every runtime dependency is already present, **Route B works with no
APT change at all**, which is the compliant choice for this project's
constraints. Route A is only needed if the operator later wants automatic Zeek
updates via `apt upgrade`.

---

## 10. Dependency-conflict assessment

**No conflict with the current Kali system is apparent.** Evidence:

- **Names don't clash:** the recommended `zeek-9.0*` package names are distinct
  from Kali's `zeek`/`zeek-common`. (OBS's *unversioned* `zeek` package does
  share Kali's name — a reason to prefer `zeek-9.0`.)
- **Files don't clash:** OBS installs under `/opt/zeek`; Kali's `zeek` would
  install under `/usr` (`/usr/bin/zeek`, `/usr/lib/x86_64-linux-gnu/...`). Disjoint.
- **Declared Conflicts:** the `zeek-9.0*` packages declare **no `Conflicts`**.
  (Only the legacy `zeek-lts*` family declares conflicts against older names.)
- **t64/library naming:** handled via `Provides` (section 7) — resolves cleanly.
- **ABI/runtime:** host glibc `2.42` ≥ required `2.38`; host libstdc++ `16` ≥
  required `14`. The binary is built for Debian 13, the same release family as
  Kali 2025.4.
- **Kali's `zeek 5.1.1-0kali3` remains unsatisfiable** and is unrelated; it is
  neither installed nor relied upon.

Residual risk: the OBS binary is built against Debian 13's library set, while
Kali Rolling ships a slightly newer glibc/libstdc++ — forward-compatible, but
this is not a Kali-tested target (see Risks).

---

## 11. Proposed installation method (for the next phase — not executed)

Compliant, repo-free, isolated:

```
# 1. Fetch the minimal core package (read-only validation already done)
cd ~/soc-lab/soc-003/evidence/   # or any scratch dir
curl -fLO https://download.opensuse.org/repositories/security:/zeek/Debian_13/amd64/zeek-9.0-core_9.0.0-0_amd64.deb

# 2. Verify the publisher signature against the OBS key (recommended)
#    key fingerprint F9FA 0223 B56B 116C 3637 37EF 5DA5 7BDD 6DD7 85CA

# 3. Install locally; deps resolve from the existing system (no repo added)
sudo apt-get install ./zeek-9.0-core_9.0.0-0_amd64.deb

# 4. Smoke test (offline, no capture)
/opt/zeek/bin/zeek -v
```

If a fuller install is wanted, add `zeekctl-9.0`, `zeek-9.0-client` (and, for
the full meta, `zeek-9.0` which also pulls `-core-dev`, `-spicy-dev`, `-zkg`).

**Note:** installing requires an interactive `sudo` password on this host (per
`PHASE1_REPORT.md`, no passwordless rule applies to `saidi`), so the install
itself is deferred to a later, operator-approved step.

---

## 12. Risks and rollback

**Risks**

- **Non-Kali build target.** The `.deb` is built for Debian 13, not Kali.
  Forward ABI compatibility is expected (newer glibc/libstdc++ on Kali), but it
  is not an officially tested combination.
- **Rolling-base drift.** A future Kali library bump could, in principle,
  outrun what a Debian-13-built binary expects. Low probability short-term.
- **Router/sensor scope.** Installing Zeek does not enable capture or change
  networking, but a later live mode (`zeek -i`) would need interface/privs
  decisions — out of scope for this phase.
- **Unsigned manual download.** Route B skips APT's transport signature check;
  mitigate by verifying the `.deb` against the OBS key and the `Packages`
  SHA256 (section 4).

**Rollback**

- Remove packages: `sudo apt-get remove 'zeek-9.0*'` (Kali has no conflicting
  Zeek to restore).
- Purge leftover config/state: `sudo rm -rf /opt/zeek` (only if the operator
  wants a full wipe; the tree is package-owned).
- If Route A were ever used: delete
  `/etc/apt/sources.list.d/security:zeek.list` and
  `/etc/apt/trusted.gpg.d/security_zeek.gpg`, then `apt update`.
- Rollback is confined to the Zeek packages and `/opt/zeek`; no `/usr`, `/etc`,
  `/var`, network, or SOC-001/SOC-002 change is involved.

---

## 13. Evidence of method (read-only commands used)

```
cat /etc/os-release; dpkg --print-architecture; ldd --version
apt-cache policy zeek zeek-common
curl -sI  https://download.opensuse.org/repositories/security:/zeek/            # project index
curl -s   https://api.opensuse.org/public/source/security:zeek/zeek-9.0/VERSION # -> 9.0.0
curl -s   https://api.opensuse.org/public/source/security:zeek/zeek-9.0/debian-template.control
curl -s   https://api.opensuse.org/public/source/security:zeek/zeek-9.0/debian-template.rules
curl -sL  https://download.opensuse.org/repositories/security:/zeek/Debian_13/InRelease
curl -sL  https://download.opensuse.org/repositories/security:/zeek/Debian_13/Packages.gz
curl -sIL https://download.opensuse.org/repositories/security:/zeek/Debian_13/amd64/zeek-9.0-core_9.0.0-0_amd64.deb
curl -sL  https://download.opensuse.org/repositories/security:/zeek/Debian_13/Release.key | gpg --show-keys --with-fingerprint
curl -sL  https://zeek.org/get-zeek/ ; curl -sL https://docs.zeek.org/en/current/install/install.html
dpkg-query -W -f='${Version}' libc6 libgcc-s1 libkrb5-3 libpcap0.8t64 libssl3t64 libstdc++6 zlib1g libmaxminddb0 libzmq5
```

All inspection was metadata/HTTP level. Two small index files were written to
`/tmp` for parsing and were deleted afterward.

---

## 14. Constraint compliance

Not done, as required: no Zeek (or other package) installed; no APT repository
added; no `/etc/apt` source or key modified; no filesystem change beyond
temporary `/tmp` index files (since removed); no VM started; no traffic
captured; no networking/firewall/DNS/route/`ip_forward` change; SOC-001 and
SOC-002 untouched; no `git init`; no credentials or secrets written or exposed.
No `sudo` command was run.

Pre-existing (not created by this run): `/tmp/zeek-inspect/` holds a previously
downloaded Kali `zeek 5.1.1-0kali3` `.deb` (confirms the Phase 1 blocker). It
was left in place, untouched.

Files created by this phase: **this report only**:

```
~/soc-lab/soc-003/PHASE1_1_INSTALL_ROUTE_REPORT.md
```
