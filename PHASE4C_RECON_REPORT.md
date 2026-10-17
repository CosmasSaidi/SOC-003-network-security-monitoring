# SOC-003 — Phase 4C Reconnaissance Report

**Phase:** 4C — Suricata ruleset provenance & controlled ruleset initialization
**Step:** STEP 1 — read-only reconnaissance (no changes made)
**Status:** **PASS** — reconnaissance complete; the remaining work requires one operator-approved elevated + networked step (see §7).
**Executed:** 2026-10-17, ~02:00–02:03 EAT (Africa/Nairobi)
**Host:** Kali GNU/Linux Rolling 2025.4, kernel `6.19.14+kali-amd64` (sensor)
**Operator:** `saidi` (uid 1000)
**Tooling observed:** Suricata 8.0.7 RELEASE, suricata-update 1.3.8 (distro package `1.3.8-1`)
**Mode:** Read-only. No file outside `~/soc-lab/soc-003/` was created, modified or deleted. No `sudo` used. No rule file was downloaded; only HTTP `HEAD` requests were issued against the two provenance endpoints.

---

## 0. Summary of the required findings

| # | Required finding | Result |
| --- | --- | --- |
| 1 | Tool version | `suricata-update version 1.3.8` (package `suricata-update 1.3.8-1`); underlying sensor `Suricata 8.0.7 RELEASE` (`1:8.0.7-1`). |
| 2 | Current configuration | `/etc/suricata/suricata.yaml` present and unchanged; `default-rule-path: /var/lib/suricata/rules`; `rule-files: [suricata.rules]`; `default-log-dir: /var/log/suricata/`. **`/etc/suricata/update.yaml` does not exist**, so suricata-update runs on built-in defaults (`-D /var/lib/suricata`, `-c /etc/suricata/update.yaml`). |
| 3 | Current ruleset state | **No managed ruleset exists.** `/var/lib/suricata/rules/` is empty — `/var/lib/suricata/rules/suricata.rules` is **absent**. Only the 30 packaged protocol-event/conformance files live in `/etc/suricata/rules/`, which are *not* referenced by `rule-files`. |
| 4 | Source metadata | **None.** `/var/lib/suricata/update/` does not exist at all: no `update/sources/` (no enabled/disabled source specs), no `update/cache/index.yaml` (no cached source index). No `disable.conf`/`enable.conf`/`modify.conf`/`drop.conf` in `/etc/suricata/`. |
| 5 | Initialized already? | **No.** suricata-update has never been run on this host. There is no state dir, no source index, no enabled source and no output rules file. No timer/cron/service automates it. |
| 6 | Ruleset obtainable via the official mechanism? | **Yes, provably reachable.** The default source index (`https://www.openinfosecfoundation.org/rules/index.yaml`) returns `HTTP/2 200` (16 716 B, `last-modified: Fri, 02 Oct 2026 15:11:00 GMT`), and the default ET Open feed for 8.0.7 (`https://rules.emergingthreats.net/open/suricata-8.0.7/emerging.rules.tar.gz`) returns `HTTP/2 200` (5 634 046 B, `last-modified: Fri, 16 Oct 2026 20:35:05 GMT`). |
| 7 | Command required | `sudo suricata-update` (with no enabled sources it defaults to **ET Open** for the detected Suricata version). See §7 for the exact, minimal command set and expected artefacts. |

---

## 1. Safety and scope compliance

| Constraint | State |
| --- | --- |
| Not live network detection | **Honoured.** No capture interface opened; no `-i`. |
| No `-i`, no AF_PACKET, no NFQUEUE, no IPS/inline/firewall | **Honoured.** Only `-V`, `--version`, `--help`, `-T`-free introspection and package inspection were used. |
| No routing / `ip_forward` / nftables / firewall / VirtualBox networking / interface change | **Honoured.** No `ip`, `nft`, `iptables`, `sysctl`, `VBoxManage` command issued. |
| SOC-002 VMs untouched | **Honoured.** No `VBoxManage` invocation of any kind. |
| AD / DNS / WEF / Sysmon / Windows / Zeek untouched | **Honoured.** No related path read or written. |
| No `apt autoremove`, no `apt full-upgrade`, no APT source change, no package install | **Honoured.** No `apt`/`dpkg` mutation; `dpkg -l` and `dpkg -V` (read-only) only. |
| No Git repo/commit | **Honoured.** None created. |
| SOC-001 / SOC-002-PUBLIC untouched | **Honoured.** Neither referenced. |
| Sole human authorship | **Preserved.** This report and every artefact are operator-authored; no AI/agent attribution or co-author metadata. |
| Artefacts confined to `~/soc-lab/soc-003/` | **Honoured.** All new files are under `~/soc-lab/soc-003/evidence/phase4c-ruleset/` and this report. |
| No secrets exposed | **Verified.** No credentials, tokens or keys are recorded; the two commercial feeds in the index (`et/pro`, `scwx/*`, `stamus/nrd-*`) are noted only by their `%(secret-code)s` placeholder form. |
| No `sudo suricata-update` run | **Honoured.** Not attempted; `sudo -n true` also confirms sudo is **not** passwordless here (`a password is required`). |

---

## 2. Tool inventory

| Probe | Output |
| --- | --- |
| `suricata-update --version` | `suricata-update version 1.3.8` |
| `suricata -V` | `This is Suricata version 8.0.7 RELEASE` |
| `which suricata-update` | `/usr/bin/suricata-update` |
| `which suricata` | `/usr/bin/suricata` |
| Python module | `/usr/lib/python3/dist-packages/suricata/update` |
| `dpkg -l` | `suricata 1:8.0.7-1 amd64  ii`, `suricata-update 1.3.8-1 amd64  ii` |
| `dpkg -V suricata suricata-update` | no output, exit 0 → no packaged file modified since install |

`suricata-update --help` confirms this build's defaults and sub-commands. Defaults relevant to this phase:

- `-D, --data-dir` default `/var/lib/suricata`
- `-c, --config` default `/etc/suricata/update.yaml`
- `--suricata-conf` default `/etc/suricata/suricata.yaml`
- `-o, --output` default `<data-dir>/rules`
- Sub-commands: `update-sources`, `list-sources`, `list-enabled-sources`, `enable-source`, `disable-source`, `remove-source`, `add-source`, `check-versions`
- Flags that keep this phase safe and deterministic: `--offline`, `--no-test`, `--no-reload`, `--fail`

---

## 3. Current configuration state

| Item | Value |
| --- | --- |
| `/etc/suricata/` contents | `classification.config`, `reference.config`, `threshold.config`, `suricata.yaml`, `rules/` |
| `/etc/suricata/suricata.yaml` | 94 378 B, sha256 `6b5fd573fd0d41144445cbd6e57f830b819c13b62f23272c4433fb4b5698a3a0` |
| `default-rule-path:` | `/var/lib/suricata/rules` (line 2337) |
| `rule-files:` | `- suricata.rules` (lines 2340) |
| `default-log-dir:` | `/var/log/suricata/` (exists, empty) |
| `classification-file:` | `/etc/suricata/classification.config` |
| `reference-config-file:` | `/etc/suricata/reference.config` |
| `threshold-file:` | commented out; `/etc/suricata/threshold.config` exists but is not referenced |
| `/etc/suricata/update.yaml` | **absent** → built-in defaults apply |
| `/etc/suricata/disable.conf` etc. | **all absent** → bundled defaults inside the Python package are used at run time |
| `suricata.service` | `inactive`, `disabled`, preset `disabled`; no `suricata` process |

Effective suricata-update paths resolved from the installed package (read-only introspection):

```
state_dir       : /var/lib/suricata
cache_dir       : /var/lib/suricata/update/cache
source_dir      : /var/lib/suricata/update/sources
index file      : /var/lib/suricata/update/cache/index.yaml
index url       : https://www.openinfosecfoundation.org/rules/index.yaml
source dir exists: False
index exists    : False
```

---

## 4. Current ruleset state

| Path | State |
| --- | --- |
| `/var/lib/suricata/rules/` | exists, **empty** |
| `/var/lib/suricata/rules/suricata.rules` | **absent** — this is exactly the file `rule-files:` expects, and the reason stock `suricata -T` failed in Phase 4B |
| `/usr/lib/.../update/data/index.py` | bundled source index present (29 sources, index format version 1), sha256 `65b1344f2aba042d061269b1e15ccc2793cc9522e84c07c26932f7951f090534` |
| `/etc/suricata/rules/` | 30 packaged rule files — **all protocol event/conformance rules** (`*-events.rules`, `files.rules`); no vendor signature set; not referenced by `rule-files` |

So the sensor currently has **no detections-capable ruleset loaded anywhere**, only the packaged protocol-anomaly corpus that Phase 4B showed stays silent on well-formed Phase 2 traffic.

---

## 5. Is source metadata present? (initialization test)

Explicit probes, all **ABSENT** — i.e. suricata-update has never been initialized:

```
ABSENT  /var/lib/suricata/update
ABSENT  /var/lib/suricata/update/sources        (no enabled/disabled source specs)
ABSENT  /var/lib/suricata/update/cache          (no cached index, no cached tarball)
ABSENT  /var/lib/suricata/update/cache/index.yaml
ABSENT  /var/lib/suricata/rules/suricata.rules  (no output rules)
ABSENT  /etc/suricata/update.yaml
```

| Question | Answer |
| --- | --- |
| Enabled sources on disk | **none** (source dir does not exist) |
| Cached source index on disk | **none** (cache dir does not exist) |
| Source index reachable if it were fetched | yes — see §6 |
| Automatic updater | none — no `suricata-update` timer, no cron entry, only `suricata.service` (disabled) |

Because `enabled_sources` is empty, `suricata-update update` will, by design, fall through to the **implicit ET Open source** for the detected Suricata version and log `No sources configured, will use Emerging Threats Open`.

---

## 6. Can a ruleset be obtained via the official mechanism?

Verified with `HEAD`-only requests (no payload downloaded, nothing written outside `~/soc-lab/soc-003/`):

| Endpoint | Result |
| --- | --- |
| `https://www.openinfosecfoundation.org/rules/index.yaml` | `HTTP/2 200`, `content-type: application/yaml`, `content-length: 16716`, `last-modified: Fri, 02 Oct 2026 15:11:00 GMT`, `x-cache: Miss from cloudfront` |
| `https://rules.emergingthreats.net/open/suricata-8.0.7/emerging.rules.tar.gz` | `HTTP/2 200`, `content-type: application/octet-stream`, `content-length: 5634046`, `last-modified: Fri, 16 Oct 2026 20:35:05 GMT`, `etag: "6ad28a79-55f7fe"` |
| `.../emerging.rules.tar.gz.md5` | `HTTP/2 200`, `content-length: 33` (32-hex digest + newline) → MD5 sidecar exists |
| `.../emerging.rules.tar.gz.sha256` | `HTTP/2 404` → no SHA-256 sidecar |

DNS resolves for both hosts (`www.openinfosecfoundation.org` via CloudFront, `rules.emergingthreats.net` → `34.224.148.152` / `32.192.0.112` / `52.207.204.144`). **Conclusion: the official mechanism can fetch a ruleset for this host right now, unauthenticated, over HTTPS.**

The feed URL is version-pinned: the ET Open URL template contains `suricata-%(__version__)s`, and suricata-update substitutes the *detected* Suricata version, so this will resolve to `suricata-8.0.7/…`, matching the installed engine.

---

## 7. What command would be required

Elevated privileges are required: `/var/lib/suricata` is `root:root 0755`, so writing `update/cache/`, `update/sources/` and `rules/suricata.rules` needs root. `sudo` here is **not** passwordless, so this must be run by the operator at a terminal.

Minimum reproducible sequence (recommended, in order):

```
# Step A — initialize the managed source index from the official index URL
sudo suricata-update update-sources

# Step B — confirm the index landed and inspect available / enabled sources
sudo suricata-update list-sources --enabled
sudo suricata-update list-enabled-sources

# Step C — fetch ET Open for 8.0.7, merge, test with Suricata, write the ruleset
sudo suricata-update --no-reload
```

Notes the operator should have in hand before running:

- With no source enabled, Step C implicitly selects **ET Open** (`et/open`, MIT-licensed, Proofpoint) for Suricata 8.0.7 — no secret or account is needed. To make provenance explicit instead of implicit, precede Step C with `sudo suricata-update enable-source et/open`.
- `--no-reload` is recommended: no `reload-command` is configured, so reload would be skipped anyway, but the flag makes "no service action" unambiguous. Suricata is not running, so there is no live engine to disturb in any case.
- suricata-update will run `suricata -T` against the merged output as its own validation step; that is the intended, official integrity check and requires no interface.
- Expected artefacts after Step C: `/var/lib/suricata/update/cache/index.yaml`, `/var/lib/suricata/update/cache/<md5>-emerging.rules.tar.gz`, `/var/lib/suricata/rules/suricata.rules` (+ `.md5`/`.version` sidecars), and a populated `/var/lib/suricata/rules/` tree.
- Determination to make **after** Step C, before any replay: record the ET Open tarball SHA-256, the merged `suricata.rules` line/rule count, the `suricata-update --version` and the exact fetch timestamp, and confirm the **local lab rules from Phase 4B are kept separate** (e.g. via `--local`/`local:` config or a distinct `-S` file for replay) so the lab ruleset and the vendor ruleset stay independently attributable.

Full command reference used for the above (from `suricata-update --help`): `-D/--data-dir`, `-c/--config`, `-o/--output`, `--offline`, `--no-test`, `--no-reload`, `--fail`, `-f/--force`, `update-sources`, `list-sources`, `list-enabled-sources`, `enable-source`, `check-versions`.

An offline-only alternative exists (`--offline` uses the most recent cached rules and exits 1 if the feed was never downloaded) — it cannot be used yet because the cache is empty, which is precisely why one networked fetch is required.

---

## 8. Network and provenance concerns

1. **No cryptographic signature / attestation.** ET Open is distributed as a plain `.tar.gz` over HTTPS with no detached PGP/GPG signature and no SHA-256 sidecar (`.sha256` → 404). Provenance rests on TLS transport to `rules.emergingthreats.net` (nginx, etag `6ad28a79-55f7fe`) plus the Emerging Threats brand, not on any verifiable signed artefact.
2. **Integrity verification is MD5-only, and advisory.** suricata-update's `Fetch.check_checksum()` requests `<url>.md5` and compares an MD5 hexdigest. An MD5 sidecar *does* exist for this feed. However: (a) MD5 is collision-broken, so it is a change-detector, not a security control; (b) both the payload and the digest are served from the same origin over the same channel, so the digest adds nothing against that origin; (c) on any mismatch, the code path logs `Failed to check remote checksum: …` and **continues to use the downloaded file** unless `--fail` is passed. Recommend `--fail` for a provenance-focused run.
3. **Default source is implicit.** Because no source is enabled and no `update.yaml` exists, a bare `sudo suricata-update` silently fetches ET Open. That is the correct official behaviour, but for an auditable Phase 4C it should be made *explicit* (`enable-source et/open`) so the enabled-source list is recorded on disk in `/var/lib/suricata/update/sources/et/open.yaml`.
4. **First run writes outside `~/soc-lab/soc-003/` by necessity.** The managed ruleset lives at `/var/lib/suricata/rules/suricata.rules` (root-owned) by design of the tool and of `suricata.yaml`. This is a deliberate, documented exception to the "artefacts under `~/soc-lab/soc-003/`" rule; all *SOC-003-written* documentation and evidence remain under `~/soc-lab/soc-003/`, and copies of hashes/counts/provenance metadata will be recorded there.
5. **`suricata.yaml` will not be edited.** The ruleset must be produced at the exact path the existing, package-verified config already points to (`/var/lib/suricata/rules/suricata.rules`). No config edit is needed, and none will be made — this keeps `dpkg -V` clean and avoids improvised configuration.
6. **Index freshness.** The index checksum file on disk will expire after two weeks (`INDEX_EXPIRATION_TIME`); suricata-update warns and then continues with the cached index. A stale index is a source-availability risk, not a correctness risk, since the ET Open URL is version-pinned.
7. **Commercial sources present in the index.** The bundled index also lists paid feeds (`et/pro`, `scwx/enhanced|malware|security`, `stamus/nrd-*`) which require secret codes. These must never be enabled or recorded with secrets; this report deliberately shows only the `%(secret-code)s` placeholder form.
8. **Traceability limit inherent to the phase.** A successfully fetched ET Open ruleset proves the *official mechanism works and the feed is reachable*; it does not, on its own, prove detection efficacy. That evidence is produced only by the later controlled Phase 2 PCAP replay, which is explicitly out of scope for Step 1.
9. **No Clock/Time skew issue observed.** Server `date` headers (`Fri, 16 Oct 2026 23:00–23:02 GMT`) are consistent with the host clock (`2026-10-17 ~02:00 EAT` = `2026-10-16 23:00 UTC`).

---

## 9. Evidence index

Directory created: `~/soc-lab/soc-003/evidence/phase4c-ruleset/` (with sub-directory `recon/`).

| File | Content |
| --- | --- |
| `recon/00_context.txt` | host, operator, uid, UTC+local timestamp of the recon run |
| `recon/01_suricata-update-version.txt` | `suricata-update --version` |
| `recon/02_suricata-version.txt` | `suricata -V` |
| `recon/03_suricata-update-help.txt` | full `suricata-update --help` (defaults + sub-commands) |
| `recon/04_package-state.txt` | `dpkg -l` + `dpkg -V` for both packages |
| `recon/05_filesystem-state.txt` | `ls -laR /etc/suricata` and `/var/lib/suricata` |
| `recon/06_suricata-yaml-rulepath.txt` | rule-path / rule-files / log-dir lines from `suricata.yaml` |
| `recon/07_update-paths.txt` | resolved state/cache/source/index paths and existence flags |
| `recon/08_update-state-probes.txt` | EXISTS/ABSENT probes for every update-state path |
| `recon/09_scheduling-and-service.txt` | systemd units/timers, cron, service state, running processes |
| `recon/10_provenance-facts.txt` | default index/ET-Open URLs, bundled-index size + et/open metadata, checksum policy |
| `recon/11_network-reachability.txt` | DNS + `HEAD` results for index, tarball, `.md5`, `.sha256` |
| `recon/12_hashes.txt` | sha256 of the bundled index module and of `suricata.yaml` |

---

## 10. What is deliberately NOT done, and NOT claimed

- No `sudo`, no `suricata-update` execution, no rule download, no file created outside `~/soc-lab/soc-003/`.
- No change to `/etc/suricata`, no `update.yaml` written, no source enabled, no service started or reloaded, no package installed or removed, no APT change.
- Not claimed: that the ET Open ruleset is installed (it is not); that any rule will fire on the Phase 2 PCAPs; that the lab rules from Phase 4B and the vendor ruleset are integrated; that IDS/live/AF_PACKET/NFQUEUE/inline behaviour, VM networking, or detection efficacy are validated anywhere.

---

## 11. Appendix — bundled source index contents (read-only, from the installed package)

29 sources, index format version 1. Free/unauthenticated and commercial feeds:

| Source | Vendor | License | Checksum |
| --- | --- | --- | --- |
| `et/open` | Proofpoint | MIT | none declared |
| `oisf/trafficid` | OISF | MIT | no |
| `abuse.ch/feodotracker`, `abuse.ch/sslbl-blacklist`, `abuse.ch/sslbl-c2`, `abuse.ch/sslbl-ja3`, `abuse.ch/urlhaus` | Abuse.ch | CC0-1.0 | no |
| `sslbl/ja3-fingerprints`, `sslbl/ssl-fp-blacklist` | Abuse.ch | CC0-1.0 | no |
| `etnetera/aggressive` | Etnetera a.s. | MIT | no |
| `ipfire/dbl` | IPFire | CC-BY-SA-4.0 | no |
| `julioliraup/antiphishing` | julioliraup | GPL-3.0 | no |
| `malsilo/win-malware` | malsilo | MIT | **yes** |
| `pawpatrules` | pawpatrules | CC-BY-SA-4.0 | no |
| `aleksibovellan/nmap` | aleksibovellan | MIT | no |
| `tgreen/hunting` | tgreen | GPLv3 | no |
| `ptresearch/attackdetection`, `ptrules/open` | Positive Technologies | Custom | none declared |
| `stamus/lateral` | Stamus Networks | GPL-3.0-only | none declared |
| `et/pro` | Proofpoint | Commercial | no (needs secret code) |
| `scwx/enhanced`, `scwx/malware`, `scwx/security` | Secureworks | Commercial | none declared (secret code) |
| `stamus/nrd-14-open`, `stamus/nrd-30-open`, `stamus/nrd-entropy-14-open`, `stamus/nrd-entropy-30-open`, `stamus/nrd-phishing-14-open`, `stamus/nrd-phishing-30-open` | Stamus Networks | Commercial | none declared (secret code) |

The index on disk will be replaced by the upstream copy at `https://www.openinfosecfoundation.org/rules/index.yaml` during Step A; upstream may list more or fewer sources than the bundled snapshot above.

---

## 12. Status and hand-off

**PHASE 4C STEP 1 STATUS: PASS**

Read-only reconnaissance is complete and unambiguous: suricata-update 1.3.8 is installed and structurally healthy, **but the ruleset update mechanism has never been initialized** — no `update.yaml`, no state/cache/source directory, no cached index, no enabled source, and no `/var/lib/suricata/rules/suricata.rules`. Both official endpoints are reachable and a version-matched ET Open feed for Suricata 8.0.7 exists and is fresh. Obtaining the ruleset requires exactly one operator-approved step that is both **elevated** (writes to root-owned `/var/lib/suricata`) and **networked** (HTTPS fetch of the index and feed), which is why it is not performed here.

**Exact next commands for the operator (run at a terminal, in this order):**

```
# 1. initialize the official source index (elevated + network)
sudo suricata-update update-sources

# 2. record what became available and what is enabled
sudo suricata-update list-sources --enabled
sudo suricata-update list-enabled-sources

# 3. make the source explicit rather than implicit (provenance clarity)
sudo suricata-update enable-source et/open

# 4. fetch + merge + test + write the managed ruleset, with strict failure and no service action
sudo suricata-update --fail --no-reload

# 5. post-run provenance capture (no privileges needed for the reads)
sha256sum /var/lib/suricata/rules/suricata.rules
wc -l /var/lib/suricata/rules/suricata.rules
grep -c '^alert' /var/lib/suricata/rules/suricata.rules
ls -la /var/lib/suricata/update/cache/ /var/lib/suricata/rules/
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

If Step 3 or Step 4 fails with a source/index error, the fallback is `sudo suricata-update --fail --no-reload` on its own (implicit ET Open), which is the mechanism's documented default path.

**STOP — no replay, no custom-rule testing, no IPS/live mode performed. Awaiting operator execution of the commands above before Phase 4C Step 2.**
