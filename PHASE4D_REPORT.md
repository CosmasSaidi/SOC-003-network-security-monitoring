# SOC-003 — Phase 4D Report: Combined Suricata Ruleset Replay + Anomaly-Tuning Decision

**Phase:** 4D — combined detection layer (managed ET Open + SOC-003 custom + Suricata-provided anomaly rules) and checksum-tuning decision
**Status:** **PASS** (see §14)
**Executed:** 2026-10-17, ~10:45–11:05 EAT (Africa/Nairobi)
**Host:** Kali GNU/Linux Rolling 2025.4 (sensor); Suricata 8.0.7 RELEASE
**Operator:** `saidi` (uid 1000)
**Mode:** Offline PCAP replay only. No `-i`, AF_PACKET, NFQUEUE, IPS/inline; service not started (verified inactive/disabled at §12); no firewall/routing/VirtualBox/VM/AD/DNS/WEF/Sysmon/Zeek change; no `apt`; managed ET Open ruleset and `/etc/suricata/suricata.yaml` unchanged (hash-verified); no Git repo/commit; sole human authorship — no AI/agent attribution anywhere.

---

## 1. Objective

Determine the behaviour of the full combined Suricata detection layer on the
existing controlled evidence, and make a conservative, evidence-based decision
on the checksum-anomaly noise. Optional: diagnose the scan-silence observed in
Phase 4C.

## 2. Existing detection layers (from prior phases)

| Layer | Identity | Prior measured result |
| --- | --- | --- |
| Managed ET Open vendor rules | 53,211 enabled (of 69,171) in `/var/lib/suricata/rules/suricata.rules`, SHA-256 `1988785c…`, suricata-update/`et/open`, snapshot 2026-10-17 02:10 +0300 | Phase 4C: 0 alerts on Phase 2 PCAP; 0 on controls A/B/D; 544 incidental checksum alerts on control C |
| SOC-003 custom lab rules | `detections/suricata/soc003-lab.rules`, sids 9003001–9003003, hand-written, loaded per-run (not part of any config file) | Phase 4B: 4 alerts / 4 TP / 0 FP, recall 3/3 injected Phase 2 behaviours; silent on all benign controls |
| Suricata-provided packet-anomaly rules | inside the managed file (Suricata `decoder-events.rules`), sids 2200073/74/75 relevant | Phase 4C: fired only on control C's benign capture artifact; cause measured (guest-side checksum offload) |

Ground truth reused, not regenerated: Phase 2 PCAP SHA-256 verified
`c63484f0…1780` ✓; Phase 3D capture `1e677617…` ✓; Phase 1 `18de8498…` ✓;
Phase 3B `addfcd3f…` ✓; `soc003-lab.rules` `21448205…` (recorded this phase).

## 3. Combined replay methodology

* **Additive loading, verified not exclusive.** The SOC-003 rules were loaded
  with `-s` — `suricata --help` states `-s` = *"path to signature file loaded
  in addition to suricata.yaml settings"*, while `-S` is the *exclusive* flag
  (used in Phase 4B only). Engine confirmation in every combined run:
  `"2 rule files processed. 53214 rules successfully loaded, 0 rules failed, 0
  rules skipped"` (53,211 + 3). The managed ruleset was neither replaced nor
  modified (hash re-verified after all runs).
* Run pattern: `suricata -c /etc/suricata/suricata.yaml -s soc003-lab.rules
  -r <pcap> -l <user-owned outdir>` per capture, stdout/stderr/exit/wall/RSS
  captured via the established runner.
* Tuning demonstration variant: same command plus
  `--set threshold-file=…soc003-lab-anomaly-thresholds.conf` (engine-level
  override; no config file touched; engine logs `Threshold config parsed:
  3 rule(s) found`).

## 4. Phase 2 combined results

**Total 4 alerts — vendor 0, custom 4, anomaly 0.**

| sid | layer | fired | classification | severity |
| --- | --- | --- | --- | --- |
| 9003001 (DET-201, empty SYN probes) | custom | 2 | Detection of a Network Scan | 3 |
| 9003002 (DET-202, DNS burst `lab.test`) | custom | 1 | Misc activity | 3 |
| 9003003 (DET-203, heartbeat GETs) | custom | 1 | Potential Corporate Privacy Violation | 1 |

The combined load reproduces the Phase 4B custom-rule baseline **exactly** —
the 53,211 vendor rules neither interfere with, duplicate, nor add to the
custom detections on this PCAP. EVE: 160 events (70 dns, 10 http, 10 fileinfo,
69 flow, 1 stats). Exit 0; wall 43.82 s (≈ 21 s rule-load dominated); engine
pcap-processing 0.133 s; peak RSS 565,792 kB. Buffered run evidence:
`evidence/phase4d-combined/replay-combined/`.

## 5. Negative-control matrix

`evidence/phase4d-combined/negative-controls/` (separate output dirs; captures not regenerated):

| PCAP | Packets | Vendor | Custom | Anomaly | Total | Assessment |
| --- | --- | --- | --- | --- | --- | --- |
| A — Phase 1 synthetic baseline | 20 | 0 | 0 | 0 | **0** | clean |
| B — Phase 3B benign AD | 18 | 0 | 0 | 0 | **0** | clean |
| C — Phase 3D WS001↔DC1 guest | 712 | 0 | 0 | **544** | **544** | incidental only (checksum artifact, measured benign; §7) |
| D — in-PCAP benign blocks | (in Phase 2 run) | 0 | 0 | 0 | **0** | correct silence |

Custom rules: no false positives on any control. Vendor rules: no alerts on
any control. Anomaly layer: unchanged versus Phase 4C (544).

## 6. ET Open / custom / anomaly comparison

Full detail: `evidence/phase4d-combined/analysis/layer-comparison.md`,
per-run JSONs `analysis/run-*.json`, matrix `analysis/combined-matrix.json`.

1. **Vendor coverage demonstrated:** loading, evaluation and integration are
   demonstrated; **fired detections: 0** across all four captures. No vendor
   coverage of the injected behaviours is demonstrated.
2. **Custom coverage demonstrated:** 3/3 injected behaviours, 4 TP / 0 FP,
   preserved under co-loading at 53,214 total rules.
3. **Packet-anomaly visibility:** the anomaly layer is the only layer that
   produces signal on the guest capture; it is silent on all other captured
   traffic — including every Phase 2 attack block (they are application/
   behavioural, not packet-validity, properties).
4. **False-positive/noise behaviour:** 544/capture anomaly noise on control C,
   all from one measured benign artifact; zero vendor or custom FP.
5. **Overlap:** zero SID overlap across layers; complementary, not redundant.
6. **Gaps (measured):** no vendor signal for the injected scan/DNS-burst/
   heartbeat behaviours in this evidence; anomaly layer flags benign artifacts.

## 7. Checksum anomaly investigation (Step 4)

Complete evidence trail — exact packets (272), direction (100 % WS001→DC1),
protocols/ports (AD/DNS/NTP service ports), checksum values (independent
RFC-1071 recomputation: all 272 invalid at both IPv4 and TCP/UDP layer; all
438 reverse packets valid), otherwise-valid L7 processing, VirtualBox guest
offload relation, and the Phase 4C fix-and-replay experiment — is consolidated
in `evidence/phase4d-combined/analysis/checksum-anomaly-tuning.md`. Nothing was
found to change that evidence; the 4D untuned replay reproduced 544/544.

## 8. Tuning decision

**Decision (conservative, evidence-based): keep anomaly detection unchanged
(option C) — the 544 alerts are classified as *expected collection noise*
with a measured benign cause — and ship a prepared, tested, opt-in,
lab-only tuning artifact (option D implemented, not deployed):**

* `detections/suricata/soc003-lab-anomaly-thresholds.conf` — per-source
  `type limit, count 1, seconds 3600` thresholds on sids 2200073/2200074/2200075;
* applied per-run only via `--set threshold-file=…`; measured effects:
  control C noise **544 → 3** (first-per-source retained: exactly one alert
  per SID), Phase 2 detections **unchanged (4/4 TP)**;
* documented in `detections/suricata/TUNING.md` (what/why/scope/visibility
  lost/lab-specificity/reversal = do not pass the flag; nothing deployed to undo);
* measured Suricata 8 syntax caveat recorded: threshold-file entries must not
  end with `;` (validated empirically — trailing `;` fails the whole file with
  a pcre2 parse error, engine exit 1).

Full `suppress` (option B) was rejected: it would discard the only fired
anomaly signal class in the matrix; blanket "leave unchanged" (option A)
without classification/documentation was judged incomplete. No production
recommendation is made — this tuning is scoped to this lab's VirtualBox
capture path only.

## 9. Scan-silence diagnosis (Step 5 — completed within scope)

`evidence/phase4d-combined/analysis/scan-silence-diagnosis.md`. Narrow, read
only, no rule modification:

* Of the enabled TCP scan-classtype rules, **32 of 33 are inbound-only**
  (`$EXTERNAL_NET any -> $HOME_NET …`); the packaged `$EXTERNAL_NET` is
  `!$HOME_NET` and `$HOME_NET` is RFC 1918 — the lab scanner `192.168.56.150`
  is *inside* `$HOME_NET`, so those rules never enter header matching for the
  lab's outbound scan.
* The single outbound rule, `ET SCAN Potential SSH Scan OUTBOUND`
  (sid 2003068, port 22 only), gates on `count 5, seconds 120, track by_src`;
  the lab scan sends **4 port-22 probes** (one per host — tshark-verified) →
  below the gate → no alert.
* Verdict: confident *for this traffic* — silence is a property of rule
  directionality and per-port count gates, not evidence about ET Open's
  general scan capability. Rules untouched; no coverage claim made in either
  direction beyond these wheels. DNS-burst / heartbeat silence remains
  *unable to determine* (out of the optional scope).

## 10. Detection engineering assessment

| # | Dimension | Assessment (evidence-scoped) |
| --- | --- | --- |
| 1 | Vendor coverage demonstrated | Loading/integration only; 0 fired detections in the tested matrix. |
| 2 | Custom coverage demonstrated | 3/3 lab behaviours, 4 TP / 0 FP, robust under co-load. |
| 3 | Packet-anomaly visibility | Sole signal on the guest capture; captures transport-validity, not behavioural, properties; silent on Phase 2 blocks. |
| 4 | FP/noise behaviour | 544/capture anomaly noise (benign artifact, measured); zero vendor/custom FP; artifact has a tested, reversible lab tuning (544→3). |
| 5 | Detection overlap | None; layers complementary (behavioural lab rules / validity anomalies / silent vendor layer on this evidence). |
| 6 | Detection gaps | No vendor signal for any injected behaviour; vendor scan rules measured as inbound-oriented with per-port gates (this traffic). |
| 7 | Tuning decision | C (keep + classify as collection noise) + D artifact (opt-in, lab-only, measured 544→3, detections unchanged). |
| 8 | Remaining blind spots | Everything not covered by the four captures: no live/inline behaviour, no inbound-scan vendor results (untested), no DNS/HTTP-behaviour vendor diagnosis, ET Open snapshot is time-bound, anomaly rules blind to offload-correct patches of the artifact. |

## 11. Limitations

1. Four deterministic captures only; a 53,211-rule ruleset is exercised on a
   narrow slice (215/20/18/712 packets).
2. `-s` co-load semantics verified empirically for this build; other Suricata
   versions may differ.
3. The scan-silence diagnosis inspected classtype-tagged scan rules; any
   scan-relevant rules in *other* categories were not exhaustively enumerated.
4. Threshold artifact demonstration uses `--set`; persistence behaviour of a
   real deployment (yaml `threshold-file:` field) was deliberately not tested
   (requires a config change, prohibited).
5. Alert counts under thresholds are samples, not event counts (Phase 4B §7.3);
   the tuned 3-alert result means "artifact persists per source", not "3 events".
6. The checksum-artifact cause ("guest TX offload") is a measured-consistent
   inference; the lab has no second capture path for a differential proof.

## 12. Integrity verification

`evidence/phase4d-combined/INTEGRITY_VERIFICATION.txt`:

* **427 manifest entries, 0 failures** across Phase 1/1.2/2/3/3B/3C/3D
  manifests **plus the Phase 4B and Phase 4C evidence manifests** (4C's
  114-file manifest re-verified → Phase 4C evidence unchanged).
* Inputs re-hashed this phase: Phase 2 PCAP, Phase 3D/1/3B captures,
  `soc003-lab.rules` — all match prior records.
* `/etc/suricata/suricata.yaml` (`6b5fd573…`), managed `suricata.rules`
  (`1988785c…`), `classification.config`, `et-open.yaml` — unchanged;
  `dpkg -V` clean; `suricata.service` inactive/disabled, 0 processes.
* SOC-001 (0 modified), SOC-002-PUBLIC (git clean, HEAD `ba479eb`,
  no new commits), SOC-002-windows-ad (0), Zeek (0, v9.0.0) — unchanged.
* Intentional Phase 4D additions are exactly three documented files:
  `detections/suricata/soc003-lab-anomaly-thresholds.conf`,
  `detections/suricata/TUNING.md`, and the `evidence/phase4d-combined/`
  tree, plus `scripts/phase4d_analyze.py`.
* New evidence hashed: `evidence/phase4d-combined/SHA256SUMS.txt`
  (83 files, self-verified).

## 13. Explicit non-claims

No generic network-scan, DNS-burst, C2/beacon or exfiltration detection;
no threat-intelligence effectiveness; no production readiness; no
comprehensive ET Open coverage; no live/inline/IPS behaviour; no claim that
the scan-silence diagnosis generalizes beyond this traffic; no production
tuning recommendation; no zero-system-wide-writes claim beyond the measured
checks. Sole human authorship preserved; no AI/agent attribution.

## 14. Final status

**PHASE 4D STATUS: PASS**

All Step objectives were validated with measured evidence: the combined layer
loads and evaluates correctly (53,214 rules, exit 0 in all six runs), the
custom layer's validated 4-TP result is preserved under co-load, the negative
controls behave identically to the independent-layer runs (0/0/544 anomaly),
the checksum anomaly has a completed investigation and an evidence-based
conservative tuning decision with a tested opt-in artifact, and the optional
scan-silence diagnosis was completed with a confident, narrow answer. Integrity
of all prior work is re-verified with zero failures.

**Exact numbers**

| Metric | Value |
| --- | --- |
| Combined Phase 2 alerts | **4** (vendor 0 / custom 4 / anomaly 0) |
| Controls A / B / C (viz D) | 0 / 0 / 544 (viz 0) — combined identical to per-layer runs |
| Tuned: control C | **3** (544→3, first-per-source) |
| Tuned: Phase 2 detections | **4** (unchanged) |
| Rules loaded in combined runs | 53,214 (53,211 vendor + 3 custom), 0 failed/skipped |
| Checksum tuning decision | C primary (keep + "expected collection noise") with tested opt-in D artifact (lab-only, not deployed) |
| Scan-silence diagnosis | Completed — inbound-rule directionality (32/33) + single outbound gate (count 5 @ port 22) unmet by lab's 4 probes |

**Recommended next phase:** **Phase 5 — Zeek + Suricata joint-lens case
packaging (or the operator-defined Phase 5 scope)**, now that the sensor's
detection layer (behavioural lab rules + managed vendor rules + anomaly layer
with documented noise policy) is measured end-to-end on the same evidence as
the existing Zeek detections. A Phase 5 candidate objective: correlate
Zeek DET-201/202/203 logs with Suricata 9003001–9003003 alerts in one case
bundle on the same PCAP, with claim-disciplined reporting. Live-capture,
IPS/inline and production deployment remain out of scope until explicitly
planned and operator-approved.
