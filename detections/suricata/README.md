# SOC-003 — Suricata local detection rules (Phase 4B)

**Directory:** `~/soc-lab/soc-003/detections/suricata/`
**Rule file:** `soc003-lab.rules` (3 rules, sid 9003001–9003003)
**Status:** validated offline against the Phase 2 deterministic PCAP (see
`../../PHASE4B_REPORT.md`, Phase 4B).

These are **local, lab-scoped, hand-written** rules. They are **not** vendor
signatures, **not** a ruleset feed, and **not** evidence of generic capability.
The vendor/ET Open ruleset is **not installed** on this sensor
(`/var/lib/suricata/rules/suricata.rules` does not exist), so `/etc/suricata` was
deliberately left untouched and these rules are loaded per-run with `-S`.

---

## Rules

| sid | Analogous Zeek detection | Trigger (observable network behaviour) | Expected result on Phase 2 PCAP |
| --- | --- | --- | --- |
| 9003001 | DET-201 | ≥10 zero-payload TCP **SYN** packets from one `$HOME_NET` source to ports `22/80/443/445/3389` on `$EXTERNAL_NET` destinations within 60 s (`threshold: type threshold, track by_src, count 10, seconds 60`) | alerts during Phase 2 block B (`192.168.56.150`, 20 probes) |
| 9003002 | DET-202 | ≥20 DNS queries containing `lab.test` from one `$HOME_NET` source within 60 s (`dns.query` + `content:"lab.test"` + `threshold … count 20, seconds 60`) | alerts during Phase 2 block C (`192.168.56.151`, 30 queries) |
| 9003003 | DET-203 | ≥4 `GET` requests to the `/api/v1/heartbeat` path from one `$HOME_NET` source within 300 s (`http.method`/`http.uri` + `threshold … count 4, seconds 300`) | alerts during Phase 2 block D (`192.168.56.152`, 6 requests at 30 s) |

Rationale: each rule mirrors the *count/port/path* gate used by the Phase 2 Zeek
detections (`detections/zeek/det-20*.zeek`) so that the Suricata result can be
compared against the existing ground truth, while being expressed in Suricata's
own keywords (`flags`/`dsize`, `dns.query`, `http.*`, `threshold`).

## How to run (offline only)

```bash
# configuration test of the rule file only (does not start the engine)
suricata -T -c /etc/suricata/suricata.yaml \
  -S ~/soc-lab/soc-003/detections/suricata/soc003-lab.rules \
  -l <output-dir>

# offline PCAP replay into an isolated output directory
suricata -c /etc/suricata/suricata.yaml \
  -S ~/soc-lab/soc-003/detections/suricata/soc003-lab.rules \
  -l <output-dir> \
  -r ~/soc-lab/soc-003/evidence/phase2-controlled-network-behaviour/phase2-controlled-network-behaviour.pcap
```

Never use `-i`, AF_PACKET, NFQUEUE, inline/IPS mode or live capture with these
rules in SOC-003: the phase is offline validation only.

## Results (Phase 4B, 2026-10-17)

| sid | expected | observed (Phase 2 PCAP) | verdict |
| --- | --- | --- | --- |
| 9003001 | ≥1 alert | 2 alerts (probes #18, #20) | true positive |
| 9003002 | ≥1 alert | 1 alert (query #23) | true positive |
| 9003003 | ≥1 alert | 1 alert (request #2) | true positive |
| (all) | 0 alerts on benign controls | 0 alerts on Phase 1 baseline, Phase 3B benign AD, Phase 3D benign AD capture, and on the in-PCAP benign/control blocks | no false positives observed |

Exit code 0, 215/215 packets read, 3/3 rules loaded. Full evidence and analysis:
`~/soc-lab/soc-003/evidence/phase4b-suricata-install/`.

## Limitations (read before quoting any result)

- **Lab-artefact tuning.** 9003001 is restricted to the lab's probe port set and
  to `$HOME_NET`→`$EXTERNAL_NET`; 9003002 is restricted to the `lab.test` domain.
  These restrictions make the rules *narrow by construction*. They do **not**
  demonstrate general port-scan, DNS-tunnelling or beaconing detection.
- **`threshold` alerts are sampled, not 1:1.** Suricata's `type threshold`
  produced roughly `floor(matches/count)` alerts per tracker and the *specific*
  triggering packet was not reproducible between runs (e.g. count=10 over the 20
  Phase 2 probes yielded 2 alerts on different probes in different runs).
  Alert counts therefore must **not** be read as event counts.
- **No interval/jitter modelling.** 9003003 cannot express "30.000 s ± jitter"
  the way DET-203 does; it approximates the behaviour with a repeat count. A
  slow, high-jitter beacon below the count gate is not covered.
- **DNS rule matches a lab domain string**, not subdomain uniqueness or entropy,
  so it says nothing about DGA or tunnelling detection.
- **Source-address coupling.** Rules 9003001/9003002 key on `$HOME_NET`
  (packaged default: all RFC 1918 space), not on a per-host allow-list; a busy
  legitimate host exceeding the thresholds would alert.
- Rules are unsigned, unreviewed by any third party, and exist only for this lab.
