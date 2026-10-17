# SOC-003 — Limitations and Blind Spots

Documented limitations based on measured evidence (not speculation).

## 1. VirtualBox Host-Side Guest-to-Guest Unicast Visibility
- **Finding:** On VirtualBox host-only `vboxnet0`, guest↔guest unicast frames are not delivered to the host interface (even with promiscuous mode verified). Host observes host-involved unicast + broadcast/multicast only.
- **Evidence:** Phase 3C (9 captures, promiscuity 2 verified, 0 drops) — no WS001↔DC1 unicast seen while guests actively exchanged traffic; confirmed by WEF event ingestion and live TCP sessions on guests.
- **Impact:** Host-side capture point insufficient for validating WS001↔DC1 unicast behaviours from sensor host alone.
- **Mitigation:** Guest-side capture (WS001 pktmon, Phase 3D) proved viable for obtaining WS001↔DC1 unicast traffic.

## 2. Guest-Side Capture Requirement
- **Finding:** Validated WS001↔DC1 unicast traffic obtained via guest-side `pktmon` on WS001 (ETL→pcapng).
- **Evidence:** Phase 3D (712 packets, 0 drops, filtered to WS001↔DC1 only)
- **Impact:** Capture architecture must account for hypervisor topology; sensor position matters.

## 3. Checksum-Offload Artefact
- **Finding:** Guest-side capture (Phase 3D) produced 544 checksum-anomaly alerts (sids 2200073/74/75) from benign traffic due to VirtualBox guest offload; all WS001→DC1 packets had invalid checksums at IP/TCP/UDP layer by RFC-1071 recomputation while reverse direction valid.
- **Evidence:** Phase 4C/4D checksum investigation
- **Impact:** Anomaly noise in this specific hypervisor context; opt-in lab-only threshold config prepared (`soc003-lab-anomaly-thresholds.conf`) — not deployed system-wide.

## 4. ET Open Silence on Controlled Behaviours
- **Finding:** Managed ET Open ruleset (53,211 enabled) produced 0 alerts on Phase 2 controlled behaviours.
- **Evidence:** Phase 4C/4D combined replays across PCAPs
- **Impact:** Vendor coverage of these specific lab shapes not demonstrated on this snapshot.

## 5. Suricata Threshold Sampling Semantics
- **Finding:** Threshold alerts are volume-sampled (floor(matches/count)); alert count != event count.
- **Evidence:** SID 9003001 produced 2 alerts for 20 probes (count=10); SID 9003002 produced 1 alert for 30 DNS queries (count=20); SID 9003003 produced 1 alert for 6 HTTP requests (count=4)
- **Impact:** Alert volume differs from Zeek “once-per-behaviour” notice; must not equate counts across engines.

## 6. Suricata Alert Attribution Variability
- **Finding:** Attributed packet varies between replay runs (4B vs 4D) under multi-threaded processing; earliest gate-satisfaction time may differ from alert timestamp.
- **Evidence:** `alert-crossrun-comparison.json` (Phase 5) — 9003002 attributed to query #23 vs #5, 9003003 attributed to #2 vs #5, 9003001 attributed to different probe numbers
- **Impact:** Treat Suricata alert timestamps/attributed packets as bookkeeping artefacts. Zeek timestamps are canonical for event timing.

## 7. Synthetic PCAP Limitations
- **Finding:** Phase 1/2 PCAPs are deterministic synthetic constructions with parameterised behaviours.
- **Evidence:** Generator `scripts/gen_phase2_synthetic_pcap.py`; byte-reproducible
- **Impact:** Behaviours engineered to exercise specific thresholds; not representative of real adversary tradecraft or network diversity.

## 8. Single Controlled Capture Limitations
- **Finding:** Investigations focus primarily on single Phase 2 PCAP + supporting controls.
- **Evidence:** Phase 5 joint investigation uses one primary PCAP
- **Impact:** Limited statistical power for false-positive claims; benign testing limited to specific controls.

## 9. No Production Generalisation
- **Finding:** Thresholds, rules, and conclusions are calibrated to isolated lab (vboxnet0/192.168.56.0/24).
- **Evidence:** Architecture constraints, threshold rationale in detections README
- **Impact:** Cannot claim production readiness, enterprise deployment, or generalised detection coverage.

## 10. No IPS/Inline Validation
- **Finding:** Suricata never deployed inline; no NFQUEUE/AF_PACKET in live/IPS mode; `suricata.service` never started.
- **Evidence:** Phase 4B/4C/4D explicitly enforced offline-only (`-r`), no `-i` usage
- **Impact:** No prevention/IPS capability validated.

## 11. No Live Suricata Deployment
- **Finding:** All Suricata validation was offline PCAP replay.
- **Evidence:** Service inactive/disabled throughout; no live interface monitoring
- **Impact:** No live deployment performance/behaviour claims.

## 12. No Generic Network-Scan Detection Claim
- **Finding:** DET-201/SID 9003001 detect the specific controlled multi-host/multi-port failed-probe shape under lab thresholds; ET Open silent on these specific probes.
- **Evidence:** Phase 4C/4D ET Open results (0 alerts); scan-silence diagnosis (Phase 4D)
- **Impact:** Cannot generalise to all network scans or claim broad scan coverage.

## 13. No Generic DNS-C2 Detection Claim
- **Finding:** DET-202/SID 9003002 detect lab DNS burst; C2/DGA explicitly not supported. Sequential names are generator artefact.
- **Evidence:** ATT&CK assessment (T1071.004/T1568.002 NOT SUPPORTED)
- **Impact:** No generic DNS-C2 detection capability claimed.

## 14. No Generic C2 Detection Claim
- **Finding:** DET-203/SID 9003003 detect periodic HTTP; periodicity alone insufficient to establish C2.
- **Evidence:** ATT&CK assessment (T1071.001/T1102 candidate only)
- **Impact:** No generic C2 detection capability claimed.

## 15. Specific ET Open Scan-Orientation Finding (Evidence-Scoped)
- **Finding:** Of 33 enabled TCP scan-classification rules in the managed snapshot, 32 were inbound-oriented relative to $EXTERNAL_NET → $HOME_NET, while the controlled scan source was inside $HOME_NET (outbound scan). The remaining relevant outbound rule required a higher threshold than the controlled port-22 probes.
- **Evidence:** Phase 4D scan-silence diagnosis
- **Impact:** Explains observed silence for this specific orientation/threshold combination. Do **not** generalise to "ET Open cannot detect scans".
