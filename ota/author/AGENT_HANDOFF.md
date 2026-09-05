# AGENT_HANDOFF - Stage 2 Matrix Expansion Suite

## Purpose

Closes todo 4.3 item 1: per-item OTA closure over the Stage 1 schema-v2 matrix
instead of the bounded 67-vector set. The Stage 1 device suite already sends
every `send_after_continuity_fix` case through the real terminal ledger and
records a monotonic capture window per case (`device-results.tsv` ->
`stage1-device-evidence.jsonl`). This suite adds the independent listener and
the owner-aware ordered binding. It introduces no new sender, no new MPDU, and
no device-side code.

## Execution model

`run_stage2_matrix_host.sh` orchestrates existing, individually frozen
components:

1. `../device-suite-wmi-full-frame-stage2/run_stage2_listener.sh` - brings the
   external monitor NIC up with an explicit primary/width/center contract and
   fails closed unless `iw dev ... info` matches. Its READY token gates the
   run.
2. `../device-suite-wmi-stage1-matrix/run_stage1_matrix_host.sh` - identity
   gates (module Build ID, source rev, module/common hashes, plan/sender
   hashes), persona choreography, the 633-case device run, teardown evidence,
   and schema-v2 evidence conversion. Repin its pins for every new build.
3. `../device-suite-wmi-stage1-matrix/verify_stage2_ota.py` - ordered DP
   binding of capture windows to the listener pcap; Duration/ID and
   beacon/probe TSF compared as hardware/FW-owned fields; FCS classified, not
   normalized; responses matched only as real captured frames.

## Output interpretation for agents

- `stage2-ota-verify.rc=1` (UNPROVEN) is a legitimate verdict; only rc=2 is a
  harness error. Never rerun the RF test just to turn a UNPROVEN into PASS.
- `stage2-matrix-summary.tsv` is the per-case classification. `observed` with
  a non-empty `rewrite` column is a PASS with documented owner-field rewrites,
  not a mismatch. `not_observed` plus terminal completion OK is recorded as
  the fact it is; do not report it as proof of either transmission or its
  absence.
- Cases with `operation=parse_only` are bound by precise errno, not OTA.
- Capability statements for FCS, per-rate PHY effect, and monitor RX metadata
  come exclusively from `../../evidence/capability-matrix/stage2-owner-table.md`. A PASS
  here does not upgrade unproven rows in that table.

## Preconditions and safety

- Authorized isolated RF environment; the operator supplies the actual
  authorized AP BSSID as `--target-bssid` (never the listener NIC MAC).
- The phone runs the build the Stage 1 pins expect; flash and reboot are
  user-only actions.
- The listener duration must cover the whole Stage 1 run (default 2400 s); if
  the capture finalizes early, the binding under-reports and the run must be
  repeated with a longer window rather than the results excused.

## 4.2 additions (2026-09-03 v12)

Driver-side 4.2 features do not change any OTA vector or verdict rule: the
unified chandef flow, the `frame_inject_channel_hop` debugfs scheduler,
monitor `dump_survey` (IN_USE + pdev0 noise + congestion CCA deltas) and the
self-TX OTA echo counter are local-contract features exercised by the
chandef/stage0 runners. If a listener session runs on v12, everything in the
4.1.1 section below applies unchanged (16-vector phy_ab, offchannel mode,
FCS adjudication, 6G/constructed-width sessions). Identity pins move to the
v12 build once the candidate is packaged (stage1 runner is authoritative).

## 4.1.1 OTA closure (2026-09-03 v11 extension)

The v7/4.1.1 capability batch is contract-proven (parse -> submit -> FW
completion) but its air effect was unproven. The extended PHY A/B vector set
closes each gap with one adjudication instrument per item:

- HT MCS / VHT / power: vectors 1-8 (unchanged), observed_phy comparison.
- HE SU mapping: vector `he_su_mcs7`; observed label `he_fmt0_mcs7_nsts2`.
- ANTENNA -> chain_mask: vectors `antenna_zero`/`antenna_three`; the observed
  `+antN` suffix from the listener's per-packet antenna field is the direct
  chain A/B.
- FCS caller-preserve: vector `fcs_caller_valid`; the `fcs_source.caller_valid`
  summary line returns caller_fcs_preserved / fw_regenerated_fcs /
  listener_fcs_absent (never guessed).
- Off-channel passthrough: `--vector-set offchannel --offchannel-target MHZ`
  with the listener parked on the declared target; off-phase refusals plus
  on-phase observations on the target close the loop end to end. In the main
  set, `chan_declared_*` rows are expected "missing" on the session listener
  when accepted.
- 6 GHz injection: both runners are channel-parameterized; run the whole
  session on a 6 GHz primary (e.g. 5955/20) with a 6 GHz-capable listener.
- mgmt DS bits / A-MSDU shapes / rate-conflict and HE-reject negatives:
  carried by the 756-matrix OTA binding itself (the matrix host inherits the
  v11 identity pins from the Stage 1 runner); negatives stay contract-level
  by design.

Vector bytes 11-16 are lifted verbatim from the device-proven stage1 756 plan
(only the SA is rewritten to a unique value per vector for ordered binding).
