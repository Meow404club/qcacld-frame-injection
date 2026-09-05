# AGENT_HANDOFF - Stage 2 Full-Flow External OTA Validation Kit (v11j, v21 build)

## Scope and authority

This kit validates the qcacld3 frame-injection path (helper idle reclaim + capability owner table) on a
OnePlus 13 (Peach v2) whose loaded module Build ID is
`914714cb6f296f35f093bf393bfea47c4982897c` (source revision
`698efe09e8b8+dirty-20260906-observability-admin-knobs-v21`; stats format v12,
capabilities v12, selftests 407). It
contains no kernel image or AK3; the device must already run that build.

Use only in an owned or explicitly authorized, isolated RF environment. The
independent listener pcap is the only OTA authority. Host submission and WMI
completion records are progress evidence. Never synthesize RX evidence from a
completion or interpret status 0/3 as proof that an MPDU was or was not on air.

## Full-flow scope (v8)

The kit now carries the complete OTA instrument set; a volunteer session runs
six phases in order, each restoring the phone to managed Wi-Fi afterwards:

- **P1 main suite** - 67 owner-aware vectors via `run_stage2_sender_host.sh`
  (managed-template context on the lab AP channel).
- **P2 Stage 2c** - 12 vectors after a reboot with Wi-Fi never enabled
  (`run_stage2c_sender_host.sh`); the pure constructed hidden-STA context.
- **P3 PHY A/B** - `run_stage2_phy_ab.sh` with the listener recording the
  session channel: 16 fixed vectors (HT/VHT/power positives, STBC/SGI
  negatives, HE SU, antenna chain 0/3, caller-FCS preserve, two
  declared-channel probes) in an off/on pair over the
  `frame_inject_experimental_phy` parameter. v11e reclassifies the three
  80/160 MHz family vectors (vht80_nss1_mcs3, vht160_nss2_mcs8, he_su_mcs7)
  as on-phase POSITIVES riding the v19b default bypass: a pure family
  preamble at 80 MHz or wider still RAMDUMPs the firmware when carried by
  the mgmt rate descriptor (the v13b-era both-phase negative contract), but
  since v19b the driver pins the helper peer's fixed rate to the requested
  family/MCS/NSS and submits without the tx_send_params TLV - measured
  clean on three consecutive device boots (d-wave axis7). The on-phase
  assertion requires submit success plus fw_width_bypassed exactly +1 with
  drop_reason_fw_width unmoved, so a module built from pre-v19b source
  fails loudly. v9 makes
  "submitted" a driver-evidence verdict: per-vector `frame_inject_stats` deltas
  (wmi_submitted must move exactly +1 for expected accepts, no move plus a
  drop-reason increment for expected rejects) with per-phase stats
  snapshots archived. `ab-summary.tsv` gives per-vector
  submitted(expected) / ota_state / observed_phy plus per-phase
  `fcs_source.<phase>` adjudication (caller_fcs_preserved /
  fw_regenerated_fcs / listener_fcs_absent).
- **P4 offchannel** - same script with `--vector-set offchannel
  --offchannel-target MHZ` while the listener records the TARGET channel.
  Declared-channel transmission is knob-independent since v7: both phases
  must submit; observation on the target proves declared-channel
  transmission end to end.
- **P5/P6 optional** - rerun P3 on a 6 GHz channel (e.g. `--frequency 5955`)
  and on wide channels (`--channel-width 80 --center-frequency ...`) when the
  listener hardware supports it; otherwise skip and record unproven.

Return bundle: every output directory (stage2-output-*, stage2c-*, phy-ab-*),
all listener pcaps + listener-contract.txt, and one line per skipped phase.
Never prune "odd-looking" pcap records by hand; the verifier tolerates
non-radiotap records and the author re-derives independently.

## What changed in v11b..v11e (vs the v11 kit)

- P3 contract follows the v19b driver default: the three wide-family
  vectors (vht80_nss1_mcs3 / vht160_nss2_mcs8 / he_su_mcs7) are no longer
  both-phase negatives. They ride the measured-safe peer-fixed-rate bypass
  in the on phase: submit must succeed and the fw_width_bypassed histogram
  must move exactly +1 while drop_reason_fw_width stays put (device proof:
  d-wave axis7, three consecutive boots). Off-phase knob rejects are
  unchanged.
- Pins walked v19b/v19c/v19d to v19e (module `d207b086…`, SRC_REV
  `…selftest-vht-vectors-v20a`, selftests 407 after the VHT-nss and HT-index
  ratecode selftest fixes); stats format v12 with the fw_width_bypassed
  counter; capabilities v12 (bypass lines + monitor_fcs_preserve
  default_on).
- Kit binary architecture gate: the sender was accidentally shipped as an
  x86-64 host build once; the dry-run now fails on any non-ARM kit binary.

## What changed in v11 (vs the v10 kit)

- New P7 session `run_stage2_ccmp_pmf.sh` (C-2 PMF OTA verdict): installs a
  volunteer-chosen known CCMP-128 pairwise key on the helper peer (debugfs
  frame_inject_pmf_key, present since v16a), injects protected deauth frames
  carrying the private WFA is-SA-query tx-flag, and records per-frame send
  windows for listener binding. The verdict is offline on the listener pcap
  with `decrypt_ccmp_pmf.py` (pure-python AES-CCM, MIC verification,
  --selftest covers roundtrip/tamper/wrong-key). Key bytes are never logged
  on the phone; they live only in the volunteer host's session directory.
- New P8 session `run_stage2_peer_rate_ota.sh` (C-5 listener leg,
  CONDITIONAL): requires the v19 frame_inject_peer_rate knob
  (WMI_PEER_PARAM_FIXED_RATE, V1 ratecode) and the private TX_FLAGS bit-15
  FW-default-rate submission mode. Only meaningful if the author-side d-wave
  fixed-VHT probe axis did NOT crash the firmware. Adjudication = radiotap
  rate fields of the injected TA between the baseline/fixed windows.
- `run_stage2_phy_ab.sh` persona settle upgraded to the supplicant-gone gate
  ("Wifi is disabled" is only the setting bit; the framework teardown is
  asynchronous and would otherwise destroy the persona mid-run).
- Default build id pinned to v19 `3e40b3f0…` (was v13b `e84d8cab…`); the
  --expected-build-id authorization path is unchanged.

## What changed in v10 (vs the v9 kit)

- The three family vectors declaring 80/160 MHz bandwidth became negatives
  (reject in BOTH phases; on-phase rejection must move drop_reason_fw_width
  exactly +1). Rationale: 2026-09-05 one-variable-per-boot bisect proved a
  pure HT/VHT/HE preamble with bw_mask at/above 80 MHz RAMDUMPs the
  firmware (SoC reset) at 20 MHz and 80 MHz helper contexts alike, while
  20/40 MHz family requests complete with status 0 - the kit's vht40_nss2
  mcs9/ht vectors stay positive with device-proven completions.
- Default build id pinned to the v13b gate build; ab-contract.txt now also
  records the module's stats format version and source_rev (forensics).
- Mock adb + dry-run extended: fw_width class, stats format 10, three new
  checks (both-phase rejection, gate evidence, knob counters).

## What changed in v9 (vs the v8 kit)

All 12 phy_ab script defects confirmed by the v8 return audit are fixed, plus
four more that the new mandatory local dry-run caught:

- Submitted semantics: per-vector `frame_inject_stats` deltas (wmi_submitted +
  drop-reason histogram) replace the sendto rc as the accept/reject evidence;
  expected outcomes are asserted per vector per phase (exit 7 on violation,
  after Wi-Fi restore) and per-phase stats snapshots are archived
  (`stats-<phase>-start/end.txt`, incl. helper_context_source).
- The bool module parameter is written/read back as Y/N (v8 compared 0/1 and
  could never pass); monitor setup retries the full down/type/up/freq
  sequence and asserts the final `iw info` state; an EXIT trap best-effort
  restores the parameter and managed persona on mid-run death.
- The verifier verdict is surfaced (PASS / UNPROVEN / VERIFIER_ERROR) and
  exit codes are documented: 0 orchestration ok (either verdict), 4 setup,
  5 param, 6 restore, 7 contract, 9 verifier, 10 stats unreadable.
- `--expected-build-id` must be exactly 40 hex chars; expected and loaded ids
  both land in `ab-contract.txt`. The script now also verifies kit
  SHA256SUMS before running.
- SHA256SUMS self-inclusion race fixed in all three generators
  (find|xargs could hash its own half-written output).
- `verify_stage2_ota.py`: in-window bonus raised from +100 to +100_000 so it
  dominates byte-exactness (+1_000) - an out-of-window retransmission copy
  can no longer steal an A/B phase binding (selftest covers this). Frames
  whose captured FCS does not match the body CRC (exactly the preserved
  caller-marker-FCS shape) stay matchable as fcs_state=invalid instead of
  being dropped; BADFCS-flagged frames stay excluded.
- The fcs vector now binds on its body (caller FCS stripped from the
  manifest mpdu_hex); preserve/regenerate is adjudicated per phase from the
  raw capture with window scoping and Duration-rewrite tolerance.
- Vector table: `neg_vht_sgi` was one nibble short since v8 (never actually
  sendable) - fixed and covered by a dry-run length/radiotap bounds check.
- The observed_phy walker's field size/alignment table now mirrors the
  driver's authoritative `wlan_hdd_radiotap_sizes[]` verbatim (the v8
  hand-guessed table desynced on ANTENNA/DB_ANTSIGNAL and mislabeled
  DBM_ANTSIGNAL as TX power).
- Local dry-run before packing (the v8 lesson): full mock-adb orchestration
  (main set / offchannel / contract-violation injection / setup-failure +
  trap), verifier selftest, and regressions against the v8 return's real
  pcaps (P1 66/67 owner-aware reproduction, P3 zero-packet path) - 41 checks
  green. Any future kit script change must pass the dry-run before shipping.

## What changed in v8 (vs the v7 kit)

- The full OTA instrument set moves into the kit: `run_stage2_phy_ab.sh`
  (16-vector PHY A/B + offchannel mode + FCS-source adjudication) with its
  dependencies `send_stage1_packet` and `verify_stage2_ota.py`. A volunteer
  can now run P1-P6 without author-side suites. Build pin updated to the v12c
  module (`ec49943d...`, capabilities v5); self-built modules use
  `--expected-build-id`.

## What changed in v7 (vs the v6 kit)

- Build pins updated from v11 `d2f87ff2...` to the v12 build `d181e44f...`
  (stats format v9 unchanged, capabilities v4 -> v5). The v12 driver batch is
  the 4.2 work (unified monitor chandef flow with atomic rollback, a
  driver-side channel-hop debugfs scheduler, monitor dump_survey, a self-TX
  OTA echo counter, and a per-boot stable monitor MAC). None of it changes the
  frozen kit vectors or verdict rules; external channel intents such as this
  kit's own `iw dev wlan0 set freq` choreography cancel any driver-side hop
  session, so the sender flow is unaffected. Packaging unchanged from v6.

## What changed in v6/v5 (vs the v4 kit)

- Build pins updated from v6 `4ea10539...` to the v11 build `d2f87ff2...`
  (stats format v9 unchanged, capabilities v3 -> v4). Driver-side deltas that
  matter here: the full 6 GHz band now enumerates (5955-7115, 59 channels) plus
  the extra 2.4 GHz (12/13/14) and 5 GHz (144/169/173) channels; the
  constructed context follows the monitor width; off-channel passthrough and
  the experimental PHY families are default-on. The frozen kit vectors and
  contracts are unchanged. The second-monitor-interface (mon0) path is
  deliberately re-gated (a device-side bisect proved that bringing a second
  monitor vdev up silently poisons firmware unicast delivery; this kit never
  uses mon0, so there is zero impact).
- Packaging fixes: device scripts now carry the executable bit inside the zip
  (in v4 `run_stage2c_sender_device.sh` shipped mode 644 and the operator had
  to chmod +x), and the verifier now tolerates non-radiotap records bundled by
  the listener's own capture stack (v4 return proved IGMP/MLD bare records can
  be mixed in; they are now skipped and reported as `skipped_non_radiotap=N`.
  Regression against the original v4 raw pcap: 67/67 owner-aware frames,
  verdict PASS, skipped_non_radiotap=6 - no manual derivation needed anymore).

## What changed in v4 (vs the 2026-08-31 v3 kit)

- Build pins updated from `9c956bef...` (stats v8) to the v6 build. Driver-side
  deltas since then: monitor RX radiotap quality closure (VHT mcs_nss remap,
  per-chain antenna signal), configurable monitor RX filtering (default off =
  byte-identical stock), and the probe-request explicit-channel fix (every
  injected frame now carries the explicit monitor channel; device-side
  seven-frame adjudication showed all probe-request shapes transmitting with
  29 AP responses + 4 ACKs to the injected TA as local corroboration).
- New Stage 2c constructed-context variant (12 vectors) - see below.
- RF placement guidance added after a 2026-09-02 false-negative lesson: a host
  chassis between AP and phone let retried unicast through while dropping
  every one-shot broadcast probe, mimicking an injection failure. Place all
  three nodes with clear line of sight and re-run at half distance before
  concluding anything from `completion ok + listener missing`.

## Components

| File | Role |
|---|---|
| `run_stage2_listener.sh` | Configures and validates the listener's complete channel definition before capture and READY |
| `run_stage2_sender_host.sh` | Performs phone identity gates and drives the device sender over adb (67-frame main suite) |
| `run_stage2_sender_device.sh` | Sends the frozen 67 vectors, completion-gated, one at a time |
| `run_stage2c_sender_host.sh` | Constructed-context variant: disables the framework, enters monitor at 20 MHz, drives the 12-vector sender |
| `run_stage2c_sender_device.sh` | Sends the 12 constructed-contract vectors behind a hard `helper_context_source=constructed` gate |
| `send_frame_matrix` | Android aarch64 sender binary from the frozen baseline |
| `send_frame_matrix.c` / `send_frame_matrix.host` | Sender source and host selftest binary |
| `run_stage2_phy_ab.sh` | P3/P4/P5/P6 driver: 16-vector PHY A/B with per-vector stats-delta assertions, offchannel mode, 6G/wide sessions; build-id gated, EXIT-trap + managed Wi-Fi restore |
| `send_stage1_packet` / `send_stage1_packet.c` | Android aarch64 raw sender used by the PHY A/B phases (with `--clock` capture windows) |
| `verify_stage2_ota.py` | Owner-aware OTA binder consumed by the PHY A/B phases |
| `verify_stage2_capture.py` | Owner-aware ordered pcap verifier and per-vector matrix generator (manifest-driven; works for both suites) |
| `SHA256SUMS` | Integrity manifest checked by listener and sender host scripts |

## Preconditions

- adb root (`su`) is available on the phone.
- Main 67-frame suite: managed Wi-Fi is connected to the authorized target
  network before switching to monitor; helper creation needs a recent
  authenticated managed template.
- Stage 2c constructed suite: the phone must NOT have connected Wi-Fi since
  boot. The device script hard-fails with `failure_code=16` if a managed
  template is still present - reboot without reconnecting and rerun; do not
  bypass the gate.
- The operator knows the complete channel definition: primary frequency,
  channel width, and center frequency. Stage 2c is 20 MHz only by contract.
- `--peer-mac` is the actual authorized AP/peer identity for the associated
  test context. Do not use the listener radio's MAC merely because it captures
  the traffic.
- On a self-built device, the operator may pass
  `--expected-build-id <40-hex>` to authorize that identity for the run. The
  default remains the delivered kit Build ID; both host and device gates fail
  closed on mismatch, and `result.txt` records the gated value as `build_id`.
- The loaded module Build ID must match the gated expected ID: the delivered
  kit ID by default, or an operator-authorized `--expected-build-id` override.
  Sender gates fail closed on mismatch.

## Execution contract

1. Start the listener with an explicit channel definition. For example:

   ```sh
   ./run_stage2_listener.sh --interface wlan1 --frequency 5745 \
     --channel-width 80 --center-frequency 5775 --duration 600
   ```

   For 20 MHz, omit `--center-frequency`. The script saves `iw-info.log` and
   `listener-contract.txt`, then fails before READY unless actual monitor type,
   primary frequency, width, and center frequency match.

2. Put phone `wlan0` in monitor mode with that same complete channel definition.

3. Run:

   ```sh
   ./run_stage2_sender_host.sh --peer-mac <authorized-ap-or-peer-mac> \
     --listener-ready-token READY-... \
     --acknowledge-authorized-isolated-test
   ```

   Add `--expected-build-id <40-hex>` only for an operator-authorized
   self-built module.

4. The device sender pins `frame_inject_helper_idle_ms=600000` for all 67
   frames and restores the prior value on exit. `result.txt` records the pin
   and `helper_auto_teardowns`.

5. Stage 2c (constructed context, separate listener READY at 20 MHz): start
   the listener at 20 MHz, then run

   ```sh
   ./run_stage2c_sender_host.sh --frequency 5745 \
     --peer-mac <authorized-ap-or-peer-mac> \
     --listener-ready-token READY-... \
     --acknowledge-authorized-isolated-test
   ```

   The host script disables the Wi-Fi framework itself, enters monitor on the
   requested frequency at 20 MHz, holds the persona stable, and the device
   script sends 12 frozen vectors (probe-request, hcx-probe-request,
   auth-request, assoc-request, disassoc, deauth, action, null-data,
   qos-null, ordinary-data, rts, ps-poll) with the same completion gating and
   manifest format. `result.txt` carries `helper_context_source=constructed`
   and `context-source.txt` records the gate observation.

6. Copy sender evidence to the listener host and run the verifier per README
   (once per suite against its own capture and token).

## Verdict interpretation

- Sender `verdict=COMPLETE` means all requests reached real descriptor
  completion (67 for the main suite, 12 for Stage 2c). Status 0 is recorded
  as `fw_ok`; status 3 is recorded as `fw_no_ack`. Neither is OTA proof.
- `exact_ordered_frames` counts byte-identical MPDUs.
- `owner_aware_ordered_frames` permits only Duration/ID and Beacon/Probe
  Response TSF rewrites, while requiring all other MPDU bytes to match in order.
- OTA is `PASS` only when the ordered owner-aware match covers the full
  manifest (67/67 main, 12/12 Stage 2c).
- For Stage 2c, a COMPLETE sender plus a matching listener observation closes
  the "can the pure constructed context deliver to the air" question; a
  COMPLETE sender with all frames missing is an honest negative for this run -
  re-check RF placement before treating it as a driver conclusion.
- FCS is not normalized away. Each observed frame is classified as `absent` or
  `valid`; frames advertised by the capture as bad or carrying an invalid FCS
  are classified separately and excluded from MPDU matching.
- `fw_no_ack` plus `missing` means only that the listener did not observe the
  expected MPDU; do not report that combination as proof of no transmission.
- Response indexes and global RTS/CTS/ACK/BAR/BA counts are listener facts, not
  synthesized protocol outcomes.

## Known boundaries

- Duration/ID and Beacon/Probe Response TSF are hardware/FW owned.
- A listener that omits FCS cannot close hardware-generated, caller-preserved,
  or intentional bad-FCS semantics.
- A listener that does not deliver control frames or useful PHY radiotap fields
  cannot close control RX or requested-rate semantics; report them as unproven.
- On 5 GHz the current host path maps a requested 1 Mbps CCK rate to 6 Mbps
  OFDM. Do not claim 1 Mbps OTA compliance from such a run.
- Local monitor beacon delivery can be suppressed while the helper is alive;
  the idle reclaim restores it after quiescence. Local monitor data is never the
  Stage 2 OTA authority.
- The 67 vectors are bounded coverage, not an exhaustive FC/PV1/extension,
  crypto, FCS, or PHY claim.

## Failure handling

Any nonzero sender or listener exit is a failed/incomplete run. Preserve the
entire output directory, including `iw-info.log`, `listener-contract.txt`,
`run.log`, sender manifest, pcap, and exit codes. Do not edit evidence in place.
