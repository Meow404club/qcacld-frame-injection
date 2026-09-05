# replay tools (pcap replayer + mdk4-lite)

Authorized-lab use only.

## Layout

- `replay_lib.py` - shared sender/pacing/verdict plumbing. The radiotap
  geometry table is imported from `../analyze_radiotap_pcap.py` (single
  authority, verbatim from the delivered kernel shim header).
- `pcap_replay.py` - replay pcap/pcapng captures (DLT 105/127).
- `mdk4_lite.py` - beacon-flood / probe-resp / eapol-flood / fuzz
  generators (fills the mdk4/Kismet gap in termux sources).

## Hard facts baked into these tools

- **Burst pacing is mandatory.** tx inflight is 8 with a 64-entry queue
  on current builds, but `sendto` rc=0 is QUEUE-ACCEPT: a burst faster
  than the completion rate drops silently. Default `--pps 4` is
  conservative; watch `wmi_submitted` deltas if you raise it.
- **Per-frame verdict** (adb mode) reads the driver ledger
  (`frame_inject_completions` TSV delta). `status 0` = FW OK, `status 3`
  = no ACK. Neither proves transmission; broadcast forged traffic
  normally shows 3.
- **RX-only radiotap fields are stripped** on replay (TSFT/FLAGS/
  CHANNEL/RX_FLAGS/signal/noise). RATE/MCS/VHT/HE/TX_FLAGS/ANTENNA/
  DBM_TX_POWER/DATA_RETRIES survive verbatim, so captured rate requests
  replay as rate requests.

## Modes

- `dryrun` (default): runs the sender binary's `--dry-run` parse locally.
  Build a host sender first: `cc -o /tmp/sender ../ota/kit/send_stage1_packet.c`
- `adb`: pushes the ARM sender and sends per-frame over adb with verdict
  readback (needs the monitor persona up on device - `tools/device/mon up`).
- `script`: emits a device-side batch shell script (`--out FILE`); fast,
  but no per-frame verdict.

## Selftests (run before any change ships)

```
python3 pcap_replay.py --selftest     # 11 checks
python3 mdk4_lite.py --selftest       # 11 checks
```

## Examples

```
# replay first 50 frames of a capture at 4 pps with verdicts
python3 pcap_replay.py capture.pcap --mode adb --limit 50

# emit a device-side batch instead
python3 pcap_replay.py capture.pcap --mode script --out /tmp/batch.sh

# 200 fake-AP beacons, random SSIDs, from a file of SSIDs
python3 mdk4_lite.py beacon-flood --count 200 --ssid-file ssids.txt \
    --send-mode adb --pps 8

# structurally-valid EAPOL M3 template (no crypto; operator supplies
# nonce/MIC material)
python3 pcap_replay.py --template eapol-m3 --bssid 021122334455 \
    --client 02aabbccdde0 --anonce <64hex> --mode adb
```
