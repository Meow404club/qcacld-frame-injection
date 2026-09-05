# Driver Implementation Notes

English | [简体中文](driver-notes.zh-CN.md)

What the modified QCACLD3 tree adds on top of stock, and the hard rules
each piece enforces. Source paths are relative to `qcacld-3.0/core/`.

## Injection path (the one legal route)

`hdd/src/wlan_hdd_frame_inject*.c` - a monitor-netdev transmit path that
parses a caller-supplied radiotap header (spec VHT layout), maps it
onto `wmi_mgmt_tx_send` transmit parameters, and submits through a
hidden-STA helper vdev. Hard rules baked into the code:

- The helper is constructed or template-derived; it is never a
  connection-tracking peer rewrite (no caller-identity forging).
- No host direct-DP RAW enqueue of monitor payloads (the SMMU-fault
  route is excluded at review level and by convention).
- Family-preamble requests at or above 80 MHz of bandwidth: precise
  reject (`drop_reason_fw_width`), with the **default bypass** pinning
  the helper peer's fixed rate and submitting without tx-params when
  the request carries no TLV-exclusive fields. Fail-closed: any bypass
  step failing restores the precise reject.
- Probe-state reapply: PMF key / peer-rate knobs re-apply on helper
  rebuild, deduplicated by helper generation, observable via per-knob
  reapply counters.
- Admin knobs gate at the enqueue boundary before any adapter lookup:
  a kill switch (fail-closed reject), a bounded per-second admission
  cap, and a clamped async-watchdog scale.

## Monitor RX

- `qdf_nbuf_update_radiotap()` (`qdf/src/qdf_nbuf.c`): shared radiotap
  builder - VHT mcs_nss spec remap, per-chain antenna/RSSI pairs,
  ANTNOISE only when a noise floor exists.
- Filter mode (`hdd/src/wlan_hdd_rx_monitor.c` + `dp_txrx` hook): the
  RXDMA ring ignores per-class bits, so class routing is enforced at
  the HDD delivery point with counters; fail-open on malformed headers.
- Monitor FCS delivery: default-on wiring to the DP trim-skip knob.
- Self-TX echo counter always armed in monitor persona (never
  synthesized ACKs or completions).

## Channel control

- Unified chandef core `wlan_hdd_mon_apply_chandef()`: nl80211/WEXT/
  sysfs/hop all funnel through one apply with quiesce, atomic rollback
  on failure, and fail-closed timeouts. The sysfs face is
  `/sys/class/net/wlan0/monitor_mode_channel` (`freq code` with driver
  width codes 0=20 1=40 2=80 3=160 4=80p80 7=320).
- Hop scheduler `frame_inject_channel_hop`: rtnl-trylock-safe worker,
  park-on-error, external-channel-intent soft cancel.
- Monitor survey: in-use + direct noise sampling; CCA busy stays
  unreported because firmware fills a pdev sentinel.

## Safety gates (each with the incident that motivated it)

| Gate | Blocks | Incident |
|---|---|---|
| second-monitor refusal | monitor vdev activation poisoning firmware unicast delivery until power cycle | monitor-vdev bisect (association loops, EAPOL M1 never arriving) |
| fw_width gate + bypass | descriptor-path RAMDUMPs at family >= 80 MHz | width bisect rounds (SoC resets with ramoops) |
| EXT frame-class early reject | transport-layer FC-version rejects turning into opaque -EIO | redirected to a precise, classified reject |
| parse/submit mask pairing | private TX_FLAGS bits accepted by submit but not parse (probe axes silently parse-dropped) | caught by a device round's counter walk |
| VHT spec-layout parser | captured spec-layout frames misread via a private field layout | caught by selftest vectors after layout audit against mac80211 |

## Verification assets

- In-module selftests: host-contract assertions
  (`hdd/src/wlan_hdd_frame_inject_test.c`), including spec-layout VHT
  vectors and the admin-knob pure helpers.
- The three suites (preflight/contract/ota) and their mirrors pin the
  module build-id; the contract mirror re-derives the case matrix from
  the generator and checks the pin mirrors.
- The OTA kit (`ota/kit/`) is the only external-facing artifact; every
  change to it passes `ota/dryrun/` (mock-adb checks) before packing,
  and kit binaries are cross-compiled with NDK r27d (a host cc build
  once produced an x86 ELF - dry-run architecture gates now catch
  this).
