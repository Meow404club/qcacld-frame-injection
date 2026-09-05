# Capability Boundary Table

English | [简体中文](boundaries.zh-CN.md)

Evidence hierarchy for every row: **ABI** (a missing
firmware-interface field is unimplementable), **FW behavior** (measured
on device: completion codes, counters, RAMDUMP forensics), **PHY**
(hardware capability or service bitmap), **OTA pending** (waiting on an
independent listener round - a legal state, not a claim). Machine-
readable declarations live in the driver's capabilities node
(format version 15); this table is its human-readable mirror.

## TX injection (frame-inject monitor path)

| Capability | Status | Evidence class |
|---|---|---|
| Legacy rates (1-54 Mbps) | full | OTA at 6 Mbps measured; rest host+completion |
| HT/VHT/HE family rates at 20/40 MHz | full (descriptor path) | device: status 0 across families |
| Family rates >= 80 MHz via rate descriptor | **blocked: firmware RAMDUMP** (wide-bandwidth branch of the management rate-descriptor path) | FW behavior (bisect rounds, ramoops) |
| Family >= 80 MHz via peer fixed-rate bypass | default-on; clean completion across repeated boots | FW behavior; **OTA pending** (on-air rate/width) |
| VHT radiotap field layout | spec (known u16 / flags u8 / bw u8 / mcs_nss[4]) | device-confirmed spec conformance |
| GI / LTF / FEC / STBC / RU / puncturing / MU (TX) | **no ABI field** - precise reject | ABI |
| EHT TX | **no TX bit** | ABI |
| 5/10 MHz, HE >160 MHz | **ABI gap** | ABI |
| tx power | s8 dBm x2 (0.5 dBm units); 0/unset indistinguishable | ABI |
| retry limit | firmware does not execute it (measured zero retries at maximum-length retry requests) | FW behavior |
| Management frame length in (2048, 2304] | firmware DISCARD (status 1) | FW behavior |
| A-MPDU / aggregation | WMI single-MPDU abstraction; direct-DP RAW permanently excluded (SMMU fault) | FW behavior + project ban |
| Management TX cancel | **no ABI** | ABI |
| TX no-ack flag | no bit; the four WFA tx_flags bits require no-tx-params submission | ABI |
| Beamformed steering (en_beamforming TLV) | wired (radiotap VHT BEAMFORMED flag and private TX_FLAGS bit) | device: clean submit; OTA pending |
| CFR enable / firmware-default-rate probes | wired private bits, clean submits | OTA pending |
| Off-channel TX / QoS-null over WMI | firmware service bit = 0 (code present, unserved) | FW behavior |
| PV1 / S1G / DMG | PHY lacks them | PHY |

## Firmware behavior quirks (measured, stable)

- Duration/ID rewritten on air; beacon/probe-response timestamps
  rewritten by firmware.
- The helper's lifetime suppresses locally-originated broadcast
  management delivery to our own monitor RX; the self-transmit echo is
  missing roughly one frame in six (a missing echo is not proof of
  non-transmission).
- Completion status 0 = firmware OK, 3 = no ACK. Neither proves
  transmission.
- A second monitor vdev's activation poisons firmware unicast delivery
  until power cycle -> the host refuses creation (poisoning gate).
- Multi-link monitor unsupported; 80+80 capped by firmware max-BW 160;
  320 MHz monitor channels accepted; injection context at 320 is a
  precise reject (no EHT tuple synthesis).
- Normal (non-injection) data traffic at VHT80/160 is unaffected by any
  of the above (autonomous firmware rate engine).

## RX / monitor

| Capability | Status | Evidence class |
|---|---|---|
| radiotap quality fields | per-chain RSSI pairs full; ANTNOISE has no per-PPDU noise-floor TLV (survey snapshot ceiling, adjudicated rejected) | FW behavior |
| CCA busy | firmware fills a pdev sentinel -> channel utilization stays observational | FW behavior |
| Per-class filter | the monitor ring ignores class bits; host delivery-point enforcement (measured) | FW behavior + host comp |
| FCS delivery modes | default-on trim-skip wired; hardware-generate/caller-preserve/intentional-bad-FCS **OTA pending** (listener FCS observation absent in external rounds so far) | OTA pending |
| Bad-FCS reception adjudication | deferred (needs an external bad-FCS transmitter) | environment |

## Instruments

- FIPS: the WEXT face is compiled out (invoke-level -95, structurally
  unreachable).
- Spectral scan: vendor face live under monitor persona,
  component-config-gated (INI-level activation).
- CFR: reachability on record, effect invoke pending.

## Admin and observability surface

- `frame_inject_admin_gate`: 0 open / 1 rejects all injections
  fail-closed at the enqueue boundary (module-level counter
  `drop_reason_admin`).
- `frame_inject_rate_limit`: 0 off (default) / 1-1000 caps admissions
  per second (`drop_reason_rate_limited`).
- `frame_inject_watchdog_ms`: clamped to 1000-10000; scales the async
  completion watchdog only.
- Stats node format version 13 adds the admin counters, knob readbacks
  and live queue depth.

## Quantified operating points (tool defaults)

- Hop dwell >= 200 ms is safe (measured 400 ms dwell, 38-41 ms switch).
- Sustained injection: pace at <= 4-8 pps default envelopes (completion
  latency typically 150-350 ms; worst envelope ~2.4 s).
- tx inflight 8 / queue 64 (defaults; knob range 1-8).
- Selftest count 409 / stats format 13 / capabilities format 15 on the
  current pinned build.
- The monitor-FCS default-on delivery is byte-compared across builds;
  a delivery diff after a kernel/module change is a regression signal,
  not noise.
- Monitor MAC is per-boot stable; persist with `tools/ux/mac_persist.sh`.

## Pending device rounds (not boundaries)

- hcxdumptool active-mode validation (zero driver work claimed).
- The fault/stress matrix and the final evidence package.
