# Researcher Guide

English | [简体中文](researcher-guide.zh-CN.md)

## Threat model and authorized use

This repository exists for **defensive and authorized security research
on hardware the operator owns or has written permission to test**:
driver contract verification, radio firmware behavior analysis, and
detection research. The injection tooling transmits 802.11
management/control/data frames with forged headers; using it against
networks or clients without authorization is illegal in most
jurisdictions and against the terms of this project. The maintainers
assert lab-only intent; no capability here is hidden from the driver's
own observability nodes, and every tool logs what it sends.

Out of scope by design: EAPOL relay / single-radio MITM, any second
monitor interface, synthetic ACK/BA/completion injection.

## Quick start (three commands)

On the host with the device attached and the pinned module loaded:

```
bash preflight/run_stage0_preflight_host.sh --authorized-isolated-lab   # 1. identity gate
adb push tools/device/mon.sh /data/local/tmp/bin/mon                    # (once) + chmod 755
adb shell su -c /data/local/tmp/bin/mon up                              # 2. monitor persona
tools/ux/inject-verdict.sh <radiotap+802.11 hex>                        # 3. inject + verdict
adb shell su -c /data/local/tmp/bin/mon down                            # teardown
```

For captures: `mon scan 30` (airodump display + full-fidelity tcpdump
in parallel). For replays and research-frame generation:
`tools/replay/README.md` - **respect the pacing defaults**.

## Crash recovery manual (RAMDUMP instance)

Symptom signature: an injection returns, then within ~0.5 s adb drops,
the device reboots (subsystem-restart policy: ramdump + SoC reset), and
the evidence dir has an empty `stats-after` file.

Procedure:

1. Wait for boot; confirm the module: read
   `/sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id` and compare
   against the build-id your runner pinned. A mismatch means you are
   not diagnosing the build you thought.
2. Pull forensics: `/sys/fs/pstore/console-ramoops-*`, `dmesg`. The
   known incident chain was attributed from the panic backtrace plus
   the per-vector stats-before/after snapshots in the evidence dir.
3. The driver gates the known RAMDUMP input domain (family preamble +
   wide-bandwidth descriptor requests are precise-rejected or
   bypassed); a new crash means a new input class - bisect with a
   single vector per boot (see `archives/INDEX.md`).
4. `tools/ux/ssr_watch.sh` automates steps 1-2 plus persona rebuild
   for long sessions.

A first-run settle race right after a flash (supplicant still tearing
down) is a known framework issue: retry once before diagnosing.

## Driver node reference (debugfs, monitor persona)

| Node | Mode | Meaning |
|---|---|---|
| `frame_inject_stats` | 0400 r | versioned counters (format 13): parse/drop reasons, submit/completions, bypass counter, admin knob readbacks, live queue depth |
| `frame_inject_capabilities` | 0400 r | versioned capability claims (format 15), each tagged with evidence class incl. `ota_unproven` |
| `frame_inject_selftest` | 0400 r | host-contract selftests (expect all-pass) |
| `frame_inject_completions` | 0400 r | per-frame TSV ledger (seq/ts/status/desc/ack_rssi/ppdu/rate/...) |
| `frame_inject_helper_idle_ms` | rw | hidden-STA helper idle reclaim timeout (flood sessions raise this) |
| `frame_inject_inflight_limit` | rw | 1-8 concurrent management descriptors |
| `frame_inject_monitor_filter` | rw | preset (`full/mgmt/ctrl/mgmt_ctrl`) or `raw ...` class routing |
| `frame_inject_monitor_fcs` | rw | FCS byte delivery (default on = trim-skip wiring armed) |
| `frame_inject_mon_stats` | 0400 r | monitor ring counters |
| `frame_inject_peer_rate` | rw | helper peer fixed-rate pin (`fixed <fam> <nss> <mcs>` / `raw <u32>` / `none`) |
| `frame_inject_pmf_key` | w | CCMP pairwise key install for protected-management research (never read back) |
| `frame_inject_channel_hop` | rw | `start <dwell_ms> <freq>[@width]...` / `stop` scheduler |
| `frame_inject_admin_gate` | rw | 0 open / 1 reject all injections fail-closed |
| `frame_inject_rate_limit` | rw | 0 off / 1-1000 admissions per second |
| `frame_inject_watchdog_ms` | rw | clamped 1000-10000 async completion watchdog |

## Tool pitfalls (all measured)

- airodump-ng stdout must go to `/dev/null` - redirected ncurses grows
  to ~690 MB in 50 s; `-c` takes channel numbers, not MHz.
- adb compound commands under `su -c` can half-execute - one command
  per call, with a timeout, stdin redirected.
- KernelSU hides debugfs; mount it first (`common/lib.sh
  mount_debugfs`).
- MAC changes need link-down -> set -> link-up (direct set: errno 524).
- 5G 1 Mbps requests transmit at 6 Mbps (firmware silent mapping).
- A wide-family `fw_width` `-EOPNOTSUPP` is a firmware physical
  boundary, not a bug; the default bypass submits without rate
  descriptors instead.
- During floods or long sessions keep the power state stable (suspend
  mid-session disturbs the persona); use `tools/ux/mon_keepawake.sh`.
- AF_PACKET captures include your own TX (`PACKET_OUTGOING`): filter
  `sll_pkttype` before reading "echoes".
- An all-zero 802.11 header parses as an association request (minimum
  28 bytes) - test MPDUs use deauth (FC 0x00C0, minimum 26).
- Broadcast probe requests that get no answer are usually AP policy or
  RF occlusion, not injection failure (check completion first).
