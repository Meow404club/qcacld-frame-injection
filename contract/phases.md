# Phase Pattern for Device Contract Rounds

The one-shot rounds archived in `../archives/` converged on a stable phase
shape. New rounds compose these phases instead of copying whole scripts;
helpers live in `../common/lib.sh`.

## Round skeleton

1. **gate** — identity + format pins before anything else:
   module build-id (40-hex GNU build-id note), SRC_REV string, selftest
   count, stats/caps format versions and key lines. A mismatch aborts the
   round (exit 3): never diagnose through a wrong build.
2. **persona** — `wait_supplicant_gone` (settings flip != teardown), then
   the monitor persona setup, then `persona_alive` before EVERY phase.
3. **phases** — risk-ordered, each wrapped as: stats snapshot before ->
   action -> stats snapshot after -> delta assertions + evidence copy.
   Axis template:
   - knob write (optional) + readback
   - `C5_LIVE_AXIS=<name>` banner to the log
   - one injection via the pushed sender
   - `wmi_submitted` / `fw_completion_events` deltas exactly +1
   - drop-reason counters unchanged where the axis must not touch them
   - dmesg trace grep for the expected driver note
4. **restore** — managed mode back, restore gate, working-tree check.

## Judgement rules (from the permanent constraints)

- `status 0` = FW OK, `status 3` = no ACK; neither is proof of transmission.
  `UNPROVEN` is a legal verdict — never rerun to turn a PASS.
- AF_PACKET RX observation must drop `sll_pkttype == PACKET_OUTGOING`
  (TX loopback copies match injected vectors byte-for-byte).
- Completion metadata may be absent (second frame in a burst) — pair
  evidence via dmesg submit lines + ledger TSV instead.
- Crash mid-round: `wait_device_back`, boot gate, persona rebuild, then
  continue with the remaining axes; if the device does not return, abort.
- First-run settle race right after a flash is a known framework issue:
  one retry, then treat as real.

## Burst pacing (hard fact)

tx inflight defaults to 8 with a 64-entry queue on current builds, but a
single sender thread bursting harder than the completion rate will still
drop (queue-accept semantics hide it: `sendto` rc=0). Flood-style tools
MUST throttle by `wmi_submitted` delta or queue depth — see
`../tools/replay/README.md`.
