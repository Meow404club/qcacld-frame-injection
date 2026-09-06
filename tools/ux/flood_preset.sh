#!/bin/bash
# flood-preset - pacing-safe flood presets.
#
# Flood-style sends need two device-side tweaks plus batch discipline:
#   1. raise helper idle reclaim so the hidden-STA helper does not get
#      torn down mid-run (frame_inject_helper_idle_ms knob, ms),
#   2. keep --pps below the completion rate (queue-accept drops are
#      silent; see tools/replay/README.md).
# Restores the knob on exit (EXIT trap).
#
# usage: flood-preset.sh MODE COUNT PPS [extra mdk4_lite args...]
#   MODE: beacon-flood|probe-resp|eapol-flood|fuzz
set -u
here=$(cd -- "$(dirname -- "$0")" && pwd)
mode=${1:?mode}
count=${2:?count}
pps=${3:?pps}
shift 3
idle_node=/sys/kernel/debug/wlan0/frame_inject_helper_idle_ms
idle_boost=120000   # 120 s: survive a multi-minute flood without teardown

restore()
{
	adb shell su -c "echo 0 > $idle_node" >/dev/null 2>&1 || true
}
trap restore EXIT

prev=$(adb exec-out su -c "cat $idle_node" 2>/dev/null | tr -d '\r\n')
restore_prev()
{
	[ -n "$prev" ] && adb shell su -c "echo $prev > $idle_node" >/dev/null 2>&1 || true
}
trap restore_prev EXIT

adb shell su -c "echo $idle_boost > $idle_node" || { echo "idle knob write failed (persona up?)" >&2; exit 4; }
echo "helper idle boosted to ${idle_boost}ms (restores to '${prev:-0}' on exit)"

exec python3 "$here/../replay/mdk4_lite.py" "$mode" --count "$count" \
	--pps "$pps" --mode-out adb "$@"
