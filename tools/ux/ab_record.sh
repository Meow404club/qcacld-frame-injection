#!/bin/bash
# ab-record - generic A/B phase evidence recorder.
#
# Runs a shell command twice (phase A then phase B) around a device knob
# the caller flips between them, snapshotting the driver stats node and
# dmesg tail into a timestamped evidence dir for each phase. Deltas are
# the caller's judgement call - this tool only guarantees identical
# capture shape per phase.
#
# usage: ab-record.sh --knob "adb-shell-write-cmd" --label NAME -- CMD...
#   The knob command is executed ONCE between phase A and phase B.
set -u
here=$(cd -- "$(dirname -- "$0")" && pwd)
stats=/sys/kernel/debug/wlan0/frame_inject_stats
knob=
label=ab
while [ $# -gt 0 ]; do
	case $1 in
	--knob) knob=$2; shift 2 ;;
	--label) label=$2; shift 2 ;;
	--) shift; break ;;
	*) echo "usage: ab-record.sh --knob CMD --label NAME -- CMD..." >&2; exit 2 ;;
	esac
done
[ $# -gt 0 ] || { echo "no command given" >&2; exit 2; }

snap()
{
	local phase=$1
	local d=$here/ab-$label-$stamp/$phase
	mkdir -p "$d"
	adb exec-out su -c "cat $stats" >"$d/stats.txt" 2>/dev/null
	adb exec-out su -c "cat /sys/kernel/debug/wlan0/frame_inject_completions" \
		>"$d/completions.tsv" 2>/dev/null
	adb shell su -c 'dmesg | tail -200' >"$d/dmesg-tail.txt" 2>/dev/null
	echo "$d"
}

stamp=$(date -u +%Y%m%dT%H%M%SZ)
echo "AB_RECORD_DIR=$here/ab-$label-$stamp-$$"

snap A
if [ -n "$knob" ]; then
	echo "== applying knob: $knob"
	adb shell su -c "$knob" || echo "knob rc=$? (nonzero - continuing)" >&2
fi
snap B

echo "== phase A command run"
"$@" >/dev/null
snap A2
echo "evidence under $here/ab-$label-$stamp-$$ (A, B, A2 snapshots + command between A2/B as arranged)"
