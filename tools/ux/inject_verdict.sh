#!/bin/bash
# inject-verdict - one-shot injection with completion verdict.
#
# Sends one frame (hex file or argument) through the pushed sender and
# reports the driver-ledger verdict: completion status 0 = FW OK,
# 3 = no ACK (neither proves transmission), or "none(yet)" if the
# completion ledger did not advance.
#
# usage: inject-verdict.sh HEX | inject-verdict.sh -f FILE.hex
set -u
here=$(cd -- "$(dirname -- "$0")" && pwd)
sender_src=$here/../../ota/kit/send_stage1_packet
remote=/data/local/tmp/fi-verdict-sender
stats=/sys/kernel/debug/wlan0/frame_inject_stats
comp=/sys/kernel/debug/wlan0/frame_inject_completions

hex=
case ${1:-} in
-f) hex=$(tr -d ' \r\n\t' <"$2") ;;
"") echo "usage: inject-verdict.sh HEX | -f FILE.hex" >&2; exit 2 ;;
*) hex=$(printf '%s' "$1" | tr -d ' \r\n\t') ;;
esac
[ -n "$hex" ] || { echo "empty hex" >&2; exit 2; }

adb push "$sender_src" "$remote" >/dev/null 2>&1 || { echo "push failed" >&2; exit 3; }
adb shell su -c "chmod 0755 $remote" >/dev/null 2>&1

if ! adb shell su -c "test -r $comp" >/dev/null 2>&1; then
	echo "monitor persona down (stats node absent): run mon up first" >&2
	exit 4
fi
before=$(adb exec-out su -c "cat $comp | tail -1" 2>/dev/null | tr -d '\r')
rc=$(adb shell su -c "$remote --send wlan0 $hex" >/dev/null 2>&1; echo $?)
# cold helper rebuild can take ~10 s before the first completion lands
after=
n=0
while [ $n -lt 30 ]; do
	sleep 0.5
	after=$(adb exec-out su -c "cat $comp | tail -1" 2>/dev/null | tr -d '\r')
	# accept only a real ledger row (the adapter can churn mid-poll and
	# turn reads into error text)
	case "$after" in
	[0-9]*)	[ "$after" != "$before" ] && break ;;
	esac
	n=$((n + 1))
done

echo "send rc=$rc"
if [ -n "$after" ] && [ "$after" != "$before" ]; then
	fields=$(printf '%s' "$after" | awk -F'\t' '{print "seq="$1" status="$3" ppdu="$8" rate_kbps="$9}')
	echo "verdict completion: $fields"
	case $(printf '%s' "$after" | awk -F'\t' '{print $3}') in
	0) echo "FW_OK (transmitted per FW; OTA authority = independent listener)" ;;
	3) echo "NO_ACK (transmitted, no acknowledgment - normal for forged broadcast)" ;;
	*) echo "status other than 0/3 - see stats node" ;;
	esac
else
	echo "verdict completion: none(yet) - check $stats drop_reason_* counters"
fi
