#!/bin/bash
# ssr-watch - host-side watchdog for Wi-Fi SSR (subsystem restart).
#
# Watches adb liveness; when the device drops and comes back (SoC reset
# from an SSR/ramdump), it automatically:
#   1. pulls ramoops/pstore for forensics into an evidence dir,
#   2. rebuilds the monitor persona (`tools/device/mon up` + optional
#      hop preset re-arm),
# so long capture/injection sessions survive crashes with evidence.
#
# usage: ssr-watch.sh [--hop hop2g|hop5g|hop6g] [--once]
set -u
here=$(cd -- "$(dirname -- "$0")" && pwd)
repo=$(cd -- "$here/../.." && pwd)

hop_preset=
once=0
while [ $# -gt 0 ]; do
	case $1 in
	--hop) hop_preset=$2; shift 2 ;;
	--once) once=1; shift ;;
	*) echo "usage: ssr-watch.sh [--hop hop2g|hop5g|hop6g] [--once]" >&2; exit 2 ;;
	esac
done

stamp=$(date -u +%Y%m%dT%H%M%SZ)
out=$here/ssr-evidence-$stamp-$$
mkdir -p "$out"
echo "SSR_WATCH_OUT=$out"

pull_forensics()
{
	adb exec-out su -c 'ls /sys/fs/pstore' >"$out/pstore.list" 2>&1 || true
	for f in $(adb exec-out su -c 'ls /sys/fs/pstore' 2>/dev/null | tr -d '\r'); do
		adb exec-out su -c "cat /sys/fs/pstore/$f" >"$out/$f" 2>/dev/null || true
	done
	adb shell su -c 'cat /proc/last_kmsg' >"$out/last_kmsg" 2>/dev/null || true
	adb exec-out su -c 'od -An -v -tx1 /sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id' \
		>"$out/build-id.txt" 2>/dev/null || true
}

rebuild()
{
	echo "$(date -u +%FT%TZ) rebuilding persona after SSR" | tee -a "$out/watch.log"
	bash "$repo/tools/device/mon.sh" up >>"$out/watch.log" 2>&1
	[ -n "$hop_preset" ] && bash "$repo/tools/device/mon.sh" "$hop_preset" >>"$out/watch.log" 2>&1
}

state=up
while :; do
	if adb shell 'echo up' >/dev/null 2>&1; then
		if [ "$state" = down ]; then
			echo "$(date -u +%FT%TZ) device back" | tee -a "$out/watch.log"
			sleep 20   # boot settle
			pull_forensics
			rebuild
			state=up
			[ "$once" = 1 ] && { echo "one recovery done (--once)"; exit 0; }
		fi
	else
		if [ "$state" = up ]; then
			echo "$(date -u +%FT%TZ) device dropped (SSR?)" | tee -a "$out/watch.log"
			state=down
		fi
	fi
	sleep 5
done
