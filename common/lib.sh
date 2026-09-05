#!/bin/bash
# common/lib.sh - shared helpers for the qcacld frame-injection suites.
#
# Source of truth for the patterns the archived one-shot rounds converged on
# (the converged device-round pattern). Every NEW runner sources this file instead
# of copying helpers. Legacy runners were migrated byte-identical and switch
# to this library at their next natural device round (zero-behavior-change
# migration: a runner is only migrated when its offline gate re-passes).
#
# Disciplines encoded here (violating them has cost device rounds before):
#   - adb shell compound commands can half-execute under su -c; run one
#     command per call, always with a timeout and stdin redirected.
#   - a Wi-Fi "disable" settings flip is NOT teardown: wait for
#     `pidof wpa_supplicant` to be empty (up to 60 s) before persona work.
#   - check persona liveness before every phase; rebuild if flipped.
#   - send one warm-up frame after helper rebuild before reading knobs.
#   - after a flash, the first framework-settle race is a known failure:
#     retry once instead of debugging.
#   - AF_PACKET captures loop TX copies back (PACKET_OUTGOING); RX
#     observation must filter sll_pkttype.

# adb_cmd may be pre-set by the caller (e.g. dryrun mock-bin PATH).
: "${adb_cmd:=adb}"

adb_shell()
{
	timeout 30 "${adb_cmd[@]}" shell su -c "$1" </dev/null
}

adb_exec_out()
{
	timeout 30 "${adb_cmd[@]}" exec-out su -c "$1" </dev/null
}

# key=value reader for driver debugfs TSVs
stat_value()
{
	awk -F= -v key="$2" '$1 == key {print $2; exit}' "$1"
}

# driver stats node (monitor persona only; mount debugfs if KernelSU hid it)
fi_stats_node=/sys/kernel/debug/wlan0/frame_inject_stats

mount_debugfs()
{
	local t
	t=$(adb_shell 'stat -f -c %T /sys/kernel/debug' | tr -d ' \r\n')
	if [ "$t" != 0x64626720 ] && [ "$t" != debugfs ]; then
		adb_shell 'mount -t debugfs debugfs /sys/kernel/debug'
	fi
}

# Module identity gate: refuses to run against any build but the pinned one.
pin_build_id()
{
	local expected=$1 note

	note=$(adb_exec_out 'od -An -v -tx1 /sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id' |
		tr -d ' \r\n')
	case $note in
	*"$expected"*) return 0 ;;
	*)
		echo "build id mismatch (want $expected, got ${note:-none})" >&2
		return 3
		;;
	esac
}

# Evidence directory skeleton: host-capture-<tag>-<utc-stamp>-<pid>
make_evidence_dir()
{
	local here=$1 tag=$2 stamp out

	stamp=$(date -u +%Y%m%dT%H%M%SZ)
	out=$here/host-capture-$tag-$stamp-$$
	mkdir "$out" || return 1
	echo "$out"
}

# Framework settle: wait for wpa_supplicant to leave before monitor persona.
wait_supplicant_gone()
{
	local budget=${1:-60} n=0

	while [ $n -lt "$budget" ]; do
		[ -z "$(adb_shell 'pidof wpa_supplicant' | tr -d ' \r\n')" ] && return 0
		sleep 1
		n=$((n + 1))
	done
	echo "wpa_supplicant still alive after ${budget}s" >&2
	return 4
}

persona_alive()
{
	adb_shell "test -d /sys/kernel/debug/wlan0" >/dev/null 2>&1
}

# Crash continuation: wait for the device to come back after an SSR reset.
wait_device_back()
{
	local tries=${1:-150} n=0

	while [ $n -lt "$tries" ]; do
		if adb_shell 'echo up' >/dev/null 2>&1; then
			# boot completed and module loaded?
			adb_shell 'test -d /sys/module/qca_cld3_peach_v2' >/dev/null 2>&1 && return 0
		fi
		sleep 2
		n=$((n + 1))
	done
	echo "device did not come back within $((tries * 2))s" >&2
	return 5
}

# Restore gate helper: managed mode back, connectivity re-check is the
# caller's job (environment dependent).
restore_managed()
{
	adb_shell 'cmd wifi set-wifi-enabled enabled' >/dev/null 2>&1 || true
}
