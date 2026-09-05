#!/usr/bin/env bash

set -uo pipefail

expected_build_id=914714cb6f296f35f093bf393bfea47c4982897c
expected_source_rev=698efe09e8b8+dirty-20260906-observability-admin-knobs-v21
expected_selftests=409

usage()
{
	echo "usage: $0 [--serial SERIAL] --clean-boot --acknowledge-zero-tx" >&2
	exit 2
}

serial=
clean_boot=0
acknowledged=0
while [ "$#" -gt 0 ]; do
	case $1 in
	--serial) [ "$#" -ge 2 ] || usage; serial=$2; shift 2 ;;
	--clean-boot) clean_boot=1; shift ;;
	--acknowledge-zero-tx) acknowledged=1; shift ;;
	*) usage ;;
	esac
done
[ "$clean_boot" -eq 1 ] && [ "$acknowledged" -eq 1 ] || usage

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
device_script=$script_dir/run_stage0_preflight_device.sh
[ -r "$device_script" ] || exit 3
grep -qx 'device_execution_enabled=1' "$device_script" || exit 3
grep -qx "expected_build_id=$expected_build_id" "$device_script" || exit 3
grep -qx "expected_source_rev=$expected_source_rev" "$device_script" || exit 3
grep -qx "expected_selftests=$expected_selftests" "$device_script" || exit 3
command -v adb >/dev/null || exit 3
command -v timeout >/dev/null || exit 3

if [ -z "$serial" ]; then
	mapfile -t serials < <(adb devices | awk '$2 == "device" {print $1}')
	[ "${#serials[@]}" -eq 1 ] || exit 3
	serial=${serials[0]}
fi
adb_cmd=(adb -s "$serial")
[ "$("${adb_cmd[@]}" get-state 2>/dev/null)" = device ] || exit 3

stamp=$(date -u +%Y%m%dT%H%M%SZ)
host_out=$script_dir/host-capture-stage0-preflight-$stamp-$$
mkdir "$host_out" || exit 3
echo "HOST_OUTPUT_DIR=$host_out"
cp -p "$device_script" "$host_out/" || exit 3
sha256sum "$device_script" >"$host_out/input-SHA256SUMS" || exit 3

"${adb_cmd[@]}" shell su -c 'iw dev wlan0 info' >"$host_out/iw-before.log" 2>&1 || exit 4
before_type=$(sed -n 's/^[[:space:]]*type //p' "$host_out/iw-before.log" | tr -d '\r' | head -n 1)
before_freq=$(sed -n 's/.*channel [0-9][0-9]* (\([0-9][0-9]*\) MHz).*/\1/p' "$host_out/iw-before.log" | head -n 1)
before_width=$(sed -n 's/.*width: \([0-9][0-9]*\) MHz.*/\1/p' "$host_out/iw-before.log" | head -n 1)
before_center1=$(sed -n 's/.*center1: \([0-9][0-9]*\) MHz.*/\1/p' "$host_out/iw-before.log" | head -n 1)
[ -n "$before_freq" ] && [ -n "$before_width" ] && [ -n "$before_center1" ] || exit 4
# Wake the phone out of any WoW suspend before touching the persona: a
# session that starts immediately after a WoW resume can wedge the first
# monitor vdev-up in monitor_mode_vdev_up_in_progress (set freq EBUSY).
"${adb_cmd[@]}" shell su -c 'input keyevent KEYCODE_WAKEUP' >/dev/null 2>&1 || true
"${adb_cmd[@]}" shell su -c 'svc power stayon usb' >"$host_out/stayon.log" 2>&1 || true
sleep 3
"${adb_cmd[@]}" shell su -c 'cat /sys/class/net/wlan0/ifindex' >"$host_out/ifindex-before.log" 2>&1 || exit 4
before_ifindex=$(tr -d ' \r\n' <"$host_out/ifindex-before.log")
"${adb_cmd[@]}" shell su -c 'cat /proc/sys/kernel/random/boot_id' >"$host_out/boot-id-before.txt" || exit 4
"${adb_cmd[@]}" shell su -c 'cmd wifi status' >"$host_out/wifi-before.log" 2>&1 || exit 4
grep -q 'VALIDATED' "$host_out/wifi-before.log" || exit 4
"${adb_cmd[@]}" shell su -c 'dmesg' >"$host_out/dmesg-before-mode.log" 2>&1 || true

wait_persona()
{
	wanted=$1
	old_ifindex=$2
	output=$3
	info=
	for _ in $(seq 1 120); do
		info=$("${adb_cmd[@]}" shell su -c 'iw dev wlan0 info' 2>&1 | tr -d '\r')
		type=$(sed -n 's/^[[:space:]]*type //p' <<<"$info" | head -n 1)
		ifindex=$(sed -n 's/^[[:space:]]*ifindex //p' <<<"$info" | head -n 1)
		if [ "$type" = "$wanted" ] && [ -n "$ifindex" ] && [ "$ifindex" != "$old_ifindex" ]; then
			printf '%s\n' "$info" >"$output"
			return 0
		fi
		sleep 0.25
	done
	printf '%s\n' "$info" >"$output"
	return 1
}

wait_restore()
{
	info=
	status=
	for _ in $(seq 1 160); do
		info=$("${adb_cmd[@]}" shell su -c 'iw dev wlan0 info' 2>&1 | tr -d '\r')
		status=$("${adb_cmd[@]}" shell su -c 'cmd wifi status' 2>&1 | tr -d '\r')
		if grep -q '^[[:space:]]*type managed$' <<<"$info" &&
		   grep -q '^[[:space:]]*ssid ' <<<"$info" &&
		   grep -q '^Wifi is enabled$' <<<"$status" &&
		   grep -q 'Wifi is connected to' <<<"$status" &&
		   grep -q 'VALIDATED' <<<"$status"; then
			printf '%s\n' "$info" >"$host_out/iw-restored.log"
			printf '%s\n' "$status" >"$host_out/wifi-restored.log"
			return 0
		fi
		sleep 0.25
	done
	printf '%s\n' "$info" >"$host_out/iw-restored.log"
	printf '%s\n' "$status" >"$host_out/wifi-restored.log"
	return 1
}

mounted_debugfs=0
debugfs_type=$("${adb_cmd[@]}" shell su -c 'stat -f -c %T /sys/kernel/debug' 2>/dev/null | tr -d ' \r\n')
if [ "$debugfs_type" != 0x64626720 ] && [ "$debugfs_type" != debugfs ]; then
	"${adb_cmd[@]}" shell su -c 'mount -t debugfs debugfs /sys/kernel/debug' >"$host_out/mount-debugfs.log" 2>&1 || exit 4
	mounted_debugfs=1
fi

restore_managed()
{
	rc=0
	current_ifindex=$("${adb_cmd[@]}" shell su -c 'cat /sys/class/net/wlan0/ifindex' 2>/dev/null | tr -d ' \r\n')
	current_type=$("${adb_cmd[@]}" shell su -c 'iw dev wlan0 info' 2>/dev/null | tr -d '\r' | sed -n 's/^[[:space:]]*type //p' | head -n 1)
	if [ "$current_type" = monitor ] && [ -n "$current_ifindex" ]; then
		"${adb_cmd[@]}" shell su -c 'iw dev wlan0 set type managed' >"$host_out/restore-managed.log" 2>&1 || rc=1
		wait_persona managed "$current_ifindex" "$host_out/restore-managed-info.log" || rc=1
	fi
	"${adb_cmd[@]}" shell su -c 'cmd wifi set-wifi-enabled enabled' >"$host_out/restore-wifi.log" 2>&1 || rc=1
	wait_restore || rc=1
	if [ "$mounted_debugfs" -eq 1 ]; then
		"${adb_cmd[@]}" shell su -c 'umount /sys/kernel/debug' >"$host_out/unmount-debugfs.log" 2>&1 || rc=1
	fi
	return "$rc"
}
trap restore_managed EXIT HUP INT TERM

"${adb_cmd[@]}" shell su -c 'cmd wifi set-wifi-enabled disabled' >"$host_out/disable-wifi.log" 2>&1 || exit 5
# The framework completes a Wi-Fi-off request asynchronously (observed:
# "Wifi turning off from UI" + supplicant exit + vdev destroy ~8 s after the
# disable command), which lands inside the monitor session and resets the
# injection context to disabled. Wait for the framework side to fully settle
# before touching the persona.
wifi_off_settled=0
# clean-boot note: a disable issued right after the framework finished
# (re)connecting can take well over 30 s to tear down; budget 60 s.
for _ in $(seq 1 120); do
	off_status=$("${adb_cmd[@]}" shell su -c 'cmd wifi status' 2>/dev/null | tr -d '\r')
	off_supp=$("${adb_cmd[@]}" shell su -c 'pidof wpa_supplicant' 2>/dev/null | tr -d '\r\n')
	if grep -q '^Wifi is disabled$' <<<"$off_status" && [ -z "$off_supp" ]; then
		wifi_off_settled=1
		break
	fi
	sleep 0.5
done
[ "$wifi_off_settled" -eq 1 ] || exit 5
"${adb_cmd[@]}" shell su -c 'test -e /sys/class/net/wlan0' || exit 5
if [ "$before_type" != monitor ]; then
	"${adb_cmd[@]}" shell su -c 'iw dev wlan0 set type monitor' >"$host_out/set-monitor.log" 2>&1 || exit 5
	wait_persona monitor "$before_ifindex" "$host_out/monitor-info.log" || exit 5
else
	cp "$host_out/iw-before.log" "$host_out/monitor-info.log"
fi
# The recreated monitor netdev inherits the link state of the powered-off
# framework era (DOWN). set freq returns EBUSY forever on a DOWN interface.
"${adb_cmd[@]}" shell su -c 'ip link set wlan0 up' >"$host_out/ifup-monitor.log" 2>&1 || exit 5

set_monitor_channel()
{
	for _ in $(seq 1 100); do
		if "${adb_cmd[@]}" shell su -c "iw dev wlan0 set freq $before_freq $before_width $before_center1" >>"$host_out/set-monitor-channel.log" 2>&1; then
			return 0
		fi
		sleep 0.2
	done
	return 1
}

channel_ready=0
set_monitor_channel && channel_ready=1
if [ "$channel_ready" -ne 1 ]; then
	# One bounded persona re-arm: clears a wedged monitor vdev-up flag left
	# by a choreography that started while the soc was still resuming.
	wedged_ifindex=$("${adb_cmd[@]}" shell su -c 'cat /sys/class/net/wlan0/ifindex' 2>/dev/null | tr -d ' \r\n')
	"${adb_cmd[@]}" shell su -c 'iw dev wlan0 set type managed' >>"$host_out/set-monitor.log" 2>&1 || true
	wait_persona managed "$wedged_ifindex" "$host_out/monitor-rearm-managed-info.log" || true
	managed_ifindex=$("${adb_cmd[@]}" shell su -c 'cat /sys/class/net/wlan0/ifindex' 2>/dev/null | tr -d ' \r\n')
	"${adb_cmd[@]}" shell su -c 'iw dev wlan0 set type monitor' >>"$host_out/set-monitor.log" 2>&1 || true
	wait_persona monitor "$managed_ifindex" "$host_out/monitor-rearm-info.log" || true
	"${adb_cmd[@]}" shell su -c 'ip link set wlan0 up' >>"$host_out/ifup-monitor.log" 2>&1 || true
	set_monitor_channel && channel_ready=1
fi
[ "$channel_ready" -eq 1 ] || exit 5

# OEM connectivity hooks can race a quick disable->monitor cycle; require the
# monitor persona to hold steady for 5 s before trusting it (bounded re-arms).
monitor_stable=0
for attempt in 1 2 3; do
	hold=1
	for _ in $(seq 1 10); do
		type_now=$("${adb_cmd[@]}" shell su -c 'iw dev wlan0 info' 2>/dev/null | tr -d '\r' |
			sed -n 's/^[[:space:]]*type //p' | head -n 1)
		[ "$type_now" = monitor ] || { hold=0; break; }
		sleep 0.5
	done
	if [ "$hold" -eq 1 ]; then
		monitor_stable=1
		break
	fi
	if [ "$attempt" -lt 3 ]; then
		"${adb_cmd[@]}" shell su -c 'cmd wifi set-wifi-enabled disabled' >/dev/null 2>&1 || true
		"${adb_cmd[@]}" shell su -c 'iw dev wlan0 set type monitor' >"$host_out/set-monitor.log" 2>&1 || true
		wait_persona monitor "$before_ifindex" "$host_out/monitor-info.log" || true
		"${adb_cmd[@]}" shell su -c "iw dev wlan0 set freq $before_freq $before_width $before_center1" >"$host_out/set-monitor-channel.log" 2>&1 || true
	fi
done
[ "$monitor_stable" -eq 1 ] || exit 5

ready_stats=
for _ in $(seq 1 100); do
	ready_stats=$("${adb_cmd[@]}" shell su -c 'cat /sys/kernel/debug/wlan0/frame_inject_stats' 2>&1 | tr -d '\r')
	if grep -qx 'state=ready' <<<"$ready_stats"; then
		printf '%s\n' "$ready_stats" >"$host_out/monitor-ready-stats.log"
		break
	fi
	sleep 0.2
done
grep -qx 'state=ready' <<<"$ready_stats" || exit 5

remote_script=/data/local/tmp/run_qcacld_stage0_preflight.sh
"${adb_cmd[@]}" push "$device_script" "$remote_script" >"$host_out/push.log" 2>&1 || exit 6
"${adb_cmd[@]}" shell su -c "chmod 0755 $remote_script" >"$host_out/chmod.log" 2>&1 || exit 6
loaded_note=$("${adb_cmd[@]}" exec-out su -c 'od -An -v -tx1 /sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id' | tr -d ' \r\n')
case $loaded_note in *"$expected_build_id"*) ;; *) exit 6 ;; esac

timeout 180 "${adb_cmd[@]}" shell su -c "$remote_script S --clean-boot --selftest-only" >"$host_out/test.stdout" 2>"$host_out/test.stderr"
test_rc=$?
echo "$test_rc" >"$host_out/test.exit-code"
device_out=$(sed -n 's/^OUTPUT_DIR=//p' "$host_out/test.stdout" | head -n 1 | tr -d '\r')
case $device_out in /data/local/tmp/qcacld-stage0-preflight-*) ;; *) exit 7 ;; esac
"${adb_cmd[@]}" pull "$device_out" "$host_out/device-output" >"$host_out/pull.log" 2>&1 || exit 7
grep -qx 'verdict=PASS' "$host_out/device-output/result.txt" || exit 8
grep -qx "selftests=$expected_selftests" "$host_out/device-output/result.txt" || exit 8

restore_managed || exit 9
trap - EXIT HUP INT TERM
"${adb_cmd[@]}" shell su -c 'cat /proc/sys/kernel/random/boot_id' >"$host_out/boot-id-after.txt" || exit 9
cmp -s "$host_out/boot-id-before.txt" "$host_out/boot-id-after.txt" || exit 9
sha256sum "$host_out"/* "$host_out"/device-output/* >"$host_out/HOST_SHA256SUMS" 2>/dev/null
exit "$test_rc"
