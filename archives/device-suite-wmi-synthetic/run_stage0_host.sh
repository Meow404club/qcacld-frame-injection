#!/usr/bin/env bash

set -uo pipefail

expected_build_id=d0f530a77c382b50e6bf298ce9cbf5eb26f6dd30
expected_selftests=293
suite_frozen=1

usage()
{
	echo "usage: $0 [--serial SERIAL] --clean-boot --acknowledge-read-only-selftest" >&2
	exit 2
}

serial=
clean_boot=false
acknowledged=false
while [[ "$#" -gt 0 ]]; do
	case "$1" in
		--serial)
			[[ "$#" -ge 2 && -n "$2" ]] || usage
			serial=$2
			shift 2
			;;
		--clean-boot) clean_boot=true; shift ;;
		--acknowledge-read-only-selftest) acknowledged=true; shift ;;
		*) usage ;;
	esac
done
[[ "$clean_boot" == true && "$acknowledged" == true ]] || usage

[[ "$suite_frozen" -eq 1 ]] || {
	echo "WMI synthetic Stage 0 is not frozen for host/device execution" >&2
	exit 4
}

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
device_script=$script_dir/run_stage0_device.sh
manifest=$script_dir/SHA256SUMS
[[ -r "$device_script" && -r "$manifest" ]] || exit 3
(cd "$script_dir" && sha256sum -c SHA256SUMS) || exit 3
grep -qx 'suite_frozen=1' "$device_script" || {
	echo "device-side WMI synthetic Stage 0 is not frozen" >&2
	exit 4
}
grep -qx "expected_build_id=$expected_build_id" "$device_script" || exit 3
command -v adb >/dev/null 2>&1 || exit 3
command -v timeout >/dev/null 2>&1 || exit 3

declare -a adb_cmd=(adb)
if [[ -n "$serial" ]]; then
	adb_cmd=(adb -s "$serial")
else
	mapfile -t serials < <(adb devices | awk '$2 == "device" { print $1 }')
	[[ "${#serials[@]}" -eq 1 ]] || {
		echo "exactly one authorized adb device is required" >&2
		exit 3
	}
	serial=${serials[0]}
	adb_cmd=(adb -s "$serial")
fi
[[ "$("${adb_cmd[@]}" get-state 2>/dev/null)" == device ]] || exit 3

stamp=$(date -u +%Y%m%dT%H%M%SZ)
host_out=$script_dir/host-capture-stage0-${stamp}-$$
mkdir "$host_out" || exit 3
echo "HOST_OUTPUT_DIR=$host_out"
cp -p "$device_script" "$manifest" "$host_out/" || exit 3

"${adb_cmd[@]}" shell su -c 'iw dev wlan0 info' >"$host_out/iw-before.log" 2>&1 || exit 6
before_type=$(tr -d '\r' <"$host_out/iw-before.log" | sed -n 's/^[[:space:]]*type //p' | head -n 1)
before_freq=$(tr -d '\r' <"$host_out/iw-before.log" | sed -n 's/.*channel [0-9][0-9]* (\([0-9][0-9]*\) MHz).*/\1/p' | head -n 1)
before_width=$(tr -d '\r' <"$host_out/iw-before.log" | sed -n 's/.*width: \([0-9][0-9]*\) MHz.*/\1/p' | head -n 1)
before_center1=$(tr -d '\r' <"$host_out/iw-before.log" | sed -n 's/.*center1: \([0-9][0-9]*\) MHz.*/\1/p' | head -n 1)
[[ -n "$before_freq" && -n "$before_width" && -n "$before_center1" ]] || exit 6
case "$before_width" in
	20|40|80|160) ;;
	*) echo "unsupported managed channel width: $before_width" >&2; exit 6 ;;
esac
"${adb_cmd[@]}" shell su -c 'cat /sys/class/net/wlan0/ifindex' >"$host_out/ifindex-before.log" 2>&1 || exit 6
before_ifindex=$(tr -d ' \r\n' <"$host_out/ifindex-before.log")
"${adb_cmd[@]}" shell su -c 'dmesg' >"$host_out/dmesg-before-mode.log" 2>&1 || true

wait_for_recreated_persona() {
	expected_type=$1
	old_ifindex=$2
	output_file=$3
	info=
	for ((attempt = 0; attempt < 100; attempt++)); do
		if info=$("${adb_cmd[@]}" shell su -c 'iw dev wlan0 info' 2>&1); then
			info=$(tr -d '\r' <<<"$info")
			current_type=$(sed -n 's/^[[:space:]]*type //p' <<<"$info" | head -n 1)
			current_ifindex=$(sed -n 's/^[[:space:]]*ifindex //p' <<<"$info" | head -n 1)
			if [[ "$current_type" == "$expected_type" &&
			      -n "$current_ifindex" &&
			      "$current_ifindex" != "$old_ifindex" ]]; then
				printf '%s\n' "$info" >"$output_file"
				return 0
			fi
		fi
		sleep 0.2
	done
	printf '%s\n' "$info" >"$output_file"
	return 1
}

wait_for_wifi_restore() {
	info=
	wifi_status=
	for ((attempt = 0; attempt < 120; attempt++)); do
		info=$("${adb_cmd[@]}" shell su -c 'iw dev wlan0 info' 2>&1 | tr -d '\r')
		wifi_status=$("${adb_cmd[@]}" shell su -c 'cmd wifi status' 2>&1 | tr -d '\r')
		if grep -q '^[[:space:]]*type managed$' <<<"$info" &&
		   grep -q '^[[:space:]]*ssid ' <<<"$info" &&
		   grep -q '^Wifi is enabled$' <<<"$wifi_status" &&
		   grep -q 'Wifi is connected to' <<<"$wifi_status" &&
		   grep -q 'VALIDATED' <<<"$wifi_status"; then
			printf '%s\n' "$info" >"$host_out/iw-restored.log"
			printf '%s\n' "$wifi_status" >"$host_out/wifi-restored.log"
			return 0
		fi
		sleep 0.25
	done
	printf '%s\n' "$info" >"$host_out/iw-restored.log"
	printf '%s\n' "$wifi_status" >"$host_out/wifi-restored.log"
	return 1
}

debugfs_mounted_by_runner=false
debugfs_type=$("${adb_cmd[@]}" shell su -c 'stat -f -c %T /sys/kernel/debug' 2>/dev/null | tr -d ' \r\n')
if [[ "$debugfs_type" != 0x64626720 && "$debugfs_type" != debugfs ]]; then
	"${adb_cmd[@]}" shell su -c 'mount -t debugfs debugfs /sys/kernel/debug' \
		>"$host_out/mount-debugfs.log" 2>&1 || exit 6
	debugfs_mounted_by_runner=true
else
	printf 'debugfs already mounted; preserving existing mount\n' \
		>"$host_out/mount-debugfs.log"
fi

restore_managed() {
	local restore_rc=0
	restore_ifindex=$("${adb_cmd[@]}" shell su -c 'cat /sys/class/net/wlan0/ifindex' 2>/dev/null | tr -d ' \r\n')
	restore_type=$("${adb_cmd[@]}" shell su -c 'iw dev wlan0 info' 2>/dev/null |
		tr -d '\r' | sed -n 's/^[[:space:]]*type //p' | head -n 1)
	if [[ "$restore_type" == monitor && -n "$restore_ifindex" ]]; then
		"${adb_cmd[@]}" shell su -c 'iw dev wlan0 set type managed' >"$host_out/restore-managed.log" 2>&1 || restore_rc=1
		wait_for_recreated_persona managed "$restore_ifindex" \
			"$host_out/restore-managed-info.log" || restore_rc=1
	else
		printf 'type=%s ifindex=%s; no monitor-to-managed request needed\n' \
			"$restore_type" "$restore_ifindex" >"$host_out/restore-managed.log"
	fi
	"${adb_cmd[@]}" shell su -c 'cmd wifi set-wifi-enabled enabled' >"$host_out/restore-wifi.log" 2>&1 || restore_rc=1
	wait_for_wifi_restore || restore_rc=1
	if [[ "$debugfs_mounted_by_runner" == true ]]; then
		"${adb_cmd[@]}" shell su -c 'umount /sys/kernel/debug' \
			>"$host_out/unmount-debugfs.log" 2>&1 || restore_rc=1
	fi
	return "$restore_rc"
}
trap restore_managed EXIT HUP INT TERM

# Match the Settings toggle. The framework operation is asynchronous; do
# not wait for all ClientModeManagers to disappear because that is precisely
# the point at which Android may unregister wlan0.
"${adb_cmd[@]}" shell su -c 'cmd wifi set-wifi-enabled disabled' >"$host_out/disable-wifi.log" 2>&1 || exit 6
"${adb_cmd[@]}" shell su -c 'test -e /sys/class/net/wlan0' >"$host_out/interface-preserved.log" 2>&1 || exit 6
if [[ "$before_type" != monitor ]]; then
	if ! "${adb_cmd[@]}" shell su -c 'iw dev wlan0 set type monitor' >"$host_out/set-monitor.log" 2>&1; then
		"${adb_cmd[@]}" shell su -c 'iw dev wlan0 info' >"$host_out/iw-mode-failure.log" 2>&1 || true
		"${adb_cmd[@]}" shell su -c 'cat /sys/class/net/wlan0/ifindex' >"$host_out/ifindex-mode-failure.log" 2>&1 || true
		"${adb_cmd[@]}" shell su -c 'dumpsys wifi' >"$host_out/dumpsys-wifi-mode-failure.log" 2>&1 || true
		"${adb_cmd[@]}" shell su -c 'dmesg' >"$host_out/dmesg-mode-failure.log" 2>&1 || true
		exit 6
	fi
	if ! wait_for_recreated_persona monitor "$before_ifindex" \
		"$host_out/monitor-info.log"; then
		"${adb_cmd[@]}" shell su -c 'dumpsys wifi' >"$host_out/dumpsys-wifi-mode-failure.log" 2>&1 || true
		"${adb_cmd[@]}" shell su -c 'dmesg' >"$host_out/dmesg-mode-failure.log" 2>&1 || true
		exit 6
	fi
	monitor_ready=true
else
	monitor_ready=false
fi
if [[ "$monitor_ready" == false ]]; then
	"${adb_cmd[@]}" shell su -c 'iw dev wlan0 info' >"$host_out/monitor-info.log" 2>&1 || exit 6
fi
grep -q '^[[:space:]]*type monitor$' "$host_out/monitor-info.log" || exit 6
if ! "${adb_cmd[@]}" shell su -c \
	"iw dev wlan0 set freq $before_freq $before_width $before_center1" \
	>"$host_out/set-monitor-channel.log" 2>&1; then
	"${adb_cmd[@]}" shell su -c 'dmesg' >"$host_out/dmesg-channel-failure.log" 2>&1 || true
	exit 6
fi
monitor_stats=
for ((attempt = 0; attempt < 100; attempt++)); do
	monitor_stats=$("${adb_cmd[@]}" shell su -c \
		'cat /sys/kernel/debug/wlan0/frame_inject_stats' 2>&1 | tr -d '\r')
	if grep -qx 'state=ready' <<<"$monitor_stats"; then
		printf '%s\n' "$monitor_stats" >"$host_out/monitor-ready-stats.log"
		break
	fi
	sleep 0.2
done
if ! grep -qx 'state=ready' <<<"$monitor_stats"; then
	printf '%s\n' "$monitor_stats" >"$host_out/monitor-ready-stats.log"
	"${adb_cmd[@]}" shell su -c 'dmesg' >"$host_out/dmesg-ready-failure.log" 2>&1 || true
	exit 6
fi
"${adb_cmd[@]}" shell su -c 'iw dev wlan0 info' >"$host_out/monitor-channel-info.log" 2>&1 || exit 6
grep -q "^[[:space:]]*channel .*($before_freq MHz), width: $before_width MHz, center1: $before_center1 MHz" \
	"$host_out/monitor-channel-info.log" || exit 6
"${adb_cmd[@]}" shell su -c \
	'cat /sys/module/qca_cld3_peach_v2/parameters/frame_inject_force_wmi' \
	>"$host_out/gates-before-selftest.log" 2>&1 || exit 6
[[ "$(tr -d ' \r\n' <"$host_out/gates-before-selftest.log")" == Y ]] || exit 6
remote_script=/data/local/tmp/run_qcacld_wmi_stage0.sh
"${adb_cmd[@]}" push "$device_script" "$remote_script" \
	>"$host_out/push.log" 2>&1 || exit 5
"${adb_cmd[@]}" shell su -c "chmod 0755 $remote_script" \
	>"$host_out/chmod.log" 2>&1 || exit 5
"${adb_cmd[@]}" shell su -c 'cat /proc/sys/kernel/random/boot_id' \
	>"$host_out/boot-id-before.txt" 2>"$host_out/boot-id-before.stderr" || exit 5
loaded_note=$("${adb_cmd[@]}" exec-out su -c \
	'od -An -v -tx1 /sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id' |
	tr -d ' \r\n')
[[ "$loaded_note" == *"$expected_build_id"* ]] || {
	echo "loaded module build-id mismatch" >&2
	exit 5
}

timeout 180 "${adb_cmd[@]}" shell su -c \
	"$remote_script S --clean-boot --selftest-only" \
	>"$host_out/test.stdout" 2>"$host_out/test.stderr"
test_rc=$?
echo "$test_rc" >"$host_out/test.exit-code"
device_out=$(sed -n 's/^OUTPUT_DIR=//p' "$host_out/test.stdout" |
	head -n 1 | tr -d '\r')
case "$device_out" in
	/data/local/tmp/qcacld-wmi-stage0-*-read-only-*) ;;
	*) echo "device runner did not report a valid output path" >&2; exit 6 ;;
esac
"${adb_cmd[@]}" pull "$device_out" "$host_out/device-output" \
	>"$host_out/pull.log" 2>&1 || exit 6
"${adb_cmd[@]}" shell su -c 'cat /proc/sys/kernel/random/boot_id' \
	>"$host_out/boot-id-after.txt" 2>"$host_out/boot-id-after.stderr" || exit 6
cmp -s "$host_out/boot-id-before.txt" "$host_out/boot-id-after.txt" || exit 7
grep -qx 'verdict=PASS' "$host_out/device-output/result.txt" || exit 8
grep -qx "selftests=$expected_selftests" "$host_out/device-output/result.txt" || exit 8
restore_managed || exit 9
trap - EXIT HUP INT TERM
"${adb_cmd[@]}" shell su -c 'cat /proc/sys/kernel/random/boot_id' \
	>"$host_out/boot-id-restored.txt" 2>"$host_out/boot-id-restored.stderr" || exit 9
cmp -s "$host_out/boot-id-before.txt" "$host_out/boot-id-restored.txt" || exit 9
exit "$test_rc"
