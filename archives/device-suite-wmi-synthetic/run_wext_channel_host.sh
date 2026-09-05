#!/usr/bin/env bash

set -uo pipefail
expected_build_id=6afcadef79c7a55d1f9b8c93b502d605ecc9f13e

[[ "$#" -eq 3 && "$1" == --serial && -n "$2" && "$3" == --acknowledge-mode-roundtrip ]] || {
	echo "usage: $0 --serial SERIAL --acknowledge-mode-roundtrip" >&2
	exit 2
}
serial=$2
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
probe=$script_dir/wext_freq_probe
[[ -x "$probe" ]] || exit 3
adb -s "$serial" get-state | grep -qx device || exit 3

stamp=$(date -u +%Y%m%dT%H%M%SZ)
host_out=$script_dir/host-capture-wext-$stamp-$$
mkdir "$host_out" || exit 3
echo "HOST_OUTPUT_DIR=$host_out"

adb -s "$serial" shell su -c 'iw dev wlan0 info' >"$host_out/iw-before.log" 2>&1 || exit 4
before_type=$(tr -d '\r' <"$host_out/iw-before.log" | sed -n 's/^[[:space:]]*type //p' | head -n 1)
before_freq=$(tr -d '\r' <"$host_out/iw-before.log" | awk '/channel / { value=$3; gsub(/[()]/, "", value); print value; exit }')
before_width=$(tr -d '\r' <"$host_out/iw-before.log" | awk '/channel / { print $6; exit }')
before_center1=$(tr -d '\r' <"$host_out/iw-before.log" | awk '/channel / { print $9; exit }')
[[ "$before_type" == managed && -n "$before_freq" && -n "$before_width" && -n "$before_center1" ]] || exit 4
before_ifindex=$(adb -s "$serial" shell su -c 'cat /sys/class/net/wlan0/ifindex' 2>/dev/null | tr -d ' \r\n')
boot_id=$(adb -s "$serial" shell su -c 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null | tr -d ' \r\n')
[[ -n "$before_ifindex" && -n "$boot_id" ]] || exit 4
adb -s "$serial" shell su -c 'dmesg' >"$host_out/dmesg-before.log" 2>&1 || true
loaded_note=$(adb -s "$serial" exec-out su -c \
	'od -An -v -tx1 /sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id' |
	tr -d ' \r\n')
[[ "$loaded_note" == *"$expected_build_id"* ]] || {
	echo "loaded module build-id mismatch" >&2
	exit 5
}

adb -s "$serial" push "$probe" /data/local/tmp/wext_freq_probe >"$host_out/push.log" 2>&1 || exit 5
adb -s "$serial" shell su -c 'chmod 0755 /data/local/tmp/wext_freq_probe' >"$host_out/chmod.log" 2>&1 || exit 5
adb -s "$serial" shell su -c '/data/local/tmp/wext_freq_probe get wlan0' >"$host_out/managed-wext-get.log" 2>&1
managed_get_rc=$?
echo "$managed_get_rc" >"$host_out/managed-wext-get.exit-code"
[[ "$managed_get_rc" -eq 0 ]] || exit 5
grep -q "mhz=$before_freq$" "$host_out/managed-wext-get.log" || exit 5

wait_for_persona()
{
	local expected_type=$1 old_ifindex=$2 output_file=$3 info= current_type= current_ifindex= attempt
	for ((attempt = 0; attempt < 100; attempt++)); do
		if info=$(adb -s "$serial" shell su -c 'iw dev wlan0 info' 2>&1); then
			info=$(tr -d '\r' <<<"$info")
			current_type=$(sed -n 's/^[[:space:]]*type //p' <<<"$info" | head -n 1)
			current_ifindex=$(sed -n 's/^[[:space:]]*ifindex //p' <<<"$info" | head -n 1)
			if [[ "$current_type" == "$expected_type" && -n "$current_ifindex" && "$current_ifindex" != "$old_ifindex" ]]; then
				printf '%s\n' "$info" >"$output_file"
				return 0
			fi
		fi
		sleep 0.2
	done
	printf '%s\n' "$info" >"$output_file"
	return 1
}

wait_for_restore()
{
	local info= wifi_status= attempt
	for ((attempt = 0; attempt < 120; attempt++)); do
		info=$(adb -s "$serial" shell su -c 'iw dev wlan0 info' 2>&1 | tr -d '\r')
		wifi_status=$(adb -s "$serial" shell su -c 'cmd wifi status' 2>&1 | tr -d '\r')
		if grep -q '^[[:space:]]*type managed$' <<<"$info" && grep -q '^[[:space:]]*ssid ' <<<"$info" && grep -q '^Wifi is enabled$' <<<"$wifi_status" && grep -q 'Wifi is connected to' <<<"$wifi_status" && grep -q 'VALIDATED' <<<"$wifi_status"; then
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

restore_managed()
{
	local restore_rc=0 restore_ifindex= restore_type=
	restore_ifindex=$(adb -s "$serial" shell su -c 'cat /sys/class/net/wlan0/ifindex' 2>/dev/null | tr -d ' \r\n')
	restore_type=$(adb -s "$serial" shell su -c 'iw dev wlan0 info' 2>/dev/null | tr -d '\r' | sed -n 's/^[[:space:]]*type //p' | head -n 1)
	if [[ "$restore_type" == monitor && -n "$restore_ifindex" ]]; then
		adb -s "$serial" shell su -c 'iw dev wlan0 set type managed' >"$host_out/restore-managed.log" 2>&1 || restore_rc=1
		wait_for_persona managed "$restore_ifindex" "$host_out/restore-managed-info.log" || restore_rc=1
	fi
	adb -s "$serial" shell su -c 'cmd wifi set-wifi-enabled enabled' >"$host_out/restore-wifi.log" 2>&1 || restore_rc=1
	wait_for_restore || restore_rc=1
	return "$restore_rc"
}
trap restore_managed EXIT HUP INT TERM

adb -s "$serial" shell su -c 'cmd wifi set-wifi-enabled disabled' >"$host_out/disable-wifi.log" 2>&1 || exit 6
adb -s "$serial" shell su -c 'test -e /sys/class/net/wlan0' >"$host_out/interface-preserved.log" 2>&1 || exit 6
adb -s "$serial" shell su -c 'iw dev wlan0 set type monitor' >"$host_out/set-monitor.log" 2>&1 || exit 6
wait_for_persona monitor "$before_ifindex" "$host_out/monitor-info.log" || exit 6

adb -s "$serial" shell su -c "iw dev wlan0 set freq $before_freq $before_width $before_center1" >"$host_out/set-monitor-original-chandef.log" 2>&1 || exit 7
adb -s "$serial" shell su -c 'iw dev wlan0 info' >"$host_out/monitor-before-wext.log" 2>&1 || exit 7
grep -q "^[[:space:]]*channel .*($before_freq MHz), width: $before_width MHz, center1: $before_center1 MHz" "$host_out/monitor-before-wext.log" || exit 7

adb -s "$serial" shell su -c '/data/local/tmp/wext_freq_probe get wlan0' >"$host_out/monitor-wext-get.log" 2>&1 || exit 8
grep -q "mhz=$before_freq$" "$host_out/monitor-wext-get.log" || exit 8
adb -s "$serial" shell su -c '/data/local/tmp/wext_freq_probe set-same wlan0' >"$host_out/monitor-wext-set-same.log" 2>&1 || exit 8
grep -q "operation=get-after-set-same .* mhz=$before_freq$" "$host_out/monitor-wext-set-same.log" || exit 8
adb -s "$serial" shell su -c 'iw dev wlan0 info' >"$host_out/monitor-after-wext.log" 2>&1 || exit 8
grep -q "^[[:space:]]*channel .*($before_freq MHz), width: $before_width MHz, center1: $before_center1 MHz" "$host_out/monitor-after-wext.log" || exit 8

adb -s "$serial" shell su -c 'cat /sys/module/qca_cld3_peach_v2/parameters/frame_inject_force_wmi' >"$host_out/gates.log" 2>&1 || exit 8
[[ "$(tr -d '\r' <"$host_out/gates.log")" == $'N\nN' ]] || exit 8
end_boot_id=$(adb -s "$serial" shell su -c 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null | tr -d ' \r\n')
[[ "$end_boot_id" == "$boot_id" ]] || exit 9
adb -s "$serial" shell su -c 'dmesg' >"$host_out/dmesg-after.log" 2>&1 || true

restore_managed || exit 10
trap - EXIT HUP INT TERM
restored_boot_id=$(adb -s "$serial" shell su -c 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null | tr -d ' \r\n')
[[ "$restored_boot_id" == "$boot_id" ]] || exit 10
{
	echo "verdict=PASS"
	echo "scope=wext-channel-get-set-same"
	echo "build_id=$expected_build_id"
	echo "managed_get_rc=$managed_get_rc"
	echo "frequency_mhz=$before_freq"
	echo "monitor_width_before_wext_mhz=$before_width"
	echo "monitor_width_after_wext_mhz=$before_width"
	echo "monitor_center1_before_wext_mhz=$before_center1"
	echo "monitor_center1_after_wext_mhz=$before_center1"
	echo "boot_id=$boot_id"
	echo "restored_boot_id=$restored_boot_id"
} >"$host_out/result.txt"
sha256sum "$host_out"/*.log "$host_out/result.txt" >"$host_out/SHA256SUMS"
exit 0
