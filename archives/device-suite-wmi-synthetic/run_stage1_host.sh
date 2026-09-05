#!/usr/bin/env bash

set -uo pipefail

expected_build_id=d0f530a77c382b50e6bf298ce9cbf5eb26f6dd30
suite_frozen=1

usage()
{
	cat >&2 <<'EOF'
usage: run_stage1_host.sh [--serial SERIAL] --clean-boot
       --target-bssid BSSID --acknowledge-bounded-transmit

Runs six non-deauthentication frames in one monitor persona and verifies
target-beacon reception before, between, and after the two TX rounds.
EOF
	exit 2
}

serial=
target=
clean=false
ack=false
while [[ $# -gt 0 ]]; do
	case $1 in
	--serial) [[ $# -ge 2 ]] || usage; serial=$2; shift 2 ;;
	--target-bssid) [[ $# -ge 2 ]] || usage; target=${2,,}; shift 2 ;;
	--clean-boot) clean=true; shift ;;
	--acknowledge-bounded-transmit) ack=true; shift ;;
	*) usage ;;
	esac
done
[[ $clean == true && $ack == true && $target =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]] || usage
[[ $suite_frozen -eq 1 ]] || { echo "Stage 1 is not frozen" >&2; exit 4; }

dir=$(cd -- "$(dirname -- "$0")" && pwd)
device=$dir/run_stage1_device.sh
sender=$dir/send_stage1_once
manifest=$dir/SHA256SUMS
[[ -x $device && -x $sender && -r $manifest ]] || exit 3
(cd "$dir" && sha256sum -c SHA256SUMS) || exit 3
declare -a adb_cmd=(adb)
if [[ -n $serial ]]; then
	adb_cmd=(adb -s "$serial")
else
	mapfile -t devices < <(adb devices | awk '$2 == "device" {print $1}')
	[[ ${#devices[@]} -eq 1 ]] || exit 3
	serial=${devices[0]}
	adb_cmd=(adb -s "$serial")
fi
stamp=$(date -u +%Y%m%dT%H%M%SZ)
out=$dir/host-capture-stage1-v33-$stamp-$$
mkdir "$out" || exit 3
echo "HOST_OUTPUT_DIR=$out"

"${adb_cmd[@]}" shell su -c 'iw dev wlan0 info' >"$out/iw-before.log" 2>&1 || exit 5
before_ifindex=$("${adb_cmd[@]}" shell su -c 'cat /sys/class/net/wlan0/ifindex' | tr -d ' \r\n')
before_freq=$(sed -n 's/.*channel [0-9][0-9]* (\([0-9][0-9]*\) MHz).*/\1/p' "$out/iw-before.log" | head -n1)
before_width=$(sed -n 's/.*width: \([0-9][0-9]*\) MHz.*/\1/p' "$out/iw-before.log" | head -n1)
before_center=$(sed -n 's/.*center1: \([0-9][0-9]*\) MHz.*/\1/p' "$out/iw-before.log" | head -n1)
before_bssid=$("${adb_cmd[@]}" shell su -c 'iw dev wlan0 link' | tr -d '\r' | sed -n 's/^Connected to \([0-9a-fA-F:]*\) .*/\1/p' | head -n1)
boot_id=$("${adb_cmd[@]}" shell su -c 'cat /proc/sys/kernel/random/boot_id' | tr -d ' \r\n')
[[ -n $before_freq && -n $before_width && -n $before_center && -n $before_bssid ]] || exit 5

wait_recreated_persona()
{
	expected_type=$1
	old_ifindex=$2
	output_file=$3
	info=
	for ((attempt=0; attempt<100; attempt++)); do
		info=$("${adb_cmd[@]}" shell su -c 'iw dev wlan0 info' 2>&1 | tr -d '\r')
		current_type=$(sed -n 's/^[[:space:]]*type //p' <<<"$info" | head -n1)
		current_ifindex=$(sed -n 's/^[[:space:]]*ifindex //p' <<<"$info" | head -n1)
		if [[ $current_type == "$expected_type" && -n $current_ifindex &&
		      $current_ifindex != "$old_ifindex" ]]; then
			printf '%s\n' "$info" >"$output_file"
			return 0
		fi
		sleep 0.2
	done
	printf '%s\n' "$info" >"$output_file"
	return 1
}

restore()
{
	local restore_rc=0
	current_ifindex=$("${adb_cmd[@]}" shell su -c 'cat /sys/class/net/wlan0/ifindex' 2>/dev/null | tr -d ' \r\n')
	current_type=$("${adb_cmd[@]}" shell su -c 'iw dev wlan0 info' 2>/dev/null | tr -d '\r' | sed -n 's/^[[:space:]]*type //p' | head -n1)
	if [[ $current_type == monitor && -n $current_ifindex ]]; then
		"${adb_cmd[@]}" shell su -c 'iw dev wlan0 set type managed' >"$out/restore-managed.log" 2>&1 || restore_rc=1
		wait_recreated_persona managed "$current_ifindex" \
			"$out/restore-managed-info.log" || restore_rc=1
	else
		printf 'type=%s ifindex=%s; no monitor-to-managed request needed\n' \
			"$current_type" "$current_ifindex" >"$out/restore-managed.log"
	fi
	"${adb_cmd[@]}" shell su -c 'cmd wifi set-wifi-enabled enabled' >"$out/restore-wifi.log" 2>&1 || restore_rc=1
	wait_validated || restore_rc=1
	if [[ $debugfs_mounted_by_runner == true ]]; then
		"${adb_cmd[@]}" shell su -c 'umount /sys/kernel/debug' \
			>"$out/unmount-debugfs.log" 2>&1 || restore_rc=1
		debugfs_mounted_by_runner=false
	fi
	return "$restore_rc"
}
wait_validated()
{
	for ((attempt=0; attempt<120; attempt++)); do
		info=$("${adb_cmd[@]}" shell su -c 'iw dev wlan0 info' 2>/dev/null | tr -d '\r')
		wifi=$("${adb_cmd[@]}" shell su -c 'cmd wifi status' 2>/dev/null | tr -d '\r')
		if grep -q '^[[:space:]]*type managed$' <<<"$info" &&
		   grep -q 'VALIDATED' <<<"$wifi"; then
			printf '%s\n' "$info" >"$out/iw-restored.log"
			printf '%s\n' "$wifi" >"$out/wifi-restored.log"
			return 0
		fi
		sleep 0.25
	done
	return 1
}
debugfs_mounted_by_runner=false
debugfs_type=$("${adb_cmd[@]}" shell su -c 'stat -f -c %T /sys/kernel/debug' 2>/dev/null | tr -d ' \r\n')
if [[ $debugfs_type != 0x64626720 && $debugfs_type != debugfs ]]; then
	"${adb_cmd[@]}" shell su -c 'mount -t debugfs debugfs /sys/kernel/debug' \
		>"$out/mount-debugfs.log" 2>&1 || exit 6
	debugfs_mounted_by_runner=true
else
	printf 'debugfs already mounted; preserving existing mount\n' >"$out/mount-debugfs.log"
fi
trap restore EXIT HUP INT TERM

remote=/data/local/tmp/qcacld-v33-stage1-$stamp-$$
"${adb_cmd[@]}" shell su -c "mkdir -p '$remote'" || exit 5
"${adb_cmd[@]}" push "$device" "$remote/run_stage1_device.sh" >"$out/push-device.log" 2>&1 || exit 5
"${adb_cmd[@]}" push "$sender" "$remote/send_stage1_once" >"$out/push-sender.log" 2>&1 || exit 5
"${adb_cmd[@]}" shell su -c "chmod 0755 '$remote/'*" || exit 5
note=$("${adb_cmd[@]}" exec-out su -c 'od -An -v -tx1 /sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id' | tr -d ' \r\n')
[[ $note == *"$expected_build_id"* ]] || exit 5
"${adb_cmd[@]}" shell su -c 'cmd wifi set-wifi-enabled disabled' >"$out/disable-wifi.log" 2>&1 || exit 6
"${adb_cmd[@]}" shell su -c 'iw dev wlan0 set type monitor' >"$out/set-monitor.log" 2>&1 || exit 6
wait_recreated_persona monitor "$before_ifindex" "$out/monitor-info.log" || exit 6
: >"$out/set-channel.log"
channel_set=false
for ((i=1; i<=25; i++)); do
	printf 'attempt=%d\n' "$i" >>"$out/set-channel.log"
	if "${adb_cmd[@]}" shell su -c \
		"iw dev wlan0 set freq $before_freq $before_width $before_center" \
		>>"$out/set-channel.log" 2>&1; then
		channel_set=true
		break
	fi
	sleep 0.2
done
if [[ $channel_set != true ]]; then
	"${adb_cmd[@]}" shell su -c 'dmesg' >"$out/dmesg-channel-failure.log" 2>&1 || true
	exit 6
fi
"${adb_cmd[@]}" shell su -c 'iw dev wlan0 info' >"$out/monitor-channel-info.log" 2>&1 || exit 6
grep -q "^[[:space:]]*channel .*($before_freq MHz), width: $before_width MHz, center1: $before_center MHz" \
	"$out/monitor-channel-info.log" || exit 6
monitor_stats=
for ((i=0; i<100; i++)); do
	monitor_stats=$("${adb_cmd[@]}" shell su -c \
		'cat /sys/kernel/debug/wlan0/frame_inject_stats' 2>&1 | tr -d '\r')
	if grep -qx 'state=ready' <<<"$monitor_stats"; then break; fi
	sleep 0.2
done
printf '%s\n' "$monitor_stats" >"$out/monitor-ready-stats.log"
grep -qx 'state=ready' <<<"$monitor_stats" || exit 6

timeout 180 "${adb_cmd[@]}" shell su -c "'$remote/run_stage1_device.sh' S --clean-boot --two-round-continuity '$remote/send_stage1_once' '$before_bssid' '$target'" >"$out/test.stdout" 2>"$out/test.stderr"
rc=$?
remote_out=$(sed -n 's/^OUTPUT_DIR=//p' "$out/test.stdout" | head -n1 | tr -d '\r')
[[ $remote_out == /data/local/tmp/qcacld-v33-stage1-* ]] || exit 7
"${adb_cmd[@]}" pull "$remote_out" "$out/device-output" >"$out/pull.log" 2>&1 || exit 7
[[ $rc -eq 0 ]] && grep -qx 'verdict=PASS' "$out/device-output/result.txt" || exit 8
restore
trap - EXIT HUP INT TERM
end_boot=$("${adb_cmd[@]}" shell su -c 'cat /proc/sys/kernel/random/boot_id' | tr -d ' \r\n')
[[ $end_boot == "$boot_id" ]] || exit 9
printf 'verdict=PASS\nboot_id=%s\ntarget_bssid=%s\n' "$boot_id" "$target" >"$out/host-result.txt"
exit 0
