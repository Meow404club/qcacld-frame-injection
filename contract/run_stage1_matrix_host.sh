#!/usr/bin/env bash

set -uo pipefail

expected_build_id=4c13f3b3f0b8f03d6904dd871af39164e18afa57
expected_source_rev=30442b8029b0+dirty-20260906-selftest-vht-vectors-v20a
expected_common_image_sha256=e326bb0b475ed460a4639843c536e7702d5e17924c06e869acce501502910bd6
expected_common_build_id=5dd56a4fd3739bbee7c330af5e788a7ed1f0ad89
expected_plan_sha256=823900054cd3ee6dbce28875f73f28e78fea607de17da3385e78c8871abf263a
expected_sender_sha256=c2795e6b612c065fd464a97251276ad61c0f7a5484bd7d4767fdd882adc10afc
expected_device_cases=642
expected_total_cases=756

usage()
{
	echo "usage: $0 [--serial SERIAL] --target-bssid BSSID --authorized-isolated-lab" >&2
	exit 2
}

serial=
target_bssid=
authorized=0
while [ "$#" -gt 0 ]; do
	case $1 in
	--serial) [ "$#" -ge 2 ] || usage; serial=$2; shift 2 ;;
	--target-bssid) [ "$#" -ge 2 ] || usage; target_bssid=$2; shift 2 ;;
	--authorized-isolated-lab) authorized=1; shift ;;
	*) usage ;;
	esac
done
[ "$authorized" -eq 1 ] || usage
[[ "$target_bssid" =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ ]] || usage

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
device_script=$script_dir/run_stage1_matrix_device.sh
plan=$script_dir/stage1-device-plan.tsv
sender=$script_dir/send_stage1_packet
[ -r "$device_script" ] && [ -r "$plan" ] && [ -x "$sender" ] || exit 3
grep -qx 'device_execution_enabled=1' "$device_script" || exit 3
grep -qx "expected_build_id=$expected_build_id" "$device_script" || exit 3
grep -qx "expected_source_rev=$expected_source_rev" "$device_script" || exit 3
grep -qx "expected_plan_sha256=$expected_plan_sha256" "$device_script" || exit 3
grep -qx "expected_sender_sha256=$expected_sender_sha256" "$device_script" || exit 3
command -v adb >/dev/null || exit 3
command -v timeout >/dev/null || exit 3
command -v python3 >/dev/null || exit 3

if [ -z "$serial" ]; then
	mapfile -t serials < <(adb devices | awk '$2 == "device" {print $1}')
	[ "${#serials[@]}" -eq 1 ] || exit 3
	serial=${serials[0]}
fi
adb_cmd=(adb -s "$serial")
[ "$("${adb_cmd[@]}" get-state 2>/dev/null)" = device ] || exit 3

stamp=$(date -u +%Y%m%dT%H%M%SZ)
host_out=$script_dir/host-capture-stage1-4.1-$stamp-$$
mkdir "$host_out" || exit 3
echo "HOST_OUTPUT_DIR=$host_out"
cp -p "$device_script" "$plan" "$sender" "$host_out/"
sha256sum "$device_script" "$plan" "$sender" >"$host_out/input-SHA256SUMS"

adb_shell()
{
	"${adb_cmd[@]}" shell su -c "$1"
}

before_type=
before_freq=
before_width=
before_center1=
before_ifindex=
adb_shell 'iw dev wlan0 info' >"$host_out/iw-before.log" 2>&1 || exit 4
before_type=$(sed -n 's/^[[:space:]]*type //p' "$host_out/iw-before.log" | tr -d '\r' | head -n 1)
before_freq=$(sed -n 's/.*channel [0-9][0-9]* (\([0-9][0-9]*\) MHz).*/\1/p' "$host_out/iw-before.log" | head -n 1)
before_width=$(sed -n 's/.*width: \([0-9][0-9]*\) MHz.*/\1/p' "$host_out/iw-before.log" | head -n 1)
before_center1=$(sed -n 's/.*center1: \([0-9][0-9]*\) MHz.*/\1/p' "$host_out/iw-before.log" | head -n 1)
[ -n "$before_freq" ] && [ -n "$before_width" ] && [ -n "$before_center1" ] || exit 4
# Wake the phone out of any WoW suspend before touching the persona: a
# session that starts immediately after a WoW resume can wedge the first
# monitor vdev-up in monitor_mode_vdev_up_in_progress (set freq EBUSY).
adb_shell 'input keyevent KEYCODE_WAKEUP' >/dev/null 2>&1 || true
adb_shell 'svc power stayon usb' >"$host_out/stayon.log" 2>&1 || true
sleep 3
adb_shell 'cat /sys/class/net/wlan0/ifindex' >"$host_out/ifindex-before.log" 2>&1 || exit 4
before_ifindex=$(tr -d ' \r\n' <"$host_out/ifindex-before.log")
adb_shell 'cat /proc/sys/kernel/random/boot_id' >"$host_out/boot-id-before.txt" || exit 4
adb_shell 'cmd wifi status' >"$host_out/wifi-before.log" 2>&1 || exit 4
grep -q 'VALIDATED' "$host_out/wifi-before.log" || exit 4
adb_shell 'dmesg' >"$host_out/dmesg-before-host.log" 2>&1 || true

wait_persona()
{
	wanted=$1
	old_ifindex=$2
	output=$3
	info=
	for _ in $(seq 1 160); do
		info=$(adb_shell 'iw dev wlan0 info' 2>&1 | tr -d '\r')
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

wait_restore_wifi()
{
	info=
	status=
	for _ in $(seq 1 200); do
		info=$(adb_shell 'iw dev wlan0 info' 2>&1 | tr -d '\r')
		status=$(adb_shell 'cmd wifi status' 2>&1 | tr -d '\r')
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

stats_value()
{
	awk -F= -v key="$2" '$1 == key { print $2 }' "$1" | tail -n 1
}

dmesg_last_timestamp()
{
	sed -n 's/^\[[[:space:]]*\([0-9][0-9.]*\)\].*/\1/p' "$1" | tail -n 1
}

write_new_teardown_dmesg()
{
	baseline=$1
	input=$2
	output=$3
	if [ -n "$baseline" ]; then
		awk -v baseline="$baseline" \
			'{ match($0, /^\[[[:space:]]*([0-9][0-9.]*)\]/, m); \
			  if (m[1] != "" && (m[1] + 0) > (baseline + 0)) print }' \
			"$input" >"$output"
	else
		cp "$input" "$output"
	fi
}

mounted_debugfs=0
debugfs_type=$(adb_shell 'stat -f -c %T /sys/kernel/debug' 2>/dev/null | tr -d ' \r\n')
if [ "$debugfs_type" != 0x64626720 ] && [ "$debugfs_type" != debugfs ]; then
	adb_shell 'mount -t debugfs debugfs /sys/kernel/debug' >"$host_out/mount-debugfs.log" 2>&1 || exit 4
	mounted_debugfs=1
fi

restore_managed()
{
	# The EXIT trap re-enters this function after an early exit; never run
	# the restoration twice or it clobbers the teardown evidence snapshot.
	if [ -e "$host_out/.restore-done" ]; then
		return 0
	fi
	rc=0
	current_ifindex=$(adb_shell 'cat /sys/class/net/wlan0/ifindex' 2>/dev/null | tr -d ' \r\n')
	current_type=$(adb_shell 'iw dev wlan0 info' 2>/dev/null | tr -d '\r' | sed -n 's/^[[:space:]]*type //p' | head -n 1)
	if [ "$current_type" = monitor ] && [ -n "$current_ifindex" ]; then
		# The monitor-only debugfs node is removed when the persona changes.
		# Capture the final monitor snapshot before requesting managed mode;
		# disappearance of the node afterwards is expected teardown behavior.
		adb_shell 'cat /sys/kernel/debug/wlan0/frame_inject_stats' >"$host_out/teardown-stats.log" 2>&1 || rc=1
		adb_shell 'dmesg' >"$host_out/teardown-dmesg-before.log" 2>&1 || rc=1
		teardown_dmesg_baseline=$(dmesg_last_timestamp "$host_out/teardown-dmesg-before.log")
		adb_shell 'iw dev wlan0 set type managed' >"$host_out/restore-managed.log" 2>&1 || rc=1
		wait_persona managed "$current_ifindex" "$host_out/restore-managed-info.log" || rc=1
		teardown_delete_complete=0
		for _ in $(seq 1 100); do
			adb_shell 'dmesg' >"$host_out/teardown-dmesg-after.log" 2>&1 || true
			write_new_teardown_dmesg "$teardown_dmesg_baseline" \
				"$host_out/teardown-dmesg-after.log" \
				"$host_out/teardown-dmesg-new.log"
			if grep -q 'hdd_frame_inject_helper_vdev_delete_complete' \
				"$host_out/teardown-dmesg-new.log"; then
				teardown_delete_complete=1
				break
			fi
			sleep 0.2
		done
		# Missing delete-complete is legitimate in the auto-reclaim era: the
		# idle reclaim may have destroyed the helper before the persona
		# change, so there is nothing left for the persona teardown to
		# delete. The post-run teardown gates decide via the documented
		# final-snapshot fallback; this function only records the fact.
		printf 'teardown_delete_complete=%s\n' "$teardown_delete_complete" \
			>"$host_out/teardown-delete-complete.txt"
	else
		# Preserve a deterministic record for an already-managed/early-failure
		# path; no monitor debugfs snapshot exists in that persona.
		printf '%s\n' 'persona=managed_before_restore' >"$host_out/teardown-stats.log"
		printf 'teardown_delete_complete=na\n' >"$host_out/teardown-delete-complete.txt"
	fi
	adb_shell 'cmd wifi set-wifi-enabled enabled' >"$host_out/restore-wifi.log" 2>&1 || rc=1
	wait_restore_wifi || rc=1
	if [ "$mounted_debugfs" -eq 1 ]; then
		adb_shell 'umount /sys/kernel/debug' >"$host_out/unmount-debugfs.log" 2>&1 || rc=1
	fi
	: >"$host_out/.restore-done"
	return "$rc"
}
trap restore_managed EXIT HUP INT TERM

adb_shell 'cmd wifi set-wifi-enabled disabled' >"$host_out/disable-wifi.log" 2>&1 || exit 5
# Wait out the framework's asynchronous Wi-Fi-off completion (supplicant
# exit + persona teardown can land ~8 s after the disable command and would
# otherwise reset the injection context mid-run).
wifi_off_settled=0
for _ in $(seq 1 60); do
	off_status=$(adb_shell 'cmd wifi status' 2>/dev/null | tr -d '\r')
	off_supp=$(adb_shell 'pidof wpa_supplicant' 2>/dev/null | tr -d '\r\n')
	if grep -q '^Wifi is disabled$' <<<"$off_status" && [ -z "$off_supp" ]; then
		wifi_off_settled=1
		break
	fi
	sleep 0.5
done
[ "$wifi_off_settled" -eq 1 ] || exit 5
if [ "$before_type" != monitor ]; then
	adb_shell 'iw dev wlan0 set type monitor' >"$host_out/set-monitor.log" 2>&1 || exit 5
	wait_persona monitor "$before_ifindex" "$host_out/monitor-info.log" || exit 5
else
	cp "$host_out/iw-before.log" "$host_out/monitor-info.log"
fi
# The recreated monitor netdev inherits the link state of the powered-off
# framework era (DOWN). set freq returns EBUSY forever on a DOWN interface.
adb_shell 'ip link set wlan0 up' >"$host_out/ifup-monitor.log" 2>&1 || exit 5

set_monitor_channel()
{
	for _ in $(seq 1 100); do
		if adb_shell "iw dev wlan0 set freq $before_freq $before_width $before_center1" >>"$host_out/set-monitor-channel.log" 2>&1; then
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
	wedged_ifindex=$(adb_shell 'cat /sys/class/net/wlan0/ifindex' 2>/dev/null | tr -d ' \r\n')
	adb_shell 'iw dev wlan0 set type managed' >>"$host_out/set-monitor.log" 2>&1 || true
	wait_persona managed "$wedged_ifindex" "$host_out/monitor-rearm-managed-info.log" || true
	managed_ifindex=$(adb_shell 'cat /sys/class/net/wlan0/ifindex' 2>/dev/null | tr -d ' \r\n')
	adb_shell 'iw dev wlan0 set type monitor' >>"$host_out/set-monitor.log" 2>&1 || true
	wait_persona monitor "$managed_ifindex" "$host_out/monitor-rearm-info.log" || true
	adb_shell 'ip link set wlan0 up' >>"$host_out/ifup-monitor.log" 2>&1 || true
	set_monitor_channel && channel_ready=1
fi
[ "$channel_ready" -eq 1 ] || exit 5

# OEM connectivity hooks can race a quick disable->monitor cycle and flip the
# persona back to managed seconds into a run (observed as a mid-run
# "stats unavailable" failure). Require the monitor persona to hold steady for
# 5 s before starting the device run; re-arm on a flip, bounded to 3 attempts.
monitor_stable=0
for attempt in 1 2 3; do
	hold=1
	for _ in $(seq 1 10); do
		type_now=$(adb_shell 'iw dev wlan0 info' 2>/dev/null | tr -d '\r' |
			sed -n 's/^[[:space:]]*type //p' | head -n 1)
		[ "$type_now" = monitor ] || { hold=0; break; }
		sleep 0.5
	done
	if [ "$hold" -eq 1 ]; then
		monitor_stable=1
		break
	fi
	if [ "$attempt" -lt 3 ]; then
		adb_shell 'cmd wifi set-wifi-enabled disabled' >"$host_out/disable-wifi.log" 2>&1 || true
		adb_shell 'iw dev wlan0 set type monitor' >"$host_out/set-monitor.log" 2>&1 || true
		wait_persona monitor "$before_ifindex" "$host_out/monitor-info.log" || true
		adb_shell "iw dev wlan0 set freq $before_freq $before_width $before_center1" >"$host_out/set-monitor-channel.log" 2>&1 || true
	fi
done
[ "$monitor_stable" -eq 1 ] || exit 5

ready_stats=
for _ in $(seq 1 100); do
	ready_stats=$(adb_shell 'cat /sys/kernel/debug/wlan0/frame_inject_stats' 2>&1 | tr -d '\r')
	if grep -qx 'state=ready' <<<"$ready_stats"; then
		printf '%s\n' "$ready_stats" >"$host_out/monitor-ready-stats.log"
		break
	fi
	sleep 0.2
done
grep -qx 'state=ready' <<<"$ready_stats" || exit 5

remote_dir=/data/local/tmp/qcacld-stage1-4.1-$$
remote_script=$remote_dir/run_stage1_matrix_device.sh
remote_plan=$remote_dir/stage1-device-plan.tsv
remote_sender=$remote_dir/send_stage1_packet
adb_shell "mkdir -p $remote_dir" >"$host_out/remote-mkdir.log" 2>&1 || exit 6
"${adb_cmd[@]}" push "$device_script" "$remote_script" >"$host_out/push-runner.log" 2>&1 || exit 6
"${adb_cmd[@]}" push "$plan" "$remote_plan" >"$host_out/push-plan.log" 2>&1 || exit 6
"${adb_cmd[@]}" push "$sender" "$remote_sender" >"$host_out/push-sender.log" 2>&1 || exit 6
adb_shell "chmod 0755 $remote_script $remote_sender" >"$host_out/chmod.log" 2>&1 || exit 6
loaded_note=$("${adb_cmd[@]}" exec-out su -c 'od -An -v -tx1 /sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id' | tr -d ' \r\n')
case $loaded_note in *"$expected_build_id"*) ;; *) exit 6 ;; esac

timeout 1200 "${adb_cmd[@]}" shell su -c \
	"$remote_script --plan $remote_plan --sender $remote_sender --target-bssid $target_bssid --authorized-isolated-lab" \
	>"$host_out/test.stdout" 2>"$host_out/test.stderr"
test_rc=$?
echo "$test_rc" >"$host_out/test.exit-code"
device_out=$(sed -n 's/^OUTPUT_DIR=//p' "$host_out/test.stdout" | head -n 1 | tr -d '\r')
case $device_out in /data/local/tmp/qcacld-stage1-matrix-*) ;; *) exit 7 ;; esac
"${adb_cmd[@]}" pull "$device_out" "$host_out/device-output" >"$host_out/pull.log" 2>&1 || exit 7
grep -qx 'verdict=PASS' "$host_out/device-output/result.txt" || exit 8
grep -qx "device_cases=$expected_device_cases" "$host_out/device-output/result.txt" || exit 8

restore_managed || exit 9
trap - EXIT HUP INT TERM
"${adb_cmd[@]}" shell su -c 'cat /proc/sys/kernel/random/boot_id' >"$host_out/boot-id-after.txt" || exit 9
cmp -s "$host_out/boot-id-before.txt" "$host_out/boot-id-after.txt" || exit 9

# Teardown evidence contract (auto-reclaim era): either the classic firmware
# delete-complete at persona replacement, or a final monitor snapshot with no
# helper and a zero WMA owner ledger (the idle reclaim removed the helper
# before the persona change). Shared invariants hold for whichever snapshot
# documents the tier.
teardown_invariants()
{
	[ "$(stats_value "$1" format_version)" = 9 ] || return 1
	[ "$(stats_value "$1" source_rev)" = "$expected_source_rev" ] || return 1
	[ "$(stats_value "$1" fatal_latched)" = 0 ] || return 1
	[ "$(stats_value "$1" mgmt_inflight)" = 0 ] || return 1
	[ "$(stats_value "$1" queue_depth)" = 0 ] || return 1
	[ "$(stats_value "$1" active_request_id)" = 0 ] || return 1
	return 0
}
if grep -q '^teardown_delete_complete=1$' \
		"$host_out/teardown-delete-complete.txt"; then
	teardown_tier=delete_complete
	[ -s "$host_out/teardown-stats.log" ] || exit 9
	teardown_invariants "$host_out/teardown-stats.log" || exit 9
else
	teardown_tier=final_snapshot
	final_stats=$host_out/device-output/stats-final.log
	[ -s "$final_stats" ] || exit 9
	teardown_invariants "$final_stats" || exit 9
	[ "$(stats_value "$final_stats" helper_present)" = 0 ] || exit 9
	[ "$(stats_value "$final_stats" helper_wma_owner_mask)" = "0x0" ] || exit 9
fi
{
	echo "state=managed_persona_restored"
	echo "owner_zero=1"
	echo "teardown_tier=$teardown_tier"
	echo "stats_source=$([ "$teardown_tier" = delete_complete ] &&
		echo "$host_out/teardown-stats.log" ||
		echo "$final_stats")"
	echo "helper_delete_dmesg_sha256=$(sha256sum "$host_out/teardown-dmesg-new.log" | awk '{print $1}')"
	echo "wifi_status_sha256=$(sha256sum "$host_out/wifi-restored.log" | awk '{print $1}')"
} >"$host_out/teardown-evidence.txt"

python3 "$script_dir/device_results_to_evidence.py" \
	--manifest "$script_dir/stage1-cases.jsonl" \
	--device-results "$host_out/device-output/device-results.tsv" \
	--teardown-evidence "$host_out/teardown-evidence.txt" \
	--output "$host_out/stage1-device-evidence.jsonl" >"$host_out/evidence-conversion.log" 2>&1 || exit 10
grep -qx "device_evidence_conversion=PASS cases=$expected_total_cases" "$host_out/evidence-conversion.log" || exit 10
python3 "$script_dir/verify_stage1_evidence.py" \
	--manifest "$script_dir/stage1-cases.jsonl" \
	--results "$host_out/stage1-device-evidence.jsonl" \
	--enforce-current-parser >"$host_out/evidence-verification.log" 2>&1 || exit 10
grep -q '^evidence_verdict=PASS ' "$host_out/evidence-verification.log" || exit 10

sha256sum "$host_out"/input-SHA256SUMS "$host_out"/device-output/* \
	"$host_out"/stage1-device-evidence.jsonl "$host_out"/teardown-* >"$host_out/HOST_SHA256SUMS" 2>/dev/null
exit "$test_rc"
