#!/usr/bin/env bash

# Dedicated monitor-channel WIDTH probe (todo 4.1.1 width rows).
#
# Resolves the contradiction the audit found: records said "6G 160 FW
# refuse = OBS, 80P80 never on device, 320 precisely rejected" while
# iw phy advertises 160 (5G VHT/HE) and 320 (6G EHT). Source reading
# shows the unified chandef core gate `ch_width > CH_WIDTH_10MHZ`
# rejects 320 host-side on v12c (stock 11BE allowed >CH_WIDTH_320MHZ,
# i.e. 320 passed to FW), so this run measures the CURRENT build's
# live verdicts per width:
#   - iw set freq: 5G 160 (both spans), 6G 160 (v11 OBS retest),
#     5G/6G 80p80, iw-320 keyword (iw 5.16 may not know it)
#   - sysfs numeric width: 80P80=4, 320=7 (iw-independent path)
#   - hop parser width tokens: @160 / @80p80 / @320 (v12c table lacks
#     320 -> parse reject expected; source HEAD has the entry)
# Every accepted width gets one constructed-context probe-request
# injection with frame_inject_stats deltas as the driver-layer verdict.
# Independent-listener OTA is NOT claimed here (no listener); FW
# completion + iw readback are the evidence tiers recorded.

set -uo pipefail

here=$(cd -- "$(dirname -- "$0")" && pwd)
kit=$here/../../suites/device-suite-wmi-full-frame-stage2
expected_build_id=ec49943d8a798a4c10023378bf9059de9a28a67c

serial=$(adb devices | awk '$2 == "device" {print $1}')
[ "$(printf '%s\n' "$serial" | wc -l)" -eq 1 ] || { echo "need exactly one device" >&2; exit 3; }
adb_cmd=(adb -s "$serial")
adb_shell() { "${adb_cmd[@]}" shell su -c "$1" </dev/null; }

note=$("${adb_cmd[@]}" exec-out su -c 'od -An -v -tx1 /sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id' | tr -d ' \r\n')
case $note in *"$expected_build_id"*) ;; *)
	echo "build id mismatch" >&2; exit 3 ;; esac

stamp=$(date -u +%Y%m%dT%H%M%SZ)
out=$here/host-capture-width-probe-$stamp-$$
mkdir "$out"
echo "WIDTH_PROBE_OUTPUT_DIR=$out"

# device-proven P1 probe-request vector (radiotap 12B, 29B mpdu), SA
# rewritten to a locally-administered unique value for this run
vector=00000c00068000000002180040000000ffffffffffff02abcd0000f1ffffffffffff7092000001018c

adb_shell 'iw --version' >"$out/iw-version.txt" 2>&1
adb_shell 'iw phy' >"$out/iw-phy.txt" 2>&1
grep -E 'Band [0-9]|Supported Channel Width|320MHz in 6GHz|HE40/HE80|HE160' \
	"$out/iw-phy.txt" | tr -d '\r' >"$out/iw-phy-widths.txt" || true

remote=/data/local/tmp/qcacld-width-probe-$$
adb_shell "mkdir -p $remote" || exit 3
"${adb_cmd[@]}" push "$kit/send_stage1_packet" "$remote/send_stage1_packet" \
	>"$out/push.log" 2>&1 || exit 3
adb_shell "chmod 0755 $remote/send_stage1_packet" || exit 3

# debugfs stats node (KernelSU mount dance, mirrors the offense runner)
debug_root=/sys/kernel/debug
adb_shell "test -r $debug_root/wlan0/frame_inject_stats" >/dev/null 2>&1 || \
	debug_root=$(adb_shell 'cat /proc/mounts' | awk '$3 == "debugfs" {print $2; exit}' | tr -d '\r')
if [ -z "$debug_root" ]; then
	debugfs_type=$(adb_shell 'stat -f -c %T /sys/kernel/debug' 2>/dev/null | tr -d ' \r\n')
	if [ "$debugfs_type" != 0x64626720 ] && [ "$debugfs_type" != debugfs ]; then
		adb_shell 'mount -t debugfs debugfs /sys/kernel/debug' \
			>"$out/mount-debugfs.log" 2>&1 || { echo "debugfs mount failed" >&2; exit 3; }
	fi
	debug_root=/sys/kernel/debug
fi
stats=$debug_root/wlan0/frame_inject_stats
hop=$debug_root/wlan0/frame_inject_channel_hop
sysfs_ch=/sys/class/net/wlan0/monitor_mode_channel

stat_value() { awk -F= -v key="$2" '$1 == key {print $2; exit}' "$1"; }
dmesg_mark() { adb_shell 'dmesg | wc -l' | tr -d '\r'; }
dmesg_since() { # from-line
	adb_shell "dmesg | tail -n +$(( $1 + 1 ))" 2>/dev/null | tr -d '\r' | \
		grep -E 'invalid BW|does not support this BW|monitor|chandef|vdev up|frame_inject' || true
}

# managed framework off, then monitor persona
adb_shell 'cmd wifi set-wifi-enabled disabled' >/dev/null 2>&1
settled=0
for _ in $(seq 1 60); do
	adb_shell 'cmd wifi status' 2>/dev/null | tr -d '\r' | grep -q '^Wifi is disabled$' && { settled=1; break; }
	sleep 1
done
[ "$settled" -eq 1 ] || { echo "wifi framework did not settle off" >&2; exit 4; }

monitor_ready=0
for _ in $(seq 1 20); do
	adb_shell 'ip link set wlan0 down' >/dev/null 2>&1 || true
	adb_shell 'iw dev wlan0 set type monitor' >/dev/null 2>&1 || { sleep 1; continue; }
	adb_shell 'ip link set wlan0 up' >/dev/null 2>&1 || { sleep 1; continue; }
	adb_shell 'iw dev wlan0 set freq 5745' >/dev/null 2>&1 || { sleep 1; continue; }
	monitor_ready=1
	break
done
[ "$monitor_ready" -eq 1 ] || { echo "monitor setup failed" >&2; exit 4; }

# frame_inject_* debugfs nodes exist only under the monitor persona
adb_shell "test -r $stats" >/dev/null 2>&1 || { echo "stats node unreadable under monitor persona" >&2; exit 3; }

: >"$out/width-probe.tsv"
printf 'case\tset_cmd\tset_rc\treadback\tinjected\twmi_delta\tfw_completion_delta\tdrop_context_delta\tnote\n' \
	>"$out/width-probe.tsv"

run_case() { # name set_cmd expect_freq
	local name=$1 set_cmd=$2 expect_freq=$3
	local mark rc readback inject wmi0 fwc0 drop0 wmi1 fwc1 drop1 note
	mark=$(dmesg_mark)
	eval "$set_cmd" >"$out/set-$name.log" 2>&1
	rc=$?
	adb_shell 'iw dev wlan0 info' >"$out/iw-$name.log" 2>&1
	if tr -d '\r' <"$out/iw-$name.log" | grep -q "($expect_freq MHz)"; then
		readback=freq_ok
	elif tr -d '\r' <"$out/iw-$name.log" | grep -q 'type monitor'; then
		readback=freq_mismatch
	else
		readback=not_monitor
	fi
	inject=skip
	note=
	if [ "$readback" = freq_ok ]; then
		adb_shell "cat $stats" >"$out/stats-$name-before.txt"
		wmi0=$(stat_value "$out/stats-$name-before.txt" wmi_submitted)
		fwc0=$(stat_value "$out/stats-$name-before.txt" fw_completion_events)
		drop0=$(stat_value "$out/stats-$name-before.txt" drop_reason_context)
		adb_shell "$remote/send_stage1_packet --send wlan0 $vector" \
			>"$out/inject-$name.log" 2>&1
		sleep 2
		adb_shell "cat $stats" >"$out/stats-$name-after.txt"
		wmi1=$(stat_value "$out/stats-$name-after.txt" wmi_submitted)
		fwc1=$(stat_value "$out/stats-$name-after.txt" fw_completion_events)
		drop1=$(stat_value "$out/stats-$name-after.txt" drop_reason_context)
		inject=$(( wmi1 - wmi0 ))
		note="fw_completion_delta=$(( fwc1 - fwc0 )) drop_context_delta=$(( drop1 - drop0 ))"
	fi
	dmesg_since "$mark" >"$out/dmesg-$name.log"
	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
		"$name" "$set_cmd" "$rc" "$readback" "$inject" \
		"${wmi1:--}${wmi0:+/$wmi0}" "${fwc1:--}${fwc0:+/$fwc0}" \
		"${drop1:--}${drop0:+/$drop0}" "$note" >>"$out/width-probe.tsv"
	# leave the persona parked on a known-good 20 MHz channel
	adb_shell 'iw dev wlan0 set freq 5745' >/dev/null 2>&1 || true
}

run_case 5g160_dfs   "adb_shell 'iw dev wlan0 set freq 5180 160 5250'" 5180
run_case 5g160_upper "adb_shell 'iw dev wlan0 set freq 5745 160 5825'" 5745
run_case 6g160       "adb_shell 'iw dev wlan0 set freq 5955 160 6025'" 5955
run_case 5g80p80     "adb_shell 'iw dev wlan0 set freq 5180 80p80 5210 5530'" 5180
run_case 6g80p80     "adb_shell 'iw dev wlan0 set freq 5955 80p80 5995 6155'" 5955
run_case iw320_6g    "adb_shell 'iw dev wlan0 set freq 5955 320 6115'" 5955
run_case sysfs80p80  "adb_shell 'echo \"5180 4\" > $sysfs_ch'" 5180
run_case sysfs320_6g "adb_shell 'echo \"5955 7\" > $sysfs_ch'" 5955

# hop parser width tokens (v12c table: 20/40/80/160/80p80; 320 source-only)
hop_probe() { # name plan
	local name=$1 plan=$2 mark
	mark=$(dmesg_mark)
	adb_shell "echo 'start $plan' > $hop" >"$out/hop-$name-write.log" 2>&1
	echo "write_rc=$?" >>"$out/hop-$name-write.log"
	sleep 4
	adb_shell "cat $hop" >"$out/hop-$name-state.txt" 2>&1
	adb_shell "echo stop > $hop" >/dev/null 2>&1
	sleep 1
	adb_shell "cat $hop" >>"$out/hop-$name-state.txt" 2>&1
	dmesg_since "$mark" >"$out/hop-$name-dmesg.log"
}
hop_probe 160    '1500 5180@160 5745@160'
hop_probe 80p80 '1500 5180@80p80 5745@80'
hop_probe 320    '1500 5955@320 5745@80'

adb_shell 'iw dev wlan0 info' >"$out/iw-final.log" 2>&1

# restore managed Wi-Fi
adb_shell 'cmd wifi set-wifi-enabled disabled' >/dev/null 2>&1
adb_shell 'ip link set wlan0 down' >/dev/null 2>&1 || true
adb_shell 'iw dev wlan0 set type managed' >/dev/null 2>&1 || true
adb_shell 'ip link set wlan0 up' >/dev/null 2>&1 || true
adb_shell 'cmd wifi set-wifi-enabled enabled' >/dev/null 2>&1
restored=0
for _ in $(seq 1 200); do
	status=$(adb_shell 'cmd wifi status' 2>/dev/null | tr -d '\r')
	if grep -q '^Wifi is enabled$' <<<"$status" && \
		grep -q 'Wifi is connected to' <<<"$status" && \
		grep -q 'VALIDATED' <<<"$status"; then
		restored=1
		break
	fi
	sleep 1
done
printf '%s\n' "$status" >"$out/wifi-restored.log"
[ "$restored" -eq 1 ] || { echo "WIFI RESTORE FAILED; manual action required" >&2; exit 6; }

adb_shell "rm -rf $remote" >/dev/null 2>&1 || true
column -t -s $'\t' "$out/width-probe.tsv"
echo "width_probe_complete=1 output=$out"
