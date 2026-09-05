#!/usr/bin/env bash

# v13-specific probe battery: the audit-fix behaviors that v12c could not
# show. Runs AFTER stage1 (needs the phone idle-managed between suites).
#   1. mon0 add must be precisely refused by the new second-monitor gate
#      (mission mode, monitor persona active = the poison precondition).
#   2. sysfs numeric 320 ("5955 7"): passes the stock-validity check and
#      the reverted core gate -> firmware owns the verdict for the first
#      time; iw readback decides.
#   3. hop @320: parser accepts since v13 -> apply -> FW verdict; park
#      behavior observed. hop @160 as the working control.
#   4. spec-VHT vectors (bw 4/11/1) + non-spec bw 2 (must -EINVAL) +
#     MCS-20L (20 MHz) + MCS no-HAVE_BW (defaults 20) + mcs+he conflict +
#     VHT NSS 9 / HE MCS 12 / HE NSTS 9 truncation rejects: one injection
#     each with stats deltas as the driver-layer verdict.
#   5. survey sentinel gate: iw survey dump must show IN_USE (+noise) but
#     NOT garbage time/busy/tx (FW sentinel now suppressed).

set -uo pipefail

here=$(cd -- "$(dirname -- "$0")" && pwd)
kit=$here/../../suites/device-suite-wmi-full-frame-stage2
expected_build_id=4fe1c41102f473e85f1b68be7697409cad3787a1

serial=$(adb devices | awk '$2 == "device" {print $1}')
[ "$(printf '%s\n' "$serial" | wc -l)" -eq 1 ] || { echo "need exactly one device" >&2; exit 3; }
adb_cmd=(adb -s "$serial")
adb_shell() { "${adb_cmd[@]}" shell su -c "$1" </dev/null; }

note=$("${adb_cmd[@]}" exec-out su -c 'od -An -v -tx1 /sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id' | tr -d ' \r\n')
case $note in *"$expected_build_id"*) ;; *) echo "build id mismatch" >&2; exit 3 ;; esac

stamp=$(date -u +%Y%m%dT%H%M%SZ)
out=$here/host-capture-v13-probe-$stamp-$$
mkdir "$out"
echo "V13_PROBE_OUTPUT_DIR=$out"

remote=/data/local/tmp/qcacld-v13-probe-$$
adb_shell "mkdir -p $remote" || exit 3
"${adb_cmd[@]}" push "$kit/send_stage1_packet" "$remote/send_stage1_packet" \
	>"$out/push.log" 2>&1 || exit 3
adb_shell "chmod 0755 $remote/send_stage1_packet" || exit 3

# KernelSU debugfs mount dance
debugfs_type=$(adb_shell 'stat -f -c %T /sys/kernel/debug' | tr -d ' \r\n')
if [ "$debugfs_type" != 0x64626720 ] && [ "$debugfs_type" != debugfs ]; then
	adb_shell 'mount -t debugfs debugfs /sys/kernel/debug' >"$out/mount.log" 2>&1 || exit 3
fi
stats=/sys/kernel/debug/wlan0/frame_inject_stats
hop=/sys/kernel/debug/wlan0/frame_inject_channel_hop
sysfs_ch=/sys/class/net/wlan0/monitor_mode_channel

stat_value() { awk -F= -v key="$2" '$1 == key {print $2; exit}' "$1"; }
dmesg_mark() { adb_shell 'dmesg | wc -l' | tr -d '\r'; }
dmesg_since() { adb_shell "dmesg | tail -n +$(( $1 + 1 ))" 2>/dev/null | tr -d '\r' | head -40; }

adb_shell 'cmd wifi set-wifi-enabled disabled' >/dev/null 2>&1
settled=0
for _ in $(seq 1 60); do
	adb_shell 'cmd wifi status' 2>/dev/null | tr -d '\r' | grep -q '^Wifi is disabled$' && { settled=1; break; }
	sleep 1
done
[ "$settled" -eq 1 ] || { echo "wifi did not settle off" >&2; exit 4; }
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
adb_shell "test -r $stats" >/dev/null 2>&1 || { echo "stats unreadable" >&2; exit 3; }

echo '=== 1. mon0 add refusal (second-monitor gate) ==='
mark=$(dmesg_mark)
adb_shell 'iw dev wlan0 interface add mon0 type monitor' >"$out/mon0-add.log" 2>&1
echo "add_rc=$?" | tee -a "$out/mon0-add.log"
adb_shell 'iw dev mon0 info' >"$out/mon0-info.log" 2>&1
echo "mon0_exists_rc_present=$(grep -c 'Interface mon0' "$out/mon0-info.log" 2>/dev/null || true)" >>"$out/mon0-add.log"
dmesg_since "$mark" >"$out/mon0-dmesg.log"
grep -q 'second monitor interface refused' "$out/mon0-dmesg.log" && \
	echo "mon0_gate=REFUSED_WITH_MESSAGE" | tee -a "$out/summary.txt" || \
	echo "mon0_gate=NOT_TRIGGERED(rc?)" | tee -a "$out/summary.txt"

# --- injection helper: stats-delta verdict per vector ---
probe_vector() { # name hex expect(accept|reject)
	local name=$1 hex=$2 expect=$3 mark rc wmi0 fwc0 dr0 wmi1 fwc1 dr1 dropv
	mark=$(dmesg_mark)
	adb_shell "cat $stats" >"$out/stats-$name-before.txt"
	wmi0=$(stat_value "$out/stats-$name-before.txt" wmi_submitted)
	adb_shell "$remote/send_stage1_packet --send wlan0 $hex" >"$out/send-$name.log" 2>&1
	rc=$?
	sleep 2
	adb_shell "cat $stats" >"$out/stats-$name-after.txt"
	wmi1=$(stat_value "$out/stats-$name-after.txt" wmi_submitted)
	local verdict=UNEXPECTED
	if [ "$expect" = accept ] && [ $(( wmi1 - wmi0 )) -eq 1 ]; then verdict=OK_ACCEPT
	elif [ "$expect" = reject ] && [ "$wmi1" = "$wmi0" ]; then verdict=OK_REJECT
	fi
	echo "vec.$name expect=$expect wmi_delta=$(( wmi1 - wmi0 )) sendto_rc=$rc $verdict" | tee -a "$out/summary.txt"
	dmesg_since "$mark" | grep -iE 'frame_inject|drop|invalid|BW' | head -3 >"$out/dmesg-$name.log"
}

# 24-byte probe-request MPDU tail shared by all vectors below
MP='40000000ffffffffffff02abcd0000e1ffffffffffff0000'

echo '=== 4. spec-VHT / MCS-bw / conflict / truncation vectors ==='
probe_vector vht80_spec  "000014000000200040000000041300000000000040000000ffffffffffff02abcd0000e1ffffffffffff0000" accept
probe_vector vht160_spec "0000140000002000400000000b2800000000000040000000ffffffffffff02abcd0000e1ffffffffffff0000" accept
probe_vector vht40_spec  "000014000000200040000000012900000000000040000000ffffffffffff02abcd0000e1ffffffffffff0000" accept
probe_vector vht_bw2_nonspec "000014000000200040000000021300000000000040000000ffffffffffff02abcd0000e1ffffffffffff0000" reject
probe_vector mcs_20l_20mhz "00000b000000080003020040000000ffffffffffff02abcd0000e1ffffffffffff0000" accept
probe_vector mcs_nobw_defaults20 "00000b000000080002030040000000ffffffffffff02abcd0000e1ffffffffffff0000" accept
probe_vector vht_nss9_reject "000014000000200040000000049300000000000040000000ffffffffffff02abcd0000e1ffffffffffff0000" reject
probe_vector he_mcs12_reject "000014000000800020000000000c00000000000040000000ffffffffffff02abcd0000e1ffffffffffff0000" reject
probe_vector mcs_he_conflict "00001800000088000300000020400000000000000000000040000000ffffffffffff02abcd0000e1ffffffffffff0000" reject

echo '=== 2. sysfs numeric 320 ==='
mark=$(dmesg_mark)
adb_shell "echo '5955 7' > $sysfs_ch" >"$out/sysfs320.log" 2>&1
sleep 4
adb_shell 'iw dev wlan0 info' >"$out/iw-sysfs320.log" 2>&1
tr -d '\r' <"$out/iw-sysfs320.log" | grep -E 'channel|width' | tee -a "$out/summary.txt"
dmesg_since "$mark" >"$out/dmesg-sysfs320.log"
adb_shell 'iw dev wlan0 set freq 5745' >/dev/null 2>&1 || true

echo '=== 3. hop @320 / @160 control ==='
adb_shell "echo 'start 1500 5745@20 5955@320' > $hop" >"$out/hop320-write.log" 2>&1
echo "write_rc=$?" >>"$out/hop320-write.log"
sleep 6
adb_shell 'iw dev wlan0 info' >"$out/hop320-mid.log" 2>&1
adb_shell "cat $hop" >"$out/hop320-state.txt" 2>&1
adb_shell "echo stop > $hop" >/dev/null 2>&1
sleep 1
adb_shell "cat $hop" >>"$out/hop320-state.txt" 2>&1
grep -E 'active|hops|errors|last_error|last_width' "$out/hop320-state.txt" | tr -d '\r' | head -6 | tee -a "$out/summary.txt"
adb_shell 'iw dev wlan0 set freq 5745' >/dev/null 2>&1 || true

echo '=== 5. survey sentinel gate ==='
adb_shell 'iw dev wlan0 survey dump' >"$out/survey-dump.log" 2>&1
tr -d '\r' <"$out/survey-dump.log" | grep -E 'Survey|in use|noise|channel busy|extension|transmit' | head -10 | tee -a "$out/summary.txt"

# restore
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
adb_shell "rm -rf $remote" >/dev/null 2>&1 || true
[ "$restored" -eq 1 ] || { echo "WIFI RESTORE FAILED" >&2; exit 6; }
echo "v13_probe_complete=1 output=$out"
cat "$out/summary.txt"
