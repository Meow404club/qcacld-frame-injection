#!/usr/bin/env bash

# Width probe round 2: completion timing on accepted 160 spans, the
# correct iw 5.16 `80+80` keyword, unfiltered dmesg for the sysfs width
# writes, and mid-hop iw readback (did the driver-computed center for an
# impossible 160 span silently downgrade?).

set -uo pipefail

here=$(cd -- "$(dirname -- "$0")" && pwd)
kit=$here/../../suites/device-suite-wmi-full-frame-stage2
expected_build_id=ec49943d8a798a4c10023378bf9059de9a28a67c

serial=$(adb devices | awk '$2 == "device" {print $1}')
[ "$(printf '%s\n' "$serial" | wc -l)" -eq 1 ] || { echo "need exactly one device" >&2; exit 3; }
adb_cmd=(adb -s "$serial")
adb_shell() { "${adb_cmd[@]}" shell su -c "$1" </dev/null; }

note=$("${adb_cmd[@]}" exec-out su -c 'od -An -v -tx1 /sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id' | tr -d ' \r\n')
case $note in *"$expected_build_id"*) ;; *) echo "build id mismatch" >&2; exit 3 ;; esac

stamp=$(date -u +%Y%m%dT%H%M%SZ)
out=$here/host-capture-width-probe2-$stamp-$$
mkdir "$out"
echo "WIDTH_PROBE2_OUTPUT_DIR=$out"

vector=00000c00068000000002180040000000ffffffffffff02abcd0000f2ffffffffffff7092000001018c

remote=/data/local/tmp/qcacld-width-probe2-$$
adb_shell "mkdir -p $remote" || exit 3
"${adb_cmd[@]}" push "$kit/send_stage1_packet" "$remote/send_stage1_packet" \
	>"$out/push.log" 2>&1 || exit 3
adb_shell "chmod 0755 $remote/send_stage1_packet" || exit 3

stats=/sys/kernel/debug/wlan0/frame_inject_stats
hop=/sys/kernel/debug/wlan0/frame_inject_channel_hop
sysfs_ch=/sys/class/net/wlan0/monitor_mode_channel

stat_value() { awk -F= -v key="$2" '$1 == key {print $2; exit}' "$1"; }
dump_stats() { adb_shell "cat $stats" | tr -d '\r'; }

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
adb_shell "test -r $stats" >/dev/null 2>&1 || { echo "stats node unreadable" >&2; exit 3; }

set_width_case() { # name set_cmd expect_freq expect_width
	local name=$1 set_cmd=$2 expect_freq=$3 expect_width=$4
	local rc wmi0 fwc0 wt0 dr0
	dump_stats >"$out/stats-$name-before.txt"
	wmi0=$(stat_value "$out/stats-$name-before.txt" wmi_submitted)
	fwc0=$(stat_value "$out/stats-$name-before.txt" fw_completion_events)
	wt0=$(stat_value "$out/stats-$name-before.txt" watchdog_timeouts)
	dr0=$(stat_value "$out/stats-$name-before.txt" drop_reason_timeout)
	eval "$set_cmd" >"$out/set-$name.log" 2>&1
	rc=$?
	adb_shell 'iw dev wlan0 info' >"$out/iw-$name.log" 2>&1
	adb_shell "dmesg | tail -n 15" >"$out/dmesg-$name.log" 2>&1
	if tr -d '\r' <"$out/iw-$name.log" | grep -q "($expect_freq MHz)" && \
		tr -d '\r' <"$out/iw-$name.log" | grep -q "width: $expect_width MHz"; then
		adb_shell "$remote/send_stage1_packet --send wlan0 $vector" \
			>"$out/inject-$name.log" 2>&1
		sleep 6
		dump_stats >"$out/stats-$name-after6s.txt"
		sleep 6
		dump_stats >"$out/stats-$name-after12s.txt"
		local wmi1 fwc1 wt1 dr1
		wmi1=$(stat_value "$out/stats-$name-after12s.txt" wmi_submitted)
		fwc1=$(stat_value "$out/stats-$name-after12s.txt" fw_completion_events)
		wt1=$(stat_value "$out/stats-$name-after12s.txt" watchdog_timeouts)
		dr1=$(stat_value "$out/stats-$name-after12s.txt" drop_reason_timeout)
		echo "$name: set_rc=$rc width_ok=1 wmi_delta=$((wmi1 - wmi0))" \
			"fw_completion_delta=$((fwc1 - fwc0)) watchdog_delta=$((wt1 - wt0))" \
			"drop_timeout_delta=$((dr1 - dr0))" | tee -a "$out/summary.txt"
	else
		echo "$name: set_rc=$rc width_ok=0 (readback below)" | tee -a "$out/summary.txt"
		tr -d '\r' <"$out/iw-$name.log" | grep -E 'channel|width' | tee -a "$out/summary.txt"
	fi
	adb_shell 'iw dev wlan0 set freq 5745' >/dev/null 2>&1 || true
}

set_width_case 5g160_span2 "adb_shell 'iw dev wlan0 set freq 5500 160 5580'" 5500 160
set_width_case 6g160       "adb_shell 'iw dev wlan0 set freq 5955 160 6025'" 5955 160
set_width_case 5g80p80_kw  "adb_shell 'iw dev wlan0 set freq 5180 80+80 5210 5530'" 5180 "80+80"
set_width_case 6g80p80_kw  "adb_shell 'iw dev wlan0 set freq 5955 80+80 5995 6155'" 5955 "80+80"

# sysfs numeric widths: unfiltered dmesg right after each write
for w in '5180 4:sysfs80p80' '5955 7:sysfs320' '5180 3:sysfs160'; do
	vals=${w%%:*}; name=${w##*:}
	adb_shell "echo '$vals' > $sysfs_ch" >"$out/set-$name.log" 2>&1
	echo "write_rc=$?" >>"$out/set-$name.log"
	sleep 2
	adb_shell 'iw dev wlan0 info' >"$out/iw-$name.log" 2>&1
	adb_shell "dmesg | tail -n 20" >"$out/dmesg-$name.log" 2>&1
	echo "== $name ($vals)" | tee -a "$out/summary.txt"
	tr -d '\r' <"$out/set-$name.log" | tee -a "$out/summary.txt"
	tr -d '\r' <"$out/iw-$name.log" | grep -E 'channel|width' | tee -a "$out/summary.txt"
	adb_shell 'iw dev wlan0 set freq 5745' >/dev/null 2>&1 || true
done

# mid-hop width readback: is the impossible 5745@160 span silently downgraded?
adb_shell "echo 'start 3000 5180@160 5745@160' > $hop" >"$out/hop-write.log" 2>&1
sleep 2
adb_shell 'iw dev wlan0 info' >"$out/hop-mid1.log" 2>&1
sleep 3
adb_shell 'iw dev wlan0 info' >"$out/hop-mid2.log" 2>&1
adb_shell "cat $hop" >"$out/hop-state.txt" 2>&1
adb_shell "echo stop > $hop" >/dev/null 2>&1
sleep 1
adb_shell "cat $hop" >>"$out/hop-state.txt" 2>&1

adb_shell 'iw dev wlan0 info' >"$out/iw-final.log" 2>&1

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
[ "$restored" -eq 1 ] || { echo "WIFI RESTORE FAILED; manual action required" >&2; exit 6; }
echo "width_probe2_complete=1 output=$out"
