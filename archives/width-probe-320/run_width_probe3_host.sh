#!/usr/bin/env bash

# Width probe round 3 (final gaps): 5G-160 completion timing with a long
# settle, and the iw 80+80 request with an enabled extension segment
# (5775) - the FW config max BW is 160 (not 80+80), so hdd_map_nl_chan_width
# remaps NL80211_CHAN_WIDTH_80P80 to CH_WIDTH_160MHZ; the readback decides
# whether that silent remap is observable.

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
out=$here/host-capture-width-probe3-$stamp-$$
mkdir "$out"
echo "WIDTH_PROBE3_OUTPUT_DIR=$out"

vector=00000c00068000000002180040000000ffffffffffff02abcd0000f3ffffffffffff7092000001018c

remote=/data/local/tmp/qcacld-width-probe3-$$
adb_shell "mkdir -p $remote" || exit 3
"${adb_cmd[@]}" push "$kit/send_stage1_packet" "$remote/send_stage1_packet" \
	>"$out/push.log" 2>&1 || exit 3
adb_shell "chmod 0755 $remote/send_stage1_packet" || exit 3

stats=/sys/kernel/debug/wlan0/frame_inject_stats
stat_value() { awk -F= -v key="$2" '$1 == key {print $2; exit}' "$1"; }

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

# --- 5G 160 (valid span 36-64) inject + long settle ---
adb_shell 'iw dev wlan0 set freq 5180 160 5250' >"$out/set-5g160.log" 2>&1
echo "set_rc=$?" >>"$out/set-5g160.log"
adb_shell 'iw dev wlan0 info' >"$out/iw-5g160.log" 2>&1
adb_shell "cat $stats" >"$out/stats-5g160-before.txt"
adb_shell "$remote/send_stage1_packet --send wlan0 $vector" >"$out/inject-5g160.log" 2>&1
sleep 12
adb_shell "cat $stats" >"$out/stats-5g160-after12s.txt"
wmi_delta=$(( $(stat_value "$out/stats-5g160-after12s.txt" wmi_submitted) -
	$(stat_value "$out/stats-5g160-before.txt" wmi_submitted) ))
fwc_delta=$(( $(stat_value "$out/stats-5g160-after12s.txt" fw_completion_events) -
	$(stat_value "$out/stats-5g160-before.txt" fw_completion_events) ))
wt_delta=$(( $(stat_value "$out/stats-5g160-after12s.txt" watchdog_timeouts) -
	$(stat_value "$out/stats-5g160-before.txt" watchdog_timeouts) ))
echo "5g160: wmi_delta=$wmi_delta fw_completion_delta=$fwc_delta watchdog_delta=$wt_delta" | tee "$out/summary.txt"
grep -E 'channel|width' "$out/iw-5g160.log" | tr -d '\r' | tee -a "$out/summary.txt"
adb_shell 'iw dev wlan0 set freq 5745' >/dev/null 2>&1 || true

# --- iw 80+80 with enabled extension segment (5775) ---
adb_shell 'iw dev wlan0 set freq 5180 80+80 5210 5775' >"$out/set-80p80ext.log" 2>&1
echo "set_rc=$?" >>"$out/set-80p80ext.log"
adb_shell 'iw dev wlan0 info' >"$out/iw-80p80ext.log" 2>&1
echo "80p80ext:" | tee -a "$out/summary.txt"
tr -d '\r' <"$out/set-80p80ext.log" | tee -a "$out/summary.txt"
grep -E 'channel|width|center' "$out/iw-80p80ext.log" | tr -d '\r' | tee -a "$out/summary.txt"
adb_shell "dmesg | tail -n 40" >"$out/dmesg-tail.log" 2>&1

adb_shell 'iw dev wlan0 set freq 5745' >/dev/null 2>&1 || true
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
echo "width_probe3_complete=1 output=$out"
