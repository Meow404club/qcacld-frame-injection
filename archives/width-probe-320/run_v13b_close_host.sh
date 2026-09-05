#!/usr/bin/env bash

# v13b closing probes (2026-09-05): the two remaining width-verdict cells
# that the v13 320-gate fix unblocked, plus a survey sentinel readback.
#   1. sysfs numeric 320 ("5955 7") - stock-validity gate now passes, so
#      this measures the FIRMWARE's real 320 verdict for the first time.
#   2. channel-hop @320 ("start 600 5955@320 2412@20") - same unified apply
#      core via the scheduler; park-on-error must hold if FW refuses 320.
#   3. survey node snapshot in the monitor persona (sentinel-gate check:
#      busy garbage must stay absent).
# All injections in this script are legacy (no radiotap PHY family fields);
# the v13b fw_width gate is exercised elsewhere.

set -uo pipefail

here=$(cd -- "$(dirname -- "$0")" && pwd)
expected_build_id=4c13f3b3f0b8f03d6904dd871af39164e18afa57
expected_src_rev=30442b8029b0+dirty-20260906-selftest-vht-vectors-v20a

[ "${1:-}" = "--authorized-isolated-lab" ] || { echo "usage: $0 --authorized-isolated-lab" >&2; exit 2; }

serial=$(adb devices | awk '$2 == "device" {print $1}')
[ "$(printf '%s\n' "$serial" | wc -l)" -eq 1 ] || { echo "need exactly one device" >&2; exit 3; }
adb_cmd=(adb -s "$serial")
adb_shell() { timeout 30 "${adb_cmd[@]}" shell su -c "$1" </dev/null; }

note=$(adb_shell 'od -An -v -tx1 /sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id' | tr -d ' \r\n')
case $note in *"$expected_build_id"*) ;; *) echo "build id mismatch (want v13b)" >&2; exit 3 ;; esac

stamp=$(date -u +%Y%m%dT%H%M%SZ)
out=$here/host-capture-v13b-close-$stamp-$$
mkdir "$out"
echo "CLOSE_OUTPUT_DIR=$out"

sysfs_ch=/sys/class/net/wlan0/monitor_mode_channel
hop_node=/sys/kernel/debug/wlan0/frame_inject_channel_hop
survey_node=/sys/kernel/debug/wlan0/frame_inject_survey
stats=/sys/kernel/debug/wlan0/frame_inject_stats

debugfs_type=$(adb_shell 'stat -f -c %T /sys/kernel/debug' | tr -d ' \r\n')
if [ "$debugfs_type" != 0x64626720 ] && [ "$debugfs_type" != debugfs ]; then
	adb_shell 'mount -t debugfs debugfs /sys/kernel/debug' >"$out/mount.log" 2>&1 || exit 3
fi

cleanup()
{
	adb_shell 'echo stop > /sys/kernel/debug/wlan0/frame_inject_channel_hop' >/dev/null 2>&1 || true
	adb_shell 'cmd wifi set-wifi-enabled disabled' >/dev/null 2>&1
	adb_shell 'ip link set wlan0 down' >/dev/null 2>&1 || true
	adb_shell 'iw dev wlan0 set type managed' >/dev/null 2>&1 || true
	adb_shell 'ip link set wlan0 up' >/dev/null 2>&1 || true
	adb_shell 'cmd wifi set-wifi-enabled enabled' >/dev/null 2>&1
}
trap cleanup EXIT HUP INT TERM

dmesg_lines=$(adb_shell 'dmesg | wc -l' | tr -d ' \r')

# --- persona up @ 5745/20 (plain set-freq) ---------------------------------
adb_shell 'cmd wifi set-wifi-enabled disabled' >/dev/null 2>&1
settled=0
for _ in $(seq 1 60); do
	adb_shell 'cmd wifi status' 2>/dev/null | tr -d '\r' | grep -q '^Wifi is disabled$' && { settled=1; break; }
	sleep 1
done
[ "$settled" -eq 1 ] || { echo "wifi did not settle off" >&2; exit 4; }
ready=0
for _ in $(seq 1 20); do
	adb_shell 'ip link set wlan0 down' >/dev/null 2>&1 || true
	adb_shell 'iw dev wlan0 set type monitor' >/dev/null 2>&1 || { sleep 1; continue; }
	adb_shell 'ip link set wlan0 up' >/dev/null 2>&1 || { sleep 1; continue; }
	adb_shell 'iw dev wlan0 set freq 5745' >/dev/null 2>&1 || { sleep 1; continue; }
	ready=1
	break
done
[ "$ready" -eq 1 ] || { echo "monitor setup failed" >&2; exit 4; }
adb_shell "test -r $stats" >/dev/null 2>&1 || { echo "stats unreadable" >&2; exit 3; }
rev=$(adb_shell "cat $stats" | awk -F= '$1 == "source_rev" {print $2; exit}')
[ "$rev" = "$expected_src_rev" ] || { echo "SRC_REV mismatch: $rev" >&2; exit 3; }

# --- 1. sysfs numeric 320 ("5955 7") ---------------------------------------
echo "=== 1. sysfs numeric 320 (5955 7) ==="
adb_shell 'dmesg | tail -n +'$((dmesg_lines + 1)) >"$out/dmesg-prior.txt" 2>&1 || true
adb_shell "echo '5955 7' > $sysfs_ch" >"$out/sysfs320.log" 2>&1
sysfs320_rc=$?
adb_shell 'iw dev wlan0 info' >"$out/iw-sysfs320.log" 2>&1
sleep 2
adb_shell 'iw dev wlan0 info' >"$out/iw-sysfs320-settled.log" 2>&1
adb_shell 'dmesg | tail -n +'$((dmesg_lines + 1)) >"$out/dmesg-sysfs320.txt" 2>&1 || true
sysfs320_verdict=$(tr -d '\r' <"$out/iw-sysfs320-settled.log" | grep -E 'channel|width' | paste -sd' ' -)
sysfs320_fw=$(grep -E 'does not support|invalid|BW|320' "$out/dmesg-sysfs320.txt" | tail -n 3 | tr '\n' ';' | tr -d '\r')
echo "sysfs320_rc=$sysfs320_rc iw='$sysfs320_verdict' fw='$sysfs320_fw'"

# back to a known persona state before the hop probe
adb_shell 'iw dev wlan0 set freq 5745' >/dev/null 2>&1 || true

# --- 2. channel-hop @320 ----------------------------------------------------
echo "=== 2. hop @320 ==="
adb_shell "echo 'start 600 5955@320 2412@20' > $hop_node" >"$out/hop320-start.log" 2>&1
hop320_start_rc=$?
sleep 4
adb_shell "cat $hop_node" >"$out/hop320-state.log" 2>&1
hop_active=$(awk -F= '$1 == "active" {print $2}' "$out/hop320-state.log" | tail -n 1)
hop_hops=$(awk -F= '$1 == "hops" {print $2}' "$out/hop320-state.log" | tail -n 1)
hop_errors=$(awk -F= '$1 == "errors" {print $2}' "$out/hop320-state.log" | tail -n 1)
hop_last_freq=$(awk -F= '$1 == "last_freq" {print $2}' "$out/hop320-state.log" | tail -n 1)
adb_shell 'dmesg | tail -n 40' >"$out/dmesg-hop320.txt" 2>&1 || true
hop_park=$(grep -E 'parked|320' "$out/dmesg-hop320.txt" | tail -n 2 | tr '\n' ';' | tr -d '\r')
echo "hop320_start_rc=$hop320_start_rc active=$hop_active hops=$hop_hops errors=$hop_errors last_freq=$hop_last_freq park='$hop_park'"
adb_shell 'echo stop > /sys/kernel/debug/wlan0/frame_inject_channel_hop' >/dev/null 2>&1 || true

# --- 3. survey sentinel readback --------------------------------------------
echo "=== 3. survey node ==="
adb_shell "cat $survey_node" >"$out/survey-node.log" 2>&1
adb_shell 'iw dev wlan0 survey dump' >"$out/survey-dump.log" 2>&1
survey_busy=$(grep -c 'channel time busy' "$out/survey-dump.log" 2>/dev/null || true)
survey_inuse=$(grep -ci 'in use' "$out/survey-dump.log" 2>/dev/null || true)
echo "survey_busy_lines=$survey_busy survey_inuse=$survey_inuse"

echo "close_probe_complete=1 output=$out"
