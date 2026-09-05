#!/usr/bin/env bash

# A-1 watchdog x retry envelope probe (todo 4.3 A-1, one vector per call).
#
# The 3000 ms completion watchdog vs the driver's own legal worst case:
# data_retries=126 -> 127 attempts x 2348 B at 1 Mbps on 2.4 GHz is
# ~18.8 ms airtime per attempt, ~2.4 s of pure airtime for the sequence
# before DIFS and growing contention windows. If the no-ACK completion
# arrives past 3000 ms the watchdog latches fatal, purges the queue and
# triggers recovery - a self-inflicted SSR for a request the driver
# itself accepted. This runner measures the real firmware behavior:
#
#   CONTROL   26 B deauth, 1 Mbps, attempts=1   (harness baseline)
#   LEN       2348 B deauth, attempts=1         (max-frame axis)
#   RETRIES   26 B deauth, attempts=127         (retry axis)
#   ENVELOPE  2348 B deauth, attempts=127       (self-harm candidate)
#
# All vectors are 2.4 GHz CCK (rate field 2 = 1 Mbps in 500 kb/s units,
# channel 2412 flags CCK|2GHZ) to a unicast RA nobody will ACK. Verdict
# is stats-based: watchdog_timeouts delta, fatal_latched, completion
# status and the wall time until mgmt_inflight clears (poll resolution
# ~0.2 s - good enough for the 2.4 s vs 3.0 s question). The envelope
# vector is the crash-risk item of the boot: print the banner first so
# a mid-run SSR identifies the live vector from prior stdout.

set -uo pipefail

here=$(cd -- "$(dirname -- "$0")" && pwd)
kit=$here/../../suites/device-suite-wmi-full-frame-stage2
expected_build_id=4c13f3b3f0b8f03d6904dd871af39164e18afa57
expected_src_rev=30442b8029b0+dirty-20260906-selftest-vht-vectors-v20a
expected_stats_format=12

usage()
{
	cat >&2 <<EOF
usage: run_a1_envelope_host.sh --vector CONTROL|LEN|RETRIES|ENVELOPE
       [--authorized-isolated-lab]
Measures the completion watchdog (3000 ms) against the legal worst-case
retry sequence (127 attempts x 2348 B x 1 Mbps, ~2.4 s pure airtime).
Run CONTROL/LEN/RETRIES first; ENVELOPE last in its boot. Verdict:
SAFE (completion beats the watchdog, margin reported) or
SELF_HARM_CONFIRMED (watchdog fired -> A-1 host fix is mandatory).
EOF
	exit 2
}

vector_key=
authorized=0
while [ "$#" -gt 0 ]; do
	case $1 in
	--vector) [ "$#" -ge 2 ] || usage; vector_key=$2; shift 2 ;;
	--authorized-isolated-lab) authorized=1; shift ;;
	*) usage ;;
	esac
done
[ "$authorized" -eq 1 ] && [ -n "$vector_key" ] || usage

# Generated + decode-asserted by gen_a1_vectors.py (2026-09-05); never
# hand-edit. Radiotap: RATE=1Mbps CHANNEL=2412/CCK|2GHZ [+DATA_RETRIES=126],
# MPDU = deauth to an absent unicast RA, 26 B or maximum 2348 B.
case $vector_key in
CONTROL)  hex=$(python3 "$here/gen_a1_vectors.py" control | cut -d= -f2) ;;
LEN)      hex=$(python3 "$here/gen_a1_vectors.py" len | cut -d= -f2) ;;
RETRIES)  hex=$(python3 "$here/gen_a1_vectors.py" retries | cut -d= -f2) ;;
ENVELOPE) hex=$(python3 "$here/gen_a1_vectors.py" envelope | cut -d= -f2) ;;
*) usage ;;
esac

serial=$(adb devices | awk '$2 == "device" {print $1}')
[ "$(printf '%s\n' "$serial" | wc -l)" -eq 1 ] || { echo "need exactly one device" >&2; exit 3; }
adb_cmd=(adb -s "$serial")
# Bounded device calls: a wedged adbd/su spawn fails fast instead of
# hanging the runner (2026-09-05 HT20 restore incident).
adb_shell() { timeout 30 "${adb_cmd[@]}" shell su -c "$1" </dev/null; }

note=$("${adb_cmd[@]}" exec-out su -c 'od -An -v -tx1 /sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id' | tr -d ' \r\n')
case $note in *"$expected_build_id"*) ;; *) echo "build id mismatch (want v14 $expected_build_id)" >&2; exit 3 ;; esac

stamp=$(date -u +%Y%m%dT%H%M%SZ)
out=$here/host-capture-a1-envelope-$vector_key-$stamp-$$
mkdir "$out"
echo "A1_OUTPUT_DIR=$out vector=$vector_key"

remote=/data/local/tmp/qcacld-a1-$$
adb_shell "mkdir -p $remote" || exit 3
"${adb_cmd[@]}" push "$kit/send_stage1_packet" "$remote/send_stage1_packet" >"$out/push.log" 2>&1 || exit 3
adb_shell "chmod 0755 $remote/send_stage1_packet" || exit 3

debugfs_type=$(adb_shell 'stat -f -c %T /sys/kernel/debug' | tr -d ' \r\n')
if [ "$debugfs_type" != 0x64626720 ] && [ "$debugfs_type" != debugfs ]; then
	adb_shell 'mount -t debugfs debugfs /sys/kernel/debug' >"$out/mount.log" 2>&1 || exit 3
fi
stats=/sys/kernel/debug/wlan0/frame_inject_stats

stat_value() { awk -F= -v key="$2" '$1 == key {print $2; exit}' "$1"; }

adb_shell 'cmd wifi set-wifi-enabled disabled' >/dev/null 2>&1
settled=0
for n in $(seq 1 60); do
	adb_shell 'cmd wifi status' 2>/dev/null | tr -d '\r' | grep -q '^Wifi is disabled$' && { settled=1; break; }
	sleep 1
done
[ "$settled" -eq 1 ] || { echo "wifi did not settle off" >&2; exit 4; }

monitor_ready=0
for n in $(seq 1 20); do
	adb_shell 'ip link set wlan0 down' >/dev/null 2>&1 || true
	adb_shell 'iw dev wlan0 set type monitor' >/dev/null 2>&1 || { sleep 1; continue; }
	adb_shell 'ip link set wlan0 up' >/dev/null 2>&1 || { sleep 1; continue; }
	adb_shell 'iw dev wlan0 set freq 2412' >/dev/null 2>&1 || { sleep 1; continue; }
	adb_shell 'iw dev wlan0 info' >"$out/monitor-info.log" 2>&1
	info_freq=$(sed -n 's/.*channel [0-9][0-9]* (\([0-9][0-9]*\) MHz).*/\1/p' "$out/monitor-info.log" | head -n 1)
	info_width=$(sed -n 's/.*width: \([0-9][0-9]*\) MHz.*/\1/p' "$out/monitor-info.log" | head -n 1)
	[ "$info_freq" = 2412 ] || { sleep 1; continue; }
	[ "$info_width" = 20 ] || { sleep 1; continue; }
	monitor_ready=1
	break
done
[ "$monitor_ready" -eq 1 ] || { echo "monitor setup failed (2412/20)" >&2; exit 4; }
adb_shell "test -r $stats" >/dev/null 2>&1 || { echo "stats unreadable" >&2; exit 3; }
adb_shell "cat $stats" >"$out/stats-before-persona.txt"
rev=$(stat_value "$out/stats-before-persona.txt" source_rev)
[ "$rev" = "$expected_src_rev" ] || { echo "SRC_REV mismatch: $rev" >&2; exit 3; }
fmt=$(stat_value "$out/stats-before-persona.txt" format_version)
[ "$fmt" = "$expected_stats_format" ] || { echo "stats format mismatch: $fmt (want $expected_stats_format)" >&2; exit 3; }

adb_shell "cat $stats" >"$out/stats-before.txt"
wmi0=$(stat_value "$out/stats-before.txt" wmi_submitted)
fwc0=$(stat_value "$out/stats-before.txt" fw_completion_events)
wdt0=$(stat_value "$out/stats-before.txt" watchdog_timeouts)
xd0=$(stat_value "$out/stats-before.txt" xmit_dropped)

echo "A1_LIVE_VECTOR=$vector_key (watchdog self-harm candidate: run last in its boot)"
t0=$(date +%s%3N)
adb_shell "$remote/send_stage1_packet --send wlan0 $hex" >"$out/send.log" 2>&1
echo "send_rc=$?" >>"$out/send.log"

# Poll until the request leaves mgmt_inflight (completion claimed it) or
# 25 s elapse. Each line is one stats observation; the first inflight=0
# line bounds the completion latency (resolution ~0.2 s, adb overhead).
# Polls use a shorter timeout than adb_shell: an SSR mid-envelope must
# not turn one wedged stats read into a 30 s stall per poll.
: >"$out/envelope-timeline.txt"
inflight_seen=0
latency_ms=
i=0
while [ $i -lt 90 ]; do
	snap=$(timeout 5 "${adb_cmd[@]}" shell su -c "cat $stats" </dev/null 2>/dev/null) || { echo "READ_FAIL poll=$i ms=$(( $(date +%s%3N) - t0 ))" >>"$out/envelope-timeline.txt"; break; }
	inflight=$(awk -F= '$1 == "mgmt_inflight" {print $2; exit}' <<<"$snap")
	wdt=$(awk -F= '$1 == "watchdog_timeouts" {print $2; exit}' <<<"$snap")
	fatal=$(awk -F= '$1 == "fatal_latched" {print $2; exit}' <<<"$snap")
	ms=$(( $(date +%s%3N) - t0 ))
	printf '%s %s %s %s %s\n' "$i" "$ms" "${inflight:-?}" "${wdt:-?}" "${fatal:-?}" >>"$out/envelope-timeline.txt"
	[ "${inflight:-1}" = 1 ] && inflight_seen=1
	if [ "$inflight_seen" -eq 1 ] && [ "${inflight:-1}" = 0 ]; then
		latency_ms=$ms
		break
	fi
	[ "${fatal:-0}" = 1 ] && break
	i=$((i + 1))
	sleep 0.15
done

adb_shell "cat $stats" >"$out/stats-after.txt" 2>/dev/null || true
adb_shell 'dmesg' >"$out/dmesg.txt" 2>/dev/null || true
submit_line=$(grep 'frame injection WMI RAW submit' "$out/dmesg.txt" | tail -n 1)
watchdog_line=$(grep 'completion watchdog expired' "$out/dmesg.txt" | tail -n 1)

if [ -s "$out/stats-after.txt" ]; then
	wmi1=$(stat_value "$out/stats-after.txt" wmi_submitted)
	fwc1=$(stat_value "$out/stats-after.txt" fw_completion_events)
	wdt1=$(stat_value "$out/stats-after.txt" watchdog_timeouts)
	xd1=$(stat_value "$out/stats-after.txt" xmit_dropped)
	fatal1=$(stat_value "$out/stats-after.txt" fatal_latched)
	status1=$(stat_value "$out/stats-after.txt" last_completion_status)
	retries1=$(stat_value "$out/stats-after.txt" last_completion_retries)
	echo "a1.$vector_key wmi_delta=$(( wmi1 - wmi0 )) fw_completion_delta=$(( fwc1 - fwc0 )) xmit_dropped_delta=$(( xd1 - xd0 ))"
	echo "a1.$vector_key watchdog_delta=$(( wdt1 - wdt0 )) fatal_latched=$fatal1 status=$status1 fw_retries=${retries1:-na} latency_ms=${latency_ms:-none}"
else
	echo "a1.$vector_key stats unreadable after send (SSR/reboot?)"
	fatal1=unknown
fi
[ -n "$submit_line" ] && echo "submit: $submit_line"
[ -n "$watchdog_line" ] && echo "watchdog: $watchdog_line"

verdict=UNDETERMINED
rc=5
if [ "${fatal1:-0}" = 1 ] || [ "${wdt1:-0}" -gt "${wdt0:-0}" ] 2>/dev/null || [ -n "$watchdog_line" ]; then
	verdict=SELF_HARM_CONFIRMED
	rc=7
elif [ -s "$out/stats-after.txt" ]; then
	if [ "$(( fwc1 - fwc0 ))" -eq 1 ] && [ "$(( wmi1 - wmi0 ))" -ge 1 ]; then
		case $status1 in
		0|3) verdict="SAFE (completion ${latency_ms:-?} ms vs 3000 ms watchdog)" ;;
		*) verdict="COMPLETED_UNEXPECTED_STATUS=$status1" ;;
		esac
		rc=0
	else
		verdict=NO_COMPLETION
		rc=5
	fi
fi
echo "a1_verdict=$verdict vector=$vector_key output=$out"

adb_shell 'cmd wifi set-wifi-enabled disabled' >/dev/null 2>&1
adb_shell 'ip link set wlan0 down' >/dev/null 2>&1 || true
adb_shell 'iw dev wlan0 set type managed' >/dev/null 2>&1 || true
adb_shell 'ip link set wlan0 up' >/dev/null 2>&1 || true
adb_shell 'cmd wifi set-wifi-enabled enabled' >/dev/null 2>&1
restored=0
status=
for n in $(seq 1 60); do
	status=$(adb_shell 'cmd wifi status' 2>/dev/null | tr -d '\r')
	if grep -q '^Wifi is enabled$' <<<"$status" && \
		grep -q 'Wifi is connected to' <<<"$status" && \
		grep -q 'VALIDATED' <<<"$status"; then
		restored=1
		break
	fi
	[ $(( n % 15 )) -eq 0 ] && echo "restore-wait $n/60 (wifi not reconnected yet)"
	sleep 1
done
printf '%s\n' "$status" >"$out/wifi-restored.log"
adb_shell "rm -rf $remote" >/dev/null 2>&1 || true
if [ "$restored" -eq 1 ]; then
	echo "a1_complete=1 vector=$vector_key verdict=$verdict"
else
	echo "WIFI RESTORE FAILED" >&2
	[ "$rc" -eq 0 ] && rc=6
fi
exit $rc
