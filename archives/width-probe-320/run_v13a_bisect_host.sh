#!/usr/bin/env bash

# FW RAMDUMP boundary bisect (post-v13a, one variable per boot).
#
# The 2026-09-05 v13 probe crashed the firmware (Q6 SYS ERROR -> RAMDUMP ->
# SoC panic) during vht160_nss2_mcs8 submission. Attribution was later
# corrected: three axes differed from the surviving vht80 control (bw/mcs/
# nss) AND our preamble mask pollution (OFDM|VHT may-choose-from) was live.
# v13a fixes the preamble semantics; this runner sends EXACTLY ONE vector
# per invocation so each boot can isolate one axis:
#   vht20    vht20_nss1_mcs3   (bw BIT(2) == 20MHz context) - pure-family probe
#   control  vht80_nss1_mcs3   (bw BIT(4), mcs BIT(3), nss BIT(0)) - CRASHED on v13a
#   nss      vht40_nss2_mcs9   (bw BIT(3), mcs BIT(9), nss BIT(1))
#   bwpure   vht160_nss1_mcs3  (ONLY bw differs from control)
#   killer   vht160_nss2_mcs8  (the original crash combination)
#   he160    he_mcs7_bw160_nsts1 (HE family, bw BIT(5))
# 2026-09-05: CONTROL (pure VHT + bw 80MHz > 20MHz context) already crashed
# the firmware on v13a, so the boundary hypothesis is "pure family preamble
# + bw_mask wider than the monitor context kills FW". VHT20 (bw == context)
# decides whether ANY pure-family rate request is usable at all.
# Crash-risk vectors must run LAST in their boot. Verdict = stats deltas
# (wmi_submitted / fw_completion_events); a reboot mid-run IS the boundary
# observation - the previous run's summary line tells which vector was live.

set -uo pipefail

here=$(cd -- "$(dirname -- "$0")" && pwd)
kit=$here/../../suites/device-suite-wmi-full-frame-stage2
expected_build_id=4c13f3b3f0b8f03d6904dd871af39164e18afa57
expected_src_rev=30442b8029b0+dirty-20260906-selftest-vht-vectors-v20a

usage()
{
	cat >&2 <<EOF
usage: run_v13a_bisect_host.sh --vector VHT20|HT20|HE20|CONTROL|NSS|BWPURE|KILLER|HE160
       [--frequency MHZ] [--width 40|80|160 --center MHZ]
       [--authorized-isolated-lab]
Boundary (2026-09-05, three crashes + one survivor): pure-family preamble
is only safe with bw_mask = BIT(2) (20 MHz); any wider bw bit crashed the
firmware at BOTH 20 MHz and 80 MHz helper contexts (width rule falsified).
Default context is a plain set-freq (20 MHz NOHT). --width/--center widen
the monitor chandef (helper vdev follows); final state is asserted by iw
readback (freq AND width).
EOF
	exit 2
}

vector_key=
frequency=5745
width=
center=
authorized=0
while [ "$#" -gt 0 ]; do
	case $1 in
	--vector) [ "$#" -ge 2 ] || usage; vector_key=$2; shift 2 ;;
	--frequency) [ "$#" -ge 2 ] || usage; frequency=$2; shift 2 ;;
	--width) [ "$#" -ge 2 ] || usage; width=$2; shift 2 ;;
	--center) [ "$#" -ge 2 ] || usage; center=$2; shift 2 ;;
	--authorized-isolated-lab) authorized=1; shift ;;
	*) usage ;;
	esac
done
[ "$authorized" -eq 1 ] && [ -n "$vector_key" ] || usage
if [ -n "$width" ]; then
	[ "$width" = 40 ] || [ "$width" = 80 ] || [ "$width" = 160 ] || usage
	[ -n "$center" ] || usage
else
	[ -z "$center" ] || usage
fi

# Vectors generated+asserted by gen_phy_vectors.py --bisect (2026-09-05);
# never hand-edit: radiotap VHT field is 12 bytes with spec bandwidth
# (0/1/4/11 = 20/40/80/160), HE data1=0x4020 (MCS+BW known), data3=MCS<<8,
# data5 low nibble = BW, data6 low nibble = NSTS.
case $vector_key in
VHT20)   hex="000014000000200040000000130000000000000040000000ffffffffffff02abcd0000f1ffffffffffff0000" ;;
HT20)    hex="00000b000000080003000040000000ffffffffffff02abcd0000f1ffffffffffff0000" ;;
HE20)    hex="000014000000800020400000000700000000010040000000ffffffffffff02abcd0000f1ffffffffffff0000" ;;
CONTROL) hex="000014000000200040000004130000000000000040000000ffffffffffff02abcd0000f1ffffffffffff0000" ;;
NSS)     hex="000014000000200040000001290000000000000040000000ffffffffffff02abcd0000f1ffffffffffff0000" ;;
BWPURE)  hex="00001400000020004000000b130000000000000040000000ffffffffffff02abcd0000f1ffffffffffff0000" ;;
KILLER)  hex="00001400000020004000000b280000000000000040000000ffffffffffff02abcd0000f1ffffffffffff0000" ;;
HE160)   hex="000014000000800020400000000700000300010040000000ffffffffffff02abcd0000f1ffffffffffff0000" ;;
*) usage ;;
esac

serial=$(adb devices | awk '$2 == "device" {print $1}')
[ "$(printf '%s\n' "$serial" | wc -l)" -eq 1 ] || { echo "need exactly one device" >&2; exit 3; }
adb_cmd=(adb -s "$serial")
# Every device call is bounded: a wedged adbd/su spawn must fail fast
# instead of hanging the whole runner (2026-09-05 HT20 restore incident).
adb_shell() { timeout 30 "${adb_cmd[@]}" shell su -c "$1" </dev/null; }

note=$("${adb_cmd[@]}" exec-out su -c 'od -An -v -tx1 /sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id' | tr -d ' \r\n')
case $note in *"$expected_build_id"*) ;; *) echo "build id mismatch (want v13a $expected_build_id)" >&2; exit 3 ;; esac

stamp=$(date -u +%Y%m%dT%H%M%SZ)
out=$here/host-capture-v13a-bisect-$vector_key-$stamp-$$
mkdir "$out"
echo "BISECT_OUTPUT_DIR=$out vector=$vector_key"

remote=/data/local/tmp/qcacld-bisect-$$
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
for _ in $(seq 1 60); do
	adb_shell 'cmd wifi status' 2>/dev/null | tr -d '\r' | grep -q '^Wifi is disabled$' && { settled=1; break; }
	sleep 1
done
[ "$settled" -eq 1 ] || { echo "wifi did not settle off" >&2; exit 4; }
if [ -n "$width" ]; then
	set_freq="iw dev wlan0 set freq $frequency $width $center"
else
	set_freq="iw dev wlan0 set freq $frequency"
fi
monitor_ready=0
for _ in $(seq 1 20); do
	adb_shell 'ip link set wlan0 down' >/dev/null 2>&1 || true
	adb_shell 'iw dev wlan0 set type monitor' >/dev/null 2>&1 || { sleep 1; continue; }
	adb_shell 'ip link set wlan0 up' >/dev/null 2>&1 || { sleep 1; continue; }
	adb_shell "$set_freq" >/dev/null 2>&1 || { sleep 1; continue; }
	# Assert the final state by readback (freq AND width) - a set that
	# silently fell back would fake a wide-context probe as narrow.
	adb_shell 'iw dev wlan0 info' >"$out/monitor-info.log" 2>&1
	info_freq=$(sed -n 's/.*channel [0-9][0-9]* (\([0-9][0-9]*\) MHz).*/\1/p' "$out/monitor-info.log" | head -n 1)
	info_width=$(sed -n 's/.*width: \([0-9][0-9]*\) MHz.*/\1/p' "$out/monitor-info.log" | head -n 1)
	[ "$info_freq" = "$frequency" ] || { sleep 1; continue; }
	[ "$info_width" = "${width:-20}" ] || { sleep 1; continue; }
	monitor_ready=1
	break
done
[ "$monitor_ready" -eq 1 ] || { echo "monitor setup failed (freq=$frequency width=${width:-20})" >&2; exit 4; }
adb_shell "test -r $stats" >/dev/null 2>&1 || { echo "stats unreadable" >&2; exit 3; }
adb_shell "cat $stats" >"$out/stats-before-persona.txt"

rev=$(stat_value "$out/stats-before-persona.txt" source_rev)
[ "$rev" = "$expected_src_rev" ] || { echo "SRC_REV mismatch: $rev" >&2; exit 3; }

adb_shell "cat $stats" >"$out/stats-before.txt"
wmi0=$(stat_value "$out/stats-before.txt" wmi_submitted)
fwc0=$(stat_value "$out/stats-before.txt" fw_completion_events)

# The send itself may crash the firmware; print the live-vector banner FIRST
# so a reboot mid-run identifies the boundary from console/prior stdout.
echo "BISECT_LIVE_VECTOR=$vector_key"
adb_shell "$remote/send_stage1_packet --send wlan0 $hex" >"$out/send.log" 2>&1
echo "send_rc=$?" >>"$out/send.log"
sleep 6
adb_shell "cat $stats" >"$out/stats-after.txt" 2>/dev/null || true
if [ -s "$out/stats-after.txt" ]; then
	wmi1=$(stat_value "$out/stats-after.txt" wmi_submitted)
	fwc1=$(stat_value "$out/stats-after.txt" fw_completion_events)
	echo "bisect.$vector_key wmi_delta=$(( wmi1 - wmi0 )) fw_completion_delta=$(( fwc1 - fwc0 ))"
else
	echo "bisect.$vector_key stats unreadable after send (crash/reboot?)"
fi

adb_shell 'iw dev wlan0 set freq 5745' >/dev/null 2>&1 || true
adb_shell 'cmd wifi set-wifi-enabled disabled' >/dev/null 2>&1
adb_shell 'ip link set wlan0 down' >/dev/null 2>&1 || true
adb_shell 'iw dev wlan0 set type managed' >/dev/null 2>&1 || true
adb_shell 'ip link set wlan0 up' >/dev/null 2>&1 || true
adb_shell 'cmd wifi set-wifi-enabled enabled' >/dev/null 2>&1
restored=0
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
[ "$restored" -eq 1 ] || { echo "WIFI RESTORE FAILED" >&2; exit 6; }
echo "bisect_complete=1 vector=$vector_key output=$out"
