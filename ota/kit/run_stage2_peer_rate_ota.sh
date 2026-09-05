#!/usr/bin/env bash

set -uo pipefail

# Stage 2 peer-fixed-rate OTA session (kit v11, todo 4.3 C-5 listener leg).
#
# PRECONDITION: run this only if the on-device d-wave probe survived the
# fixed-VHT axis (c5.fixedvht completed without a firmware RAMDUMP). If
# that axis crashed, the >=80 MHz boundary holds for the peer ratectrl
# module too and this session is pointless.
#
# The phone sends FW-default-rate frames (private radiotap TX_FLAGS bit
# 15: no tx_send_params TLV, no tx_flags) in two phases:
#   baseline - helper peer left at its default rate control;
#   fixed    - WMI_PEER_PARAM_FIXED_RATE set to the requested V1 ratecode
#              on the helper peer first (debugfs frame_inject_peer_rate).
# The independent listener capture is the only authority: compare the
# radiotap rate fields of the injected TA's frames between the two
# capture windows. The phone-side evidence (completion tx_rate_kbps from
# the frame_inject_completions ledger) is recorded alongside but is NOT
# the verdict.

here=$(cd -- "$(dirname -- "$0")" && pwd)
stage1_dir=$here
expected_build_id=4c13f3b3f0b8f03d6904dd871af39164e18afa57

usage()
{
	cat >&2 <<EOF
usage: run_stage2_peer_rate_ota.sh [--serial SERIAL] [--frequency MHZ]
       [--frames N] [--fixed-rate "vht 1 9"] [--raw-ratecode U32]
       [--expected-build-id HEX40] --authorized-isolated-lab

Start the listener capture FIRST on --frequency. --fixed-rate takes the
knob triple "<ofdm|cck|ht|vht|he|eht> <nss 1-8> <rate/mcs 0-31>"
(default "vht 1 9"); --raw-ratecode passes a literal V1 ratecode
instead. Two windows are recorded into peer-rate-windows.tsv; adjudicate
by comparing the listener pcap radiotap rate fields between them.
EOF
	exit 2
}

serial=
frequency=5745
frames=10
fixed_rate="vht 1 9"
raw_ratecode=
authorized=0
while [ "$#" -gt 0 ]; do
	case $1 in
	--serial) [ "$#" -ge 2 ] || usage; serial=$2; shift 2 ;;
	--frequency) [ "$#" -ge 2 ] || usage; frequency=$2; shift 2 ;;
	--frames) [ "$#" -ge 2 ] || usage; frames=$2; shift 2 ;;
	--fixed-rate) [ "$#" -ge 2 ] || usage; fixed_rate=$2; shift 2 ;;
	--raw-ratecode) [ "$#" -ge 2 ] || usage; raw_ratecode=$2; shift 2 ;;
	--expected-build-id) [ "$#" -ge 2 ] || usage; expected_build_id=$2; shift 2 ;;
	--authorized-isolated-lab) authorized=1; shift ;;
	*) usage ;;
	esac
done
[ "$authorized" -eq 1 ] || usage
case $frames in ''|*[!0-9]*) usage ;; esac
[ "$frames" -ge 1 ] && [ "$frames" -le 64 ] || { echo "frames must be 1..64" >&2; exit 2; }
case $expected_build_id in *[!0-9a-f]*|'') usage ;; esac
[ "${#expected_build_id}" -eq 40 ] || { echo "expected-build-id must be 40 hex" >&2; exit 2; }
[ -n "$raw_ratecode" ] && [ -n "${fixed_rate:-}" ] && fixed_rate=

if [ -z "$serial" ]; then
	mapfile -t serials < <(adb devices | awk '$2 == "device" {print $1}')
	[ "${#serials[@]}" -eq 1 ] || { echo "need exactly one device" >&2; exit 3; }
	serial=${serials[0]}
fi
adb_cmd=(adb -s "$serial")
adb_shell() { timeout 30 "${adb_cmd[@]}" shell su -c "$1" </dev/null; }

session_open=1
emergency_cleanup()
{
	[ "$session_open" -eq 1 ] || return 0
	adb_shell 'echo none > /sys/kernel/debug/wlan0/frame_inject_peer_rate' >/dev/null 2>&1
	[ -n "$orig_idle" ] && adb_shell "echo $orig_idle > /sys/kernel/debug/wlan0/frame_inject_helper_idle_ms" >/dev/null 2>&1
	adb_shell 'cmd wifi set-wifi-enabled disabled' >/dev/null 2>&1
	adb_shell 'ip link set wlan0 down' >/dev/null 2>&1
	adb_shell 'iw dev wlan0 set type managed' >/dev/null 2>&1
	adb_shell 'ip link set wlan0 up' >/dev/null 2>&1
	adb_shell 'cmd wifi set-wifi-enabled enabled' >/dev/null 2>&1
	echo "EMERGENCY_CLEANUP_RAN=1 (verify the phone reconnected)" >&2
}
trap 'rc=$?; emergency_cleanup; exit $rc' EXIT

note=$("${adb_cmd[@]}" exec-out su -c 'od -An -v -tx1 /sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id' | tr -d ' \r\n')
case $note in *"$expected_build_id"*) ;; *)
	echo "loaded module build id mismatch (want $expected_build_id)" >&2
	exit 3
	;;
esac

mounts=$(adb_shell 'cat /proc/mounts' 2>/dev/null || true)
debug_root=$(awk '$3 == "debugfs" { print $2; exit }' <<<"$mounts")
if [ -z "$debug_root" ] || \
	! adb_shell "test -r $debug_root/wlan0/frame_inject_stats" >/dev/null 2>&1; then
	adb_shell 'mkdir -p /sys/kernel/debug' >/dev/null 2>&1 || true
	adb_shell 'mount -t debugfs debugfs /sys/kernel/debug' >/dev/null 2>&1 || true
	debug_root=/sys/kernel/debug
fi
stats_node=$debug_root/wlan0/frame_inject_stats
adb_shell "test -r $stats_node" >/dev/null 2>&1 || {
	echo "frame_inject_stats not readable at $stats_node" >&2
	exit 10
	}
# The peer-rate knob is the v19 surface; its absence means the loaded
# module predates v19 and the session cannot run.
adb_shell "test -e $debug_root/wlan0/frame_inject_peer_rate" >/dev/null 2>&1 || {
	echo "frame_inject_peer_rate knob missing (module predates v19)" >&2
	exit 3
	}

stamp=$(date -u +%Y%m%dT%H%M%SZ)
out=$here/peer-rate-$stamp-$$
mkdir "$out" || exit 3
echo "PEER_RATE_OUTPUT_DIR=$out"
printf 'expected_build_id=%s\nfrequency=%s\nframes=%s\nfixed_rate=%s\nraw_ratecode=%s\n' \
	"$expected_build_id" "$frequency" "$frames" "${fixed_rate:-none}" \
	"${raw_ratecode:-none}" >"$out/session.txt"

# Golden persona discipline: supplicant must be gone, not just the bit.
adb_shell 'cmd wifi set-wifi-enabled disabled' >/dev/null 2>&1
settled=0
for n in $(seq 1 120); do
	status=$(adb_shell 'cmd wifi status' 2>/dev/null | tr -d '\r')
	supp=$(adb_shell 'pidof wpa_supplicant' 2>/dev/null | tr -d '\r\n')
	grep -q '^Wifi is disabled$' <<<"$status" && [ -z "$supp" ] && { settled=1; break; }
	sleep 0.5
done
[ "$settled" -eq 1 ] || { echo "Wi-Fi framework did not settle off (supplicant alive)" >&2; exit 4; }

monitor_ready=0
for n in $(seq 1 30); do
	adb_shell 'ip link set wlan0 down' >/dev/null 2>&1 || true
	adb_shell 'iw dev wlan0 set type monitor' >/dev/null 2>&1 || { sleep 1; continue; }
	adb_shell 'ip link set wlan0 up' >/dev/null 2>&1 || { sleep 1; continue; }
	adb_shell "iw dev wlan0 set freq $frequency" >/dev/null 2>&1 || { sleep 1; continue; }
	monitor_ready=1
	break
done
[ "$monitor_ready" -eq 1 ] || { echo "monitor/channel setup failed" >&2; exit 4; }
adb_shell 'iw dev wlan0 info' >"$out/iw-monitor.log" 2>&1
grep -q "channel [0-9][0-9]* ($frequency MHz)" "$out/iw-monitor.log" || exit 4

sender_remote=/data/local/tmp/qcacld-peerrate-$$
adb_shell "mkdir -p $sender_remote" || exit 4
"${adb_cmd[@]}" push "$stage1_dir/send_stage1_packet" \
	"$sender_remote/send_stage1_packet" >"$out/push.log" 2>&1 || exit 4
adb_shell "chmod 0755 $sender_remote/send_stage1_packet" || exit 4

stat_value() { awk -F= -v key="$2" '$1 == key {print $2; exit}' "$1"; }

idle_knob=$debug_root/wlan0/frame_inject_helper_idle_ms
orig_idle=$(adb_shell "cat $idle_knob" 2>/dev/null | tr -d ' \r\n')
case $orig_idle in ''|*[!0-9]*) orig_idle=5000 ;; esac
adb_shell "echo 600000 > $idle_knob" >/dev/null 2>&1 || { echo "idle knob set failed" >&2; exit 5; }

# FW-default-rate frame: private TX_FLAGS bit 15 only - the WMI command
# goes out with neither the tx_send_params TLV nor tx_flags, so the rate
# is whatever the firmware default / peer ratectrl produces.
FWDEFAULT_HEX=$(python3 - <<'PY'
import struct
ra = bytes([0x02,0x11,0x22,0x33,0x44,0x55]); ta = bytes([0x02,0xAB,0xCD,0x00,0x00,0xF1])
mpdu = struct.pack("<HH",0x00C0,0)+ra+ta+ra+struct.pack("<H",0)+struct.pack("<H",1)
tx = struct.pack("<H", 0x8000)
hdr = struct.pack("<BBHI",0,0,8+len(tx),1<<15)
pkt = hdr+tx+mpdu
assert (pkt[2] | (pkt[3]<<8)) == 10 and (pkt[8] | (pkt[9]<<8)) == 0x8000
print(pkt.hex())
PY
)

printf 'phase\twindow_start_ns\twindow_end_ns\twmi_delta\tfw_completion_delta\n' >"$out/peer-rate-windows.tsv"

send_window() # phase
{
	local phase=$1 i w0 w1 c0 c1 t0 t1
	adb_shell "cat $stats_node" >"$out/stats-$phase-start.txt"
	t0=$(date +%s%N)
	i=1
	while [ $i -le "$frames" ]; do
		adb_shell "$sender_remote/send_stage1_packet --send wlan0 $FWDEFAULT_HEX" \
			>"$out/$phase-send-f$i.log" 2>&1
		sleep 1
		i=$((i + 1))
	done
	t1=$(date +%s%N)
	adb_shell "cat $stats_node" >"$out/stats-$phase-end.txt"
	adb_shell "cat /sys/kernel/debug/wlan0/frame_inject_completions" >"$out/$phase-ledger.txt" 2>&1 || true
	w0=$(stat_value "$out/stats-$phase-start.txt" wmi_submitted); w1=$(stat_value "$out/stats-$phase-end.txt" wmi_submitted)
	c0=$(stat_value "$out/stats-$phase-start.txt" fw_completion_events); c1=$(stat_value "$out/stats-$phase-end.txt" fw_completion_events)
	printf '%s\t%s\t%s\t%s\t%s\n' "$phase" "$t0" "$t1" "$((w1 - w0))" "$((c1 - c0))" >>"$out/peer-rate-windows.tsv"
	awk -F'\t' 'NR>1 && $1=="'"$phase"'" {last=$9} END{if (last!="") print "phase='"$phase"' last_tx_rate_kbps=" last}' \
		"$out/$phase-ledger.txt" 2>/dev/null || true
}

# baseline phase (peer at default rate control)
send_window baseline
sleep 3

# fixed phase: re-arm helper (idle teardown), then set the peer fixed rate
adb_shell "$sender_remote/send_stage1_packet --send wlan0 $FWDEFAULT_HEX" >/dev/null 2>&1
sleep 3
if [ -n "$raw_ratecode" ]; then
	adb_shell "echo raw $raw_ratecode > $debug_root/wlan0/frame_inject_peer_rate" 2>&1 | tr -d '\r'
else
	adb_shell "echo fixed $fixed_rate > $debug_root/wlan0/frame_inject_peer_rate" 2>&1 | tr -d '\r'
fi
adb_shell "cat $debug_root/wlan0/frame_inject_peer_rate" >"$out/peer-rate-knob.txt" 2>&1
grep -q 'last_status=0' "$out/peer-rate-knob.txt" || { echo "peer fixed rate apply failed" >&2; exit 5; }
sleep 1
send_window fixed

adb_shell "echo none > $debug_root/wlan0/frame_inject_peer_rate" >/dev/null 2>&1
adb_shell "echo $orig_idle > $idle_knob" >/dev/null 2>&1
adb_shell "cat $stats_node" >"$out/stats-final.txt"
fatal=$(stat_value "$out/stats-final.txt" fatal_latched)
session_open=0

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
	sleep 1
done
printf '%s\n' "$status" >"$out/wifi-restored.log"
adb_shell "rm -rf $sender_remote" >/dev/null 2>&1 || true

{
	printf 'verdict=PHONE_SIDE_COMPLETE\n'
	printf 'scope=peer-fixed-rate-fw-default-ota-v1\n'
	printf 'build_id=%s\n' "$expected_build_id"
	printf 'frames_per_phase=%s\n' "$frames"
	printf 'fatal_latched=%s\n' "$fatal"
	printf 'restored=%s\n' "$restored"
	printf 'adjudication=compare listener pcap radiotap rate fields between peer-rate-windows.tsv windows\n'
	printf 'ta=02:AB:CD:00:00:F1\n'
} >"$out/result.txt"
cat "$out/result.txt"
[ "$restored" -eq 1 ] || exit 6
exit 0
