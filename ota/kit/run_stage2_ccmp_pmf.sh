#!/usr/bin/env bash

set -uo pipefail

# Stage 2 CCMP PMF verdict session (kit v11, todo 4.3 C-2 OTA closing).
#
# Question: does the firmware encrypt an injected protected management
# frame with the pairwise key the phone installed on the injection
# helper peer? The phone side (this script) installs a KNOWN 16-byte
# CCMP key via debugfs frame_inject_pmf_key and injects protected
# deauth frames carrying the private WFA is-SA-query tx-flag bit (the
# tx_params_valid=0 submission mode). The listener runs an independent
# capture on the same channel. The verdict is OFFLINE, on the listener
# pcap, with decrypt_ccmp_pmf.py and the same key:
#
#   decrypt_ccmp_pmf.py LISTENER.pcap KEY32HEX --ta 02:AB:CD:00:00:F1
#   -> verdict=FW_LOCAL_CCMP_PROVEN_WITH_KNOWN_KEY (MIC verified)
#
# A MIC failure is reported verbatim; UNPROVEN is a legal verdict and
# the session must never be re-run just to convert it.

here=$(cd -- "$(dirname -- "$0")" && pwd)
stage1_dir=$here
expected_build_id=914714cb6f296f35f093bf393bfea47c4982897c

usage()
{
	cat >&2 <<EOF
usage: run_stage2_ccmp_pmf.sh [--serial SERIAL] --key KEY32HEX
       [--frequency MHZ] [--frames N] [--expected-build-id HEX40]
       --authorized-isolated-lab

Start the listener capture FIRST (same channel as --frequency), then
run this script. KEY32HEX is the volunteer-chosen CCMP-128 pairwise
key; the same 32 hex chars feed decrypt_ccmp_pmf.py afterwards. The
key bytes are never logged by the phone (key_bytes_never_logged) and
are only echoed into this host's own artifact directory.
EOF
	exit 2
}

serial=
key=
frequency=5745
frames=12
authorized=0
while [ "$#" -gt 0 ]; do
	case $1 in
	--serial) [ "$#" -ge 2 ] || usage; serial=$2; shift 2 ;;
	--key) [ "$#" -ge 2 ] || usage; key=$2; shift 2 ;;
	--frequency) [ "$#" -ge 2 ] || usage; frequency=$2; shift 2 ;;
	--frames) [ "$#" -ge 2 ] || usage; frames=$2; shift 2 ;;
	--expected-build-id) [ "$#" -ge 2 ] || usage; expected_build_id=$2; shift 2 ;;
	--authorized-isolated-lab) authorized=1; shift ;;
	*) usage ;;
	esac
done
[ "$authorized" -eq 1 ] || usage
[ -n "$key" ] || usage
case $key in ''|*[!0-9a-fA-F]*) usage ;; esac
[ "${#key}" -eq 32 ] || { echo "key must be 32 hex chars (CCMP-128)" >&2; exit 2; }
case $frames in ''|*[!0-9]*) usage ;; esac
[ "$frames" -ge 1 ] && [ "$frames" -le 64 ] || { echo "frames must be 1..64" >&2; exit 2; }
case $expected_build_id in *[!0-9a-f]*|'') usage ;; esac
[ "${#expected_build_id}" -eq 40 ] || { echo "expected-build-id must be 40 hex" >&2; exit 2; }

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
	adb_shell "echo none > /data/local/tmp/qcacld-ccmp-key-none 2>/dev/null" >/dev/null 2>&1
	adb_shell 'echo none > /sys/kernel/debug/wlan0/frame_inject_pmf_key' >/dev/null 2>&1
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

stamp=$(date -u +%Y%m%dT%H%M%SZ)
out=$here/ccmp-pmf-$stamp-$$
mkdir "$out" || exit 3
echo "CCMP_PMF_OUTPUT_DIR=$out"
printf 'expected_build_id=%s\nloaded_build_id_note=%s\nfrequency=%s\nframes=%s\n' \
	"$expected_build_id" "$note" "$frequency" "$frames" >"$out/session.txt"
# The key lives only in this host artifact (never in any phone log).
printf '%s\n' "$key" >"$out/session.key"

# Phone prep: golden persona discipline - "Wifi is disabled" is only the
# SETTING bit; the framework teardown is asynchronous and a still-living
# supplicant would destroy the monitor persona mid-session.
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
grep -q '^[[:space:]]*type monitor$' "$out/iw-monitor.log" || exit 4
grep -q "channel [0-9][0-9]* ($frequency MHz)" "$out/iw-monitor.log" || exit 4

sender_remote=/data/local/tmp/qcacld-ccmp-$$
adb_shell "mkdir -p $sender_remote" || exit 4
"${adb_cmd[@]}" push "$stage1_dir/send_stage1_packet" \
	"$sender_remote/send_stage1_packet" >"$out/push.log" 2>&1 || exit 4
adb_shell "chmod 0755 $sender_remote/send_stage1_packet" || exit 4

stat_value() { awk -F= -v key="$2" '$1 == key {print $2; exit}' "$1"; }

idle_knob=$debug_root/wlan0/frame_inject_helper_idle_ms
orig_idle=$(adb_shell "cat $idle_knob" 2>/dev/null | tr -d ' \r\n')
case $orig_idle in ''|*[!0-9]*) orig_idle=5000 ;; esac
adb_shell "echo 600000 > $idle_knob" >/dev/null 2>&1 || { echo "idle knob set failed" >&2; exit 5; }
printf 'orig_idle_ms=%s\nrun_idle_ms=600000\n' "$orig_idle" >"$out/idle-knob.txt"

# Vectors: plain warm-up deauth (creates the helper) and the protected
# deauth carrying the private WFA is-SA-query bit (protected bit + CCMP
# under the installed key). TA is fixed so the listener/decryptor can
# filter with --ta.
WARMUP_HEX=$(python3 - <<'PY'
import struct
ra = bytes([0x02,0x11,0x22,0x33,0x44,0x55]); ta = bytes([0x02,0xAB,0xCD,0x00,0x00,0xF1])
mpdu = struct.pack("<HH",0x00C0,0)+ra+ta+ra+struct.pack("<H",0)+struct.pack("<H",1)
rt = struct.pack("<B", 12)
hdr = struct.pack("<BBHI",0,0,8+len(rt),1<<2)
pkt = hdr+rt+mpdu
assert (pkt[2] | (pkt[3]<<8)) == 9 and len(mpdu) == 26
print(pkt.hex())
PY
)
PROTECTED_HEX=$(python3 - <<'PY'
import struct
ra = bytes([0x02,0x11,0x22,0x33,0x44,0x55]); ta = bytes([0x02,0xAB,0xCD,0x00,0x00,0xF1])
mpdu = struct.pack("<HH",0x00C0 | 0x0400, 0)+ra+ta+ra+struct.pack("<H",0)+struct.pack("<H",1)
tx = struct.pack("<H", 0x0800)  # private bit 11 = IS_SA_QUERY
hdr = struct.pack("<BBHI",0,0,8+len(tx),1<<15)
pkt = hdr+tx+mpdu
assert (pkt[2] | (pkt[3]<<8)) == 10 and (pkt[8] | (pkt[9]<<8)) == 0x0800
print(pkt.hex())
PY
)

# Warm-up + key install inside the helper lifetime.
adb_shell "cat $stats_node" >"$out/stats-warmup-before.txt"
adb_shell "$sender_remote/send_stage1_packet --send wlan0 $WARMUP_HEX" >"$out/warmup-send.log" 2>&1
sleep 4
adb_shell "echo 'ccmp $key' > $debug_root/wlan0/frame_inject_pmf_key" 2>&1 | tr -d '\r'
sleep 2
adb_shell "cat $debug_root/wlan0/frame_inject_pmf_key" >"$out/pmf-key-state.txt" 2>&1
grep -q 'installed=1' "$out/pmf-key-state.txt" || { echo "key install failed (helper alive?)" >&2; exit 5; }
echo "ccmp.key_install OK (helper peer, direct WMI)"

printf 'index\twindow_start_ns\twindow_end_ns\twmi_delta\tfw_completion_delta\n' >"$out/send-manifest.tsv"
wmi_all0=$(stat_value "$out/stats-warmup-before.txt" wmi_submitted)
fwc_all0=$(stat_value "$out/stats-warmup-before.txt" fw_completion_events)
i=1
while [ $i -le "$frames" ]; do
	adb_shell "cat $stats_node" >"$out/stats-f$i-before.txt"
	t0=$(date +%s%N)
	adb_shell "$sender_remote/send_stage1_packet --send wlan0 $PROTECTED_HEX" >"$out/send-f$i.log" 2>&1
	sleep 1
	t1=$(date +%s%N)
	adb_shell "cat $stats_node" >"$out/stats-f$i-after.txt"
	w0=$(stat_value "$out/stats-f$i-before.txt" wmi_submitted); w1=$(stat_value "$out/stats-f$i-after.txt" wmi_submitted)
	c0=$(stat_value "$out/stats-f$i-before.txt" fw_completion_events); c1=$(stat_value "$out/stats-f$i-after.txt" fw_completion_events)
	printf '%s\t%s\t%s\t%s\t%s\n' "$i" "$t0" "$t1" "$((w1 - w0))" "$((c1 - c0))" >>"$out/send-manifest.tsv"
	i=$((i + 1))
done
adb_shell "cat /sys/kernel/debug/wlan0/frame_inject_completions" >"$out/completions.txt" 2>&1 || true
adb_shell "cat $stats_node" >"$out/stats-final.txt"
wmi_all1=$(stat_value "$out/stats-final.txt" wmi_submitted)
fwc_all1=$(stat_value "$out/stats-final.txt" fw_completion_events)
fatal=$(stat_value "$out/stats-final.txt" fatal_latched)
wdt=$(stat_value "$out/stats-final.txt" watchdog_timeouts)

# Clear the key and restore the idle knob before the persona flip.
adb_shell "echo none > $debug_root/wlan0/frame_inject_pmf_key" >/dev/null 2>&1
adb_shell "cat $debug_root/wlan0/frame_inject_pmf_key" >"$out/pmf-key-cleared.txt" 2>&1
adb_shell "echo $orig_idle > $idle_knob" >/dev/null 2>&1
session_open=0

# Restore managed persona with the full wait loop.
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
	printf 'scope=ccmp-pmf-known-key-protected-deauth-v1\n'
	printf 'build_id=%s\n' "$expected_build_id"
	printf 'frames=%s\n' "$frames"
	printf 'wmi_delta_total=%s\n' "$((wmi_all1 - wmi_all0))"
	printf 'fw_completion_delta_total=%s\n' "$((fwc_all1 - fwc_all0))"
	printf 'fatal_latched=%s watchdog_timeouts=%s\n' "$fatal" "$wdt"
	printf 'key_cleared=%s\n' "$(grep -c 'installed=0' "$out/pmf-key-cleared.txt" 2>/dev/null || echo 0)"
	printf 'restored=%s\n' "$restored"
	printf 'listener_verdict_command=decrypt_ccmp_pmf.py LISTENER.pcap %s --ta 02:AB:CD:00:00:F1\n' "$key"
} >"$out/result.txt"
cat "$out/result.txt"
[ "$restored" -eq 1 ] || exit 6
[ $((wmi_all1 - wmi_all0)) -eq $((frames + 1)) ] || { echo "submit count mismatch (want $((frames + 1)) incl warmup)" >&2; exit 7; }
exit 0
