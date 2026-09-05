#!/usr/bin/env bash

# todo 4.5/4.3 monitor-RX radiotap audit, run on the current flashed build
# (7a7ddf46, already device-verified by stage0/stage1/chandef rounds).
# Verification-only RX characterization of the stock monitor-RX pipeline
# (RXDMA mon rings -> HAL TLV parser -> mon_rx_status ->
# qdf_nbuf_update_radiotap -> packet socket):
#   1. passive listening window on the lab AP channel - frame class
#      visibility (mgmt/data/ctrl) and radiotap field population/quality
#      (TSFT monotonicity, RSSI range, channel flags, rate, layout walk);
#   2. controlled stimulus - inject one unicast auth (must draw a real
#      OTA ACK from the AP) and one broadcast deauth (no ACK expected)
#      while a capture window is open; the ACK record in the local pcap
#      must reference the injected TA. Self-TX frame visibility in the
#      local monitor is recorded as an observation, never an on-air claim.
# No radiotap field accuracy vs ground truth is claimed: local monitor
# facts only. The analyzer (analyze_radiotap_pcap.py, selftested against
# the shipping kernel's radiotap bit table) runs on the host after the
# device phase; the runner must end with managed persona restored, Wi-Fi
# reconnected and VALIDATED, no mon0, idle window and knobs restored,
# owner ledger zero, boot id unchanged, no fatal markers in dmesg delta.

set -uo pipefail

expected_build_id=ec49943d8a798a4c10023378bf9059de9a28a67c
expected_source_rev=93896078f500+dirty-20260903-4.2-chandef-hop-survey-v12
expected_stats_format=9
expected_sender_sha256=c2795e6b612c065fd464a97251276ad61c0f7a5484bd7d4767fdd882adc10afc
knob_path=/sys/module/qca_cld3_peach_v2/parameters/frame_inject_constructed_context
# injected TA (local-administered unicast); the real ACK must carry it as RA
probe_ta=02:11:22:33:44:55
probe_ta_hex=021122334455
# auth req (30B, unicast -> ACK) and broadcast deauth (26B, no ACK), each
# behind an 8-byte zero-presence radiotap header (minimal legal TX input)
passive_seconds=60
stimulus_seconds=25
fail_count=0

usage()
{
	echo "usage: $0 --serial SERIAL --target-bssid BSSID --authorized-isolated-lab" >&2
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

[ -n "$serial" ] && [ -n "$target_bssid" ] && [ "$authorized" -eq 1 ] || usage
[[ "$target_bssid" =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ ]] || usage
target_bssid_hex=$(printf '%s' "$target_bssid" | tr -d ':')

probe_unicast_hex="0000080000000000b0000000${target_bssid_hex}${probe_ta_hex}${target_bssid_hex}0000000000010000"
probe_broadcast_hex="0000080000000000c0000000ffffffffffff${probe_ta_hex}ffffffffffff00000007"

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
sender=$script_dir/../device-suite-wmi-stage1-matrix/send_stage1_packet
analyzer=$script_dir/analyze_radiotap_pcap.py
[ -x "$sender" ] && [ -r "$analyzer" ] || { echo "missing sender or analyzer" >&2; exit 3; }
python3 "$analyzer" --selftest >/dev/null || { echo "analyzer selftest failed" >&2; exit 3; }
sender_sha=$(sha256sum "$sender" | awk '{print $1}')
[ "$sender_sha" = "$expected_sender_sha256" ] || { echo "sender sha mismatch: $sender_sha" >&2; exit 3; }

stamp=$(date -u +%Y%m%dT%H%M%SZ)
host_out=$script_dir/host-capture-rx-audit-$stamp-$$
mkdir -p "$host_out" || exit 3

adb_cmd=(adb -s "$serial")
adb_shell()
{
	# </dev/null: adb forwards local stdin to the remote shell, so an
	# un-redirected call inside a `while read` loop would otherwise eat
	# the loop's stdin. No adb_shell command ever needs stdin.
	"${adb_cmd[@]}" shell su -c "$1" </dev/null
}

sv() # key from stats text on stdin
{
	awk -F= -v key="$1" '$1 == key { print $2 }' | tail -n 1
}

stats()
{
	adb_shell 'cat /sys/kernel/debug/wlan0/frame_inject_stats'
}

iw_info_field()
{
	case $1 in
	type) sed -n 's/^[[:space:]]*type //p' ;;
	ifindex) sed -n 's/^[[:space:]]*ifindex //p' ;;
	freq) sed -n 's/.*channel [0-9][0-9]* (\([0-9][0-9]*\) MHz).*/\1/p' | head -n 1 ;;
	width) sed -n 's/.*width: \([0-9][0-9]*\) MHz.*/\1/p' | head -n 1 ;;
	center1) sed -n 's/.*center1: \([0-9][0-9]*\) MHz.*/\1/p' | head -n 1 ;;
	*) return 1 ;;
	esac
}

read_state()
{
	local info
	info=$(adb_shell 'iw dev wlan0 info' 2>&1 | tr -d '\r')
	state_type=$(printf '%s\n' "$info" | iw_info_field type | head -n 1)
	state_freq=$(printf '%s\n' "$info" | iw_info_field freq)
	state_width=$(printf '%s\n' "$info" | iw_info_field width)
	state_center1=$(printf '%s\n' "$info" | iw_info_field center1)
}

wait_persona() # wanted old_ifindex output_file
{
	local wanted=$1 old_ifindex=$2 output=$3 info type ifindex
	info=
	for _ in $(seq 1 160); do
		info=$(adb_shell 'iw dev wlan0 info' 2>&1 | tr -d '\r')
		type=$(printf '%s\n' "$info" | iw_info_field type | head -n 1)
		ifindex=$(printf '%s\n' "$info" | iw_info_field ifindex | head -n 1)
		if [ "$type" = "$wanted" ] && [ -n "$ifindex" ] && [ "$ifindex" != "$old_ifindex" ]; then
			printf '%s\n' "$info" >"$output"
			return 0
		fi
		sleep 0.25
	done
	printf '%s\n' "$info" >"$output"
	return 1
}

note_fail()
{
	fail_count=$((fail_count + 1))
	echo "FAIL: $*" >&2
}

# ---------------------------------------------------------------- baseline
adb_shell 'cat /proc/sys/kernel/random/boot_id' >"$host_out/boot-id-before.txt" || exit 4
adb_shell 'iw dev wlan0 info' >"$host_out/iw-before.log" 2>&1 || exit 4
before_type=$(iw_info_field type <"$host_out/iw-before.log" | head -n 1)
before_freq=$(iw_info_field freq <"$host_out/iw-before.log")
before_width=$(iw_info_field width <"$host_out/iw-before.log")
before_center1=$(iw_info_field center1 <"$host_out/iw-before.log")
[ "$before_type" = managed ] && [ -n "$before_freq" ] && [ -n "$before_width" ] &&
	[ -n "$before_center1" ] || {
		echo "baseline: wlan0 is not a managed persona with a full chandef" >&2
		exit 4
	}
adb_shell 'cmd wifi status' >"$host_out/wifi-before.log" 2>&1 || exit 4
grep -q 'Wifi is connected to' "$host_out/wifi-before.log" || {
	echo "baseline: Wi-Fi must be connected (the lab AP provides the template)" >&2
	exit 4
}
grep -q 'VALIDATED' "$host_out/wifi-before.log" || exit 4
grep -q "$target_bssid" "$host_out/wifi-before.log" ||
	{ echo "baseline: not connected to target bssid" >&2; exit 4; }
before_ifindex=$(adb_shell 'cat /sys/class/net/wlan0/ifindex' 2>/dev/null | tr -d ' \r\n')
[ -n "$before_ifindex" ] || exit 4
# Wake the phone before touching the persona (WoW resume can wedge the
# monitor vdev-up; same guard as the chandef runner).
adb_shell 'input keyevent KEYCODE_WAKEUP' >/dev/null 2>&1 || true
adb_shell 'svc power stayon usb' >"$host_out/stayon.log" 2>&1 || true
sleep 3
adb_shell 'dmesg' >"$host_out/dmesg-before.log" 2>&1 || true
adb_shell 'iw dev' >"$host_out/iw-dev-before.log" 2>&1 || true

mounted_debugfs=0
debugfs_type=$(adb_shell 'stat -f -c %T /sys/kernel/debug' 2>/dev/null | tr -d ' \r\n')
if [ "$debugfs_type" != 0x64626720 ] && [ "$debugfs_type" != debugfs ]; then
	adb_shell 'mount -t debugfs debugfs /sys/kernel/debug' >"$host_out/mount-debugfs.log" 2>&1 || exit 4
	mounted_debugfs=1
fi

knob_read()
{
	local v
	v=$(adb_shell "cat $knob_path" 2>&1 | tr -d ' \r\n')
	case $v in
	Y|1) echo 1 ;;
	N|0) echo 0 ;;
	*) echo "X:$v" ;;
	esac
}

knob_before=$(knob_read)
printf 'knob_before=%s\n' "$knob_before" >"$host_out/knob-trail.txt"
case $knob_before in
0|1) ;;
*) echo "knob unavailable: $knob_before" >&2; exit 4 ;;
esac

idle_ms_path=/sys/kernel/debug/wlan0/frame_inject_helper_idle_ms
idle_ms_before=$(adb_shell "cat $idle_ms_path" 2>/dev/null | tr -d ' \r\n')
case $idle_ms_before in
''|*[!0-9]*) idle_ms_before=5000 ;;
*) printf 'idle_ms_before=%s\n' "$idle_ms_before" >>"$host_out/knob-trail.txt" ;;
esac

reclaim_helper()
{
	# The idle window is never modified by this runner, so the default
	# idle reclaim fires ~5 s after the last stimulus frame; wait it out
	# so the pre-flip stats snapshot is the final ledger state (helper
	# absent, owner zero). Bounded to 30 s.
	for _ in $(seq 1 60); do
		if grep -q 'helper_present=0' <(stats 2>/dev/null); then
			return 0
		fi
		sleep 0.5
	done
	return 1
}

restore_managed()
{
	if [ -e "$host_out/.restore-done" ]; then
		return 0
	fi
	local rc=0
	local current_ifindex current_type
	current_ifindex=$(adb_shell 'cat /sys/class/net/wlan0/ifindex' 2>/dev/null | tr -d ' \r\n')
	current_type=$(adb_shell 'iw dev wlan0 info' 2>/dev/null | tr -d '\r' | iw_info_field type | head -n 1)
	if [ "$current_type" = monitor ] && [ -n "$current_ifindex" ]; then
		# The frame_inject debugfs nodes exist only on the monitor adapter,
		# so the ledger gates must read the LAST monitor-mode snapshot:
		# bring the helper down via one idle reclaim before the flip.
		reclaim_helper || rc=1
		stats >"$host_out/teardown-stats.log" 2>&1 || rc=1
		adb_shell 'dmesg' >"$host_out/teardown-dmesg.log" 2>&1 || rc=1
		adb_shell 'iw dev wlan0 set type managed' >"$host_out/restore-managed.log" 2>&1 || rc=1
		wait_persona managed "$current_ifindex" "$host_out/restore-managed-info.log" || rc=1
	else
		printf '%s\n' 'persona=managed_before_restore' >"$host_out/teardown-stats.log"
	fi
	adb_shell "echo $knob_before > $knob_path" >>"$host_out/knob-trail.txt" 2>&1 || rc=1
	adb_shell 'cmd wifi set-wifi-enabled enabled' >"$host_out/restore-wifi.log" 2>&1 || rc=1
	local reconnected=0 info status
	for _ in $(seq 1 240); do
		info=$(adb_shell 'iw dev wlan0 info' 2>&1 | tr -d '\r')
		status=$(adb_shell 'cmd wifi status' 2>&1 | tr -d '\r')
		if [ "$(printf '%s\n' "$info" | iw_info_field type | head -n 1)" = managed ] &&
			grep -q '^Wifi is enabled$' <<<"$status" &&
			grep -q 'Wifi is connected to' <<<"$status" &&
			grep -q 'VALIDATED' <<<"$status"; then
			printf '%s\n' "$info" >"$host_out/iw-restored.log"
			printf '%s\n' "$status" >"$host_out/wifi-restored.log"
			reconnected=1
			break
		fi
		sleep 0.5
	done
	[ "$reconnected" -eq 1 ] || rc=1
	adb_shell 'iw dev mon0 del' >"$host_out/mon0-cleanup.log" 2>&1 || true
	adb_shell 'cat /proc/sys/kernel/random/boot_id' >"$host_out/boot-id-after.txt" 2>&1 || rc=1
	adb_shell 'dmesg' >"$host_out/dmesg-after.log" 2>&1 || rc=1
	if [ "$mounted_debugfs" -eq 1 ]; then
		adb_shell 'umount /sys/kernel/debug' >"$host_out/unmount-debugfs.log" 2>&1 || rc=1
	fi
	: >"$host_out/.restore-done"
	return "$rc"
}
trap restore_managed EXIT HUP INT TERM

[ "$knob_before" = 1 ] || {
	adb_shell "echo 1 > $knob_path" >>"$host_out/knob-trail.txt" 2>&1 || exit 5
	[ "$(knob_read)" = 1 ] || { echo "knob enable failed" >&2; exit 5; }
}

# ---------------------------------------------------------------- monitor entry
adb_shell 'cmd wifi set-wifi-enabled disabled' >"$host_out/disable-wifi.log" 2>&1 || exit 5
wifi_off_settled=0
# clean-boot note: a disable issued right after the framework finished
# (re)connecting can take well over 30 s to tear down; budget 60 s.
for _ in $(seq 1 120); do
	off_status=$(adb_shell 'cmd wifi status' 2>/dev/null | tr -d '\r')
	off_supp=$(adb_shell 'pidof wpa_supplicant' 2>/dev/null | tr -d '\r\n')
	if grep -q '^Wifi is disabled$' <<<"$off_status" && [ -z "$off_supp" ]; then
		wifi_off_settled=1
		break
	fi
	sleep 0.5
done
[ "$wifi_off_settled" -eq 1 ] || { echo "framework Wi-Fi-off never settled" >&2; exit 5; }
adb_shell 'iw dev wlan0 set type monitor' >"$host_out/set-monitor.log" 2>&1 || exit 5
wait_persona monitor "$before_ifindex" "$host_out/monitor-info.log" || exit 5
# The recreated monitor netdev inherits the framework-era DOWN link state;
# capture and set freq both need it UP.
adb_shell 'ip link set wlan0 up' >"$host_out/ifup-monitor.log" 2>&1 || exit 5

enter_ap_chandef()
{
	for _ in $(seq 1 100); do
		if adb_shell "iw dev wlan0 set freq $before_freq $before_width $before_center1" \
			>>"$host_out/set-ap-channel.log" 2>&1; then
			return 0
		fi
		sleep 0.2
	done
	return 1
}

channel_ready=0
enter_ap_chandef && channel_ready=1
[ "$channel_ready" -eq 1 ] || { echo "ap chandef set failed" >&2; exit 5; }

# OEM connectivity hooks can race a quick disable->monitor cycle; require
# the monitor persona to hold steady for 5 s (same guard as chandef).
monitor_stable=0
for attempt in 1 2 3; do
	hold=1
	for _ in $(seq 1 10); do
		read_state
		[ "$state_type" = monitor ] || { hold=0; break; }
		sleep 0.5
	done
	if [ "$hold" -eq 1 ]; then
		monitor_stable=1
		break
	fi
	if [ "$attempt" -lt 3 ]; then
		adb_shell 'cmd wifi set-wifi-enabled disabled' >>"$host_out/disable-wifi.log" 2>&1 || true
		adb_shell 'iw dev wlan0 set type monitor' >>"$host_out/set-monitor.log" 2>&1 || true
		adb_shell 'ip link set wlan0 up' >>"$host_out/ifup-monitor.log" 2>&1 || true
		enter_ap_chandef || true
	fi
done
[ "$monitor_stable" -eq 1 ] || { echo "monitor persona unstable" >&2; exit 5; }

ready_stats=$(stats)
printf '%s\n' "$ready_stats" >"$host_out/monitor-ready-stats.log" 2>&1
grep -qx 'state=ready' <<<"$ready_stats" || { echo "ctx not ready" >&2; exit 5; }
[ "$(printf '%s\n' "$ready_stats" | sv source_rev)" = "$expected_source_rev" ] || {
	echo "source_rev mismatch" >&2
	exit 5
}
[ "$(printf '%s\n' "$ready_stats" | sv format_version)" = "$expected_stats_format" ] || {
	echo "stats format mismatch" >&2
	exit 5
}
loaded_note=$("${adb_cmd[@]}" exec-out su -c 'od -An -v -tx1 /sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id' | tr -d ' \r\n')
case $loaded_note in *"$expected_build_id"*) ;; *)
	echo "loaded module build id mismatch" >&2
	exit 5
	;;
esac

remote_dir=/data/local/tmp/qcacld-rx-audit-$$
adb_shell "mkdir -p $remote_dir" >"$host_out/push-sender.log" 2>&1 || exit 5
"${adb_cmd[@]}" push "$sender" $remote_dir/send_stage1_packet >>"$host_out/push-sender.log" 2>&1 || exit 5
adb_shell "chmod 0755 $remote_dir/send_stage1_packet" >>"$host_out/push-sender.log" 2>&1 || exit 5


# ---------------------------------------------------------------- passive window
adb_shell "$remote_dir/send_stage1_packet --capture-bssid wlan0 $target_bssid $passive_seconds $remote_dir/passive.pcap" \
	>"$host_out/passive-capture.log" 2>&1
passive_rc=$?
grep -q 'capture=PASS' "$host_out/passive-capture.log" && grep -q ' target_beacons=[1-9]' "$host_out/passive-capture.log"
beacon_gate=$?
if [ "$passive_rc" -ne 0 ] || [ "$beacon_gate" -ne 0 ]; then
	note_fail "passive window: no target beacons captured (rc=$passive_rc)"
fi
stats >"$host_out/stats-after-passive.log" 2>&1

# ---------------------------------------------------------------- stimulus window
adb_shell "$remote_dir/send_stage1_packet --capture-bssid wlan0 $target_bssid $stimulus_seconds $remote_dir/stimulus.pcap" \
	>"$host_out/stimulus-capture.log" 2>&1 &
stimulus_pid=$!
sleep 5

stim_fw_before=$(printf '%s\n' "$(stats 2>/dev/null)" | sv fw_completion_events)
adb_shell "$remote_dir/send_stage1_packet --send wlan0 $probe_unicast_hex" \
	>"$host_out/send-unicast.log" 2>&1
send_unicast_rc=$?
sleep 3
adb_shell "$remote_dir/send_stage1_packet --send wlan0 $probe_broadcast_hex" \
	>"$host_out/send-broadcast.log" 2>&1
send_broadcast_rc=$?
wait "$stimulus_pid"
stimulus_capture_rc=$?

stats >"$host_out/stats-after-stimulus.log" 2>&1
stim_fw_after=$(printf '%s\n' "$(stats 2>/dev/null)" | sv fw_completion_events)
stim_fw_delta=$((stim_fw_after - stim_fw_before))

for f in unicast broadcast; do
	eval "rc=\$send_${f}_rc"
	[ "$rc" -eq 0 ] || note_fail "send $f returned $rc (must be a precise refusal or success, never silent)"
done
grep -q 'capture=PASS' "$host_out/stimulus-capture.log" ||
	note_fail "stimulus window capture failed rc=$stimulus_capture_rc"

# ---------------------------------------------------------------- restore
restore_managed
restore_rc=$?

# ---------------------------------------------------------------- evidence pull
"${adb_cmd[@]}" pull $remote_dir/passive.pcap "$host_out/passive.pcap" >"$host_out/pull.log" 2>&1 || note_fail "pull passive.pcap"
"${adb_cmd[@]}" pull $remote_dir/stimulus.pcap "$host_out/stimulus.pcap" >>"$host_out/pull.log" 2>&1 || note_fail "pull stimulus.pcap"
adb_shell "rm -rf $remote_dir" >>"$host_out/pull.log" 2>&1 || true

# ---------------------------------------------------------------- host analysis
[ -r "$host_out/passive.pcap" ] && python3 "$analyzer" "$host_out/passive.pcap" >"$host_out/analysis-passive.txt" 2>&1
[ -r "$host_out/stimulus.pcap" ] && python3 "$analyzer" "$host_out/stimulus.pcap" >"$host_out/analysis-stimulus.txt" 2>&1

passive_packets=$(sed -n 's/^files=[0-9]* packets=\([0-9]*\)$/\1/p' "$host_out/analysis-passive.txt" 2>/dev/null | head -n 1)
stimulus_packets=$(sed -n 's/^files=[0-9]* packets=\([0-9]*\)$/\1/p' "$host_out/analysis-stimulus.txt" 2>/dev/null | head -n 1)
passive_walk_bad=$(sed -n 's/^layout walk mismatches.*: \([0-9]*\)$/\1/p' "$host_out/analysis-passive.txt" 2>/dev/null)
stimulus_walk_bad=$(sed -n 's/^layout walk mismatches.*: \([0-9]*\)$/\1/p' "$host_out/analysis-stimulus.txt" 2>/dev/null)
passive_nsconflict=$(sed -n 's/^NAMESPACE+VENDOR same-word conflicts.*: \([0-9]*\)$/\1/p' "$host_out/analysis-passive.txt" 2>/dev/null)
passive_chainidx_bad=$(sed -n 's/^per-chain index values > 7.*: \([0-9]*\)$/\1/p' "$host_out/analysis-passive.txt" 2>/dev/null)

# Stimulus facts straight from the pcap via the analyzer module (no shell
# parsing of formatted report lines): real ACKs answering the injected TA,
# and whether the local monitor looped back our own injected frames.
stim_counts=$(python3 - "$host_out/stimulus.pcap" "$probe_ta" <<EOF
import sys
sys.path.insert(0, "$script_dir")
import analyze_radiotap_pcap as a
import struct
pcap, ta = sys.argv[1], bytes.fromhex(sys.argv[2].replace(":", ""))
acks_to_ta = acks_total = selftx = 0
try:
    pkts = a.parse_pcap(pcap)
except Exception as e:
    print(f"acks_to_probe_ta=0 acks_total=0 selftx_delivered=0 parse_error={e}")
    raise SystemExit(0)
for _, pkt in pkts:
    f, body, _ = a.parse_radiotap(pkt)
    if len(body) >= 2:
        fc = struct.unpack("<H", body[:2])[0]
        if (fc >> 2) & 3 == 1 and (fc >> 4) & 15 == 0xD and len(body) >= 10:
            acks_total += 1
            if body[4:10] == ta:
                acks_to_ta += 1
        if len(body) >= 10 and body[4:10] == ta:
            selftx += 1
print(f"acks_to_probe_ta={acks_to_ta} acks_total={acks_total} selftx_delivered={selftx}")
EOF
)
eval "$stim_counts"

[ -n "$passive_packets" ] && [ "$passive_packets" -gt 0 ] ||
	note_fail "passive analysis produced no packets"
[ -n "$passive_walk_bad" ] && [ "$passive_walk_bad" -eq 0 ] ||
	note_fail "passive pcap has radiotap layout walk mismatches: $passive_walk_bad"
[ -n "$stimulus_walk_bad" ] && [ "$stimulus_walk_bad" -eq 0 ] ||
	note_fail "stimulus pcap has radiotap layout walk mismatches: $stimulus_walk_bad"
[ -n "$passive_nsconflict" ] && [ "$passive_nsconflict" -eq 0 ] ||
	note_fail "passive pcap has NAMESPACE+VENDOR malformed frames: $passive_nsconflict"
[ -n "$passive_chainidx_bad" ] && [ "$passive_chainidx_bad" -eq 0 ] ||
	note_fail "passive pcap has misaligned per-chain pairs: $passive_chainidx_bad"
[ "${acks_to_probe_ta:-0}" -ge 1 ] ||
	note_fail "no real ACK to the injected TA found in the stimulus capture"

# teardown invariants
[ "$restore_rc" -eq 0 ] || note_fail "restore_managed rc=$restore_rc"
cmp -s "$host_out/boot-id-before.txt" "$host_out/boot-id-after.txt" ||
	note_fail "boot id changed mid-run"
# helper lifecycle gate: the pre-flip snapshot is the final monitor-mode
# ledger (the debugfs nodes disappear with the monitor adapter)
grep -q 'helper_present=0' "$host_out/teardown-stats.log" 2>/dev/null ||
	note_fail "helper still present in final monitor-mode snapshot"
grep -qx 'helper_wma_owner_mask=0x0' "$host_out/teardown-stats.log" 2>/dev/null ||
	note_fail "WMA owner ledger not zero in final monitor-mode snapshot"
# Fatal scan on the dmesg delta with the pattern calibrated by the chandef
# rounds: the full-mode monitor transition legitimately logs a PCIe PERST
# cycle ("Assert the reset"), theia watchdog actions and a cmdline echo,
# none of which are faults.
base_ts=$(sed -n 's/^\[[[:space:]]*\([0-9][0-9.]*\)\].*/\1/p' "$host_out/dmesg-before.log" | tail -n 1)
awk -v base="$base_ts" '$0 ~ /^\[/ { t=$0; gsub(/^\[[ ]*|[ ]*\].*/, "", t); if (t+0 > base+0) print }' \
	"$host_out/dmesg-after.log" 2>/dev/null >"$host_out/dmesg-delta.log"
fatal_markers=0
grep -Eq 'Kernel panic|CFI failure|Internal error|arm-smmu|spl_kmem_cache|subsystem-restart|WLAN recovery|cnss.*recovery|qdf_fatal|BUG:|Oops:' \
	"$host_out/dmesg-delta.log" && fatal_markers=1
[ "$fatal_markers" -eq 0 ] || note_fail "fatal markers in dmesg delta"
adb_shell 'ip link show mon0' >"$host_out/mon0-after.log" 2>&1 && note_fail "mon0 still present after restore"

# ---------------------------------------------------------------- result
verdict=FAIL
[ "$fail_count" -eq 0 ] && verdict=PASS
{
	echo "verdict=$verdict"
	echo "fail_count=$fail_count"
	echo "boot_id=$(tr -d ' \r\n' <"$host_out/boot-id-before.txt")"
	echo "passive_packets=${passive_packets:-0}"
	echo "stimulus_packets=${stimulus_packets:-0}"
	echo "stimulus_acks_to_probe_ta=${acks_to_probe_ta:-0}"
	echo "stimulus_acks_total=${acks_total:-0}"
	echo "selftx_delivered=${selftx_delivered:-0}"
	echo "stim_fw_completion_delta=$stim_fw_delta"
	echo "passive_walk_mismatches=${passive_walk_bad:-NA}"
	echo "stimulus_walk_mismatches=${stimulus_walk_bad:-NA}"
	echo "dmesg_fatal_markers=$fatal_markers"
	echo "evidence=$host_out"
} | tee "$host_out/result.txt"

echo
echo "evidence dir: $host_out"
[ "$verdict" = PASS ]
