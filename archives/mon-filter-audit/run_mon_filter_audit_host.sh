#!/usr/bin/env bash

# todo 4.5 monitor filter-mode audit for the frame_inject_monitor_filter
# debugfs knob (live DP advance-filter reprogram via cdp_set_monitor_filter).
# All facts are from the local monitor pcap (the RX filter contract is about
# what our own ring delivers); no OTA claim is made. Phases, each with a
# passive window on the lab AP channel:
#   P0 default   - knob untouched: node shows stock full masks; beacons
#                  visible; class mix recorded as the environment baseline;
#   P1 preset mgmt  - beacons still visible, data and ctrl frames excluded;
#   P2 preset ctrl  - injected unicast auth draws real OTA ACKs from the AP
#                  (ctrl pass-through) while beacons are excluded (mgmt
#                  filtered) - both directions of the filter proven;
#   P3 persistence  - preset mgmt survives a full persona flip
#                  (monitor -> managed -> monitor): beacons visible, and the
#                  drawn ACK must NOT appear (ctrl still filtered after
#                  re-entry);
#   P4 restore   - back to full, managed persona restored, Wi-Fi reconnected
#                  and VALIDATED, ledger zero, boot id unchanged, no fatal
#                  markers in the dmesg delta.
# Environment caveat handled honestly: if P0 sees no background data frames,
# "data excluded" in P1/P2 is env-limited (reported, not failed).

set -uo pipefail

expected_build_id=ec49943d8a798a4c10023378bf9059de9a28a67c
expected_source_rev=93896078f500+dirty-20260903-4.2-chandef-hop-survey-v12
expected_stats_format=9
expected_sender_sha256=c2795e6b612c065fd464a97251276ad61c0f7a5484bd7d4767fdd882adc10afc
knob_path=/sys/module/qca_cld3_peach_v2/parameters/frame_inject_constructed_context
probe_ta=02:11:22:33:44:55
probe_ta_hex=021122334455
passive_seconds=25
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

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
sender=$script_dir/../device-suite-wmi-stage1-matrix/send_stage1_packet
analyzer=$script_dir/../rx-radiotap-audit/analyze_radiotap_pcap.py
[ -x "$sender" ] && [ -r "$analyzer" ] || { echo "missing sender or analyzer" >&2; exit 3; }
python3 "$analyzer" --selftest >/dev/null || { echo "analyzer selftest failed" >&2; exit 3; }
sender_sha=$(sha256sum "$sender" | awk '{print $1}')
[ "$sender_sha" = "$expected_sender_sha256" ] || { echo "sender sha mismatch: $sender_sha" >&2; exit 3; }

stamp=$(date -u +%Y%m%dT%H%M%SZ)
host_out=$script_dir/host-capture-mon-filter-$stamp-$$
mkdir -p "$host_out" || exit 3

adb_cmd=(adb -s "$serial")
adb_shell()
{
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

filter_node=/sys/kernel/debug/wlan0/frame_inject_monitor_filter

filter_get() # key from the filter node text on stdin
{
	awk -F= -v key="$1" '$1 == key { print $2 }' | tail -n 1
}

filter_write() # mode -> 0 on success (write + last_status gate)
{
	local mode=$1 rc
	adb_shell "echo $mode > $filter_node" >"$host_out/filter-write-$mode.log" 2>&1
	rc=$?
	[ "$rc" -eq 0 ] || return 1
	adb_shell "cat $filter_node" >"$host_out/filter-after-$mode.log" 2>&1
	[ "$(filter_get last_status <"$host_out/filter-after-$mode.log")" = 0 ]
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

# class counts from a pcap via the shared analyzer module: mgmt/ctrl/data
# totals, beacons carrying the target BSSID, real ACKs to the injected TA,
# and self-TX loopback visibility (observation only).
count_classes() # pcap -> key=val lines on stdout
{
	python3 - "$1" "$target_bssid_hex" "$probe_ta_hex" <<EOF
import sys
sys.path.insert(0, "$script_dir/../rx-radiotap-audit")
import analyze_radiotap_pcap as a
import struct
pcap, bssid, ta = sys.argv[1], bytes.fromhex(sys.argv[2]), bytes.fromhex(sys.argv[3])
mgmt = ctrl = data = beacons = acks_total = acks_ta = selftx = mgmt_noself = 0
try:
    pkts = a.parse_pcap(pcap)
except Exception as e:
    print(f"parse_error={e} mgmt=0 ctrl=0 data=0 beacons=0 acks_total=0 acks_ta=0 selftx=0 mgmt_noself=0")
    raise SystemExit(0)
for _, pkt in pkts:
    f, body, _ = a.parse_radiotap(pkt)
    if len(body) < 2:
        continue
    fc = struct.unpack("<H", body[:2])[0]
    ftype = (fc >> 2) & 3
    subtype = (fc >> 4) & 15
    from_ta = len(body) >= 16 and body[10:16] == ta
    if ftype == 0:
        mgmt += 1
        if not from_ta:
            mgmt_noself += 1
        if subtype == 8 and len(body) >= 16 and (body[10:16] == bssid or body[16:22] == bssid):
            beacons += 1
    elif ftype == 1:
        ctrl += 1
        if subtype == 0xD and len(body) >= 10:
            acks_total += 1
            if body[4:10] == ta:
                acks_ta += 1
    elif ftype == 2:
        data += 1
    if from_ta:
        selftx += 1
print(f"mgmt={mgmt} ctrl={ctrl} data={data} beacons={beacons} acks_total={acks_total} acks_ta={acks_ta} selftx={selftx} mgmt_noself={mgmt_noself}")
EOF
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
	echo "baseline: Wi-Fi must be connected" >&2
	exit 4
	}
grep -q 'VALIDATED' "$host_out/wifi-before.log" || exit 4
grep -q "$target_bssid" "$host_out/wifi-before.log" ||
	{ echo "baseline: not connected to target bssid" >&2; exit 4; }
before_ifindex=$(adb_shell 'cat /sys/class/net/wlan0/ifindex' 2>/dev/null | tr -d ' \r\n')
[ -n "$before_ifindex" ] || exit 4
adb_shell 'input keyevent KEYCODE_WAKEUP' >/dev/null 2>&1 || true
adb_shell 'svc power stayon usb' >"$host_out/stayon.log" 2>&1 || true
sleep 3
adb_shell 'dmesg' >"$host_out/dmesg-before.log" 2>&1 || true

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

reclaim_helper()
{
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
		# frame_inject nodes exist only on the monitor adapter: bring the
		# helper down via one idle reclaim, then snapshot the final ledger
		# before the flip.
		reclaim_helper || rc=1
		stats >"$host_out/teardown-stats.log" 2>&1 || rc=1
		adb_shell "cat $filter_node" >"$host_out/teardown-filter-node.log" 2>&1 || rc=1
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

enter_monitor()
{
	# (re)enter the monitor persona on the lab AP chandef; old ifindex from
	# the caller. Returns 0 when stable.
	local old_ifindex=$1 tag=$2
	adb_shell 'cmd wifi set-wifi-enabled disabled' >>"$host_out/disable-wifi.log" 2>&1 || return 1
	local settled=0 off_status off_supp
	for _ in $(seq 1 120); do
		off_status=$(adb_shell 'cmd wifi status' 2>/dev/null | tr -d '\r')
		off_supp=$(adb_shell 'pidof wpa_supplicant' 2>/dev/null | tr -d '\r\n')
		if grep -q '^Wifi is disabled$' <<<"$off_status" && [ -z "$off_supp" ]; then
			settled=1
			break
		fi
		sleep 0.5
	done
	[ "$settled" -eq 1 ] || return 1
	adb_shell 'iw dev wlan0 set type monitor' >>"$host_out/set-monitor-$tag.log" 2>&1 || return 1
	wait_persona monitor "$old_ifindex" "$host_out/monitor-info-$tag.log" || return 1
	adb_shell 'ip link set wlan0 up' >>"$host_out/ifup-monitor-$tag.log" 2>&1 || return 1
	local n=0
	until adb_shell "iw dev wlan0 set freq $before_freq $before_width $before_center1" \
		>>"$host_out/set-ap-channel-$tag.log" 2>&1; do
		n=$((n + 1))
		[ "$n" -lt 100 ] || return 1
		sleep 0.2
	done
	local attempt hold
	for attempt in 1 2 3; do
		hold=1
		for _ in $(seq 1 10); do
			read_state
			[ "$state_type" = monitor ] || { hold=0; break; }
			sleep 0.5
		done
		[ "$hold" -eq 1 ] && return 0
		[ "$attempt" -lt 3 ] || return 1
		adb_shell 'cmd wifi set-wifi-enabled disabled' >/dev/null 2>&1 || true
		adb_shell 'iw dev wlan0 set type monitor' >/dev/null 2>&1 || true
		adb_shell 'ip link set wlan0 up' >/dev/null 2>&1 || true
		adb_shell "iw dev wlan0 set freq $before_freq $before_width $before_center1" >/dev/null 2>&1 || true
	done
	return 1
}

enter_monitor "$before_ifindex" main || { echo "monitor entry failed" >&2; exit 5; }

ready_stats=$(stats)
printf '%s\n' "$ready_stats" >"$host_out/monitor-ready-stats.log" 2>&1
grep -qx 'state=ready' <<<"$ready_stats" || { echo "ctx not ready" >&2; exit 5; }
[ "$(printf '%s\n' "$ready_stats" | sv source_rev)" = "$expected_source_rev" ] || {
	echo "source_rev mismatch" >&2
	exit 5
}
loaded_note=$("${adb_cmd[@]}" exec-out su -c 'od -An -v -tx1 /sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id' | tr -d ' \r\n')
case $loaded_note in *"$expected_build_id"*) ;; *)
	echo "loaded module build id mismatch" >&2
	exit 5
	;;
esac

adb_shell "cat $filter_node" >"$host_out/filter-node-P0.log" 2>&1 ||
	{ echo "monitor filter node missing" >&2; exit 5; }

remote_dir=/data/local/tmp/qcacld-mon-filter-$$
adb_shell "mkdir -p $remote_dir" >"$host_out/push-sender.log" 2>&1 || exit 5
"${adb_cmd[@]}" push "$sender" $remote_dir/send_stage1_packet >>"$host_out/push-sender.log" 2>&1 || exit 5
adb_shell "chmod 0755 $remote_dir/send_stage1_packet" >>"$host_out/push-sender.log" 2>&1 || exit 5

capture() # phase out.pcap -> sender log at $host_out/capture-<phase>.log
{
	adb_shell "$remote_dir/send_stage1_packet --capture-bssid wlan0 $target_bssid $passive_seconds $remote_dir/$2" \
		>"$host_out/capture-$1.log" 2>&1
}

# ---------------------------------------------------------------- P0 default
p0_apply_before=$(filter_get apply_count <"$host_out/filter-node-P0.log")
capture p0 p0.pcap
grep -q 'capture=PASS' "$host_out/capture-p0.log" ||
	note_fail "P0 capture failed"
"${adb_cmd[@]}" pull $remote_dir/p0.pcap "$host_out/p0.pcap" >>"$host_out/pull.log" 2>&1 ||
	note_fail "pull p0.pcap"
eval "$(count_classes "$host_out/p0.pcap")"
echo "P0 classes: $mgmt mgmt, $ctrl ctrl, $data data, $beacons beacons" | tee "$host_out/p0-classes.txt"
[ "$beacons" -ge 1 ] || note_fail "P0 default full: no target beacons delivered"
[ "$(filter_get name <"$host_out/filter-node-P0.log")" = full ] ||
	note_fail "P0 node: name is not full"
# configured=1 with name=full is the legitimate restored state of a previous
# run in the same boot; the invariant is "sitting at stock full".
[ "$(filter_get name <"$host_out/filter-node-P0.log")" = full ] ||
	note_fail "P0 node: not at stock full"
# stock full masks (peach FP_MGMT_FILTER = 0xffff & ~(BEACON|PROBE_RES) = 0xfedf)
[ "$(filter_get mode <"$host_out/filter-node-P0.log")" = "0x0003" ] ||
	note_fail "P0 node: mode is not 0x0003"
[ "$(filter_get fp_mgmt <"$host_out/filter-node-P0.log")" = "0xfedf" ] ||
	note_fail "P0 node: fp_mgmt is not the peach stock 0xfedf"
[ "$(filter_get fp_ctrl <"$host_out/filter-node-P0.log")" = "0xffff" ] ||
	note_fail "P0 node: fp_ctrl not stock"
[ "$(filter_get mo_mgmt <"$host_out/filter-node-P0.log")" = "0xffff" ] ||
	note_fail "P0 node: mo_mgmt not stock"
env_data_baseline=$data

# ---------------------------------------------------------------- P1 preset mgmt
filter_write mgmt || note_fail "P1 write mgmt failed (write rc or last_status)"
[ "$(filter_get name <"$host_out/filter-after-mgmt.log")" = mgmt ] ||
	note_fail "P1 node: name not mgmt"
[ "$(filter_get configured <"$host_out/filter-after-mgmt.log")" = 1 ] ||
	note_fail "P1 node: configured not 1"
[ "$(filter_get fp_ctrl <"$host_out/filter-after-mgmt.log")" = "0x0000" ] ||
	note_fail "P1 node: fp_ctrl not 0"
[ "$(filter_get fallback_status <"$host_out/filter-after-mgmt.log")" = 0 ] ||
	note_fail "P1 node: fallback fired"
capture p1 p1.pcap
"${adb_cmd[@]}" pull $remote_dir/p1.pcap "$host_out/p1.pcap" >>"$host_out/pull.log" 2>&1 ||
	note_fail "pull p1.pcap"
eval "$(count_classes "$host_out/p1.pcap")"
echo "P1 classes: $mgmt mgmt, $ctrl ctrl, $data data, $beacons beacons" | tee "$host_out/p1-classes.txt"
[ "$beacons" -ge 1 ] || note_fail "P1 mgmt preset: beacons no longer delivered"
[ "$ctrl" -eq 0 ] || note_fail "P1 mgmt preset: $ctrl ctrl frames delivered (filter not applied)"
[ "$data" -eq 0 ] || note_fail "P1 mgmt preset: $data data frames delivered (filter not applied)"

# ---------------------------------------------------------------- P2 preset ctrl + stimulus
filter_write ctrl || note_fail "P2 write ctrl failed"
capture p2 p2.pcap &
p2_pid=$!
sleep 5
stim_fw_before=$(printf '%s\n' "$(stats 2>/dev/null)" | sv fw_completion_events)
adb_shell "$remote_dir/send_stage1_packet --send wlan0 $probe_unicast_hex" \
	>"$host_out/send-p2.log" 2>&1
send_p2_rc=$?
wait "$p2_pid"
stats >"$host_out/stats-after-p2.log" 2>&1
stim_fw_after=$(printf '%s\n' "$(stats 2>/dev/null)" | sv fw_completion_events)
p2_fw_delta=$((stim_fw_after - stim_fw_before))
"${adb_cmd[@]}" pull $remote_dir/p2.pcap "$host_out/p2.pcap" >>"$host_out/pull.log" 2>&1 ||
	note_fail "pull p2.pcap"
eval "$(count_classes "$host_out/p2.pcap")"
echo "P2 classes: $mgmt mgmt, $ctrl ctrl, $data data, $beacons beacons, acks_ta $acks_ta" | tee "$host_out/p2-classes.txt"
p2_acks_ta=$acks_ta
[ "$send_p2_rc" -eq 0 ] || note_fail "P2 injection rc=$send_p2_rc"
[ "$p2_fw_delta" -ge 1 ] || note_fail "P2: no FW completion for the injected frame"
[ "$acks_ta" -ge 1 ] || note_fail "P2 ctrl preset: no real ACK to injected TA delivered"
[ "$beacons" -eq 0 ] || note_fail "P2 ctrl preset: $beacons beacons delivered (mgmt not filtered)"
[ "$mgmt_noself" -eq 0 ] || note_fail "P2 ctrl preset: $mgmt_noself mgmt frames delivered beyond own loopback"
[ "$data" -eq 0 ] || note_fail "P2 ctrl preset: $data data frames delivered"

# ---------------------------------------------------------------- P3 persistence across persona flip
filter_write mgmt || note_fail "P3 write mgmt failed"
monitor_ifindex=$(adb_shell 'cat /sys/class/net/wlan0/ifindex' 2>/dev/null | tr -d ' \r\n')
adb_shell 'iw dev wlan0 set type managed' >"$host_out/flip-managed.log" 2>&1 ||
	note_fail "P3 flip to managed failed"
wait_persona managed "$monitor_ifindex" "$host_out/flip-managed-info.log" ||
	note_fail "P3 managed persona never appeared"
p3_mid_ifindex=$(adb_shell 'cat /sys/class/net/wlan0/ifindex' 2>/dev/null | tr -d ' \r\n')
enter_monitor "$p3_mid_ifindex" reentry || note_fail "P3 monitor re-entry failed"
adb_shell "cat $filter_node" >"$host_out/filter-node-P3.log" 2>&1 ||
	note_fail "P3 filter node missing after re-entry"
[ "$(filter_get name <"$host_out/filter-node-P3.log")" = mgmt ] ||
	note_fail "P3 node: name did not persist as mgmt"
[ "$(filter_get configured <"$host_out/filter-node-P3.log")" = 1 ] ||
	note_fail "P3 node: configured flag lost"
p3_apply=$(filter_get apply_count <"$host_out/filter-node-P3.log")
p3_apply_delta=$((p3_apply - p0_apply_before))
[ "$p3_apply_delta" -ge 4 ] ||
	note_fail "P3 apply_count delta $p3_apply_delta (expected >=4: 3 writes + re-entry apply)"
# The persona flip dropped the managed template, so the next injection runs on
# the constructed context, whose contract is 20 MHz only; the re-entry chandef
# above restored the AP's 80 MHz and the injection would be precisely refused
# with drop_reason_context. Drop to HT20 for the P3 stimulus (beacon visibility
# is bandwidth-independent).
adb_shell "iw dev wlan0 set freq $before_freq" >>"$host_out/set-p3-ht20.log" 2>&1 ||
	note_fail "P3 20 MHz chandef set failed"
capture p3 p3.pcap &
p3_pid=$!
sleep 5
stim_fw_before=$(printf '%s\n' "$(stats 2>/dev/null)" | sv fw_completion_events)
adb_shell "$remote_dir/send_stage1_packet --send wlan0 $probe_unicast_hex" \
	>"$host_out/send-p3.log" 2>&1
send_p3_rc=$?
wait "$p3_pid"
sleep 3
stim_fw_after=$(printf '%s\n' "$(stats 2>/dev/null)" | sv fw_completion_events)
stats >"$host_out/stats-after-p3.log" 2>&1
p3_fw_delta=$((stim_fw_after - stim_fw_before))
"${adb_cmd[@]}" pull $remote_dir/p3.pcap "$host_out/p3.pcap" >>"$host_out/pull.log" 2>&1 ||
	note_fail "pull p3.pcap"
eval "$(count_classes "$host_out/p3.pcap")"
echo "P3 classes: $mgmt mgmt, $ctrl ctrl, $data data, $beacons beacons, acks_ta $acks_ta, selftx $selftx" | tee "$host_out/p3-classes.txt"
[ "$send_p3_rc" -eq 0 ] || note_fail "P3 injection rc=$send_p3_rc"
[ "$p3_fw_delta" -ge 1 ] || note_fail "P3: no FW completion for the injected frame"
[ "$beacons" -ge 1 ] || note_fail "P3 re-entry: beacons not delivered (monitor RX broken)"
[ "$acks_ta" -eq 0 ] ||
	note_fail "P3 re-entry: ACK to injected TA delivered - mgmt mode did not survive the flip"
[ "$ctrl" -eq 0 ] ||
	note_fail "P3 re-entry: $ctrl ctrl frames delivered - mgmt mode did not survive the flip"

# ---------------------------------------------------------------- P4 restore + teardown
filter_write full || note_fail "P4 write full failed"
[ "$(filter_get name <"$host_out/filter-after-full.log")" = full ] ||
	note_fail "P4 node: name not full"

restore_managed
restore_rc=$?

adb_shell "rm -rf $remote_dir" >>"$host_out/pull.log" 2>&1 || true

# teardown invariants
[ "$restore_rc" -eq 0 ] || note_fail "restore_managed rc=$restore_rc"
cmp -s "$host_out/boot-id-before.txt" "$host_out/boot-id-after.txt" ||
	note_fail "boot id changed mid-run"
grep -q 'helper_present=0' "$host_out/teardown-stats.log" 2>/dev/null ||
	note_fail "helper still present in final monitor-mode snapshot"
grep -qx 'helper_wma_owner_mask=0x0' "$host_out/teardown-stats.log" 2>/dev/null ||
	note_fail "WMA owner ledger not zero in final monitor-mode snapshot"
[ "$(filter_get name <"$host_out/teardown-filter-node.log" 2>/dev/null)" = full ] ||
	note_fail "teardown snapshot: filter node not left at full"
base_ts=$(sed -n 's/^\[[[:space:]]*\([0-9][0-9.]*\)\].*/\1/p' "$host_out/dmesg-before.log" | tail -n 1)
awk -v base="$base_ts" '$0 ~ /^\[/ { t=$0; gsub(/^\[[ ]*|[ ]*\].*/, "", t); if (t+0 > base+0) print }' \
	"$host_out/dmesg-after.log" 2>/dev/null >"$host_out/dmesg-delta.log"
fatal_markers=0
grep -Eq 'Kernel panic|CFI failure|Internal error|arm-smmu|spl_kmem_cache|subsystem-restart|WLAN recovery|cnss.*recovery|qdf_fatal|BUG:|Oops:' \
	"$host_out/dmesg-delta.log" && fatal_markers=1
[ "$fatal_markers" -eq 0 ] || note_fail "fatal markers in dmesg delta"
adb_shell 'ip link show mon0' >"$host_out/mon0-after.log" 2>&1 && note_fail "mon0 still present after restore"

if [ "$env_data_baseline" -gt 0 ]; then data_exclusion=env_proven; else data_exclusion=env_limited; fi

verdict=FAIL
[ "$fail_count" -eq 0 ] && verdict=PASS
{
	echo "verdict=$verdict"
	echo "fail_count=$fail_count"
	echo "boot_id=$(tr -d ' \r\n' <"$host_out/boot-id-before.txt")"
	echo "data_exclusion=$data_exclusion (P0 baseline data=$env_data_baseline)"
	echo "p2_acks_to_probe_ta=${p2_acks_ta:-0}"
	echo "p2_fw_completion_delta=$p2_fw_delta"
	echo "p3_fw_completion_delta=$p3_fw_delta"
	echo "p3_selftx_delivered=${selftx:-0}"
	echo "apply_count_delta=$p3_apply_delta"
	echo "dmesg_fatal_markers=$fatal_markers"
	echo "evidence=$host_out"
} | tee "$host_out/result.txt"

echo
echo "evidence dir: $host_out"
[ "$verdict" = PASS ]
