#!/usr/bin/env bash

# probe-req A/B adjudication for the aireplay --test "No Answer" outcome.
# v6 proved explicit chanfreq alone does not put aireplay's wildcard
# broadcast probe requests on the air (or the AP ignores them). Two live
# hypotheses must be separated before any further driver change:
#   H1 AP policy - the lab AP answers directed probes (it answered 20+ in
#      window during r4-r6, all to real clients) but ignores wildcard
#      broadcast probes;
#   H2 FW subtype handling - mgmt_tx probe requests are silently completed
#      without transmission (deauth broadcasts echoed in the rx-audit
#      rounds, so neither broadcast nor the WMI path as a whole is broken).
# Three sender frames on the lab channel, one side capture adjudicates:
#   A directed unicast probe req (dst/BSSID=AP, SSID=lab ESSID) - the AP
#     answers directed probes, so a response proves the whole probe-req TX
#     chain end to end;
#   B wildcard broadcast probe req (dst/BSSID=ff:.., empty SSID) - the
#     aireplay --test frame class;
#   C broadcast deauth - self-TX loopback positive control.
# Facts come from the local monitor pcap plus the driver stats counters;
# no OTA claim is made beyond what the AP itself answers.

set -uo pipefail

expected_build_id=ec49943d8a798a4c10023378bf9059de9a28a67c
expected_source_rev=93896078f500+dirty-20260903-4.2-chandef-hop-survey-v12
expected_sender_sha256=c2795e6b612c065fd464a97251276ad61c0f7a5484bd7d4767fdd882adc10afc
knob_path=/sys/module/qca_cld3_peach_v2/parameters/frame_inject_constructed_context
probe_ta=02:11:22:33:44:55
probe_ta_hex=021122334455
lab_freq=5745
tp=/data/data/com.termux/files/usr
tool_env="env LD_LIBRARY_PATH=$tp/lib HOME=/data/data/com.termux/files/home PATH=$tp/bin:/system/bin"
fail_count=0

usage()
{
	echo "usage: $0 --serial SERIAL --target-bssid BSSID --essid ESSID --authorized-isolated-lab" >&2
	exit 2
}

serial=
target_bssid=
essid=
authorized=0
while [ "$#" -gt 0 ]; do
	case $1 in
	--serial) [ "$#" -ge 2 ] || usage; serial=$2; shift 2 ;;
	--target-bssid) [ "$#" -ge 2 ] || usage; target_bssid=$2; shift 2 ;;
	--essid) [ "$#" -ge 2 ] || usage; essid=$2; shift 2 ;;
	--authorized-isolated-lab) authorized=1; shift ;;
	*) usage ;;
	esac
done

[ -n "$serial" ] && [ -n "$target_bssid" ] && [ -n "$essid" ] && [ "$authorized" -eq 1 ] || usage
[[ "$target_bssid" =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ ]] || usage
target_bssid_hex=$(printf '%s' "$target_bssid" | tr -d ':')

# frame assembly ------------------------------------------------------------
# the sender's --send hex starts with a minimal 8-byte radiotap header
# (version 0, it_len 8, no presence bits) followed by the raw 802.11 frame;
# the same shape as the mon-filter/rx-audit stimulus frames
rtap_null=0000080000000000
# supported rates IE (id=1 len=8: 6,9,12,18,24,36,48,54 Mbps x2)
rates_ie_hex=01080c121824304860606c
essid_hex=$(printf '%s' "$essid" | od -An -v -tx1 | tr -d ' \n')
essid_len=$(printf '%s' "$essid" | wc -c)
# A: directed unicast probe req (dst=AP, ta, bssid=AP)
frame_a_hex="${rtap_null}40000000${target_bssid_hex}${probe_ta_hex}${target_bssid_hex}000000$(printf '%02x' "$essid_len")${essid_hex}${rates_ie_hex}"
# B: wildcard broadcast probe req (dst=ff.., bssid=ff.., empty SSID IE)
frame_b_hex="${rtap_null}40000000ffffffffffff${probe_ta_hex}ffffffffffff0000000000${rates_ie_hex}"
# C: broadcast deauth, reason 3 (26B, the rx-audit positive-control class)
frame_c_hex="${rtap_null}c0000000ffffffffffff${probe_ta_hex}ffffffffffff00000300"
# D: directed unicast probe req with WILDCARD SSID (isolates the SSID
# variable from the broadcast-dst variable of frame B)
frame_d_hex="${rtap_null}40000000${target_bssid_hex}${probe_ta_hex}${target_bssid_hex}0000000000${rates_ie_hex}"
# E: broadcast probe req with the SPECIFIC lab SSID (the other isolation)
frame_e_hex="${rtap_null}40000000ffffffffffff${probe_ta_hex}ffffffffffff000000$(printf '%02x' "$essid_len")${essid_hex}${rates_ie_hex}"

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
sender=$script_dir/../device-suite-wmi-stage1-matrix/send_stage1_packet
analyzer=$script_dir/../rx-radiotap-audit/analyze_radiotap_pcap.py
[ -x "$sender" ] && [ -r "$analyzer" ] || { echo "missing sender or analyzer" >&2; exit 3; }
python3 "$analyzer" --selftest >/dev/null || { echo "analyzer selftest failed" >&2; exit 3; }
sender_sha=$(sha256sum "$sender" | awk '{print $1}')
[ "$sender_sha" = "$expected_sender_sha256" ] || { echo "sender sha mismatch: $sender_sha" >&2; exit 3; }

stamp=$(date -u +%Y%m%dT%H%M%SZ)
host_out=$script_dir/host-capture-probe-ab-$stamp-$$
mkdir -p "$host_out" || exit 3
remote_dir=/data/local/tmp/probe-ab-$$

adb_cmd=(adb -s "$serial")
adb_shell()
{
	"${adb_cmd[@]}" shell su -c "$1" </dev/null
}

sv()
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
}

wait_persona()
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

note_obs()
{
	echo "obs: $*" | tee -a "$host_out/observations.txt"
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

mounted_debugfs=0
debugfs_type=$(adb_shell 'stat -f -c %T /sys/kernel/debug' 2>/dev/null | tr -d ' \r\n')
if [ "$debugfs_type" != 0x64626720 ] && [ "$debugfs_type" != debugfs ]; then
	adb_shell 'mount -t debugfs debugfs /sys/kernel/debug' >"$host_out/mount-debugfs.log" 2>&1 || exit 4
	mounted_debugfs=1
fi

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
			reconnected=1
			break
		fi
		sleep 0.5
	done
	[ "$reconnected" -eq 1 ] || rc=1
	adb_shell "rm -rf $remote_dir" >/dev/null 2>&1 || true
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

# ---------------------------------------------------------------- entry
enter_monitor()
{
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
	until adb_shell "iw dev wlan0 set freq $lab_freq" >>"$host_out/set-freq-$tag.log" 2>&1; do
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
		adb_shell "iw dev wlan0 set freq $lab_freq" >/dev/null 2>&1 || true
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
adb_shell "mkdir -p $remote_dir" >/dev/null 2>&1 || exit 5
"${adb_cmd[@]}" push "$sender" "$remote_dir/send_stage1_packet" >"$host_out/push.log" 2>&1 || exit 5
adb_shell "chmod 0755 $remote_dir/send_stage1_packet" >>"$host_out/push.log" 2>&1 || exit 5

# ---------------------------------------------------------------- sends + side capture
stats >"$host_out/stats-before.log" 2>&1
sub_before=$(printf '%s\n' "$(stats 2>/dev/null)" | sv wmi_submitted)
fw_before=$(printf '%s\n' "$(stats 2>/dev/null)" | sv fw_completion_events)

"${adb_cmd[@]}" shell su -c "timeout -k 5 -s INT 70 $tool_env $tp/bin/tcpdump -i wlan0 -s 0 -U -w $remote_dir/ab.pcap" \
	</dev/null >"$host_out/tcpdump.log" 2>&1 &
cap_pid=$!

send_one() # tag hex -> rc from sender
{
	local tag=$1 hex=$2 rc
	adb_shell "$remote_dir/send_stage1_packet --send wlan0 $hex" >"$host_out/send-$tag.log" 2>&1
	rc=$?
	sleep 4
	return $rc
}
send_one a "$frame_a_hex" || note_fail "A directed probe req send rc!=0"
send_one b "$frame_b_hex" || note_fail "B broadcast probe req send rc!=0"
send_one c "$frame_c_hex" || note_fail "C broadcast deauth send rc!=0"
send_one d "$frame_d_hex" || note_fail "D directed wildcard-SSID probe req send rc!=0"
send_one e "$frame_e_hex" || note_fail "E broadcast specific-SSID probe req send rc!=0"

# pass 2: same shapes with the interface MAC as TA (the aireplay identity;
# the helper vdev may carry this same MAC - suspected FW self-TA guard)
iface_mac=$(sed -n 's/^[[:space:]]*addr \(\([[:xdigit:]]\{2\}:\)\{5\}[[:xdigit:]]\{2\}\).*/\1/p' \
	"$host_out/monitor-info-main.log" 2>/dev/null | head -n 1)
iface_ta_hex=$(printf '%s' "$iface_mac" | tr -d ':')
echo "iface_mac=$iface_mac" | tee "$host_out/iface-mac.txt"
frame_f_hex="${rtap_null}40000000ffffffffffff${iface_ta_hex}ffffffffffff0000000000${rates_ie_hex}"
frame_g_hex="${rtap_null}40000000${target_bssid_hex}${iface_ta_hex}${target_bssid_hex}000000$(printf '%02x' "$essid_len")${essid_hex}${rates_ie_hex}"
if [ -n "$iface_ta_hex" ] && [ "${#iface_ta_hex}" -eq 12 ]; then
	send_one f "$frame_f_hex" || note_fail "F bcast wildcard probe req (iface TA) send rc!=0"
	send_one g "$frame_g_hex" || note_fail "G directed probe req (iface TA) send rc!=0"
else
	note_fail "could not read monitor iface MAC for pass 2"
fi

wait "$cap_pid" 2>/dev/null || true
stats >"$host_out/stats-after.log" 2>&1
sub_after=$(printf '%s\n' "$(stats 2>/dev/null)" | sv wmi_submitted)
fw_after=$(printf '%s\n' "$(stats 2>/dev/null)" | sv fw_completion_events)
sub_delta=$((sub_after - sub_before))
fw_delta=$((fw_after - fw_before))
echo "submit_delta=$sub_delta fw_delta=$fw_delta (expected 7/7)" | tee "$host_out/deltas.txt"
[ "$sub_delta" -eq 7 ] || note_fail "expected 7 submits, got $sub_delta"
[ "$fw_delta" -eq 7 ] || note_fail "expected 7 completions, got $fw_delta"

read_state
[ "$state_type" = monitor ] || note_fail "persona lost mid-run"

"${adb_cmd[@]}" pull "$remote_dir/ab.pcap" "$host_out/ab.pcap" >"$host_out/pull.log" 2>&1 ||
	note_fail "side capture missing"

# ---------------------------------------------------------------- adjudication
if [ -r "$host_out/ab.pcap" ]; then
	adj=$(python3 - "$host_out/ab.pcap" "$probe_ta_hex" "$target_bssid_hex" "$iface_ta_hex" <<EOF
import struct, sys
sys.path.insert(0, "$script_dir/../rx-radiotap-audit")
import analyze_radiotap_pcap as a
ta = bytes.fromhex(sys.argv[2])
ap = bytes.fromhex(sys.argv[3])
ita = bytes.fromhex(sys.argv[4]) if len(sys.argv) > 4 and sys.argv[4] else None
echo = {"A": 0, "B": 0, "D": 0, "E": 0, "F": 0, "G": 0}
resps_probe = resps_iface = acks_probe = acks_iface = 0
echo_deauth = beacons = others = 0
def classify(body):
    dst = bytes(body[4:10])
    ssid_present = len(body) > 26 and body[24] == 0 and body[25] > 0
    if dst == ap:
        return ("D" if not ssid_present else "A") + "_unicast"
    return ("B" if not ssid_present else "E") + "_bcast"
for _, pkt in a.parse_pcap(sys.argv[1]):
    f, body, _ = a.parse_radiotap(pkt)
    if len(body) < 10:
        continue
    fc = struct.unpack("<H", body[:2])[0]
    ftype = (fc >> 2) & 3
    subtype = (fc >> 4) & 15
    ra = bytes(body[4:10])
    frame_ta = bytes(body[10:16]) if len(body) >= 16 else b""
    if ftype == 0:
        if subtype == 4:
            if frame_ta == ta:
                echo[classify(body)[0]] += 1
            elif ita and frame_ta == ita:
                echo["G" if ra == ap else "F"] += 1
            else:
                others += 1
        elif subtype == 5:
            if ra == ta:
                resps_probe += 1
            elif ita and ra == ita:
                resps_iface += 1
        elif subtype == 8:
            beacons += 1
        elif subtype == 12 and frame_ta == ta:
            echo_deauth += 1
    elif ftype == 1 and subtype == 0xD:
        if ra == ta:
            acks_probe += 1
        elif ita and ra == ita:
            acks_iface += 1
print("echo_A_unicast_ssid=%d echo_B_bcast_wild=%d echo_D_unicast_wild=%d echo_E_bcast_ssid=%d echo_F_bcast_wild_iface_ta=%d echo_G_unicast_ssid_iface_ta=%d" %
      (echo["A"], echo["B"], echo["D"], echo["E"], echo["F"], echo["G"]))
print(f"echo_deauth={echo_deauth} resps_probe_ta={resps_probe} resps_iface_ta={resps_iface} acks_probe_ta={acks_probe} acks_iface_ta={acks_iface} beacons={beacons} other_probe_reqs={others}")
EOF
	)
	printf '%s\n' "$adj" | tee "$host_out/adjudication.txt"
	kv()
	{
		sed -n "s/.*\(^\|[^_[:alnum:]]\)$2=\([^ =]*\).*/\2/p;s/^$2=\([^ =]*\).*/\1/p" <<<"$1" | head -n 1
	}
	resps=$(kv "$adj" resps_probe_ta)
	acks=$(kv "$adj" acks_probe_ta)
	resps_if=$(kv "$adj" resps_iface_ta)
	acks_if=$(kv "$adj" acks_iface_ta)
	echo_deauth=$(kv "$adj" echo_deauth)
	beacons=$(kv "$adj" beacons)
	total_echo=$(grep -o 'echo_[A-G][^=]*=[0-9]*' <<<"$adj" | awk -F= '{ s += $2 } END { print s + 0 }')
	[ "${beacons:-0}" -ge 1 ] 2>/dev/null || note_fail "side capture saw 0 beacons (capture broken)"
	[ "${echo_deauth:-0}" -ge 1 ] 2>/dev/null ||
		note_fail "C control failed: broadcast deauth did not loop back (self-TX echo broken this run)"
	# echo loopback is per-frame flaky (~75-80%); the end-to-end OTA proof is
	# the AP answering and ACKing, not the echo of any single frame
	if [ "${resps:-0}" -ge 1 ] 2>/dev/null && [ "${acks:-0}" -ge 1 ] 2>/dev/null; then
		a_verdict=answered
		note_obs "probe_ta frames: AP answered (${resps} responses) and ACKed (${acks}) - probe-req TX OTA-proven (echo total ${total_echo})"
	else
		a_verdict=silent
		note_fail "probe_ta frames: no AP response (${resps:-0}) / no ACK (${acks:-0})"
	fi
	for key in A B D E F G; do
		n=$(kv "$adj" "echo_${key}_[a-z_]*" 2>/dev/null)
		n=$(grep -o "echo_${key}_[a-z_]*=[0-9]*" <<<"$adj" | head -n 1 | awk -F= '{ print $2 }')
		if [ "${n:-0}" -ge 1 ] 2>/dev/null; then
			note_obs "frame $key: echoed (transmitted)"
		else
			note_obs "frame $key: NOT echoed this run"
		fi
	done
	if [ "${resps_if:-0}" -ge 1 ] 2>/dev/null || [ "${acks_if:-0}" -ge 1 ] 2>/dev/null; then
		note_obs "iface-TA frames (F/G): AP answered (${resps_if} responses, ${acks_if} ACKs) - interface-MAC TA transmits fine"
	fi
else
	a_verdict=unavailable
	note_fail "no side capture to adjudicate"
fi

# ---------------------------------------------------------------- teardown
restore_managed
restore_rc=$?
[ "$restore_rc" -eq 0 ] || note_fail "restore_managed rc=$restore_rc"
cmp -s "$host_out/boot-id-before.txt" "$host_out/boot-id-after.txt" ||
	note_fail "boot id changed mid-run"
base_ts=$(sed -n 's/^\[[[:space:]]*\([0-9][0-9.]*\)\].*/\1/p' "$host_out/dmesg-before.log" | tail -n 1)
awk -v base="$base_ts" '$0 ~ /^\[/ { t=$0; gsub(/^\[[ ]*|[ ]*\].*/, "", t); if (t+0 > base+0) print }' \
	"$host_out/dmesg-after.log" 2>/dev/null >"$host_out/dmesg-delta.log"
fatal_markers=0
grep -Eq 'Kernel panic|CFI failure|Internal error|arm-smmu|spl_kmem_cache|subsystem-restart|WLAN recovery|cnss.*recovery|qdf_fatal|BUG:|Oops:' \
	"$host_out/dmesg-delta.log" && fatal_markers=1
[ "$fatal_markers" -eq 0 ] || note_fail "fatal markers in dmesg delta"

verdict=FAIL
[ "$fail_count" -eq 0 ] && verdict=PASS
{
	echo "verdict=$verdict"
	echo "fail_count=$fail_count"
	echo "boot_id=$(tr -d ' \r\n' <"$host_out/boot-id-before.txt")"
	echo "submit_delta=$sub_delta fw_delta=$fw_delta"
	echo "$(cat "$host_out/adjudication.txt" 2>/dev/null)"
	echo "a_directed_probe=$a_verdict"
	echo "observations=$(tr '\n' ';' <"$host_out/observations.txt" 2>/dev/null)"
	echo "dmesg_fatal_markers=$fatal_markers"
	echo "evidence=$host_out"
} | tee "$host_out/result.txt"

echo
echo "evidence dir: $host_out"
[ "$verdict" = PASS ]
