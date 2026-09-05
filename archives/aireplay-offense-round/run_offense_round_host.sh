#!/usr/bin/env bash

# todo 4.2 tool-experience round: airodump cross-burst tracking, aireplay
# replay/deauth against the lab AP, and the driver-side hop scheduler vs a
# standard tool (external channel intent must win). Standard tools only
# (termux aircrack-ng suite, zero patches); every verdict is tool-contract
# level (tool ran, sent frames, did not wedge the persona) or explicitly
# environment-limited - never an OTA claim beyond what the tool itself
# prints. Fragmentation/PRGA needs a WEP AP and is recorded as an
# environment boundary, not run.
#
# Preconditions: v12 build (pinned), managed persona connected+VALIDATED to
# the lab AP, termux aircrack-ng present. The associated client
# (82:03:D8:D7:87:A7 by default, override with --client-mac) is discovered
# on the air before any client-directed step; steps needing it degrade to
# OBS when it is absent.

set -uo pipefail

expected_build_id=ec49943d8a798a4c10023378bf9059de9a28a67c
expected_source_rev=93896078f500+dirty-20260903-4.2-chandef-hop-survey-v12
default_client=82:03:D8:D7:87:A7

usage()
{
	echo "usage: $0 [--serial SERIAL] [--target-bssid BSSID] [--client-mac MAC]" >&2
	echo "       --authorized-isolated-lab" >&2
	exit 2
}

mode=run
serial=
target_bssid=
client_mac=$default_client
authorized=0
while [ "$#" -gt 0 ]; do
	case $1 in
	--serial) [ "$#" -ge 2 ] || usage; serial=$2; shift 2 ;;
	--target-bssid) [ "$#" -ge 2 ] || usage; target_bssid=$2; shift 2 ;;
	--client-mac) [ "$#" -ge 2 ] || usage; client_mac=$2; shift 2 ;;
	--authorized-isolated-lab) authorized=1; shift ;;
	*) usage ;;
	esac
done
[ "$authorized" -eq 1 ] || usage
if [ -n "$target_bssid" ]; then
	[[ "$target_bssid" =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ ]] || usage
fi
[[ "$client_mac" =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ ]] || usage

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
mounted_debugfs=0
tp=/data/data/com.termux/files/usr
tp_home=/data/data/com.termux/files/home
tool_env="env LD_LIBRARY_PATH=$tp/lib HOME=$tp_home TERM=xterm-256color TERMINFO=$tp/share/terminfo PATH=$tp/bin:/system/bin:/vendor/bin"
hop_node=/sys/kernel/debug/wlan0/frame_inject_channel_hop
command -v adb >/dev/null || exit 3
command -v timeout >/dev/null || exit 3

if [ -z "$serial" ]; then
	mapfile -t serials < <(adb devices | awk '$2 == "device" {print $1}')
	[ "${#serials[@]}" -eq 1 ] || exit 3
	serial=${serials[0]}
fi
adb_cmd=(adb -s "$serial")
[ "$("${adb_cmd[@]}" get-state 2>/dev/null)" = device ] || exit 3

stamp=$(date -u +%Y%m%dT%H%M%SZ)
host_out=$script_dir/host-capture-offense-$stamp-$$
mkdir "$host_out" || exit 3
echo "HOST_OUTPUT_DIR=$host_out"

results_tsv=$host_out/offense-results.tsv
printf '%s\t%s\t%s\t%s\n' step tool verdict detail >"$results_tsv"
fail_count=0
note_fail()
{
	fail_count=$((fail_count + 1))
	echo "FAIL: $*" >&2
}
record()
{
	printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >>"$results_tsv"
}

adb_shell()
{
	"${adb_cmd[@]}" shell su -c "$1" </dev/null
}

iw_info_field()
{
	case $1 in
	type) sed -n 's/^[[:space:]]*type //p' ;;
	freq) sed -n 's/.*channel [0-9][0-9]* (\([0-9][0-9]*\) MHz).*/\1/p' | head -n 1 ;;
	*) return 1 ;;
	esac
}

wait_persona() # wanted old_ifindex output
{
	local wanted=$1 old_ifindex=$2 output=$3 info type ifindex
	info=
	for _ in $(seq 1 160); do
		info=$(adb_shell 'iw dev wlan0 info' 2>&1 | tr -d '\r')
		type=$(printf '%s\n' "$info" | iw_info_field type | head -n 1)
		ifindex=$(adb_shell 'cat /sys/class/net/wlan0/ifindex' 2>/dev/null | tr -d ' \r\n')
		if [ "$type" = "$wanted" ] && [ -n "$ifindex" ] && [ "$ifindex" != "$old_ifindex" ]; then
			printf '%s\n' "$info" >"$output"
			return 0
		fi
		sleep 0.25
	done
	printf '%s\n' "$info" >"$output"
	return 1
}

# ---------------------------------------------------------------- baseline
status=$(adb_shell 'cmd wifi status' 2>/dev/null | tr -d '\r')
grep -q 'Wifi is connected to' <<<"$status" || { echo "not connected" >&2; exit 4; }
grep -q 'VALIDATED' <<<"$status" || { echo "not VALIDATED" >&2; exit 4; }
printf '%s\n' "$status" >"$host_out/wifi-baseline.log"
lab_essid=$(grep -o 'Wifi is connected to "[^"]*"' "$host_out/wifi-baseline.log" | head -n 1 | sed 's/.*"\([^"]*\)".*/\1/')
[ -n "$lab_essid" ] || { echo "no essid in baseline" >&2; exit 4; }

info=$(adb_shell 'iw dev wlan0 info' 2>/dev/null | tr -d '\r')
[ "$(printf '%s\n' "$info" | iw_info_field type | head -n 1)" = managed ] || exit 4
lab_freq=$(printf '%s\n' "$info" | iw_info_field freq)
[ -n "$lab_freq" ] || exit 4

# airodump -c wants a channel number, not MHz (passing 5745 made every dump
# exit before writing a single csv row).
freq_to_channel()
{
	awk -v f="$1" 'BEGIN{
		if (f >= 2412 && f <= 2472) { printf "%d\n", (f - 2407) / 5 }
		else if (f == 2484) print 14
		else if (f >= 4910 && f <= 4980) printf "%d\n", (f - 4000) / 5
		else if (f >= 5035 && f <= 5880) printf "%d\n", (f - 5000) / 5
		else if (f >= 5955 && f <= 7115) printf "%d\n", (f - 5950) / 5
		else print f
	}'
}
lab_channel=$(freq_to_channel "$lab_freq")

# KernelSU hides /sys/kernel/debug; mount it for the hop node (mirrors the
# chandef runner; without this the O6 hop writes hit ENOENT).
mounted_debugfs=0
debugfs_type=$(adb_shell 'stat -f -c %T /sys/kernel/debug' 2>/dev/null | tr -d ' \r\n')
if [ "$debugfs_type" != 0x64626720 ] && [ "$debugfs_type" != debugfs ]; then
	adb_shell 'mount -t debugfs debugfs /sys/kernel/debug' >"$host_out/mount-debugfs.log" 2>&1 || exit 4
	mounted_debugfs=1
fi
[ -n "$target_bssid" ] || {
	target_bssid=$(adb_shell 'dumpsys wifi | grep -m1 "mWifiInfo SSID"' 2>/dev/null | tr -d '\r')
	# BSSID from dumpsys is unreliable across builds; fall back to the first
	# beacon seen on the lab channel during the discovery step.
	target_bssid=
}

dmesg_base=$(adb_shell 'dmesg' 2>/dev/null | tail -n 1 | sed -n 's/^\[\([0-9.]*\)\].*/\1/p')
boot_id=$(adb_shell 'cat /proc/sys/kernel/random/boot_id' | tr -d ' \r\n')

loaded_note=$("${adb_cmd[@]}" exec-out su -c 'od -An -v -tx1 /sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id' | tr -d ' \r\n')
case $loaded_note in *"$expected_build_id"*) ;; *)
	echo "loaded module build id mismatch" >&2
	exit 5
	;;
esac
# --help prints the banner and then exits non-zero (usage exit), so gate on
# the banner text rather than the return code.
adb_shell "$tool_env $tp/bin/aireplay-ng --help" >"$host_out/aireplay-banner.log" 2>&1 || true
grep -q "Aireplay-ng" "$host_out/aireplay-banner.log" ||
	{ echo "aireplay-ng not runnable" >&2; exit 5; }

remote_dir=/data/local/tmp/qcacld-offense-$$
adb_shell "mkdir -p $remote_dir" >/dev/null 2>&1

enter_monitor()
{
	adb_shell 'cmd wifi set-wifi-enabled disabled' >>"$host_out/disable-wifi.log" 2>&1
	for _ in $(seq 1 60); do
		off_status=$(adb_shell 'cmd wifi status' 2>/dev/null | tr -d '\r')
		off_supp=$(adb_shell 'pidof wpa_supplicant' 2>/dev/null | tr -d '\r\n')
		grep -q '^Wifi is disabled$' <<<"$off_status" && [ -z "$off_supp" ] && break
		sleep 0.5
	done
	local prev_ifindex
	prev_ifindex=$(adb_shell 'cat /sys/class/net/wlan0/ifindex' 2>/dev/null | tr -d ' \r\n')
	adb_shell 'iw dev wlan0 set type monitor' >>"$host_out/set-monitor.log" 2>&1 || return 1
	wait_persona monitor "$prev_ifindex" "$host_out/monitor-info.log" || return 1
	adb_shell 'ip link set wlan0 up' >>"$host_out/ifup.log" 2>&1 || return 1
	adb_shell "iw dev wlan0 set freq $lab_freq" >>"$host_out/set-freq.log" 2>&1 || return 1
	return 0
}

restore_managed()
{
	local mon_ifindex
	mon_ifindex=$(adb_shell 'cat /sys/class/net/wlan0/ifindex' 2>/dev/null | tr -d ' \r\n')
	adb_shell 'iw dev wlan0 set type managed' >"$host_out/restore-managed.log" 2>&1 || true
	wait_persona managed "$mon_ifindex" "$host_out/restore-managed-info.log" || return 1
	adb_shell 'cmd wifi set-wifi-enabled enabled' >"$host_out/restore-wifi.log" 2>&1 || return 1
	for _ in $(seq 1 240); do
		status=$(adb_shell 'cmd wifi status' 2>/dev/null | tr -d '\r')
		grep -q 'Wifi is connected to' <<<"$status" && grep -q 'VALIDATED' <<<"$status" && return 0
		sleep 0.5
	done
	return 1
}

cleanup()
{
	adb_shell "echo stop > $hop_node" >/dev/null 2>&1 || true
	if [ "$mounted_debugfs" -eq 1 ]; then
		adb_shell 'umount /sys/kernel/debug' >/dev/null 2>&1 || true
	fi
	adb_shell 'iw dev wlan0 set type managed' >/dev/null 2>&1 || true
	adb_shell 'cmd wifi set-wifi-enabled enabled' >/dev/null 2>&1 || true
	adb_shell "rm -rf $remote_dir" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

enter_monitor || { echo "monitor entry failed" >&2; exit 6; }

# ---------------------------------------------------------------- O1 discovery
adb_shell "timeout -k 10 -s INT 15 $tool_env $tp/bin/airodump-ng -c ${lab_channel} --write $remote_dir/o1_scan --output-format csv wlan0" \
	>/dev/null 2>"$host_out/o1-airodump.log"
adb_shell "cat $remote_dir/o1_scan-01.csv" >"$host_out/o1-scan.csv" 2>/dev/null || true
client_seen=0
grep -qi "$client_mac" "$host_out/o1-scan.csv" 2>/dev/null && client_seen=1
if [ -z "$target_bssid" ]; then
	target_bssid=$(awk -F, 'NR>5 && $1 ~ /^[0-9A-Fa-f:]{17}$/ { gsub(/ /,"",$1); print $1; exit }' \
		"$host_out/o1-scan.csv" 2>/dev/null)
fi
if [ -n "$target_bssid" ] && [ "$client_seen" -eq 1 ]; then
	record O1_discovery airodump PASS "ap=$target_bssid client=$client_mac seen"
elif [ -n "$target_bssid" ]; then
	record O1_discovery airodump PASS "ap=$target_bssid client_absent_env_limited"
else
	record O1_discovery airodump FAIL "no AP row discovered"
	note_fail "O1: no AP discovered on $lab_freq"
fi

if [ "$client_seen" -eq 1 ]; then
	replay_target_h="-h $client_mac"
else
	replay_target_h=""
fi

# ---------------------------------------------------------------- O2 cross-burst tracking
adb_shell "timeout -k 10 -s INT 60 $tool_env $tp/bin/airodump-ng -c ${lab_channel} --write $remote_dir/o2_track --output-format csv wlan0" \
	>/dev/null 2>"$host_out/o2-airodump.log" &
o2_pid=$!
sleep 12
adb_shell "timeout 12 $tool_env $tp/bin/aireplay-ng --fakeauth 0 -e "$lab_essid" -a $target_bssid wlan0" \
	>"$host_out/o2-fakeauth.log" 2>&1
sleep 10
adb_shell "timeout 8 $tool_env $tp/bin/aireplay-ng --deauth 5 -a $target_bssid wlan0" \
	>"$host_out/o2-deauth.log" 2>&1
wait $o2_pid 2>/dev/null
o2_rc=$?
adb_shell "cat $remote_dir/o2_track-01.csv" >"$host_out/o2-track.csv" 2>/dev/null || true
o2_ap_row=0
o2_station_rows=0
if [ -n "$target_bssid" ] &&
	grep -qi "$target_bssid" "$host_out/o2-track.csv" 2>/dev/null; then
	o2_ap_row=1
fi
o2_station_rows=$(awk -F, 'BEGIN{stations=0; in_st=0}
	/^Station MAC/{in_st=1; next}
	in_st && $1 ~ /^[0-9A-Fa-f:]{17}$/ {stations++}
	END{print stations+0}' "$host_out/o2-track.csv" 2>/dev/null)
if [ "$o2_ap_row" -eq 1 ] && [ "${o2_station_rows:-0}" -ge 1 ] && grep -q "Sending DeAuth" "$host_out/o2-deauth.log" 2>/dev/null; then
	record O2_cross_burst "airodump+aireplay" PASS "ap_row=1 stations=$o2_station_rows bursts_attributed"
else
	record O2_cross_burst "airodump+aireplay" FAIL "ap_row=$o2_ap_row stations=${o2_station_rows:-0} o2_rc=$o2_rc"
	note_fail "O2: cross-burst tracking evidence incomplete"
fi

# ---------------------------------------------------------------- O3 arpreplay
if [ "$client_seen" -eq 1 ]; then
	adb_shell "timeout 25 $tool_env $tp/bin/aireplay-ng --arpreplay -b $target_bssid -h $client_mac wlan0" \
		>"$host_out/o3-arpreplay.log" 2>&1
	o3_sent=$(grep -oE "Sent [0-9]+ packets" "$host_out/o3-arpreplay.log" | tail -n 1 | awk '{print $2}')
	o3_read=$(grep -oE "Read [0-9]+ packets" "$host_out/o3-arpreplay.log" | tail -n 1 | awk '{print $2}')
	if [ "${o3_sent:-0}" -gt 0 ]; then
		record O3_arpreplay aireplay-ng PASS "sent=${o3_sent:-0} read=${o3_read:-0} tool_contract_only"
	else
		record O3_arpreplay aireplay-ng OBS "no ARP captured in window (sent=${o3_sent:-0}) env_limited"
	fi
else
	record O3_arpreplay aireplay-ng OBS "client $client_mac absent; replay target unavailable"
fi

# ---------------------------------------------------------------- O4 fragmentation (WEP-only)
record O4_fragmentation aireplay-ng OBS "env_unsupported: fragmentation needs a WEP AP (PRGA); lab AP is WPA"

# ---------------------------------------------------------------- O5 directed deauth at client
if [ "$client_seen" -eq 1 ]; then
	adb_shell "timeout 15 $tool_env $tp/bin/aireplay-ng --deauth 3 -a $target_bssid -c $client_mac wlan0" \
		>"$host_out/o5-deauth-directed.log" 2>&1
	if grep -q "directed DeAuth" "$host_out/o5-deauth-directed.log" 2>/dev/null; then
		o5_acks=$(grep -oE "[0-9]+\|[0-9]+ ACKs" "$host_out/o5-deauth-directed.log" | tail -n 1)
		record O5_deauth_directed aireplay-ng PASS "directed deauth sent; client ACK counter=$o5_acks"
	else
		record O5_deauth_directed aireplay-ng FAIL "tool did not send directed deauth"
		note_fail "O5: directed deauth not sent"
	fi
else
	record O5_deauth_directed aireplay-ng OBS "client absent"
fi

# ---------------------------------------------------------------- O6 driver hop vs airodump (external wins)
adb_shell "echo 'start 300 2412 2437 2462' > $hop_node" >"$host_out/o6-hop-start.log" 2>&1
sleep 2
o6_hop_active=$(adb_shell "cat $hop_node" 2>/dev/null | awk -F= '$1 == "active" {print $2}' | tail -n 1)
adb_shell "timeout -k 10 -s INT 20 $tool_env $tp/bin/airodump-ng -c ${lab_channel} --write $remote_dir/o6_hop --output-format csv wlan0" \
	>/dev/null 2>"$host_out/o6-airodump.log"
sleep 2
o6_hop_after=$(adb_shell "cat $hop_node" 2>/dev/null | awk -F= '$1 == "active" {print $2}' | tail -n 1)
o6_freq_after=$(adb_shell 'iw dev wlan0 info' 2>/dev/null | tr -d '\r' | iw_info_field freq)
o6_airodump_ok=0
adb_shell "cat $remote_dir/o6_hop-01.csv" >"$host_out/o6-hop.csv" 2>/dev/null || true
[ -s "$host_out/o6-hop.csv" ] && o6_airodump_ok=1
if [ "$o6_hop_active" = 1 ] && [ "$o6_hop_after" = 0 ] && [ "${o6_freq_after:-0}" = "$lab_freq" ]; then
	record O6_hop_external_wins "hop+airodump" PASS "session cancelled by tool channel set; freq=$o6_freq_after"
else
	record O6_hop_external_wins "hop+airodump" FAIL "active=$o6_hop_active->$o6_hop_after freq=$o6_freq_after want=$lab_freq"
	note_fail "O6: external channel intent did not cancel hop session"
fi

adb_shell "cat $hop_node" >"$host_out/o6-hop-node-final.log" 2>&1

# ---------------------------------------------------------------- teardown
adb_shell "echo stop > $hop_node" >/dev/null 2>&1 || true
restore_managed || { echo "restore failed" >&2; exit 9; }
trap - EXIT HUP INT TERM
boot_id_after=$(adb_shell 'cat /proc/sys/kernel/random/boot_id' | tr -d ' \r\n')
[ "$boot_id" = "$boot_id_after" ] || { echo "boot id changed" >&2; exit 9; }
adb_shell 'cmd wifi status' >"$host_out/wifi-final.log" 2>&1
grep -q 'Wifi is connected to' "$host_out/wifi-final.log" ||
	note_fail "Wi-Fi not reconnected at teardown"
adb_shell "rm -rf $remote_dir" >/dev/null 2>&1 || true

adb_shell 'dmesg' >"$host_out/dmesg-after.log" 2>&1 || true
if [ -n "$dmesg_base" ]; then
	awk -v baseline="$dmesg_base" \
		'{ match($0, /^\[[[:space:]]*([0-9][0-9.]*)\]/, m); \
		  if (m[1] != "" && (m[1] + 0) > (baseline + 0)) print }' \
		"$host_out/dmesg-after.log" >"$host_out/dmesg-delta.log"
else
	cp "$host_out/dmesg-after.log" "$host_out/dmesg-delta.log"
fi
if grep -Eq 'Kernel panic|CFI failure|Internal error|arm-smmu|subsystem-restart|WLAN recovery|qdf_fatal|BUG:|Oops:' \
	"$host_out/dmesg-delta.log" 2>/dev/null; then
	record Dmesg_fatal scan FAIL "markers present"
	note_fail "fatal markers in dmesg delta"
else
	record Dmesg_fatal scan PASS "markers=0"
fi

overall=PASS
[ "$fail_count" -eq 0 ] || overall=FAIL
{
	echo "verdict=$overall"
	echo "fail_count=$fail_count"
	echo "lab_freq=$lab_freq ap=${target_bssid:-unknown} client=$client_mac seen=$client_seen"
	echo "ota_claim=none_tool_contract_only"
	echo "host_output=$host_out"
} >"$host_out/result.txt"
sha256sum "$host_out"/o1-scan.csv "$host_out"/o2-track.csv "$results_tsv" \
	"$host_out"/result.txt >"$host_out/HOST_SHA256SUMS" 2>/dev/null || true
echo "verdict=$overall fail_count=$fail_count"
[ "$overall" = PASS ]
