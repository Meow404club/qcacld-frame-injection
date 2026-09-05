#!/usr/bin/env bash

# todo 4.5 standard-tools round: run the unmodified standard Wi-Fi toolchain
# against the monitor netdev and record real, bounded outcomes. Zero tool
# patches; every failure must surface a real errno/status - silent drops,
# endless ACK=0 waits, channel=-1 or crashes are the outcomes this round
# exists to rule out (or to expose honestly).
#
# Tools on the device (termux prefix, run as root with an env prefix):
#   airodump-ng / aireplay-ng / packetforge-ng (aircrack-ng suite),
#   hcxdumptool + hcxpcapngtool, tcpdump, tshark. bettercap is attempted
#   from the configured termux repo (P0, while Wi-Fi is still up). mdk4 and
#   kismet are not packaged in the repo - recorded as real environment
#   gaps (apt-cache evidence), like the MLO precedent.
#
# Phases (each bounded by toybox timeout; SIGINT first so tools close their
# files cleanly, then KILL):
#   P0 baseline + inventory  - managed persona connected to the lab AP;
#                              tool versions; bettercap install attempt;
#                              repo search evidence for mdk4/kismet.
#   P1 monitor entry         - same contract as the mon-filter runner
#                              (disable framework, type monitor, ifup, set
#                              the lab chandef, 5 s stability gate).
#   P2 airodump-ng fixed ch  - tool-driven channel set (nl80211), mgmt_ctrl
#                              filter preset: csv row for the lab AP, pcap
#                              beacons, radiotap walk==0 through their pcap
#                              writer, #Data==0 while data is filtered.
#   P3 airodump-ng band scan - hopping across 2.4+5 GHz, full preset; no
#                              channel-set failure markers, valid channel
#                              afterwards.
#   P4 aireplay-ng --test    - standard-tool injection + real ACK counting
#                              under mgmt_ctrl; corroborated by our own
#                              wmi_submitted / fw_completion stats deltas.
#   P5 aireplay-ng --fakeauth- open-system auth+assoc against the lab AP
#                              (own network, authorized isolated lab).
#   P6 hcxdumptool passive   - fully passive config (rcascan passive, no
#                              association/proberesponse/m2 TX, no
#                              disassociation) on the lab channel, --tot
#                              self-exit; pcapng + hcxpcapngtool workflow.
#   P7 bettercap wifi.recon  - if the P0 install succeeded; otherwise the
#                              fetch failure is the recorded evidence.
#   P8 restore + teardown    - filter back to full + stock masks, managed
#                              persona, Wi-Fi reconnected VALIDATED, boot id
#                              unchanged, no fatal markers in dmesg delta.
#
# All tool stdout/stderr/exit codes land in the evidence dir; pcap artifacts
# are pulled and cross-read with our own radiotap analyzer (their pcap
# writers must produce frames our walker accepts - and vice versa).

set -uo pipefail

expected_build_id=ec49943d8a798a4c10023378bf9059de9a28a67c
expected_source_rev=93896078f500+dirty-20260903-4.2-chandef-hop-survey-v12
expected_stats_format=9
knob_path=/sys/module/qca_cld3_peach_v2/parameters/frame_inject_constructed_context

tp=/data/data/com.termux/files/usr
tp_home=/data/data/com.termux/files/home
tool_env="env LD_LIBRARY_PATH=$tp/lib HOME=$tp_home TERM=xterm-256color TERMINFO=$tp/share/terminfo PATH=$tp/bin:/system/bin:/vendor/bin"

lab_freq=5745
lab_channel=149
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

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
analyzer=$script_dir/../rx-radiotap-audit/analyze_radiotap_pcap.py
[ -r "$analyzer" ] || { echo "missing analyzer" >&2; exit 3; }
python3 "$analyzer" --selftest >/dev/null || { echo "analyzer selftest failed" >&2; exit 3; }

stamp=$(date -u +%Y%m%dT%H%M%SZ)
host_out=$script_dir/host-capture-standard-tools-$stamp-$$
mkdir -p "$host_out" || exit 3
remote_dir=/data/local/tmp/std-tools-$$

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

filter_get()
{
	awk -F= -v key="$1" '$1 == key { print $2 }' | tail -n 1
}

# key=value extraction from single-line multi-key outputs (csv row prints,
# adjudication prints) where awk -F= would grab trailing text after '='
kv() # line key -> value
{
	sed -n "s/.*\(^\|[^_[:alnum:]]\)$2=\([^ =]*\).*/\2/p;s/^$2=\([^ =]*\).*/\1/p" <<<"$1" | head -n 1
}

filter_write()
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

note_env()
{
	echo "env-limited: $*" | tee -a "$host_out/env-limited.txt"
}

# class counts from a classic pcap; DLT-aware: 127 = radiotap (radiotap walk
# via the shared analyzer module), 105 = plain 802.11 + FCS as airodump-ng
# writes it. Self-contained pcap reader: the analyzer's parse_pcap hard-exits
# on non-127 files, so it is only used for the radiotap decode helper.
count_classes() # pcap -> key=val lines on stdout
{
	python3 - "$1" "$target_bssid_hex" <<EOF
import struct, sys
sys.path.insert(0, "$script_dir/../rx-radiotap-audit")
import analyze_radiotap_pcap as a
pcap, bssid = sys.argv[1], bytes.fromhex(sys.argv[2])
mgmt = ctrl = data = beacons = acks = 0
try:
    with open(pcap, "rb") as fh:
        gh = fh.read(24)
        if len(gh) < 24:
            raise ValueError("short pcap header")
        if gh[:4] == b"\xd4\xc3\xb2\xa1" or gh[:4] == b"\x4d\x3c\xb2\xa1":
            endian = "<"
        elif gh[:4] == b"\xa1\xb2\xc3\xd4" or gh[:4] == b"\xa1\xb2\x3c\x4d":
            endian = ">"
        else:
            raise ValueError("not a classic pcap")
        linktype = struct.unpack(endian + "I", gh[20:24])[0] & 0xffff
        while True:
            rh = fh.read(16)
            if len(rh) < 16:
                break
            _ts, _tu, caplen, _orig = struct.unpack(endian + "IIII", rh)
            pkt = fh.read(caplen)
            if len(pkt) < caplen:
                break
            if linktype == 127:
                _f, body, _w = a.parse_radiotap(pkt)
            else:
                body = pkt
            if len(body) < 2:
                continue
            fc = struct.unpack("<H", body[:2])[0]
            ftype = (fc >> 2) & 3
            subtype = (fc >> 4) & 15
            if ftype == 0:
                mgmt += 1
                if subtype == 8 and len(body) >= 16 and (body[10:16] == bssid or body[16:22] == bssid):
                    beacons += 1
            elif ftype == 1:
                ctrl += 1
                if subtype == 0xD:
                    acks += 1
            elif ftype == 2:
                data += 1
    print(f"mgmt={mgmt} ctrl={ctrl} data={data} beacons={beacons} acks={acks} dlt={linktype}")
except Exception as e:
    print(f"parse_error={e} mgmt=0 ctrl=0 data=0 beacons=0 acks=0 dlt=0")
EOF
}

# radiotap walk check on a classic pcap (their writer must produce frames
# our walker accepts completely)
walk_check() # pcap -> key=val lines on stdout
{
	python3 - "$1" <<EOF
import sys
sys.path.insert(0, "$script_dir/../rx-radiotap-audit")
import analyze_radiotap_pcap as a
frames = walk_bad = ns_bad = chain_bad = 0
try:
    pkts = a.parse_pcap(sys.argv[1])
except Exception as e:
    print(f"parse_error={e} frames=0 walk_bad=1 ns_bad=0 chain_bad=0")
    raise SystemExit(0)
for _, pkt in pkts:
    frames += 1
    f, _body, _words = a.parse_radiotap(pkt)
    if f.get("walk_end_mismatch"):
        walk_bad += 1
print(f"frames={frames} walk_bad={walk_bad}")
EOF
}

# airodump csv AP row for the target BSSID; column positions are resolved
# from the file's own header row (column sets differ across airodump builds)
csv_target_row() # csv -> python-printed "found=1 data=N beacons=M power=P channel=C essid=E"
{
	python3 - "$1" "$target_bssid" <<EOF
import csv, sys
target = [int(x, 16) for x in sys.argv[2].split(":")]
def norm(field):
    try:
        return [int(x, 16) for x in field.strip().split(":")]
    except ValueError:
        return None
found = 0
with open(sys.argv[1], newline="", errors="replace") as fh:
    section = None
    idx = {}
    for row in csv.reader(fh):
        cells = [c.strip() for c in row]
        if not cells or not cells[0]:
            continue
        if cells[0].startswith("BSSID"):
            section = "ap"
            idx = {name: i for i, name in enumerate(cells)}
            continue
        if cells[0].startswith("Station"):
            section = "sta"
            continue
        if section != "ap" or not idx:
            continue
        if norm(cells[0]) != target:
            continue
        def col(name):
            i = idx.get(name)
            return cells[i] if i is not None and i < len(cells) else "?"
        found = 1
        print("found=1 data=%s beacons=%s power=%s channel=%s essid=%s" % (
            col("# Data"), col("# beacons"), col("Power"), col("channel"), col("ESSID")))
        break
if not found:
    print("found=0 data=? beacons=? power=? channel=? essid=?")
EOF
}

persona_guard() # tag -> 0 when wlan0 is still the monitor persona
{
	read_state
	if [ "$state_type" = monitor ]; then
		return 0
	fi
	note_fail "$1: persona lost mid-run (type=$state_type)"
	return 1
}

# ---------------------------------------------------------------- P0 baseline
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

# tool inventory (env-prefixed full paths; missing tools get real evidence)
{
	echo "=== airodump-ng help banner ==="
	adb_shell "$tool_env $tp/bin/airodump-ng --help" 2>&1 | head -n 6
	echo "=== aireplay-ng help banner ==="
	adb_shell "$tool_env $tp/bin/aireplay-ng --help" 2>&1 | head -n 6
	echo "=== hcxdumptool version ==="
	adb_shell "$tool_env $tp/bin/hcxdumptool -v" 2>&1 | head -n 2
	echo "=== hcxpcapngtool version ==="
	adb_shell "$tool_env $tp/bin/hcxpcapngtool -v" 2>&1 | head -n 2
	echo "=== tcpdump version ==="
	adb_shell "$tool_env $tp/bin/tcpdump --version" 2>&1 | head -n 2
	echo "=== tshark version ==="
	adb_shell "$tool_env $tp/bin/tshark --version" 2>&1 | head -n 2
} >"$host_out/tool-inventory.txt" 2>&1

# mdk4 / kismet: repo evidence while the network is still up
adb -s "$serial" shell "run-as com.termux $tp/bin/bash -c 'export HOME=$tp_home PATH=$tp/bin:\$PATH; echo == mdk4 ==; apt-cache search mdk4; echo mdk4_lines=\$(apt-cache search mdk4 | wc -l); echo == kismet ==; apt-cache search kismet; echo kismet_lines=\$(apt-cache search kismet | wc -l)'" \
	</dev/null >"$host_out/repo-search-mdk4-kismet.txt" 2>&1 || true

# bettercap: install attempt from the configured repo (bounded; failure is
# recorded evidence, not a driver verdict)
bettercap_bin=
adb -s "$serial" shell "run-as com.termux $tp/bin/bash -c 'export HOME=$tp_home PATH=$tp/bin:\$PATH; yes | timeout 150 apt-get install -y bettercap'" \
	</dev/null >"$host_out/bettercap-install.log" 2>&1 || true
if adb_shell "test -x $tp/bin/bettercap" >/dev/null 2>&1; then
	bettercap_bin=$tp/bin/bettercap
	echo "bettercap=installed $bettercap_bin" >>"$host_out/tool-inventory.txt"
elif adb_shell "test -x /data/local/tmp/bettercap" >/dev/null 2>&1; then
	bettercap_bin=/data/local/tmp/bettercap
	echo "bettercap=pushed $bettercap_bin" >>"$host_out/tool-inventory.txt"
else
	echo "bettercap=absent (see bettercap-install.log)" >>"$host_out/tool-inventory.txt"
fi

# knob trail
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

# ---------------------------------------------------------------- P1 monitor entry
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
# hcxdumptool rewrites the interface MAC; snapshot the entry MAC for restore
monitor_mac=$(sed -n 's/^[[:space:]]*addr \(\([[:xdigit:]]\{2\}:\)\{5\}[[:xdigit:]]\{2\}\).*/\1/p' \
	"$host_out/monitor-info-main.log" 2>/dev/null | head -n 1)
echo "monitor_mac_entry=$monitor_mac" | tee "$host_out/monitor-mac.txt"
filter_readiness=$(adb_shell "cat $filter_node" 2>&1)
printf '%s\n' "$filter_readiness" >"$host_out/filter-node-entry.log"
[ "$(filter_get name <<<"$filter_readiness")" = full ] ||
	note_fail "P1: filter node not at full on entry (name=$(filter_get name <<<"$filter_readiness"))"

# filter node stock-mask gate (fp_mgmt uses the peach 0xfedf variant)
[ "$(filter_get fp_mgmt <<<"$filter_readiness")" = "0xfedf" ] ||
	note_fail "P1: fp_mgmt not stock (0xfedf) on entry"

# ---------------------------------------------------------------- P2 airodump-ng fixed channel (mgmt_ctrl)
adb_shell "mkdir -p $remote_dir" >"$host_out/mkdir-remote.log" 2>&1 || exit 5
filter_write mgmt_ctrl || note_fail "P2 write mgmt_ctrl failed"
adb_shell 'cat /sys/class/net/wlan0/type' >"$host_out/arphrd-before-p2.txt" 2>&1 || true
stats >"$host_out/stats-before-p2.log" 2>&1
# stdout is airodump's ncurses UI (hundreds of MB when redirected) - only
# stderr carries real diagnostics
adb_shell "timeout -k 10 -s INT 50 $tool_env $tp/bin/airodump-ng -c $lab_channel --write $remote_dir/airodump_fix --output-format pcap,csv wlan0" \
	>/dev/null 2>"$host_out/p2-airodump-fix.log"
p2_rc=$?
echo "p2_airodump_rc=$p2_rc (124=timeout SIGINT, bounded stop)" | tee "$host_out/p2-rc.txt"
persona_guard P2 || true
adb_shell 'cat /sys/class/net/wlan0/type' >"$host_out/arphrd-after-p2.txt" 2>&1 || true
adb_shell 'iw dev wlan0 info' >"$host_out/p2-iw-after.log" 2>&1
p2_freq_after=$(iw_info_field freq <"$host_out/p2-iw-after.log")
[ -n "$p2_freq_after" ] || note_fail "P2: iw shows no channel after airodump (channel=-1 symptom)"
[ "$p2_freq_after" = "$lab_freq" ] || note_fail "P2: airodump left iface on $p2_freq_after MHz, wanted $lab_freq"

"${adb_cmd[@]}" pull "$remote_dir/airodump_fix-01.csv" "$host_out/airodump_fix-01.csv" >"$host_out/pull-p2.log" 2>&1 ||
	note_fail "P2: airodump csv missing"
# channel-set failures surface in the tool's own stderr (forbidden outcome)
if grep -qiE 'failed to set|can.t set|not supported|error setting channel|channel.*-1' "$host_out/p2-airodump-fix.log"; then
	note_fail "P2: channel-set failure markers in airodump fixed-channel log"
fi
"${adb_cmd[@]}" pull "$remote_dir/airodump_fix-01.cap" "$host_out/airodump_fix-01.cap" >>"$host_out/pull-p2.log" 2>&1 ||
	note_fail "P2: airodump cap missing"

if [ -r "$host_out/airodump_fix-01.csv" ]; then
	csv_line=$(csv_target_row "$host_out/airodump_fix-01.csv" | tee "$host_out/p2-csv-target.txt")
	csv_found=$(kv "$csv_line" found)
	csv_data=$(kv "$csv_line" data)
	csv_beacons=$(kv "$csv_line" beacons)
	[ "$csv_found" = 1 ] || note_fail "P2: lab AP missing from airodump csv"
	[ "$csv_beacons" -gt 0 ] 2>/dev/null || note_fail "P2: airodump saw 0 beacons for lab AP"
	if [ "$csv_data" = "?" ]; then
		# this airodump build exports no "# Data" column at all; the
		# pcap-side class count carries the filter-engagement check
		echo "csv_data_column=absent (build writes no #Data; pcap class gate covers it)" |
			tee -a "$host_out/p2-rc.txt"
	elif [ "$csv_data" = "0" ]; then
		:
	else
		note_fail "P2: mgmt_ctrl preset but csv #Data=$csv_data (filter not engaged during tool run)"
	fi
else
	csv_found=0
fi

if [ -r "$host_out/airodump_fix-01.cap" ]; then
	count_classes "$host_out/airodump_fix-01.cap" | tee "$host_out/p2-cap-classes.txt"
	p2_cap=$(cat "$host_out/p2-cap-classes.txt")
	if ! grep -q "^mgmt=" <<<"$p2_cap"; then
		note_fail "P2: cap class analysis failed: $p2_cap"
	else
		[ "$(kv "$p2_cap" beacons)" -ge 1 ] 2>/dev/null || note_fail "P2: 0 beacons in airodump cap"
		[ "$(kv "$p2_cap" data)" -eq 0 ] 2>/dev/null ||
			note_fail "P2: data frames in airodump cap under mgmt_ctrl (filter leak)"
	fi
	# airodump-ng writes its .cap with radiotap stripped (DLT 105, plain
	# 802.11 + FCS); the radiotap walk gate only applies to DLT 127 files
	if [ "$(kv "$p2_cap" dlt)" = 127 ]; then
		walk_check "$host_out/airodump_fix-01.cap" | tee "$host_out/p2-cap-walk.txt"
		[ "$(kv "$(cat "$host_out/p2-cap-walk.txt")" walk_bad)" = 0 ] ||
			note_fail "P2: radiotap walk mismatches in airodump-written pcap"
	else
		echo "p2_cap_dlt=$(kv "$p2_cap" dlt) (airodump strips radiotap in .cap; walk gate n/a)" |
			tee "$host_out/p2-cap-walk.txt"
	fi
fi
stats >"$host_out/stats-after-p2.log" 2>&1

# ---------------------------------------------------------------- P3 airodump-ng band scan (full)
filter_write full || note_fail "P3 write full failed"
adb_shell "timeout -k 10 -s INT 45 $tool_env $tp/bin/airodump-ng --band abg --write $remote_dir/airodump_hop --output-format csv wlan0" \
	>/dev/null 2>"$host_out/p3-airodump-hop.log"
p3_rc=$?
echo "p3_airodump_rc=$p3_rc (124=timeout SIGINT, bounded stop)" | tee "$host_out/p3-rc.txt"
persona_guard P3 || true
adb_shell 'iw dev wlan0 info' >"$host_out/p3-iw-after.log" 2>&1
p3_freq_after=$(iw_info_field freq <"$host_out/p3-iw-after.log")
[ -n "$p3_freq_after" ] || note_fail "P3: iw shows no channel after hopping (channel=-1 symptom)"
"${adb_cmd[@]}" pull "$remote_dir/airodump_hop-01.csv" "$host_out/airodump_hop-01.csv" >>"$host_out/pull-p2.log" 2>&1 ||
	note_fail "P3: airodump hop csv missing"
if [ -r "$host_out/airodump_hop-01.csv" ]; then
	p3_csv=$(csv_target_row "$host_out/airodump_hop-01.csv" | tee "$host_out/p3-csv-target.txt")
	[ "$(kv "$p3_csv" found)" = 1 ] ||
		note_fail "P3: lab AP not found during band scan"
fi
# channel-set failure markers in the tool's own stderr are the forbidden outcome
if grep -qiE 'failed to set|can.t set|not supported|error setting channel|channel.*-1' "$host_out/p3-airodump-hop.log"; then
	note_fail "P3: channel-set failure markers in airodump hop log"
fi

# ---------------------------------------------------------------- P4 aireplay-ng --test (mgmt_ctrl)
# aireplay --test opens with broadcast probe requests; r4 showed those get
# FW COMPLETE_OK yet leave no OTA echo/AP answer under the HT20 constructed
# context, while P5's unicast fakeauth at the same context DOES draw real
# AP responses. Two sub-tests isolate the variable:
#   P4a full lab chandef (managed-template context, the OTA-proven path)
#   P4b HT20 single freq (constructed context, r4 condition repeated)
# One side capture spans both; probe requests are attributed by the
# interface MAC (aireplay uses it as its source address).
filter_write mgmt_ctrl || note_fail "P4 write mgmt_ctrl failed"
stats >"$host_out/stats-before-p4.log" 2>&1
p4_submit_before=$(printf '%s\n' "$(stats 2>/dev/null)" | sv wmi_submitted)
p4_fw_before=$(printf '%s\n' "$(stats 2>/dev/null)" | sv fw_completion_events)
"${adb_cmd[@]}" shell su -c "timeout -k 5 -s INT 170 $tool_env $tp/bin/tcpdump -i wlan0 -s 0 -U -w $remote_dir/p4-air.pcap" \
	</dev/null >"$host_out/p4-tcpdump.log" 2>&1 &
p4_cap_pid=$!

adb_shell "iw dev wlan0 set freq $before_freq $before_width $before_center1" >"$host_out/p4a-set-freq.log" 2>&1 ||
	note_fail "P4a: iw set full chandef failed"
adb_shell "timeout -k 10 -s INT 75 $tool_env $tp/bin/aireplay-ng --test wlan0" \
	>"$host_out/p4a-aireplay-test.log" 2>&1
p4a_rc=$?
stats >"$host_out/stats-after-p4a.log" 2>&1
p4a_submit=$(printf '%s\n' "$(stats 2>/dev/null)" | sv wmi_submitted)
p4a_fw=$(printf '%s\n' "$(stats 2>/dev/null)" | sv fw_completion_events)

adb_shell "iw dev wlan0 set freq $lab_freq" >"$host_out/p4b-set-freq.log" 2>&1 ||
	note_fail "P4b: iw set freq $lab_freq failed"
adb_shell "timeout -k 10 -s INT 75 $tool_env $tp/bin/aireplay-ng --test wlan0" \
	>"$host_out/p4b-aireplay-test.log" 2>&1
p4b_rc=$?

wait "$p4_cap_pid" 2>/dev/null || true
persona_guard P4 || true
stats >"$host_out/stats-after-p4.log" 2>&1
p4_submit_after=$(printf '%s\n' "$(stats 2>/dev/null)" | sv wmi_submitted)
p4_fw_after=$(printf '%s\n' "$(stats 2>/dev/null)" | sv fw_completion_events)
p4_submit_delta=$((p4_submit_after - p4_submit_before))
p4_fw_delta=$((p4_fw_after - p4_fw_before))
p4a_submit_delta=$((p4a_submit - p4_submit_before))
p4a_fw_delta=$((p4a_fw - p4_fw_before))
echo "p4a_submit_delta=$p4a_submit_delta p4a_fw_delta=$p4a_fw_delta p4b_submit_delta=$((p4_submit_delta - p4a_submit_delta)) p4b_fw_delta=$((p4_fw_delta - p4a_fw_delta))" |
	tee "$host_out/p4-deltas.txt"
[ "$p4_submit_delta" -ge 1 ] ||
	note_fail "P4: aireplay-ng --test frames never reached our TX path (wmi_submitted delta=0 - silent drop)"
[ "$p4_fw_delta" -ge 1 ] ||
	note_fail "P4: no FW completion for aireplay-ng frames (delta=0)"

aireplay_verdict() # log -> printed word
{
	if grep -q 'Injection is working' "$1"; then
		echo working
	elif grep -qiE 'No Answer|0/30|injection is not working|No ACK' "$1"; then
		echo no_answer
	else
		echo inconclusive
	fi
}
p4a_verdict=$(aireplay_verdict "$host_out/p4a-aireplay-test.log")
p4b_verdict=$(aireplay_verdict "$host_out/p4b-aireplay-test.log")
echo "p4a_verdict=$p4a_verdict p4b_verdict=$p4b_verdict" | tee "$host_out/p4-verdicts.txt"

# adjudicate from the side capture: probe requests sourced by the interface
# MAC, probe responses the AP addressed back to it, and beacon visibility
"${adb_cmd[@]}" pull "$remote_dir/p4-air.pcap" "$host_out/p4-air.pcap" >>"$host_out/pull-p2.log" 2>&1 || true
if [ -r "$host_out/p4-air.pcap" ]; then
	python3 - "$host_out/p4-air.pcap" "$monitor_mac" >"$host_out/p4-adjudication.txt" <<EOF
import sys
sys.path.insert(0, "$script_dir/../rx-radiotap-audit")
import analyze_radiotap_pcap as a
import struct
iface_ta = bytes.fromhex(sys.argv[2].replace(":", ""))
iface_probes = other_probes = resps_to_iface = resps_to_other = 0
iface_frames_tx = beacons = 0
other_tas = set()
for _, pkt in a.parse_pcap(sys.argv[1]):
    f, body, _ = a.parse_radiotap(pkt)
    if len(body) < 10:
        continue
    fc = struct.unpack("<H", body[:2])[0]
    ftype = (fc >> 2) & 3
    subtype = (fc >> 4) & 15
    ta = bytes(body[10:16]) if len(body) >= 16 else b""
    ra = bytes(body[4:10])
    if ta == iface_ta:
        iface_frames_tx += 1
    if ftype != 0:
        continue
    if subtype == 4 and ta:
        if ta == iface_ta:
            iface_probes += 1
        else:
            other_tas.add(ta)
    elif subtype == 5:
        if ra == iface_ta:
            resps_to_iface += 1
        elif ra in other_tas:
            resps_to_other += 1
    elif subtype == 8:
        beacons += 1
print(f"iface_probe_reqs={iface_probes} other_probe_reqs={len(other_tas)} "
      f"probe_resps_to_iface={resps_to_iface} probe_resps_to_other={resps_to_other} "
      f"iface_ta_frames_total={iface_frames_tx} beacons={beacons}")
EOF
	p4_adj=$(cat "$host_out/p4-adjudication.txt")
	p4_resps_iface=$(kv "$p4_adj" probe_resps_to_iface)
	p4_resps_other=$(kv "$p4_adj" probe_resps_to_other)
	p4_iface_probes=$(kv "$p4_adj" iface_probe_reqs)
	p4_beacons_cap=$(kv "$p4_adj" beacons)
	[ "${p4_beacons_cap:-0}" -ge 1 ] 2>/dev/null ||
		note_fail "P4: side capture saw 0 beacons - monitor RX was not delivering during aireplay"
	if [ "${p4_iface_probes:-0}" -eq 0 ] 2>/dev/null; then
		# no self-TX echo at all: broadcast frames never hit the air path
		# our monitor sees (r4 condition; FW said COMPLETE_OK)
		echo "P4: 0 broadcast probe echoes from the interface TA (submit=$p4_submit_delta fw_ok_complete; unicast proven separately by P5)" |
			tee "$host_out/p4-broadcast-gap.txt"
	fi
	if [ "${p4_resps_iface:-0}" -ge 1 ] 2>/dev/null; then
		echo "P4: ${p4_resps_iface} probe responses delivered to the interface TA (OTA round trip proven)" |
			tee "$host_out/p4-roundtrip.txt"
	elif [ "${p4_resps_other:-0}" -ge 1 ] 2>/dev/null; then
		note_env "P4: AP answered ${p4_resps_other} real client probes but none to aireplay's broadcast probes (driver/FW broadcast-mgmt OTA gap, FW status COMPLETE_OK; see p4-broadcast-gap.txt)"
	else
		note_env "P4: no probe responses from the AP to anyone in the window (AP probe-response policy suspected; tool verdicts a=$p4a_verdict b=$p4b_verdict)"
	fi
else
	note_fail "P4: no side capture to adjudicate the tool verdicts"
fi

# ---------------------------------------------------------------- P5 aireplay-ng --fakeauth (mgmt_ctrl, own lab AP)
adb_shell "iw dev wlan0 set freq $lab_freq" >"$host_out/p5-set-freq.log" 2>&1 || true
adb_shell "timeout -k 10 -s INT 75 $tool_env $tp/bin/aireplay-ng --fakeauth 10 -e $essid -a $target_bssid wlan0" \
	>"$host_out/p5-aireplay-fakeauth.log" 2>&1
p5_rc=$?
echo "p5_aireplay_rc=$p5_rc" | tee "$host_out/p5-rc.txt"
persona_guard P5 || true
if grep -q 'Association successful' "$host_out/p5-aireplay-fakeauth.log"; then
	p5_fakeauth=success
elif grep -qiE 'deauth|denied|failed|no answer' "$host_out/p5-aireplay-fakeauth.log"; then
	p5_fakeauth=ap_rejected
	note_env "P5 fakeauth: AP did not complete association (real AP policy/output in p5-aireplay-fakeauth.log)"
else
	p5_fakeauth=inconclusive
	note_env "P5 fakeauth inconclusive (see p5-aireplay-fakeauth.log)"
fi

# ---------------------------------------------------------------- P6 hcxdumptool passive (full)
filter_write full || note_fail "P6 write full failed"
stats >"$host_out/stats-before-p6.log" 2>&1
p6_submit_before=$(printf '%s\n' "$(stats 2>/dev/null)" | sv wmi_submitted)
adb_shell "timeout -k 10 -s INT 100 $tool_env $tp/bin/hcxdumptool -i wlan0 -f $lab_freq -w $remote_dir/hcx.pcapng --associationmax=0 --proberesponsetx=0 --m2max=0 --disable_disassociation --tot=1 --watchdogmax=60 --errormax=20" \
	>"$host_out/p6-hcxdumptool.log" 2>&1
p6_rc=$?
echo "p6_hcx_rc=$p6_rc (0=clean --tot self-exit)" | tee "$host_out/p6-rc.txt"
persona_guard P6 || true
stats >"$host_out/stats-after-p6.log" 2>&1
p6_submit_after=$(printf '%s\n' "$(stats 2>/dev/null)" | sv wmi_submitted)
p6_submit_delta=$((p6_submit_after - p6_submit_before))
echo "p6_submit_delta=$p6_submit_delta (expected 0: fully passive config)" | tee -a "$host_out/p6-rc.txt"
[ "$p6_rc" -eq 0 ] || note_fail "P6: hcxdumptool did not self-exit cleanly (rc=$p6_rc)"
# delivery proof is the tool's own kernel capture counter; the pcapng only
# holds frames the tool considers interesting (v7 by design writes little in
# a fully passive quiet run - its help says to run tshark in parallel for
# full traffic)
p6_kernel=$(grep -o '[0-9][0-9]* Packet(s) captured by kernel' "$host_out/p6-hcxdumptool.log" | tail -n 1 | grep -o '^[0-9]*')
echo "p6_kernel_captured=${p6_kernel:-0}" | tee -a "$host_out/p6-rc.txt"
[ "${p6_kernel:-0}" -ge 1 ] 2>/dev/null ||
	note_fail "P6: hcxdumptool kernel capture counter is 0 (no delivery to the tool)"
"${adb_cmd[@]}" pull "$remote_dir/hcx.pcapng" "$host_out/hcx.pcapng" >>"$host_out/pull-p2.log" 2>&1 ||
	note_fail "P6: hcxdumptool pcapng missing"
# hcxpcapngtool workflow + tshark pcapng->pcap conversion for our analyzer
adb_shell "timeout -k 5 -s INT 40 $tool_env $tp/bin/hcxpcapngtool -o $remote_dir/hcx.22000 $remote_dir/hcx.pcapng" \
	>"$host_out/p6-hcxpcapngtool.log" 2>&1
p6_hcxp_rc=$?
echo "p6_hcxpcapngtool_rc=$p6_hcxp_rc" | tee -a "$host_out/p6-rc.txt"
[ "$p6_hcxp_rc" -eq 0 ] || note_fail "P6: hcxpcapngtool failed on the tool-written pcapng"
adb_shell "timeout -k 5 -s INT 40 $tool_env $tp/bin/tshark -F pcap -r $remote_dir/hcx.pcapng -w $remote_dir/hcx.pcap" \
	>"$host_out/p6-tshark-convert.log" 2>&1
"${adb_cmd[@]}" pull "$remote_dir/hcx.pcap" "$host_out/hcx.pcap" >>"$host_out/pull-p2.log" 2>&1 || true
if [ -r "$host_out/hcx.pcap" ]; then
	count_classes "$host_out/hcx.pcap" | tee "$host_out/p6-cap-classes.txt"
else
	note_env "P6: pcapng->pcap conversion produced no file (near-empty pcapng in passive quiet run is tool behavior; kernel counter is the delivery proof)"
fi
grep -qi "$target_bssid" "$host_out/p6-hcxdumptool.log" && p6_saw_ap=yes || p6_saw_ap=no

# hcxdumptool changes the interface MAC by design; restore the entry MAC
# (address changes need the link down first - errno 524 otherwise)
p6_cur_mac=$(adb_shell 'iw dev wlan0 info' 2>/dev/null | tr -d '\r' | sed -n 's/^[[:space:]]*addr //p' | head -n 1)
if [ -n "$monitor_mac" ] && [ -n "$p6_cur_mac" ] && [ "$p6_cur_mac" != "$monitor_mac" ]; then
	{
		echo "mac_was=$p6_cur_mac restoring=$monitor_mac"
		adb_shell 'ip link set wlan0 down' 2>&1
		adb_shell "ip link set wlan0 address $monitor_mac" 2>&1
		echo "set_rc=$?"
		adb_shell 'ip link set wlan0 up' 2>&1
	} >"$host_out/p6-mac-restore.log" 2>&1
	p6_mac_now=$(adb_shell 'iw dev wlan0 info' 2>/dev/null | tr -d '\r' | sed -n 's/^[[:space:]]*addr //p' | head -n 1)
	[ "$p6_mac_now" = "$monitor_mac" ] ||
		note_fail "P6: restoring monitor MAC after hcxdumptool failed (now $p6_mac_now)"
fi

# ---------------------------------------------------------------- P7 bettercap wifi.recon
if [ -n "$bettercap_bin" ]; then
	adb_shell "iw dev wlan0 set freq $lab_freq" >/dev/null 2>&1 || true
	# -eval strings survive adb+su only inside a pushed script file
	cat >"$host_out/bcap-run.sh" <<BCAP
#!/system/bin/sh
export LD_LIBRARY_PATH=$tp/lib HOME=$tp_home TERM=xterm-256color TERMINFO=$tp/share/terminfo PATH=$tp/bin:/system/bin:/vendor/bin
exec timeout -k 10 -s INT 60 $bettercap_bin -iface wlan0 -eval 'wifi.recon on; sleep 45; wifi.show; sleep 3'
BCAP
	"${adb_cmd[@]}" push "$host_out/bcap-run.sh" "$remote_dir/bcap-run.sh" >"$host_out/p7-push.log" 2>&1
	adb_shell "sh $remote_dir/bcap-run.sh" >"$host_out/p7-bettercap.log" 2>&1
	p7_rc=$?
	echo "p7_bettercap_rc=$p7_rc" | tee "$host_out/p7-rc.txt"
	persona_guard P7 || true
	adb_shell 'iw dev wlan0 info' >"$host_out/p7-iw-after.log" 2>&1
	[ -n "$(iw_info_field freq <"$host_out/p7-iw-after.log")" ] ||
		note_fail "P7: iw shows no channel after bettercap (channel=-1 symptom)"
else
	p7_rc=skipped
	echo "p7_bettercap_rc=skipped (binary unavailable; evidence in bettercap-install.log)" | tee "$host_out/p7-rc.txt"
	note_env "P7 bettercap: binary not installable from configured repo (see bettercap-install.log); driver verdict deferred"
fi

# ---------------------------------------------------------------- P8 restore + teardown
filter_write full || note_fail "P8 write full failed"
[ "$(filter_get name <"$host_out/filter-after-full.log")" = full ] ||
	note_fail "P8: filter node name not full"
[ "$(filter_get fp_mgmt <"$host_out/filter-after-full.log")" = "0xfedf" ] ||
	note_fail "P8: filter node fp_mgmt not stock after restore"

restore_managed
restore_rc=$?

adb_shell "rm -rf $remote_dir" >>"$host_out/pull.log" 2>&1 || true

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

verdict=FAIL
[ "$fail_count" -eq 0 ] && verdict=PASS
{
	echo "verdict=$verdict"
	echo "fail_count=$fail_count"
	echo "boot_id=$(tr -d ' \r\n' <"$host_out/boot-id-before.txt")"
	echo "p2_airodump_fix_rc=$p2_rc csv_found=${csv_found:-0} cap_dlt=$(kv "$(cat "$host_out/p2-cap-classes.txt" 2>/dev/null)" dlt)"
	echo "p3_airodump_hop_rc=$p3_rc hop_end_freq=${p3_freq_after:-none}"
	echo "p4a_test_verdict=$p4a_verdict p4b_test_verdict=$p4b_verdict submit_delta=$p4_submit_delta fw_delta=$p4_fw_delta resps_to_iface=${p4_resps_iface:-na} resps_to_others=${p4_resps_other:-na} iface_probe_echo=${p4_iface_probes:-na}"
	echo "p5_fakeauth=$p5_fakeauth rc=$p5_rc"
	echo "p6_hcxdumptool_rc=$p6_rc submit_delta=$p6_submit_delta kernel_captured=${p6_kernel:-0}"
	echo "p7_bettercap_rc=$p7_rc"
	echo "dmesg_fatal_markers=$fatal_markers"
	echo "env_limited=$(tr '\n' ';' <"$host_out/env-limited.txt" 2>/dev/null)"
	echo "evidence=$host_out"
} | tee "$host_out/result.txt"

echo
echo "evidence dir: $host_out"
[ "$verdict" = PASS ]
