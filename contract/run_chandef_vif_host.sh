#!/usr/bin/env bash

# todo 4.2/4.5 channel/width matrix + userspace hopping + netdev UP/DOWN +
# monitor MAC change + monitor-VIF add attempts, plus the v12 4.2 additions:
# unified-chandef sysfs path, monitor survey (dump_survey IN_USE/noise/CCA),
# driver-side channel-hop session (start/stop/park-on-error/external-wins)
# and per-boot stable monitor MAC across a second persona entry.
# Verification-only: every TX probe claims a WMI/FW completion round trip or
# a precise terminal drop classification from the stats v9 ledger - never an
# on-air claim, and channel operations must never silently change the
# persona.
#
# Context model (driver truth, v7+ maxsqueeze): the managed template stays
# preferred on its own frequency when the monitor width does not exceed it;
# every other channel/width uses the constructed context which now follows
# the monitor width (20/40/80/160/80p80; HT from 40, 5G VHT from 80, 6G HE).
# The first TX probe at the AP's own chandef classifies the session mode via
# helper_context_source; both modes are legal and the per-case TX tiers from
# chandef-cases.tsv are resolved accordingly.
#
# The runner must start from a connected, VALIDATED managed persona (the lab
# AP provides the template) and ends with: managed persona restored, Wi-Fi
# reconnected and VALIDATED, no mon0, original monitor MAC restored, knob and
# helper idle window restored, WMA owner ledger zero, boot id unchanged, no
# fatal markers in the dmesg delta.

set -uo pipefail

expected_build_id=914714cb6f296f35f093bf393bfea47c4982897c
expected_source_rev=698efe09e8b8+dirty-20260906-observability-admin-knobs-v21
expected_stats_format=13
expected_sender_sha256=c2795e6b612c065fd464a97251276ad61c0f7a5484bd7d4767fdd882adc10afc
expected_case_id=frame.pv0.mgmt.12.deauthentication.minimal
expected_setfreq_cases=109
expected_hop_cases=12
expected_converge_cases=1
knob_path=/sys/module/qca_cld3_peach_v2/parameters/frame_inject_constructed_context
test_mac_local=02:1a:2b:3c:4d:5e

usage()
{
	echo "usage: $0 [--serial SERIAL] [--target-bssid BSSID] --authorized-isolated-lab" >&2
	echo "       $0 --selfcheck | --print-plan" >&2
	exit 2
}

mode=run
serial=
target_bssid=
authorized=0
while [ "$#" -gt 0 ]; do
	case $1 in
	--serial) [ "$#" -ge 2 ] || usage; serial=$2; shift 2 ;;
	--target-bssid) [ "$#" -ge 2 ] || usage; target_bssid=$2; shift 2 ;;
	--authorized-isolated-lab) authorized=1; shift ;;
	--selfcheck|--print-plan)
		mode=${1#--}
		shift
		[ "$#" -eq 0 ] || usage
		;;
	*) usage ;;
	esac
done

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
cases_tsv=$script_dir/chandef-cases.tsv
plan=$script_dir/stage1-device-plan.tsv
sender=$script_dir/send_stage1_packet
[ -r "$cases_tsv" ] && [ -r "$plan" ] && [ -x "$sender" ] || exit 3

# ---------------------------------------------------------------- case table
case_rows()
{
	awk -F'\t' '$1 !~ /^#/ && NF == 9' "$cases_tsv"
}

selfcheck()
{
	local bad=0
	local widths_re='^(HT20|HT40-|HT40\+|NOHT|5|10|80|160|80\+80|AUTO)$'
	local tiers_re='^(must_accept|observation)$'
	local tx_re='^(must_complete|must_refuse_either|observation|-)$'
	local setfreq=0 hop=0 converge=0
	while IFS=$'\t' read -r id phase freq width center set_tier tx_flag tier_t tier_c; do
		case $id$phase$freq$width$center$set_tier$tier_t$tier_c in
		*[[:space:]]*) echo "selfcheck: whitespace inside fields: $id"; bad=1 ;;
		esac
		[ -n "$id" ] || { echo "selfcheck: empty case id"; bad=1; }
		case $phase in
		setfreq) setfreq=$((setfreq + 1)) ;;
		hop) hop=$((hop + 1)) ;;
		converge) converge=$((converge + 1)) ;;
		*) echo "selfcheck: bad phase '$phase' in $id"; bad=1 ;;
		esac
		if [ "$phase" = converge ]; then
			[ "$width" = AUTO ] || {
				echo "selfcheck: converge row without AUTO width in $id"; bad=1
			}
			[ "$center" = AUTO ] || {
				echo "selfcheck: converge row without AUTO center in $id"; bad=1
			}
		else
			echo "$width" | grep -Eq "$widths_re" || {
				echo "selfcheck: bad width token '$width' in $id"; bad=1
			}
			case $center in
			-) ;;
			''|*[!0-9]*) echo "selfcheck: bad center '$center' in $id"; bad=1 ;;
			esac
		fi
		echo "$set_tier" | grep -Eq "$tiers_re" || {
			echo "selfcheck: bad set tier '$set_tier' in $id"; bad=1
		}
		case $tx_flag in 0|1) ;; *) echo "selfcheck: bad tx_flag '$tx_flag' in $id"; bad=1 ;; esac
		echo "$tier_t" | grep -Eq "$tx_re" || {
			echo "selfcheck: bad template tier '$tier_t' in $id"; bad=1
		}
		echo "$tier_c" | grep -Eq "$tx_re" || {
			echo "selfcheck: bad constructed tier '$tier_c' in $id"; bad=1
		}
		if [ "$tx_flag" = 0 ] && { [ "$tier_t" != - ] || [ "$tier_c" != - ]; }; then
			echo "selfcheck: tiers without tx probe in $id"; bad=1
		fi
		case $freq in ''|*[!0-9]*) echo "selfcheck: bad freq '$freq' in $id"; bad=1 ;; esac
	done < <(case_rows)
	[ "$setfreq" -eq "$expected_setfreq_cases" ] || {
		echo "selfcheck: setfreq rows $setfreq != $expected_setfreq_cases"; bad=1
	}
	[ "$hop" -eq "$expected_hop_cases" ] || {
		echo "selfcheck: hop rows $hop != $expected_hop_cases"; bad=1
	}
	[ "$converge" -eq "$expected_converge_cases" ] || {
		echo "selfcheck: converge rows $converge != $expected_converge_cases"; bad=1
	}
	[ "$bad" -eq 0 ] || exit 3
	echo "selfcheck=PASS setfreq=$setfreq hop=$hop converge=$converge"
}

print_plan()
{
	printf 'phase\tcase_id\tfreq\twidth\tcenter\tset_tier\ttx_flag\ttx_tier_template\ttx_tier_constructed\n'
	case_rows
}

selfcheck
if [ "$mode" = selfcheck ]; then
	exit 0
fi
if [ "$mode" = print-plan ]; then
	print_plan
	exit 0
fi
if [ "$mode" != run ] || [ "$authorized" -ne 1 ]; then
	usage
fi

# ---------------------------------------------------------------- inputs
plan_line=$(awk -F'\t' -v id="$expected_case_id" '$1 == id { print }' "$plan" | head -n 1)
[ -n "$plan_line" ] || exit 3
plan_operation=$(awk -F'\t' -v id="$expected_case_id" '$1 == id { print $4 }' "$plan" | head -n 1)
plan_packet_sha256=$(awk -F'\t' -v id="$expected_case_id" '$1 == id { print $3 }' "$plan" | head -n 1)
packet_hex=$(awk -F'\t' -v id="$expected_case_id" '$1 == id { print $7 }' "$plan" | head -n 1 | tr -d '\r')
[ "$plan_operation" = send_after_continuity_fix ] || exit 3
[ -n "$plan_packet_sha256" ] && [ -n "$packet_hex" ] || exit 3
packet_sha256=$(python3 -c 'import binascii,hashlib,sys; print(hashlib.sha256(binascii.unhexlify(sys.argv[1])).hexdigest())' "$packet_hex")
[ "$packet_sha256" = "$plan_packet_sha256" ] || exit 3
sender_sha256=$(sha256sum "$sender" | awk '{print $1}')
[ "$sender_sha256" = "$expected_sender_sha256" ] || exit 3
command -v adb >/dev/null || exit 3
command -v timeout >/dev/null || exit 3
command -v python3 >/dev/null || exit 3
if [ -n "$target_bssid" ]; then
	[[ "$target_bssid" =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ ]] || usage
fi

if [ -z "$serial" ]; then
	mapfile -t serials < <(adb devices | awk '$2 == "device" {print $1}')
	[ "${#serials[@]}" -eq 1 ] || exit 3
	serial=${serials[0]}
fi
adb_cmd=(adb -s "$serial")
[ "$("${adb_cmd[@]}" get-state 2>/dev/null)" = device ] || exit 3

stamp=$(date -u +%Y%m%dT%H%M%SZ)
host_out=$script_dir/host-capture-chandef-vif-$stamp-$$
mkdir "$host_out" || exit 3
echo "HOST_OUTPUT_DIR=$host_out"
cp -p "$cases_tsv" "$sender" "$host_out/"
{
	echo "case_vector=$expected_case_id"
	echo "packet_sha256=$packet_sha256"
	echo "sender_sha256=$sender_sha256"
	echo "target_bssid=${target_bssid:-none}"
} >"$host_out/session-facts.txt"

# Columns: case_id op rc errno set_ok persona post_freq post_width post_center
#          elapsed_ms tx_outcome tx_detail verdict
results_tsv=$host_out/chandef-results.tsv
printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
	case_id op rc errno set_ok persona post_freq post_width post_center \
	elapsed_ms tx_outcome tx_detail verdict >"$results_tsv"

record_row()
{
	printf '%s\n' "$1" >>"$results_tsv"
}

fail_count=0

note_fail()
{
	fail_count=$((fail_count + 1))
	echo "FAIL: $*" >&2
}

adb_shell()
{
	# </dev/null: adb forwards local stdin to the remote shell, so an
	# un-redirected call inside a `while read` loop would otherwise eat the
	# loop's stdin (observed as both table-driven loops collapsing to one
	# case). No adb_shell command ever needs stdin.
	"${adb_cmd[@]}" shell su -c "$1" </dev/null
}

stats()
{
	adb_shell 'cat /sys/kernel/debug/wlan0/frame_inject_stats'
}

sv() # key from stats text on stdin
{
	awk -F= -v key="$1" '$1 == key { print $2 }' | tail -n 1
}

rejection_sum() # stats text on stdin -> sum of all reject counters
{
	awk -F= '$1 ~ /^drop_reason_/ || $1 == "parse_failed" || $1 == "backend_unsupported" || $1 == "state_dropped" || $1 == "queue_full_events" { s += $2 } END { print s + 0 }'
}

iw_info_field() # field from iw dev wlan0 info text on stdin: type|freq|width|center1|ifindex
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

read_state() # -> state_type/state_freq/state_width/state_center1
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

extract_errno() # iw stderr text on stdin -> -NNN
{
	sed -n 's/.*(\(-[0-9][0-9]*\)).*/\1/p' | tail -n 1
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
adb_shell 'cat /sys/class/net/wlan0/address' >"$host_out/mac-original.txt" 2>&1 || exit 4
original_mac=$(tr -d ' \r\n' <"$host_out/mac-original.txt")
[[ "$original_mac" =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ ]] || exit 4
adb_shell 'cmd wifi status' >"$host_out/wifi-before.log" 2>&1 || exit 4
grep -q 'Wifi is connected to' "$host_out/wifi-before.log" || {
	echo "baseline: Wi-Fi must be connected (the lab AP provides the template)" >&2
	exit 4
}
grep -q 'VALIDATED' "$host_out/wifi-before.log" || exit 4
if [ -n "$target_bssid" ]; then
	grep -q "$target_bssid" "$host_out/wifi-before.log" ||
		{ echo "baseline: not connected to target bssid" >&2; exit 4; }
fi
before_ifindex=$(adb_shell 'cat /sys/class/net/wlan0/ifindex' 2>/dev/null | tr -d ' \r\n')
[ -n "$before_ifindex" ] || exit 4
# Wake the phone out of any WoW suspend before touching the persona: a session
# that starts immediately after a WoW resume can wedge the first monitor
# vdev-up in monitor_mode_vdev_up_in_progress (set freq EBUSY).
adb_shell 'input keyevent KEYCODE_WAKEUP' >/dev/null 2>&1 || true
adb_shell 'svc power stayon usb' >"$host_out/stayon.log" 2>&1 || true
sleep 3
adb_shell 'dmesg' >"$host_out/dmesg-before.log" 2>&1 || true
dmesg_baseline=$(sed -n 's/^\[[[:space:]]*\([0-9][0-9.]*\)\].*/\1/p' "$host_out/dmesg-before.log" | tail -n 1)
adb_shell 'iw phy' >"$host_out/iw-phy-before.log" 2>&1 || true
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
# The helper idle window lives under the monitor-only debugfs node; it is read
# right after monitor entry (idle_ms_read guards the restore write).
idle_ms_before=5000
idle_ms_read=0

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
		adb_shell 'dmesg' >"$host_out/teardown-dmesg-before.log" 2>&1 || rc=1
		adb_shell 'iw dev wlan0 set type managed' >"$host_out/restore-managed.log" 2>&1 || rc=1
		wait_persona managed "$current_ifindex" "$host_out/restore-managed-info.log" || rc=1
	else
		printf '%s\n' 'persona=managed_before_restore' >"$host_out/teardown-stats.log"
	fi
	# The helper idle window is only read (never modified) by this runner, so
	# there is nothing to restore on that knob; the module parameter is.
	adb_shell "echo $knob_before > $knob_path" >>"$host_out/knob-trail.txt" 2>&1 || rc=1
	adb_shell 'cmd wifi set-wifi-enabled enabled' >"$host_out/restore-wifi.log" 2>&1 || rc=1
	# Reconnect gate: the framework must come back to a connected, VALIDATED
	# managed persona before the mission-mode VIF probes may run.
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
for _ in $(seq 1 60); do
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
# The recreated monitor netdev inherits the link state of the powered-off
# framework era (DOWN). set freq returns EBUSY forever on a DOWN interface.
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
if [ "$channel_ready" -ne 1 ]; then
	# One bounded persona re-arm: clears a wedged monitor vdev-up flag left by
	# a choreography that started while the soc was still resuming.
	wedged_ifindex=$(adb_shell 'cat /sys/class/net/wlan0/ifindex' 2>/dev/null | tr -d ' \r\n')
	adb_shell 'iw dev wlan0 set type managed' >>"$host_out/set-monitor.log" 2>&1 || true
	wait_persona managed "$wedged_ifindex" "$host_out/monitor-rearm-managed-info.log" || true
	managed_ifindex=$(adb_shell 'cat /sys/class/net/wlan0/ifindex' 2>/dev/null | tr -d ' \r\n')
	adb_shell 'iw dev wlan0 set type monitor' >>"$host_out/set-monitor.log" 2>&1 || true
	wait_persona monitor "$managed_ifindex" "$host_out/monitor-rearm-info.log" || exit 5
	adb_shell 'ip link set wlan0 up' >>"$host_out/ifup-monitor.log" 2>&1 || true
	enter_ap_chandef && channel_ready=1
fi
[ "$channel_ready" -eq 1 ] || { echo "ap chandef set failed" >&2; exit 5; }

# OEM connectivity hooks can race a quick disable->monitor cycle and flip the
# persona back to managed seconds into a run. Require the monitor persona to
# hold steady for 5 s; re-arm on a flip, bounded to 3 attempts.
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
# 4.2 predictable MAC: the persona-assigned monitor identity this session;
# the end-of-run second persona entry must reuse it (per-boot stable random).
adb_shell 'cat /sys/class/net/wlan0/address' >"$host_out/mac-stable-entry.txt" 2>&1
stable_mac_entry=$(tr -d ' \r\n' <"$host_out/mac-stable-entry.txt")
grep -qx 'state=ready' <<<"$ready_stats" || { echo "ctx not ready" >&2; exit 5; }
[ "$(printf '%s\n' "$ready_stats" | sv source_rev)" = "$expected_source_rev" ] || {
	echo "source_rev mismatch" >&2
	exit 5
}
[ "$(printf '%s\n' "$ready_stats" | sv format_version)" = "$expected_stats_format" ] || {
	echo "stats format mismatch" >&2
	exit 5
}
idle_ms_now=$(adb_shell 'cat /sys/kernel/debug/wlan0/frame_inject_helper_idle_ms' 2>/dev/null | tr -d ' \r\n')
case $idle_ms_now in
''|*[!0-9]*) ;;
*)
	idle_ms_before=$idle_ms_now
	idle_ms_read=1
	printf 'idle_ms_before=%s\n' "$idle_ms_before" >>"$host_out/knob-trail.txt"
	;;
esac

remote_dir=/data/local/tmp/qcacld-chandef-vif-$$
"${adb_cmd[@]}" push "$sender" $remote_dir/send_stage1_packet >"$host_out/push-sender.log" 2>&1 || exit 5
adb_shell "mkdir -p $remote_dir" >>"$host_out/push-sender.log" 2>&1 || exit 5
adb_shell "chmod 0755 $remote_dir/send_stage1_packet" >"$host_out/chmod.log" 2>&1 || exit 5
loaded_note=$("${adb_cmd[@]}" exec-out su -c 'od -An -v -tx1 /sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id' | tr -d ' \r\n')
case $loaded_note in *"$expected_build_id"*) ;; *)
	echo "loaded module build id mismatch" >&2
	exit 5
	;;
esac

# ---------------------------------------------------------------- tx probe
# sendto() only proves netdev acceptance; the terminal outcome (FW completion
# round trip or a precise drop reason) is read from the stats v9 ledger.
TX_OUTCOME=
TX_DETAIL=
TX_VERDICT=
tx_probe() # case_id tier
{
	local case_id=$1 tier=$2
	local before b_fw b_rej b_ctx send_rc now fw_d rej_d ctx_d outcome detail
	before=$(stats 2>/dev/null)
	b_fw=$(printf '%s\n' "$before" | sv fw_completion_events)
	b_rej=$(printf '%s\n' "$before" | rejection_sum)
	b_ctx=$(printf '%s\n' "$before" | sv drop_reason_context)
	adb_shell "$remote_dir/send_stage1_packet --send wlan0 $packet_hex" \
		>"$host_out/tx-$case_id.log" 2>&1
	send_rc=$?
	outcome=indeterminate
	detail="send_rc=$send_rc"
	if [ "$send_rc" -ne 0 ]; then
		outcome=sendto_error
	fi
	for _ in $(seq 1 32); do
		now=$(stats 2>/dev/null)
		fw_d=$(( $(printf '%s\n' "$now" | sv fw_completion_events) - b_fw ))
		rej_d=$(( $(printf '%s\n' "$now" | rejection_sum) - b_rej ))
		ctx_d=$(( $(printf '%s\n' "$now" | sv drop_reason_context) - b_ctx ))
		if [ "$fw_d" -gt 0 ]; then
			outcome=fw_completion
			detail="fw_delta=$fw_d"
			break
		fi
		if [ "$rej_d" -gt 0 ]; then
			outcome=rejected
			detail="reject_delta=$rej_d context_delta=$ctx_d reason=$(printf '%s\n' "$now" | sv last_terminal_reason) errno=$(printf '%s\n' "$now" | sv last_terminal_errno)"
			break
		fi
		if [ "$send_rc" -ne 0 ]; then
			break
		fi
		sleep 0.25
	done
	TX_OUTCOME=$outcome
	TX_DETAIL="$detail"
	case $tier in
	must_complete)
		if [ "$outcome" = fw_completion ]; then
			TX_VERDICT=PASS
		else
			TX_VERDICT=FAIL
			note_fail "$case_id tx expected completion got $outcome ($detail)"
		fi
		;;
	must_refuse_either)
		if [ "$outcome" = rejected ] && [ "$ctx_d" -gt 0 ]; then
			TX_VERDICT=PASS
		elif [ "$outcome" = sendto_error ]; then
			# A refusal already at the socket boundary is still a precise
			# failure, never a silent success.
			TX_VERDICT=PASS
			TX_DETAIL="$detail precise_socket_refusal"
		else
			TX_VERDICT=FAIL
			note_fail "$case_id tx expected precise refusal got $outcome ($detail)"
		fi
		;;
	observation)
		TX_VERDICT=OBS
		;;
	*)
		TX_VERDICT=FAIL
		note_fail "$case_id tx bad tier $tier"
		;;
	esac
}

# ---------------------------------------------------------------- set freq case
# Sets SET_RESULT (rc errno set_ok persona post_freq post_width post_center
# elapsed_ms), SET_VERDICT and setfreq_ok.
setfreq_ok=0
SET_RESULT=
SET_VERDICT=
run_setfreq() # case_id freq width center tier
{
	local case_id=$1 freq=$2 width=$3 center=$4 tier=$5
	local args rc errno elapsed start
	if [ "$center" = - ]; then
		args="$freq $width"
	else
		args="$freq $width $center"
	fi
	start=$(date +%s%3N)
	adb_shell "iw dev wlan0 set freq $args" >"$host_out/setfreq-$case_id.log" 2>&1
	rc=$?
	elapsed=$(( $(date +%s%3N) - start ))
	errno=$(extract_errno <"$host_out/setfreq-$case_id.log")
	read_state
	setfreq_ok=0
	if [ "$rc" -eq 0 ] && [ "$state_type" = monitor ] && [ "$state_freq" = "$freq" ]; then
		setfreq_ok=1
	fi
	SET_RESULT="$rc	${errno:--}	$setfreq_ok	$state_type	${state_freq:--}	${state_width:--}	${state_center1:--}	$elapsed"
	case $tier in
	must_accept)
		if [ "$setfreq_ok" -eq 1 ]; then
			SET_VERDICT=PASS
		else
			SET_VERDICT=FAIL
			note_fail "$case_id setfreq refused rc=$rc errno=${errno:--} post=$state_type/$state_freq"
		fi
		;;
	observation)
		SET_VERDICT=OBS
		;;
	esac
}

# ---------------------------------------------------------------- mode probe
# Observation tier on purpose: both a template completion and a constructed
# refusal/completion are legal session shapes; helper_context_source decides.
context_mode=
helper_source=
tx_probe ap.first observation
if [ "$TX_OUTCOME" = fw_completion ]; then
	helper_source=
	for _ in $(seq 1 40); do
		snapshot=$(stats 2>/dev/null)
		grep -qx 'helper_present=1' <<<"$snapshot" || {
			sleep 0.25
			continue
		}
		helper_source=$(printf '%s\n' "$snapshot" | sv helper_context_source)
		[ -n "$helper_source" ] && [ "$helper_source" != none ] && break
		sleep 0.25
	done
	case $helper_source in
	managed_template)
		context_mode=template
		record_row "ap.first	send@ap_chandef	-	-	-	monitor	$before_freq	$before_width	$before_center1	0	$TX_OUTCOME	source=$helper_source	PASS"
		;;
	constructed)
		context_mode=constructed
		record_row "ap.first	send@ap_chandef	-	-	-	monitor	$before_freq	$before_width	$before_center1	0	$TX_OUTCOME	source=$helper_source	PASS"
		;;
	*)
		record_row "ap.first	send@ap_chandef	-	-	-	monitor	$before_freq	$before_width	$before_center1	0	$TX_OUTCOME	source=${helper_source:-unlatched}	FAIL"
		note_fail "ap.first completion without a usable helper_context_source"
		;;
	esac
elif [ "$TX_OUTCOME" = rejected ]; then
	rej_ctx=${TX_DETAIL#*context_delta=}
	rej_ctx=${rej_ctx%% *}
	case $rej_ctx in
	''|*[!0-9]*) rej_ctx=0 ;;
	esac
	if [ "$rej_ctx" -gt 0 ]; then
		# The template latch missed (disconnect settled slowly); the whole
		# matrix then runs in constructed mode, which is a legal session.
		context_mode=constructed
		helper_source=constructed
		record_row "ap.first	send@ap_chandef	-	-	-	monitor	$before_freq	$before_width	$before_center1	0	$TX_OUTCOME	template_latch_missed	PASS"
	else
		record_row "ap.first	send@ap_chandef	-	-	-	monitor	$before_freq	$before_width	$before_center1	0	$TX_OUTCOME	$TX_DETAIL	FAIL"
		note_fail "ap.first rejected without the context reason: $TX_DETAIL"
	fi
else
	record_row "ap.first	send@ap_chandef	-	-	-	monitor	$before_freq	$before_width	$before_center1	0	$TX_OUTCOME	$TX_DETAIL	FAIL"
	note_fail "ap.first indeterminate mode probe: $TX_OUTCOME"
fi
[ -n "$context_mode" ] || { echo "mode probe failed" >&2; exit 6; }
printf 'context_mode=%s helper_context_source=%s template_width=%s\n' \
	"$context_mode" "$helper_source" "$before_width" >"$host_out/context-mode.txt"
# The AP-chandef 80 MHz row only completes through a matching 80 MHz template.
ap_80_template_tier=must_complete
[ "$before_width" = 80 ] || ap_80_template_tier=must_refuse_either

# ---------------------------------------------------------------- setfreq matrix
while IFS=$'\t' read -r case_id phase freq width center set_tier tx_flag tier_t tier_c; do
	[ "$phase" = setfreq ] || continue
	resolved_tier=$([ "$context_mode" = template ] && echo "$tier_t" || echo "$tier_c")
	if [ "$case_id" = ch.5g.5745.80 ] && [ "$context_mode" = template ]; then
		resolved_tier=$ap_80_template_tier
	fi
	run_setfreq "$case_id" "$freq" "$width" "$center" "$set_tier"
	tx_out=-
	tx_det=-
	tx_verd=-
	if [ "$setfreq_ok" -eq 1 ] && [ "$tx_flag" = 1 ]; then
		tx_probe "$case_id" "$resolved_tier"
		tx_out=$TX_OUTCOME
		tx_det=$TX_DETAIL
		tx_verd=$TX_VERDICT
	elif [ "$tx_flag" = 1 ]; then
		# Set refused: for must_refuse_either this is the other half of the
		# either-layer contract; must_complete rows already failed above.
		if [ "$resolved_tier" = must_refuse_either ]; then
			tx_out=set_refused
			tx_det="set refusal satisfies either-layer contract"
			tx_verd=PASS
		else
			tx_out=skipped
			tx_det="set refused"
			tx_verd=OBS
		fi
	fi
	record_row "$case_id	setfreq	$SET_RESULT	$tx_out	$tx_det	$tx_verd"
done < <(case_rows)

# ---------------------------------------------------------------- hopping
hop_ok_count=0
while IFS=$'\t' read -r case_id phase freq width center set_tier tx_flag tier_t tier_c; do
	[ "$phase" = hop ] || continue
	# First attempt carries no gate: one transient EBUSY from the vdev restart
	# must not fail the hop; the bounded retry then carries the gate.
	run_setfreq "$case_id" "$freq" "$width" "$center" observation
	if [ "$setfreq_ok" -ne 1 ]; then
		run_setfreq "$case_id" "$freq" "$width" "$center" "$set_tier"
	fi
	if [ "$setfreq_ok" -eq 1 ]; then
		hop_ok_count=$((hop_ok_count + 1))
		record_row "$case_id	hop	$SET_RESULT	-	-	$SET_VERDICT"
	else
		record_row "$case_id	hop	$SET_RESULT	-	-	$SET_VERDICT"
	fi
done < <(case_rows)
[ "$hop_ok_count" -eq "$expected_hop_cases" ] ||
	note_fail "hopping $hop_ok_count/$expected_hop_cases hops accepted"

# ---------------------------------------------------------------- converge
converge_width=$([ "$context_mode" = template ] && echo "$before_width" || echo HT20)
converge_center=$([ "$context_mode" = template ] && echo "$before_center1" || echo -)
run_setfreq converge.5745 5745 "$converge_width" "$converge_center" must_accept
set_result_conv=$SET_RESULT
set_verdict_conv=$SET_VERDICT
tx_probe converge.5745 must_complete
record_row "converge.5745	converge	$set_result_conv	$TX_OUTCOME	$TX_DETAIL	$set_verdict_conv/$TX_VERDICT"

# ---------------------------------------------------------------- 4.2 sysfs channel (unified chandef flow)
# The WEXT/sysfs monitor channel path now funnels through the same unified
# apply core as nl80211 (wlan_hdd_mon_apply_chandef): a sysfs write must move
# the channel exactly like "iw set freq" and leave injection re-armed.
sysfs_chan=/sys/class/net/wlan0/monitor_mode_channel
adb_shell "echo 5180 0 > $sysfs_chan" >"$host_out/sysfs-chan-5180.log" 2>&1
sleep 1
read_state
sysfs_ok=0
[ "${state_freq:-0}" = 5180 ] && sysfs_ok=1
if [ "$sysfs_ok" -eq 1 ]; then
	record_row "sysfs.set_5180_20	sysfs monitor_mode_channel	0	-	1	monitor	${state_freq}	${state_width:-}	${state_center1:--}	0	-	unified_apply_moved_channel	PASS"
else
	record_row "sysfs.set_5180_20	sysfs monitor_mode_channel	1	-	0	monitor	${state_freq:--}	-	-	0	-	channel_did_not_move	FAIL"
	note_fail "sysfs monitor_mode_channel write did not move the channel"
fi
tx_probe sysfs.tx_after must_complete
record_row "sysfs.tx_after	sysfs then send	-	-	-	monitor	5180	-	-	0	$TX_OUTCOME	$TX_DETAIL	$TX_VERDICT"
# Back to the AP chandef through the nl80211 path (external intent wins).
run_setfreq sysfs.back_to_ap 5745 "$converge_width" "$converge_center" must_accept
record_row "sysfs.back_to_ap	iw set freq after sysfs	$SET_RESULT	-	-	$SET_VERDICT"

# ---------------------------------------------------------------- 4.2 monitor survey
# dump_survey in the monitor persona must report IN_USE on the operating
# channel (the stock path never sets it for a monitor adapter). Noise floor
# and CCA time/busy/tx deltas depend on the firmware answering the on-demand
# congestion-stats request, so their absence is a recorded FW boundary (OBS),
# never silently a PASS.
hop_node=/sys/kernel/debug/wlan0/frame_inject_channel_hop
survey_node=/sys/kernel/debug/wlan0/frame_inject_survey
adb_shell "cat $survey_node" >"$host_out/survey-node-1.log" 2>&1
adb_shell 'iw dev wlan0 survey dump' >"$host_out/survey-dump-1.log" 2>&1
sleep 3
adb_shell 'iw dev wlan0 survey dump' >"$host_out/survey-dump-2.log" 2>&1
sleep 3
adb_shell 'iw dev wlan0 survey dump' >"$host_out/survey-dump-3.log" 2>&1
adb_shell "cat $survey_node" >"$host_out/survey-node-2.log" 2>&1
survey_inuse=0
for f in survey-dump-1 survey-dump-2 survey-dump-3; do
	# iw prints "\tfrequency: 5745 MHz" plus "\tchannel: 149 [IN USE]" for
	# the in-use record; accept the MHz on either line.
	if grep -Eq "(frequency|channel).*${state_freq}.*MHz|channel.*\[IN USE\]" \
		"$host_out/$f.log" 2>/dev/null &&
		grep -qi "in use" "$host_out/$f.log" 2>/dev/null; then
		survey_inuse=$((survey_inuse + 1))
	fi
done
if [ "$survey_inuse" -ge 2 ]; then
	record_row "survey.in_use	dump_survey monitor	0	-	1	monitor	${state_freq}	-	-	0	-	in_use_seen=$survey_inuse/3	PASS"
else
	record_row "survey.in_use	dump_survey monitor	0	-	0	monitor	${state_freq:--}	-	-	0	-	in_use_seen=$survey_inuse/3	FAIL"
	note_fail "monitor survey IN_USE not reported ($survey_inuse/3 dumps)"
fi
survey_noise_state=$(awk -F= '$1 == "nf_valid" { print $2 }' "$host_out/survey-node-2.log" 2>/dev/null | tail -n 1)
survey_cca_state=$(awk -F= '$1 == "cca_updates" { print $2 }' "$host_out/survey-node-2.log" 2>/dev/null | tail -n 1)
survey_busy_state=absent
grep -q "channel time busy" "$host_out/survey-dump-3.log" 2>/dev/null && survey_busy_state=present
record_row "survey.noise_fw	nf via congestion stats	0	-	0	-	-	-	-	0	-	nf_valid=$survey_noise_state	fw_boundary_$survey_noise_state	OBS"
record_row "survey.cca_time_busy	time/busy/tx deltas	0	-	0	-	-	-	-	0	-	cca_updates=$survey_cca_state busy=$survey_busy_state	fw_boundary_$survey_cca_state	OBS"

# ---------------------------------------------------------------- 4.2 driver-side channel hop
# Kernel-scheduled hop over the same unified apply path. Assertions:
#   - the node exists and parses (bad syntax -> EINVAL, no session);
#   - a session cycles the listed channels with real switch latency;
#   - a plan whose second entry the firmware refuses (2484 per the
#     chandef-109 verdict) parks the session after exactly one hop;
#   - "stop" cancels and an external set wins.
adb_shell "cat $hop_node" >"$host_out/hop-idle.log" 2>&1
hop_idle_active=$(awk -F= '$1 == "active" { print $2 }' "$host_out/hop-idle.log" 2>/dev/null | tail -n 1)
[ "$hop_idle_active" = 0 ] || note_fail "hop node not idle at section start"
adb_shell "echo 'start 5 2412' > $hop_node" >"$host_out/hop-bad-dwell.log" 2>&1
hop_bad_dwell_rc=$?
adb_shell "echo 'go 100 2412' > $hop_node" >"$host_out/hop-bad-verb.log" 2>&1
hop_bad_verb_rc=$?
adb_shell "cat $hop_node" >"$host_out/hop-after-bad.log" 2>&1
hop_still_idle=$(awk -F= '$1 == "active" { print $2 }' "$host_out/hop-after-bad.log" 2>/dev/null | tail -n 1)
if [ "$hop_bad_dwell_rc" -ne 0 ] && [ "$hop_bad_verb_rc" -ne 0 ] && [ "$hop_still_idle" = 0 ]; then
	record_row "hop.reject_bad_syntax	debugfs write	0	-	1	-	-	-	-	0	-	dwell_and_verb_refused_idle_stayed	PASS"
else
	record_row "hop.reject_bad_syntax	debugfs write	0	-	0	-	-	-	-	0	-	rc_dwell=$hop_bad_dwell_rc rc_verb=$hop_bad_verb_rc active=$hop_still_idle	FAIL"
	note_fail "hop bad syntax not precisely refused"
fi
adb_shell "echo 'start 400 2412 2437 2462' > $hop_node" >"$host_out/hop-start.log" 2>&1
# Cycle detection samples the scheduler's own last_freq trail with a pushed
# script (100ms cadence): kernel truth, dense enough that a ~440ms-per-
# channel rotation cannot alias a channel away. Host-side adb polling aliased
# it away at 0.3s and 0.5s cadence, and an inline device-side loop died on
# adb/su quote stripping ("syntax error: unexpected 'do'") - so the sampler
# is a real file, executed with sh (the r3 rule: never fight adb quoting).
cat >"$host_out/hop_sample.sh" <<'HSEOF'
#!/system/bin/sh
i=0
while [ "$i" -lt 90 ]; do
	sed -n 's/^last_freq=//p' /sys/kernel/debug/wlan0/frame_inject_channel_hop
	sleep 0.1
	i=$((i + 1))
done
HSEOF
"${adb_cmd[@]}" push "$host_out/hop_sample.sh" $remote_dir/hop_sample.sh \
	>"$host_out/hop-trail-push.log" 2>&1 || exit 5
adb_shell "sh $remote_dir/hop_sample.sh" >"$host_out/hop-trail.log" 2>&1
hop_cycle_seen=0
hop_freqs_seen=$(sort -u "$host_out/hop-trail.log" 2>/dev/null | \
	grep -E '^(2412|2437|2462)$' | paste -sd, -)
for want in 2412 2437 2462; do
	case ",$hop_freqs_seen," in
	*",$want,"*) hop_cycle_seen=$((hop_cycle_seen + 1)) ;;
	esac
done
adb_shell "cat $hop_node" >"$host_out/hop-running.log" 2>&1
hop_active_run=$(awk -F= '$1 == "active" { print $2 }' "$host_out/hop-running.log" | tail -n 1)
hop_hops_run=$(awk -F= '$1 == "hops" { print $2 }' "$host_out/hop-running.log" | tail -n 1)
hop_errors_run=$(awk -F= '$1 == "errors" { print $2 }' "$host_out/hop-running.log" | tail -n 1)
hop_switch_ms=$(awk -F= '$1 == "last_switch_ns" { printf "%d", $2 / 1000000 }' "$host_out/hop-running.log" | tail -n 1)
adb_shell "echo stop > $hop_node" >"$host_out/hop-stop.log" 2>&1
sleep 1
adb_shell "cat $hop_node" >"$host_out/hop-stopped.log" 2>&1
hop_active_stop=$(awk -F= '$1 == "active" { print $2 }' "$host_out/hop-stopped.log" | tail -n 1)
if [ "$hop_active_run" = 1 ] && [ "${hop_hops_run:-0}" -ge 8 ] && [ "$hop_errors_run" = 0 ] &&
	[ "$hop_cycle_seen" -eq 3 ] && [ "$hop_active_stop" = 0 ]; then
	record_row "hop.session	dwell 400ms x3 ch	0	-	1	monitor	-	-	-	0	-	hops=$hop_hops_run cycle=$hop_cycle_seen/3 switch_ms=$hop_switch_ms	PASS"
else
	record_row "hop.session	dwell 400ms x3 ch	0	-	0	monitor	-	-	-	0	-	active=$hop_active_run hops=${hop_hops_run:-0} cycle=$hop_cycle_seen/3 errors=$hop_errors_run stopped=$hop_active_stop	FAIL"
	note_fail "driver hop session did not cycle as specified"
fi
# Park-on-error: the @80p80 hop entry is refused by the unified core (FW
# vht max BW is 160, measured 2026-09-04: "invalid BW received 4"), so the
# session must park after ~one hop with a non-zero last_error. Firmware
# owns the verdict: if it accepts the combo this boot, there is no refusal
# to park on and the row records that fact. (The former plan used 5955@160,
# but that verdict was a bad-vector artifact - 6025 is a legal center and
# 6G 160 is accepted end-to-end; 80p80 is the proven-refused entry.)
adb_shell "echo 'start 400 2412 5955@80p80' > $hop_node" >"$host_out/hop-park-start.log" 2>&1
# The refused channel fails through the unified core's fail-closed path
# (vdev-up wait), so allow the full timeout window before reading state.
sleep 9
adb_shell "cat $hop_node" >"$host_out/hop-park.log" 2>&1
hop_park_active=$(awk -F= '$1 == "active" { print $2 }' "$host_out/hop-park.log" | tail -n 1)
hop_park_hops=$(awk -F= '$1 == "hops" { print $2 }' "$host_out/hop-park.log" | tail -n 1)
hop_park_err=$(awk -F= '$1 == "last_error" { print $2 }' "$host_out/hop-park.log" | tail -n 1)
if [ "$hop_park_active" = 0 ] && [ "${hop_park_hops:-99}" -le 2 ] && [ "$hop_park_err" != 0 ] && [ -n "$hop_park_err" ]; then
	record_row "hop.park_on_error	plan with FW-refused ch	0	-	1	monitor	2412	-	-	0	-	hops=$hop_park_hops last_error=$hop_park_err	PASS"
else
	record_row "hop.park_on_error	plan with FW-refused ch	0	-	0	monitor	-	-	-	0	-	active=$hop_park_active hops=${hop_park_hops:-0} last_error=${hop_park_err:-none}	fw_accepted_no_refusal_this_boot	OBS"
fi
# External set wins: an iw set freq must end any doubt about ownership and
# restore the AP chandef for the remaining sections.
run_setfreq hop.back_to_ap 5745 "$converge_width" "$converge_center" must_accept
record_row "hop.back_to_ap	external set after hop	$SET_RESULT	-	-	$SET_VERDICT"
adb_shell "cat $hop_node" >"$host_out/hop-final.log" 2>&1

# ---------------------------------------------------------------- up/down
updown_down_rc=0
adb_shell 'ip link set wlan0 down' >"$host_out/updown-down.log" 2>&1 || updown_down_rc=$?
read_state
if [ "$updown_down_rc" -eq 0 ] && [ "$state_type" = monitor ]; then
	record_row "updown.down	ip link down	0	-	1	monitor	${state_freq:--}	${state_width:--}	${state_center1:--}	0	-	-	PASS"
elif [ "$updown_down_rc" -ne 0 ]; then
	record_row "updown.down	ip link down	$updown_down_rc	-	0	${state_type:--}	-	-	-	0	-	-	FAIL"
	note_fail "updown: ip link down refused rc=$updown_down_rc"
else
	record_row "updown.down	ip link down	0	-	0	${state_type:--}	-	-	-	0	-	persona_changed	FAIL"
	note_fail "updown: persona changed on link down"
fi
tx_probe updown.tx_down observation
record_row "updown.tx_down	send while down	-	-	-	monitor	-	-	-	0	$TX_OUTCOME	$TX_DETAIL	$TX_VERDICT"
adb_shell 'ip link set wlan0 up' >"$host_out/updown-up.log" 2>&1 ||
	note_fail "updown: ip link up refused"
run_setfreq updown.reassert 5745 "$converge_width" "$converge_center" must_accept
set_result_up=$SET_RESULT
set_verdict_up=$SET_VERDICT
tx_probe updown.tx_up must_complete
record_row "updown.reassert	setfreq after up	$set_result_up	$TX_OUTCOME	$TX_DETAIL	$set_verdict_up/$TX_VERDICT"

# ---------------------------------------------------------------- monitor MAC
adb_shell 'ip link set wlan0 down' >"$host_out/mac-down.log" 2>&1 || true
adb_shell "ip link set wlan0 address $test_mac_local" >"$host_out/mac-set.log" 2>&1
mac_set_rc=$?
mac_set_errno=$(extract_errno <"$host_out/mac-set.log")
adb_shell 'cat /sys/class/net/wlan0/address' >"$host_out/mac-after-set.txt" 2>&1
mac_after_set=$(tr -d ' \r\n' <"$host_out/mac-after-set.txt")
adb_shell 'ip link set wlan0 up' >"$host_out/mac-up.log" 2>&1 || true
mac_set_ok=0
[ "$mac_after_set" = "$test_mac_local" ] && mac_set_ok=1
mac_verdict=FAIL
mac_note=
if [ "$mac_set_rc" -eq 0 ] && [ "$mac_set_ok" -eq 1 ]; then
	mac_verdict=PASS
	mac_note=applied
elif [ "$mac_set_rc" -ne 0 ] && [ -n "$mac_set_errno" ]; then
	mac_verdict=PASS
	mac_note=precise_refusal
else
	note_fail "mac set neither applied nor precisely refused rc=$mac_set_rc"
fi
record_row "mac.set_random	set address	$mac_set_rc	${mac_set_errno:--}	$mac_set_ok	-	-	-	-	0	-	addr=$mac_after_set note=$mac_note	$mac_verdict"
run_setfreq mac.reassert 5745 "$converge_width" "$converge_center" must_accept
set_result_mac=$SET_RESULT
set_verdict_mac=$SET_VERDICT
tx_probe mac.tx_after_change must_complete
record_row "mac.reassert	setfreq after mac	$set_result_mac	$TX_OUTCOME	$TX_DETAIL	$set_verdict_mac/$TX_VERDICT"
adb_shell 'ip link set wlan0 down' >"$host_out/mac-restore-down.log" 2>&1 || true
adb_shell "ip link set wlan0 address $original_mac" >"$host_out/mac-restore.log" 2>&1 || true
adb_shell 'ip link set wlan0 up' >"$host_out/mac-restore-up.log" 2>&1 || true
adb_shell 'cat /sys/class/net/wlan0/address' >"$host_out/mac-after-restore.txt" 2>&1
mac_after_restore=$(tr -d ' \r\n' <"$host_out/mac-after-restore.txt")
if [ "$mac_after_restore" = "$original_mac" ]; then
	record_row "mac.restore	restore original	0	-	1	-	-	-	-	0	-	addr=$mac_after_restore	PASS"
else
	record_row "mac.restore	restore original	0	-	0	-	-	-	-	0	-	addr=$mac_after_restore	FAIL"
	note_fail "monitor MAC not restored to the original address"
fi

# ---------------------------------------------------------------- mon0 while standalone monitor
# FW poison verdict (2026-09-03 bisect, boots 3d9531c9..5c964214): bringing a
# second monitor vdev UP silently corrupts FW unicast delivery (EAPOL M1 lost,
# reason=15 until power cycle), with or without a concurrent STA. v11 restored
# the p2p LPC gate, so monitor-type adds must be REFUSED here; creation is
# forbidden (never bring it up). add/del without up is FW-safe but pointless.
adb_shell 'iw dev wlan0 interface add mon0 type monitor' >"$host_out/mon0-add-monitor-state.log" 2>&1
mon0_ms_rc=$?
mon0_ms_errno=$(extract_errno <"$host_out/mon0-add-monitor-state.log")
adb_shell 'iw dev' >"$host_out/iw-dev-monitor-state.log" 2>&1
if grep -q 'Interface mon0' "$host_out/iw-dev-monitor-state.log"; then
	adb_shell 'iw dev mon0 del' >"$host_out/mon0-ms-del.log" 2>&1 || true
	record_row "vifms.mon0_add	add mon0 monitor-state	$mon0_ms_rc	${mon0_ms_errno:--}	1	-	-	-	-	0	-	created_then_deleted	FORBIDDEN(FW poison on mon0 up; gate should have refused)"
	note_fail "mon0 add unexpectedly accepted (v11 LPC gate must refuse monitor adds)"
else
	record_row "vifms.mon0_add	add mon0 monitor-state	$mon0_ms_rc	${mon0_ms_errno:--}	0	-	-	-	-	0	-	refused	PASS"
fi

# ---------------------------------------------------------------- teardown + mission-mode VIF
# Wait for the idle reclaim so the final snapshot documents owner zero
# (bounded by the configured idle window plus slack).
reclaimed=0
for _ in $(seq 1 $(( idle_ms_before / 500 + 40 ))); do
	snapshot=$(stats 2>/dev/null)
	if grep -qx 'helper_present=0' <<<"$snapshot" &&
		grep -qx 'helper_wma_owner_mask=0x0' <<<"$snapshot"; then
		reclaimed=1
		break
	fi
	sleep 0.5
done
printf '%s\n' "${snapshot:-$(stats 2>/dev/null)}" >"$host_out/stats-pre-restore.log"
[ "$reclaimed" -eq 1 ] || note_fail "helper never idle-reclaimed before persona restore"

restore_managed || {
	echo "restore failed" >&2
	exit 9
}
trap - EXIT HUP INT TERM

adb_shell 'cat /proc/sys/kernel/random/boot_id' >"$host_out/boot-id-after.txt" || exit 9
cmp -s "$host_out/boot-id-before.txt" "$host_out/boot-id-after.txt" || {
	echo "boot id changed" >&2
	exit 9
}

teardown_invariants()
{
	[ "$(sv format_version <"$1")" = "$expected_stats_format" ] || return 1
	[ "$(sv source_rev <"$1")" = "$expected_source_rev" ] || return 1
	[ "$(sv fatal_latched <"$1")" = 0 ] || return 1
	[ "$(sv mgmt_inflight <"$1")" = 0 ] || return 1
	[ "$(sv queue_depth <"$1")" = 0 ] || return 1
	[ "$(sv active_request_id <"$1")" = 0 ] || return 1
	return 0
}
final_stats=$host_out/stats-pre-restore.log
teardown_invariants "$final_stats" || { echo "teardown stats invariants failed" >&2; exit 9; }
[ "$(sv helper_present <"$final_stats")" = 0 ] || exit 9
[ "$(sv helper_wma_owner_mask <"$final_stats")" = "0x0" ] || exit 9

# Mission-mode VIF probes: v11 restored the LPC gate, so monitor adds must be
# refused precisely; managed must survive every refusal. If a mon0 ever slips
# through, delete it WITHOUT bringing it up (mon0 up = FW poison, see the
# 2026-09-03 bisect verdict in the standalone block above).
adb_shell 'iw dev wlan0 interface add mon0 type monitor' >"$host_out/mon0-add-mission.log" 2>&1
mon0_mm_rc=$?
mon0_mm_errno=$(extract_errno <"$host_out/mon0-add-mission.log")
adb_shell 'iw dev' >"$host_out/iw-dev-mission.log" 2>&1
if grep -q 'Interface mon0' "$host_out/iw-dev-mission.log"; then
	adb_shell 'iw dev mon0 del' >"$host_out/mon0-mm-del.log" 2>&1 || true
	record_row "vifmm.mon0_plain	add mon0 mission	$mon0_mm_rc	${mon0_mm_errno:--}	1	-	-	-	-	0	created_then_deleted	FORBIDDEN(FW poison on mon0 up; gate should have refused)"
	note_fail "mon0 add unexpectedly accepted in mission state (v11 LPC gate must refuse)"
else
	record_row "vifmm.mon0_plain	add mon0 mission	$mon0_mm_rc	${mon0_mm_errno:--}	0	-	-	-	-	0	-	precise_refusal	PASS"
fi
adb_shell 'iw dev wlan0 interface add mon0 type monitor flag otherbss' \
	>"$host_out/mon0-add-otherbss.log" 2>&1
mon0_ob_rc=$?
mon0_ob_errno=$(extract_errno <"$host_out/mon0-add-otherbss.log")
adb_shell 'iw dev' >"$host_out/iw-dev-after-otherbss.log" 2>&1
if grep -q 'Interface mon0' "$host_out/iw-dev-after-otherbss.log"; then
	adb_shell 'iw dev mon0 del' >>"$host_out/mon0-add-otherbss.log" 2>&1 || true
	record_row "vifmm.mon0_otherbss	add mon0 otherbss	$mon0_ob_rc	${mon0_ob_errno:--}	1	-	-	-	-	0	-	created_deleted	OBS"
else
	record_row "vifmm.mon0_otherbss	add mon0 otherbss	$mon0_ob_rc	${mon0_ob_errno:--}	0	-	-	-	-	0	-	precise_refusal	PASS"
fi
adb_shell 'cmd wifi status' >"$host_out/wifi-after-vif.log" 2>&1
adb_shell 'iw dev wlan0 info' >"$host_out/iw-after-vif.log" 2>&1
vif_survivor=1
grep -q 'Wifi is connected to' "$host_out/wifi-after-vif.log" || vif_survivor=0
grep -q 'VALIDATED' "$host_out/wifi-after-vif.log" || vif_survivor=0
[ "$(iw_info_field type <"$host_out/iw-after-vif.log" | head -n 1)" = managed ] || vif_survivor=0
grep -q 'Interface mon0' "$host_out/iw-dev-after-otherbss.log" && vif_survivor=0
if [ "$vif_survivor" -eq 1 ]; then
	record_row "vifmm.managed_survives	status after VIF	0	-	1	managed	-	-	-	0	-	connected_validated_no_mon0	PASS"
else
	record_row "vifmm.managed_survives	status after VIF	1	-	0	$(iw_info_field type <"$host_out/iw-after-vif.log" | head -n 1)	-	-	-	0	-	-	FAIL"
	note_fail "managed persona did not survive the VIF probes"
fi
record_row "mlo.env	status	0	-	0	-	-	-	-	0	-	environment_limited_no_mlo_ap	OBS"

# ---------------------------------------------------------------- 4.2 monitor MAC stability
# Second monitor persona entry in the same boot: the v12 per-boot stable
# random MAC must be reused (default policy; a user-armed MAC would be a
# different, explicitly selected identity). Also proves the self-TX echo
# hook recorded the persona identity.
adb_shell 'cmd wifi set-wifi-enabled disabled' >"$host_out/mac2-disable.log" 2>&1
mac2_off=0
for _ in $(seq 1 60); do
	off_status=$(adb_shell 'cmd wifi status' 2>/dev/null | tr -d '\r')
	off_supp=$(adb_shell 'pidof wpa_supplicant' 2>/dev/null | tr -d '\r\n')
	if grep -q '^Wifi is disabled$' <<<"$off_status" && [ -z "$off_supp" ]; then
		mac2_off=1
		break
	fi
	sleep 0.5
done
[ "$mac2_off" -eq 1 ] || note_fail "mac2: Wi-Fi off never settled"
mac2_prev_ifindex=$(adb_shell 'cat /sys/class/net/wlan0/ifindex' 2>/dev/null | tr -d ' \r\n')
adb_shell 'iw dev wlan0 set type monitor' >"$host_out/mac2-monitor.log" 2>&1
if wait_persona monitor "$mac2_prev_ifindex" "$host_out/mac2-monitor-info.log"; then
	adb_shell 'cat /sys/class/net/wlan0/address' >"$host_out/mac-stable-second.txt" 2>&1
	stable_mac_second=$(tr -d ' \r\n' <"$host_out/mac-stable-second.txt")
	adb_shell 'cat /sys/kernel/debug/wlan0/frame_inject_monitor_filter' 		>"$host_out/mac2-filter-node.log" 2>&1
	echo_mac_hook=$(awk -F= '$1 == "self_tx_echo_monitor_mac" { print $2 }' \
		"$host_out/mac2-filter-node.log" 2>/dev/null | tail -n 1)
	if [ "$stable_mac_second" = "$stable_mac_entry" ]; then
		record_row "mac2.stable_per_boot	second persona entry	0	-	1	monitor	-	-	-	0	-	mac=$stable_mac_second hook_mac=$echo_mac_hook	PASS"
	else
		record_row "mac2.stable_per_boot	second persona entry	0	-	0	monitor	-	-	-	0	-	entry=$stable_mac_entry second=$stable_mac_second	FAIL"
		note_fail "monitor MAC changed between persona entries (stable-per-boot policy violated)"
	fi
	adb_shell 'iw dev wlan0 set type managed' >"$host_out/mac2-restore-managed.log" 2>&1 || true
	mac2_mon_ifindex=$(adb_shell 'cat /sys/class/net/wlan0/ifindex' 2>/dev/null | tr -d ' \r\n')
	wait_persona managed "$mac2_mon_ifindex" "$host_out/mac2-managed-info.log" || \
		note_fail "mac2: persona restore to managed failed"
else
	record_row "mac2.stable_per_boot	second persona entry	1	-	0	-	-	-	-	0	-	monitor entry failed	OBS"
	note_fail "mac2: second monitor entry failed"
fi
adb_shell 'cmd wifi set-wifi-enabled enabled' >"$host_out/mac2-wifi-on.log" 2>&1 || true
mac2_reconnected=0
for _ in $(seq 1 240); do
	status=$(adb_shell 'cmd wifi status' 2>/dev/null | tr -d '\r')
	if grep -q 'Wifi is connected to' <<<"$status" && grep -q 'VALIDATED' <<<"$status"; then
		printf '%s\n' "$status" >"$host_out/mac2-wifi-restored.log"
		mac2_reconnected=1
		break
	fi
	sleep 0.5
done
[ "$mac2_reconnected" -eq 1 ] || note_fail "mac2: Wi-Fi did not reconnect after second cycle"
record_row "mac2.reconnect	managed after 2nd cycle	0	-	$mac2_reconnected	managed	-	-	-	0	-	connected_validated	$([ $mac2_reconnected -eq 1 ] && echo PASS || echo FAIL)"

adb_shell "rm -rf $remote_dir" >"$host_out/remote-cleanup.log" 2>&1 || true
adb_shell 'rm -rf /data/local/tmp/qcacld-chandef-vif-*' >>"$host_out/remote-cleanup.log" 2>&1 || true

# ---------------------------------------------------------------- fatal scan
adb_shell 'dmesg' >"$host_out/dmesg-after.log" 2>&1 || true
if [ -n "$dmesg_baseline" ]; then
	awk -v baseline="$dmesg_baseline" \
		'{ match($0, /^\[[[:space:]]*([0-9][0-9.]*)\]/, m); \
		  if (m[1] != "" && (m[1] + 0) > (baseline + 0)) print }' \
		"$host_out/dmesg-after.log" >"$host_out/dmesg-delta.log"
else
	cp "$host_out/dmesg-after.log" "$host_out/dmesg-delta.log"
fi
fatal_markers=0
grep -Eq 'Kernel panic|CFI failure|Internal error|arm-smmu|spl_kmem_cache|subsystem-restart|WLAN recovery|cnss.*recovery|qdf_fatal|BUG:|Oops:' \
	"$host_out/dmesg-delta.log" && fatal_markers=1
if [ "$fatal_markers" -eq 0 ]; then
	record_row "dmesg.fatal_scan	scan delta	0	-	1	-	-	-	-	0	-	markers=0	PASS"
else
	record_row "dmesg.fatal_scan	scan delta	0	-	0	-	-	-	-	0	-	markers=1	FAIL"
	note_fail "fatal markers in dmesg delta"
fi
grep -i 'frame_inject' "$host_out/dmesg-delta.log" >"$host_out/dmesg-frame-inject-delta.log" 2>/dev/null || true

# ---------------------------------------------------------------- verdict
overall=PASS
[ "$fail_count" -eq 0 ] || overall=FAIL
{
	echo "verdict=$overall"
	echo "context_mode=$context_mode helper_context_source=$helper_source"
	echo "template_chandef=$before_freq/$before_width/$before_center1"
	echo "setfreq_cases=$expected_setfreq_cases hop_cases=$expected_hop_cases hop_accepted=$hop_ok_count"
	echo "fail_count=$fail_count"
	echo "restore=managed_connected_validated"
	echo "owner_zero=1"
	echo "idle_ms_restored=$idle_ms_before knob_restored=$knob_before"
	if [ "$mac_after_restore" = "$original_mac" ]; then
		echo "mac_restored=1"
	else
		echo "mac_restored=0"
	fi
	echo "mlo=environment_limited_no_mlo_ap"
	echo "ota_claim=none"
	echo "host_output=$host_out"
} >"$host_out/result.txt"
sha256sum "$host_out"/session-facts.txt "$results_tsv" "$host_out"/context-mode.txt \
	"$host_out"/stats-pre-restore.log "$host_out"/result.txt >"$host_out/HOST_SHA256SUMS" 2>/dev/null
echo "verdict=$overall context_mode=$context_mode hops=$hop_ok_count/$expected_hop_cases fail_count=$fail_count"
[ "$overall" = PASS ]
