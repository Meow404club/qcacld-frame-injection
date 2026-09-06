#!/bin/bash
# run_e_wave_host.sh - fault/stress matrix device round.
#
# Phases: gate -> admin knobs A/B -> rate limit -> watchdog clamp ->
# rx soak with periodic injection -> knob pressure loop -> queue
# burst -> restore.  (A screen suspend/resume phase was dropped:
# screen-on auto-re-enables Wi-Fi on some setups - e.g. LSPosed
# without a blocking module - which fights the persona teardown for
# environmental reasons, not driver ones.)
# Persona discipline from common/lib.sh (supplicant teardown wait,
# liveness checks, settle-race retry policy).
#
# usage: run_e_wave_host.sh --authorized-isolated-lab [--soak-secs N]
set -u
here=$(cd -- "$(dirname -- "$0")" && pwd)
repo=$(cd -- "$here/.." && pwd)
. "$repo/common/lib.sh"

expected_build_id=914714cb6f296f35f093bf393bfea47c4982897c
expected_src_rev=698efe09e8b8+dirty-20260906-observability-admin-knobs-v21
expected_selftests=409
expected_stats_format=13

authorized=
soak_secs=180
while [ $# -gt 0 ]; do
	case $1 in
	--authorized-isolated-lab) authorized=1; shift ;;
	--soak-secs) soak_secs=$2; shift 2 ;;
	*) echo "usage: $0 --authorized-isolated-lab [--soak-secs N]" >&2; exit 2 ;;
	esac
done
[ "$authorized" = 1 ] || { echo "refusing: lab authorization flag required" >&2; exit 2; }

fail=0
note() { echo "e.$1"; }
fail_note() { echo "e.$1 FAILED"; fail=1; }

mount_debugfs || { echo "debugfs unavailable" >&2; exit 3; }
pin_build_id "$expected_build_id" || exit 3

# ---- persona (gold-standard dance) ----
adb_shell 'cmd wifi set-wifi-enabled disabled' >/dev/null 2>&1
if ! wait_wifi_disabled 60; then
	echo "first settle race: retry once" >&2
	sleep 10
	adb_shell 'cmd wifi set-wifi-enabled disabled' >/dev/null 2>&1
	wait_wifi_disabled 60 || { echo "wifi never disabled" >&2; exit 4; }
fi
persona_up=0
for n in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
	adb_shell 'iw dev wlan0 set type monitor' >/dev/null 2>&1 || { sleep 1; continue; }
	adb_shell 'ip link set wlan0 up' >/dev/null 2>&1 || { sleep 1; continue; }
	adb_shell 'iw dev wlan0 set freq 5745' >/dev/null 2>&1
	adb_shell 'iw dev wlan0 info' 2>/dev/null | tr -d '\r' | grep -q 'channel 149' && { persona_up=1; break; }
	sleep 1
done
[ $persona_up = 1 ] || { echo "monitor persona failed" >&2; exit 4; }

out=$(make_evidence_dir "$here" e-wave) || exit 3
echo "E_WAVE_OUTPUT_DIR=$out"

remote=/data/local/tmp/fi-ewave-$$
adb_shell "mkdir -p $remote" || exit 3
"${adb_cmd[@]}" push "$repo/ota/kit/send_stage1_packet" "$remote/send_stage1_packet" >/dev/null 2>&1 || exit 3
adb_shell "chmod 0755 $remote/send_stage1_packet" || exit 3

VEC_HEX=$(python3 - <<'PY'
import struct
ra = bytes([0x02,0x11,0x22,0x33,0x44,0x55]); ta = bytes([0x02,0xAB,0xCD,0x00,0x00,0xF1])
mpdu = struct.pack("<HH",0x00C0,0)+ra+ta+ra+struct.pack("<H",0)+struct.pack("<H",1)
rt = struct.pack("<B", 12)
hdr = struct.pack("<BBHI",0,0,8+len(rt),1<<2)
pkt = hdr+rt+mpdu
assert len(mpdu) == 26 and (pkt[2] | (pkt[3]<<8)) == 9
print(pkt.hex())
PY
)

# The Wi-Fi framework can reclaim wlan0 across suspend/resume cycles (a
# measured behavior of this round); every stress phase re-asserts the
# persona and rebuilds it if the framework flipped the adapter back.
persona_rebuilds=0
ensure_persona()
{
	persona_alive && return 0
	persona_rebuilds=$((persona_rebuilds + 1))
	echo "e.persona_rebuild #$persona_rebuilds (framework reclaimed adapter)"
	# after a framework reclaim the auto-reopener can outrun a single
	# disable: retry the disable until the supplicant actually leaves
	local attempt gone
	gone=0
	for attempt in 1 2 3 4 5; do
		adb_shell 'cmd wifi set-wifi-enabled disabled' >/dev/null 2>&1
		if wait_wifi_disabled 30; then
			gone=1
			break
		fi
		echo "e.rebuild_disable_retry #$attempt"
	done
	[ $gone = 1 ] || return 1
	local n
	for n in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
		adb_shell 'iw dev wlan0 set type monitor' >/dev/null 2>&1 || { sleep 1; continue; }
		adb_shell 'ip link set wlan0 up' >/dev/null 2>&1 || { sleep 1; continue; }
		adb_shell 'iw dev wlan0 set freq 5745' >/dev/null 2>&1
		adb_shell 'iw dev wlan0 info' 2>/dev/null | tr -d '\r' | grep -q 'channel 149' && return 0
		sleep 1
	done
	return 1
}

snap_stats() { adb_exec_out "cat $fi_stats_node" >"$1" 2>/dev/null; }
delta() { awk -F= -v k="$2" '$1==k {print $2; exit}' "$1" "$3" 2>/dev/null | awk 'NR==1{a=$1} NR==2{print $2-$1}'; }
get2() { v1=$(awk -F= -v k="$2" '$1==k {print $2; exit}' "$1"); v2=$(awk -F= -v k="$2" '$1==k {print $2; exit}' "$3"); }

# ---- gate ----
adb_exec_out "cat $fi_stats_node" >"$out/stats-gate.txt"
[ "$(stat_value "$out/stats-gate.txt" format_version)" = "$expected_stats_format" ] && note "gate.stats_format=ok" || fail_note "gate.stats_format"
adb_exec_out 'cat /sys/kernel/debug/wlan0/frame_inject_selftest' >"$out/selftest.log" 2>/dev/null
[ "$(stat_value "$out/selftest.log" tests)" = "$expected_selftests" ] && [ "$(stat_value "$out/selftest.log" passed)" = "$expected_selftests" ] && note "gate.selftest=$expected_selftests" || fail_note "gate.selftest"
adb_exec_out 'cat /sys/kernel/debug/wlan0/frame_inject_capabilities' >"$out/capabilities.txt" 2>/dev/null
grep -q '^admin_gate=' "$out/capabilities.txt" && grep -q '^rate_limit_pps=' "$out/capabilities.txt" && grep -q '^watchdog_ms_knob=' "$out/capabilities.txt" && note "gate.caps_admin_lines=ok" || fail_note "gate.caps_admin_lines"

knobs=/sys/kernel/debug/wlan0

# ---- admin gate A/B ----
adb_shell "echo 0 > $knobs/frame_inject_admin_gate"
snap_stats "$out/admin-before.txt"
adb_shell "echo 1 > $knobs/frame_inject_admin_gate"
adb_shell "$remote/send_stage1_packet --send wlan0 $VEC_HEX" >/dev/null 2>&1
sleep 1
snap_stats "$out/admin-gated.txt"
get2 "$out/admin-before.txt" drop_reason_admin "$out/admin-gated.txt"
adm_delta=$((v2 - v1))
adb_shell "$remote/send_stage1_packet --send wlan0 $VEC_HEX" >/dev/null 2>&1
sleep 1
snap_stats "$out/admin-gated2.txt"
get2 "$out/admin-gated.txt" drop_reason_admin "$out/admin-gated2.txt"
adm2=$((v2 - v1))
adb_shell "echo 0 > $knobs/frame_inject_admin_gate"
adb_shell "$remote/send_stage1_packet --send wlan0 $VEC_HEX" >/dev/null 2>&1
sleep 1
snap_stats "$out/admin-open.txt"
get2 "$out/admin-gated2.txt" wmi_submitted "$out/admin-open.txt"
wmi_recover=$((v2 - v1))
[ "$adm_delta" = 1 ] && [ "$adm2" = 1 ] && [ "$wmi_recover" = 1 ] && note "admin_gate rejects+1/+1, reopen wmi+1" || fail_note "admin_gate ab"

# ---- rate limit ----
adb_shell "echo 1 > $knobs/frame_inject_rate_limit"
sleep 1.2
snap_stats "$out/rate-before.txt"
adb_shell "$remote/send_stage1_packet --send wlan0 $VEC_HEX" >/dev/null 2>&1
adb_shell "$remote/send_stage1_packet --send wlan0 $VEC_HEX" >/dev/null 2>&1
sleep 1
snap_stats "$out/rate-after.txt"
get2 "$out/rate-before.txt" drop_reason_rate_limited "$out/rate-after.txt"
rate_delta=$((v2 - v1))
adb_shell "echo 0 > $knobs/frame_inject_rate_limit"
[ "$rate_delta" -ge 1 ] && note "rate_limit second burst rejected (delta=$rate_delta)" || fail_note "rate_limit"

# ---- watchdog clamp ----
adb_shell "echo 0 > $knobs/frame_inject_watchdog_ms" && adb_exec_out "cat $knobs/frame_inject_watchdog_ms" >"$out/wd-low.txt"
adb_shell "echo 999999 > $knobs/frame_inject_watchdog_ms" && adb_exec_out "cat $knobs/frame_inject_watchdog_ms" >"$out/wd-high.txt"
adb_shell "echo 3000 > $knobs/frame_inject_watchdog_ms" && adb_exec_out "cat $knobs/frame_inject_watchdog_ms" >"$out/wd-default.txt"
[ "$(stat_value "$out/wd-low.txt" watchdog_ms)" = 1000 ] && [ "$(stat_value "$out/wd-high.txt" watchdog_ms)" = 10000 ] && [ "$(stat_value "$out/wd-default.txt" watchdog_ms)" = 3000 ] && note "watchdog clamp 1000/10000/default" || fail_note "watchdog_clamp"

# ---- rx soak ----
tp=/data/data/com.termux/files/usr
tp_home=/data/data/com.termux/files/home
tenv="env LD_LIBRARY_PATH=$tp/lib HOME=$tp_home TERM=xterm-256color TERMINFO=$tp/share/terminfo PATH=$tp/bin:/system/bin"
if adb_shell "test -x $tp/bin/tcpdump" >/dev/null 2>&1; then
	adb_shell "rm -f $remote/soak.pcap"
	adb_shell "$tenv tcpdump -i wlan0 -U -w $remote/soak.pcap" >/dev/null 2>&1 &
	tcpid=$!
	n=0
	interval=$(( soak_secs / 6 ))
	[ $interval -lt 5 ] && interval=5
	while [ $n -lt $soak_secs ]; do
		adb_shell "$remote/send_stage1_packet --send wlan0 $VEC_HEX" >/dev/null 2>&1
		sleep $interval
		n=$((n + interval))
		persona_alive || { fail_note "soak_persona_dead_at_${n}s"; break; }
	done
	kill $tcpid 2>/dev/null; wait $tcpid 2>/dev/null
	"${adb_cmd[@]}" pull "$remote/soak.pcap" "$out/soak.pcap" >/dev/null 2>&1
	snap_stats "$out/soak-stats.txt"
	watch=$(stat_value "$out/soak-stats.txt" watchdog_timeouts)
	fatal=$(stat_value "$out/soak-stats.txt" fatal_errors)
	cap_sz=$(stat -c%s "$out/soak.pcap" 2>/dev/null || echo 0)
	[ "$watch" = 0 ] && [ "$fatal" = 0 ] && [ "$cap_sz" -gt 24 ] && note "soak clean watchdog=0 fatal=0 pcap=${cap_sz}B" || fail_note "soak"
else
	note "soak SKIPPED (no termux tcpdump)"
fi

# ---- knob pressure ----
ensure_persona || fail_note "pressure_persona_rebuild_failed"
snap_stats "$out/pressure-before.txt"
i=0
while [ $i -lt 20 ]; do
	case $((i % 4)) in
	0) adb_shell "echo full > $knobs/frame_inject_monitor_filter" >/dev/null 2>&1 ;;
	1) adb_shell "echo mgmt > $knobs/frame_inject_monitor_filter" >/dev/null 2>&1 ;;
	2) adb_shell "echo 1 > $knobs/frame_inject_monitor_fcs" >/dev/null 2>&1 ;;
	3) adb_shell "echo 0 > $knobs/frame_inject_monitor_fcs" >/dev/null 2>&1 ;;
	esac
	lim=$(( (i % 8) + 1 ))
	adb_shell "echo $lim > $knobs/frame_inject_inflight_limit" >/dev/null 2>&1
	adb_shell "$remote/send_stage1_packet --send wlan0 $VEC_HEX" >/dev/null 2>&1
	i=$((i + 1))
done
adb_shell "echo full > $knobs/frame_inject_monitor_filter" >/dev/null 2>&1
adb_shell "echo 8 > $knobs/frame_inject_inflight_limit" >/dev/null 2>&1
sleep 3
snap_stats "$out/pressure-after.txt"
pfatal=$(stat_value "$out/pressure-after.txt" fatal_errors)
pwatch=$(stat_value "$out/pressure-after.txt" watchdog_timeouts)
[ "$pfatal" = 0 ] && note "knob_pressure x20 fatal=0 watchdog=$pwatch" || fail_note "knob_pressure"

# ---- queue burst ----
ensure_persona || fail_note "burst_persona_rebuild_failed"
snap_stats "$out/burst-before.txt"
b=0
while [ $b -lt 16 ]; do
	adb_shell "$remote/send_stage1_packet --send wlan0 $VEC_HEX" >/dev/null 2>&1 &
	b=$((b + 1))
done
wait
sleep 10
snap_stats "$out/burst-after.txt"
qdepth=$(stat_value "$out/burst-after.txt" queue_depth)
bwatch=$(stat_value "$out/burst-after.txt" watchdog_timeouts)
bfatal=$(stat_value "$out/burst-after.txt" fatal_errors)
[ "$qdepth" = 0 ] && [ "$bfatal" = 0 ] && note "queue_burst drained depth=0 watchdog=$bwatch" || fail_note "queue_burst"

# ---- restore ----
adb_shell "echo stop > $knobs/frame_inject_channel_hop" >/dev/null 2>&1 || true
adb_shell "echo 0 > $knobs/frame_inject_admin_gate" >/dev/null 2>&1 || true
adb_shell "echo 0 > $knobs/frame_inject_rate_limit" >/dev/null 2>&1 || true
adb_shell "echo 3000 > $knobs/frame_inject_watchdog_ms" >/dev/null 2>&1 || true
adb_shell "echo full > $knobs/frame_inject_monitor_filter" >/dev/null 2>&1 || true
adb_shell "echo 8 > $knobs/frame_inject_inflight_limit" >/dev/null 2>&1 || true
restore_managed
adb_shell "rm -rf $remote" >/dev/null 2>&1 || true
echo "ewave_complete=1 fail=$fail persona_rebuilds=$persona_rebuilds restored=1 output=$out"
exit $fail
