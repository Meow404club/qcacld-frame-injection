#!/usr/bin/env bash
# mon0-fwstate-bisect: map which mon0/VIF step wedges FW state so that the
# next STA (re)association completes auth/assoc but the 4-way handshake dies
# (EAPOL M1 never delivered -> reason 15). Reproduced twice on v10:
#   incident 1 (chandef run 1): add ok, up ok, setfreq -EBUSY, TX ok, del ok
#   incident 2 (bisect B):      add ok, up ok, setfreq ok, del -EBUSY
#   -> common denominator: mon0 add + ip-up with STA connected (same channel).
#
# Canary = full framework reconnect (Wi-Fi toggle -> wait connected+VALIDATED).
# On first failing canary the suite STOPS: the device is wedged until reboot.
#
# Boundary knowledge (2026-09-03, boots 3d9531c9 + 6558fcd5 + 100f3ce1):
#   c0 toggle-only     SAFE (x3)
#   A add/del          SAFE (x2)
#   D otherbss refusal SAFE
#   B1 add+up+del      BREAKER (clean rc=0, silent, reason=15 wedge)
#   B  add+up+freq+del BREAKER (superset; freq/TX/EBUSY irrelevant)
#   F add+up+del with Wi-Fi OFF (no STA at all): BREAKER (same reason=15)
#   -> monitor vdev "up" is the poison; no STA concurrency required.
#   Untested micro-step: B2 setfreq on a DOWN mon0 (does channel config
#   alone activate the vdev in FW?).
#
# Blocks:
#   default:                D  otherbss-flag add attempt (refusal-only)
#                           F  wifi-off-first lifecycle (add+up+del inside the
#                              disabled window, then re-enable)
#   --with-add-del:         A  add + del (proven safe; sanity)
#   --with-b1:              B1 add + up + del (KNOWN BREAKER; reproduction)
#   --with-mon0-freq:       B2 add + setfreq (no up) + del  (last micro-step)
#
# Verdicts: FIRST_FAILURE=<block> | ALL_PASS | BASELINE_BROKEN | WRONG_BUILD
# Runs ONLY on build f1e0ec07 (v10); the reproduction needs its mon0 path.

set -uo pipefail

expected_build_id=f1e0ec07e64b85cb10902533c8d0b5db1db6f26c

usage()
{
	echo "usage: $0 [--serial SERIAL] [--with-add-del] [--with-b1] [--with-mon0-freq]" >&2
	exit 2
}

serial=
with_freq=0
with_tx=0
with_repeat=0
with_add_del=0
with_b1=0
skip_defaults=0
while [ "$#" -gt 0 ]; do
	case $1 in
	--serial) [ "$#" -ge 2 ] || usage; serial=$2; shift 2 ;;
	--with-mon0-freq) with_freq=1; shift ;;
	--with-mon0-tx) with_tx=1; with_freq=1; shift ;;
	--with-repeat) with_repeat=1; shift ;;
	--with-add-del) with_add_del=1; shift ;;
	--with-b1) with_b1=1; shift ;;
	--skip-defaults) skip_defaults=1; shift ;;
	*) usage ;;
	esac
done

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
sender_src=$script_dir/../device-suite-wmi-stage1-matrix/send_stage1_packet
[ -x "$sender_src" ] || { echo "sender missing: $sender_src" >&2; exit 3; }

if [ -n "$serial" ]; then
	adb_cmd() { adb -s "$serial" "$@"; }
else
	adb_cmd() { adb "$@"; }
fi

adb_shell() { adb_cmd shell "$@" </dev/null; }
adb_su() { adb_cmd shell su -c "$1" </dev/null; }

stamp=$(date -u +%Y%m%dT%H%M%SZ)
host_out=$script_dir/host-capture-mon0-fwstate-$stamp-$$
mkdir -p "$host_out"
echo "HOST_OUTPUT_DIR=$host_out"

probe_req_hex=40000000ffffffffffff021a2b3c4d5effffffffffff00000000010402040b16
remote_dir=/data/local/tmp/mon0fwbisect-$$

# ------------------------------------------------------------------ helpers
mon0_exists()
{
	adb_shell 'iw dev' >"$host_out/iw-dev-check.log" 2>&1
	grep -q 'Interface mon0' "$host_out/iw-dev-check.log"
}

cleanup_mon0()
{
	if mon0_exists; then
		adb_shell 'ip link set mon0 down' >"$host_out/mon0-cleanup-down.log" 2>&1 || true
		sleep 2
		adb_shell 'iw dev mon0 del' >"$host_out/mon0-cleanup-del.log" 2>&1 || true
		sleep 1
		if mon0_exists; then
			adb_shell 'iw dev mon0 del' >"$host_out/mon0-cleanup-del2.log" 2>&1 || true
		fi
	fi
}

wifi_connected_validated()
{
	adb_shell 'cmd wifi status' >"$host_out/wifi-status-probe.log" 2>&1
	grep -q 'Wifi is connected to' "$host_out/wifi-status-probe.log" &&
		grep -q 'VALIDATED' "$host_out/wifi-status-probe.log"
}

wait_connected()
{
	local deadline=$(( $(date +%s) + $1 ))
	while [ "$(date +%s)" -lt "$deadline" ]; do
		wifi_connected_validated && return 0
		sleep 3
	done
	return 1
}

rssi_now()
{
	adb_shell 'dumpsys wifi' 2>/dev/null |
		grep -m1 -oE 'RSSI: -[0-9]+' | head -n 1
}

# canary <label>: reconnect from scratch, gate on connected+VALIDATED.
canary()
{
	local label=$1
	local log="$host_out/canary-$label.log"
	{
		echo "rssi_before=$(rssi_now)"
		adb_shell 'cmd wifi set-wifi-enabled disabled'
		local d=$(( $(date +%s) + 25 ))
		while [ "$(date +%s)" -lt "$d" ]; do
			adb_shell 'dumpsys wifi' 2>/dev/null | grep -q 'Wi-Fi is disabled' && break
			sleep 2
		done
		adb_shell 'cmd wifi set-wifi-enabled enabled'
		if ! wait_connected 120; then
			echo "canary=FAIL at wait_connected"
			adb_shell 'dumpsys wifi' 2>/dev/null | grep -m1 'mWifiInfo SSID' || true
			adb_cmd logcat -d -s wpa_supplicant 2>/dev/null | tail -40
			return 1
		fi
		local gw
		gw=$(adb_shell 'ip route' 2>/dev/null | awk '/default via .* wlan0/ {print $3; exit}')
		if [ -n "${gw:-}" ]; then
			local ok=0 i
			for i in 1 2 3; do
				adb_shell "ping -c 1 -W 2 -I wlan0 $gw" >/dev/null 2>&1 && ok=$((ok + 1))
				sleep 1
			done
			echo "ping_gateway=$ok/3"
		else
			echo "ping_gateway=no_default_route"
		fi
		echo "rssi_after=$(rssi_now)"
		echo "canary=PASS"
	} >"$log" 2>&1
	local rc=$?
	tail -3 "$log" | sed "s/^/[$label] /"
	[ "$rc" -eq 0 ]
}

record()
{
	echo "$1" | tee -a "$host_out/summary.txt"
}

fail_note()
{
	echo "verdict=$1" | tee -a "$host_out/verdict.txt"
}

# ------------------------------------------------------------------ identity
adb_cmd wait-for-device
boot_id=$(adb_shell 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null)
echo "boot_id=$boot_id" | tee "$host_out/boot-id.txt"
note=$(adb_su 'cat /sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id 2>/dev/null | od -An -v -tx1 | tr -d " \r\n"')
case $note in
*"$expected_build_id"*) ;;
*)
	echo "module build-id mismatch (need v10 $expected_build_id)" | tee "$host_out/verdict.txt"
	echo "verdict=WRONG_BUILD"
	exit 4
	;;
esac

adb_shell "mkdir -p $remote_dir" >/dev/null 2>&1
adb_cmd push "$sender_src" "$remote_dir/send_stage1_packet" >"$host_out/push-sender.log" 2>&1
adb_shell "chmod +x $remote_dir/send_stage1_packet"

# ------------------------------------------------------------------ baseline
adb_su 'dmesg' >"$host_out/dmesg-baseline.log" 2>&1 || true
if ! wifi_connected_validated; then
	echo "not connected at start; one reconnect attempt" | tee -a "$host_out/summary.txt"
	if ! canary baseline; then
		record "canary.baseline FAIL rssi=$(rssi_now) (clean boot, no mon0 step ran)"
		fail_note BASELINE_BROKEN
		exit 5
	fi
else
	record "baseline connected rssi=$(rssi_now)"
fi

if ! canary c0.toggle-only; then
	record "canary.c0.toggle-only FAIL (Wi-Fi toggle alone breaks reconnect)"
	fail_note BASELINE_BROKEN
	exit 5
fi
record "canary.c0.toggle-only PASS"

# ------------------------------------------------------------------ blocks
mon0_add()
{
	adb_shell 'iw dev wlan0 interface add mon0 type monitor' \
		>"$host_out/$1-add.log" 2>&1 || true
	mon0_exists
}

mon0_del()
{
	adb_shell 'iw dev mon0 del' >"$host_out/$1-del.log" 2>&1 || true
	sleep 1
	if mon0_exists; then
		echo "del retry (EBUSY?)" >>"$host_out/$1-del.log"
		adb_shell 'ip link set mon0 down' >>"$host_out/$1-del.log" 2>&1 || true
		sleep 2
		adb_shell 'iw dev mon0 del' >>"$host_out/$1-del.log" 2>&1 || true
	fi
	! mon0_exists
}

block_A()	# add + del only (proven SAFE on boot 3d9531c9)
{
	mon0_add A || return 9
	mon0_del A
}

block_B1()	# add + up + del (isolates the "up" step; unmapped)
{
	mon0_add B1 || return 9
	adb_shell 'ip link set mon0 up' >"$host_out/B1-up.log" 2>&1 || true
	mon0_del B1
}

block_B2()	# add + setfreq (no up) + del  [flag-gated]
{
	mon0_add B2 || return 9
	adb_shell 'iw dev mon0 set freq 5745 HT20' >"$host_out/B2-freq.log" 2>&1 || true
	mon0_del B2
}

block_B3()	# add + up + setfreq + del (known trigger)  [flag-gated]
{
	mon0_add B3 || return 9
	adb_shell 'ip link set mon0 up' >"$host_out/B3-up.log" 2>&1 || true
	adb_shell 'iw dev mon0 set freq 5745 HT20' >"$host_out/B3-freq.log" 2>&1 || true
	mon0_del B3
}

block_C()	# B3 + TX through mon0  [flag-gated]
{
	mon0_add C || return 9
	adb_shell 'ip link set mon0 up' >"$host_out/C-up.log" 2>&1 || true
	adb_shell 'iw dev mon0 set freq 5745 HT20' >"$host_out/C-freq.log" 2>&1 || true
	adb_shell "$remote_dir/send_stage1_packet --send mon0 $probe_req_hex" \
		>"$host_out/C-tx.log" 2>&1
	echo "tx_rc=$?" >>"$host_out/C-tx.log"
	mon0_del C
}

block_D()	# otherbss add attempt (refusal-only; no vdev expected)
{
	adb_shell 'iw dev wlan0 interface add mon0 type monitor flag otherbss' \
		>"$host_out/D-add.log" 2>&1 || true
	if mon0_exists; then
		adb_shell 'iw dev mon0 del' >"$host_out/D-del.log" 2>&1 || true
	fi
	! mon0_exists
}

# F: full mon0 lifecycle inside the Wi-Fi-disabled window. Delimiter:
# if the wedge needs a CONCURRENT STA, this passes; if any monitor vdev
# activation wedges FW, this fails. Wi-Fi is re-enabled on every exit path;
# the reconnect after enable is the primary canary for F.
block_F()
{
	adb_shell 'cmd wifi set-wifi-enabled disabled' >"$host_out/F-wifi-off.log" 2>&1 || true
	local d=$(( $(date +%s) + 25 ))
	while [ "$(date +%s)" -lt "$d" ]; do
		adb_shell 'dumpsys wifi' 2>/dev/null | grep -q 'Wi-Fi is disabled' && break
		sleep 2
	done
	local rc=0
	if ! mon0_add F; then
		rc=9
	else
		adb_shell 'ip link set mon0 up' >"$host_out/F-up.log" 2>&1 || true
		sleep 2
		mon0_del F || rc=11
	fi
	adb_shell 'cmd wifi set-wifi-enabled enabled' >"$host_out/F-wifi-on.log" 2>&1 || true
	if ! wait_connected 150; then
		return 10
	fi
	return $rc
}

run_block()
{
	local name=$1 fn=$2
	adb_su 'dmesg' >"$host_out/dmesg-before-$name.log" 2>&1 || true
	$fn
	local step_rc=$?
	adb_su 'dmesg' >"$host_out/dmesg-after-$name.log" 2>&1 || true
	record "step.$name rc=$step_rc mon0_leftover=$(mon0_exists && echo yes || echo no)"
	cleanup_mon0
	if canary "$name"; then
		record "canary.$name PASS"
		return 0
	fi
	record "canary.$name FAIL  <<< FIRST_FAILURE=$name"
	adb_su 'dmesg' >"$host_out/dmesg-failure-$name.log" 2>&1 || true
	fail_note "FIRST_FAILURE=$name"
	exit 6
}

enabled_blocks="D,F"
if [ "$skip_defaults" -eq 0 ]; then
run_block D block_D

# F: dedicated flow (reconnect inside the block is the primary canary)
adb_su 'dmesg' >"$host_out/dmesg-before-F.log" 2>&1 || true
block_F
f_rc=$?
adb_su 'dmesg' >"$host_out/dmesg-after-F.log" 2>&1 || true
record "step.F rc=$f_rc mon0_leftover=$(mon0_exists && echo yes || echo no)"
cleanup_mon0
if [ "$f_rc" -eq 10 ]; then
	record "canary.F FAIL (reconnect inside F)  <<< FIRST_FAILURE=F"
	adb_su 'dmesg' >"$host_out/dmesg-failure-F.log" 2>&1 || true
	fail_note "FIRST_FAILURE=F"
	exit 6
fi
if canary F; then
	case $f_rc in
	0) record "canary.F PASS (wifi-off-first mon0 lifecycle SAFE)" ;;
	*) record "canary.F PASS (add refused / del rc=$f_rc noted)" ;;
	esac
else
	record "canary.F FAIL  <<< FIRST_FAILURE=F"
	adb_su 'dmesg' >"$host_out/dmesg-failure-F.log" 2>&1 || true
	fail_note "FIRST_FAILURE=F"
	exit 6
fi
else
	enabled_blocks="none(defaults skipped)"
fi

if [ "$with_add_del" -eq 1 ]; then
	enabled_blocks="$enabled_blocks,A"
	run_block A block_A
fi
if [ "$with_b1" -eq 1 ]; then
	enabled_blocks="$enabled_blocks,B1"
	run_block B1 block_B1
fi
if [ "$with_freq" -eq 1 ]; then
	enabled_blocks="$enabled_blocks,B2"
	run_block B2 block_B2
fi

# ------------------------------------------------------------------ wrap up
adb_shell 'cmd wifi status' >"$host_out/wifi-final.log" 2>&1
adb_shell "rm -rf $remote_dir" >/dev/null 2>&1 || true
adb_su 'dmesg' >"$host_out/dmesg-final.log" 2>&1 || true
if wifi_connected_validated; then
	record "final connected rssi=$(rssi_now) blocks=$enabled_blocks"
	fail_note ALL_PASS
	exit 0
fi
fail_note "ALL_PASS_NOT_CONNECTED_AT_END blocks=$enabled_blocks"
exit 7
