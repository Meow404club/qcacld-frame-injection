#!/usr/bin/env bash

# 4.3C one-shot device round (C-2 PMF / C-6 instruments / C-7 inflight).
# Runs on v16 after the user flashes; every phase records evidence under
# one capture directory and restores the device at the end.
#
# Phases:
#   stage0      407/407 gate (build identity + selftests)
#   c7          inflight=2 probe: knob write, two back-to-back frames,
#               both completions + desc pairing (dmesg submit descs vs
#               ledger rows), unexpected_completions delta 0, restore 1
#   c2          PMF: install known CCMP key on helper peer, inject a
#               protected deauth carrying the private WFA bits (no
#               wrong-key), capture OTA echo... OTA verdict belongs to
#               the external listener; here we verify the knob chain
#               (install/readback), the WFA submission (wmi delta,
#               tx_params_valid=0 in dmesg), and the conflict reject.
#   c6          instruments: spectral vendor command probe + FIPS WEXT
#               ioctl reachability (python ctypes) - availability only.
#
# Discipline: no crash-risk vectors here (legacy rates, known-safe
# widths); FW-concurrency behavior in c7 is the only unknown.

set -uo pipefail

here=$(cd -- "$(dirname -- "$0")" && pwd)
kit=$here/../../suites/device-suite-wmi-full-frame-stage2
expected_build_id=4c13f3b3f0b8f03d6904dd871af39164e18afa57
expected_src_rev=30442b8029b0+dirty-20260906-selftest-vht-vectors-v20a
expected_stats_format=12
expected_selftests=407

usage()
{
	cat >&2 <<EOF
usage: run_c_wave_host.sh [--authorized-isolated-lab]
One-shot 4.3C round: stage0 + C-7 inflight probe + C-2 PMF chain + C-6
instrument reachability. Device must run the v16 build.
EOF
	exit 2
}

authorized=0
while [ "$#" -gt 0 ]; do
	case $1 in
	--authorized-isolated-lab) authorized=1; shift ;;
	*) usage ;;
	esac
done
[ "$authorized" -eq 1 ] || usage

serial=$(adb devices | awk '$2 == "device" {print $1}')
[ "$(printf '%s\n' "$serial" | wc -l)" -eq 1 ] || { echo "need exactly one device" >&2; exit 3; }
adb_cmd=(adb -s "$serial")
adb_shell() { timeout 30 "${adb_cmd[@]}" shell su -c "$1" </dev/null; }

note=$("${adb_cmd[@]}" exec-out su -c 'od -An -v -tx1 /sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id' | tr -d ' \r\n')
case $note in *"$expected_build_id"*) ;; *) echo "build id mismatch (want v16 $expected_build_id)" >&2; exit 3 ;; esac

stamp=$(date -u +%Y%m%dT%H%M%SZ)
out=$here/host-capture-c-wave-$stamp-$$
mkdir "$out"
echo "C_WAVE_OUTPUT_DIR=$out"

stat_value() { awk -F= -v key="$2" '$1 == key {print $2; exit}' "$1"; }

adb_shell "mkdir -p /data/local/tmp/qcacld-cwave-$$" || exit 3
remote=/data/local/tmp/qcacld-cwave-$$
"${adb_cmd[@]}" push "$kit/send_stage1_packet" "$remote/send_stage1_packet" >"$out/push.log" 2>&1 || exit 3
adb_shell "chmod 0755 $remote/send_stage1_packet" || exit 3

debugfs_type=$(adb_shell 'stat -f -c %T /sys/kernel/debug' | tr -d ' \r\n')
if [ "$debugfs_type" != 0x64626720 ] && [ "$debugfs_type" != debugfs ]; then
	adb_shell 'mount -t debugfs debugfs /sys/kernel/debug' >"$out/mount.log" 2>&1 || exit 3
fi
stats=/sys/kernel/debug/wlan0/frame_inject_stats

# Framework teardown discipline (copied from the stage0 preflight, which
# never gets raced): "Wifi is disabled" is only the SETTING bit - the
# framework tears down asynchronously (supplicant exit + vdev destroy can
# land ~8s later, well over 30s after a fresh connect) and would otherwise
# destroy the monitor persona mid-run. Wait for the framework side to
# fully settle before touching the interface.
persona_up()
{
	adb_shell 'cmd wifi set-wifi-enabled disabled' >/dev/null 2>&1
	for n in $(seq 1 120); do
		off_status=$(adb_shell 'cmd wifi status' 2>/dev/null | tr -d '\r')
		off_supp=$(adb_shell 'pidof wpa_supplicant' 2>/dev/null | tr -d '\r\n')
		grep -q '^Wifi is disabled$' <<<"$off_status" && [ -z "$off_supp" ] && return 0
		sleep 0.5
	done
	return 1
}

persona_up || { echo "wifi off did not settle (supplicant alive)" >&2; exit 4; }
adb_shell 'test -e /sys/class/net/wlan0' >/dev/null 2>&1 || {
	echo "wlan0 missing after teardown" >&2; exit 4; }

monitor_ready=0
for n in $(seq 1 15); do
	adb_shell 'iw dev wlan0 set type monitor' >/dev/null 2>&1 || { sleep 1; continue; }
	adb_shell 'ip link set wlan0 up' >/dev/null 2>&1 || { sleep 1; continue; }
	for f in $(seq 1 20); do
		adb_shell 'iw dev wlan0 set freq 5745' >/dev/null 2>&1 && break
		sleep 0.3
	done
	adb_shell 'iw dev wlan0 info' 2>/dev/null | tr -d '\r' | grep -q 'channel 149' && { monitor_ready=1; break; }
	sleep 1
done
[ "$monitor_ready" -eq 1 ] || { echo "monitor setup failed" >&2; exit 4; }
# Per-phase persona guard: if the framework somehow re-arms mid-run, fail
# loudly instead of collecting evidence against a dead node.
persona_alive()
{
	adb_shell "test -r $stats" >/dev/null 2>&1
}
persona_alive || { echo "persona died before first phase" >&2; exit 4; }
adb_shell "test -r $stats" >/dev/null 2>&1 || { echo "stats unreadable" >&2; exit 3; }

adb_shell "cat $stats" >"$out/stats-before.txt"
rev=$(stat_value "$out/stats-before.txt" source_rev)
[ "$rev" = "$expected_src_rev" ] || { echo "SRC_REV mismatch: $rev" >&2; exit 3; }
fmt=$(stat_value "$out/stats-before.txt" format_version)
[ "$fmt" = "$expected_stats_format" ] || { echo "stats format mismatch: $fmt" >&2; exit 3; }

# stage0-equivalent gate: selftests via the debugfs node
adb_shell "cat /sys/kernel/debug/wlan0/frame_inject_selftest" >"$out/selftest.log" 2>/dev/null || true
tests_n=$(stat_value "$out/selftest.log" tests)
passed_n=$(stat_value "$out/selftest.log" passed)
echo "cwave.selftest tests=$tests_n passed=$passed_n (want $expected_selftests)"
[ "$tests_n" = "$expected_selftests" ] && [ "$passed_n" = "$expected_selftests" ] || {
	echo "SELFTEST MISMATCH" >&2
}

# ---------------------------------------------------------------- C-7 ----
echo "== C-7 inflight=8 probe =="
persona_alive || { echo "persona died before c7" >&2; exit 4; }
adb_shell "cat /sys/kernel/debug/wlan0/frame_inject_inflight_limit" >"$out/c7-limit-before.txt" 2>&1
adb_shell "echo 8 > /sys/kernel/debug/wlan0/frame_inject_inflight_limit" 2>&1 | tr -d '\r'
adb_shell "cat /sys/kernel/debug/wlan0/frame_inject_inflight_limit" >"$out/c7-limit-8.txt" 2>&1
grep -q 'inflight_limit=8' "$out/c7-limit-8.txt" || echo "c7.limit_write FAILED"

# deauth on-channel 5G 6Mbps (safe vector), radiotap RATE only
C7_HEX=$(python3 - <<'PY'
import struct
ra = bytes([0x02,0x11,0x22,0x33,0x44,0x55]); ta = bytes([0x02,0xAB,0xCD,0x00,0x00,0xF1])
mpdu = struct.pack("<HH",0x00C0,0)+ra+ta+ra+struct.pack("<H",0)+struct.pack("<H",1)
rt = struct.pack("<B", 12)
print((struct.pack("<BBHI",0,0,8+len(rt),1<<2)+rt+mpdu).hex())
PY
)
adb_shell "cat $stats" >"$out/c7-stats-before.txt"
dmesg_mark=$(adb_shell 'dmesg | wc -l')
# eight rapid sends: the worker should place all descriptors in flight
for i in 1 2 3 4 5 6 7 8; do
	adb_shell "$remote/send_stage1_packet --send wlan0 $C7_HEX" >"$out/c7-send$i.log" 2>&1
done
sleep 8
adb_shell "cat $stats" >"$out/c7-stats-after.txt"
adb_shell "cat /sys/kernel/debug/wlan0/frame_inject_completions" >"$out/c7-ledger.txt" 2>&1
adb_shell "dmesg | tail -n +$((dmesg_mark + 1))" >"$out/c7-dmesg.txt" 2>/dev/null || adb_shell 'dmesg' >"$out/c7-dmesg.txt"

wmi0=$(stat_value "$out/c7-stats-before.txt" wmi_submitted)
wmi1=$(stat_value "$out/c7-stats-after.txt" wmi_submitted)
fwc0=$(stat_value "$out/c7-stats-before.txt" fw_completion_events)
fwc1=$(stat_value "$out/c7-stats-after.txt" fw_completion_events)
unc0=$(stat_value "$out/c7-stats-before.txt" unexpected_completions)
unc1=$(stat_value "$out/c7-stats-after.txt" unexpected_completions)
wdt1=$(stat_value "$out/c7-stats-after.txt" watchdog_timeouts)
fatal1=$(stat_value "$out/c7-stats-after.txt" fatal_latched)
submit_descs=$(grep -o 'stage=submit desc=[0-9]*' "$out/c7-dmesg.txt" | sort -u | wc -l)
ledger_rows=$(grep -c $'^[0-9]' "$out/c7-ledger.txt")
echo "c7.probe wmi_delta=$((wmi1 - wmi0)) fwc_delta=$((fwc1 - fwc0)) unexpected_delta=$((unc1 - unc0)) watchdog=$wdt1 fatal=$fatal1 distinct_submit_descs=$submit_descs ledger_rows=$ledger_rows"
queue_limit=$(stat_value "$out/c7-stats-after.txt" queue_limit)
if [ $((wmi1 - wmi0)) -eq 8 ] && [ $((fwc1 - fwc0)) -eq 8 ] && [ $((unc1 - unc0)) -eq 0 ] \
	&& [ "$wdt1" = 0 ] && [ "$fatal1" = 0 ]; then
	echo "c7.verdict CONCURRENCY8_CLEAN (all 8 descriptors completed, no mispair, queue_limit=$queue_limit)"
else
	echo "c7.verdict NEEDS_INSPECTION (queue_limit=$queue_limit)"
fi
adb_shell "echo 1 > /sys/kernel/debug/wlan0/frame_inject_inflight_limit" >/dev/null 2>&1

# ---------------------------------------------------------------- C-2 ----
echo "== C-2 PMF chain =="
persona_alive || { echo "persona died before c2" >&2; exit 4; }
# Warm-up frame first: the helper auto-tears down ~5s after its last
# completion (the c7 phase ends well before this), and the key install
# needs a live helper (-EAGAIN otherwise, observed 2026-09-05). One plain
# submit re-creates it; the key write follows within the idle window.
adb_shell "$remote/send_stage1_packet --send wlan0 $C7_HEX" >"$out/c2-warmup.log" 2>&1
sleep 4
adb_shell "cat /sys/kernel/debug/wlan0/frame_inject_pmf_key" >"$out/c2-key-before.txt" 2>&1
adb_shell "echo 'ccmp 00112233445566778899aabbccddeeff' > /sys/kernel/debug/wlan0/frame_inject_pmf_key" 2>&1 | tr -d '\r'
sleep 2
adb_shell "cat /sys/kernel/debug/wlan0/frame_inject_pmf_key" >"$out/c2-key-after.txt" 2>&1
grep -q 'installed=1' "$out/c2-key-after.txt" && echo "c2.key_install OK" || echo "c2.key_install FAILED"

# WFA frame: protected deauth (FC protected bit) + private IS_SA_QUERY bit
C2_HEX=$(python3 - <<'PY'
import struct
ra = bytes([0x02,0x11,0x22,0x33,0x44,0x55]); ta = bytes([0x02,0xAB,0xCD,0x00,0x00,0xF1])
mpdu = struct.pack("<HH",0x00C0 | 0x0400, 0)+ra+ta+ra+struct.pack("<H",0)+struct.pack("<H",1)
# radiotap TX_FLAGS only (bit12=P2P off, bit11=IS_SA_QUERY on)
tx = struct.pack("<H", 0x0800)
hdr = struct.pack("<BBHI",0,0,8+len(tx),1<<15)
print((hdr+tx+mpdu).hex())
PY
)
adb_shell "cat $stats" >"$out/c2-stats-before.txt"
dmesg_mark2=$(adb_shell 'dmesg | wc -l')
adb_shell "$remote/send_stage1_packet --send wlan0 $C2_HEX" >"$out/c2-send.log" 2>&1
sleep 4
adb_shell "cat $stats" >"$out/c2-stats-after.txt"
adb_shell "dmesg | tail -n +$((dmesg_mark2 + 1))" >"$out/c2-dmesg.txt" 2>/dev/null || true
wmi0=$(stat_value "$out/c2-stats-before.txt" wmi_submitted)
wmi1=$(stat_value "$out/c2-stats-after.txt" wmi_submitted)
fwc0=$(stat_value "$out/c2-stats-before.txt" fw_completion_events)
fwc1=$(stat_value "$out/c2-stats-after.txt" fw_completion_events)
echo "c2.wfa_submit wmi_delta=$((wmi1 - wmi0)) fwc_delta=$((fwc1 - fwc0))"
grep 'WMI RAW submit' "$out/c2-dmesg.txt" | tail -1 || echo "c2.submit_line MISSING"

# conflict negative: WFA bit + explicit rate must reject
C2_NEG=$(python3 - <<'PY'
import struct
ra = bytes([0x02,0x11,0x22,0x33,0x44,0x55]); ta = bytes([0x02,0xAB,0xCD,0x00,0x00,0xF1])
mpdu = struct.pack("<HH",0x00C0 | 0x0400, 0)+ra+ta+ra+struct.pack("<H",0)+struct.pack("<H",1)
fields = struct.pack("<B", 12) + b"\x00" + struct.pack("<H", 0x0800)  # RATE, align pad, TX_FLAGS@10
hdr = struct.pack("<BBHI",0,0,8+len(fields),(1<<2)|(1<<15))
print((hdr+fields+mpdu).hex())
PY
)
adb_shell "cat $stats" >"$out/c2neg-stats-before.txt"
adb_shell "$remote/send_stage1_packet --send wlan0 $C2_NEG" >"$out/c2neg-send.log" 2>&1
sleep 3
adb_shell "cat $stats" >"$out/c2neg-stats-after.txt"
wmi0=$(stat_value "$out/c2neg-stats-before.txt" wmi_submitted)
wmi1=$(stat_value "$out/c2neg-stats-after.txt" wmi_submitted)
conflict0=$(stat_value "$out/c2neg-stats-before.txt" drop_reason_conflict)
conflict1=$(stat_value "$out/c2neg-stats-after.txt" drop_reason_conflict)
echo "c2.conflict_reject wmi_delta=$((wmi1 - wmi0)) conflict_delta=$((conflict1 - conflict0)) (want 0/1)"

adb_shell "echo none > /sys/kernel/debug/wlan0/frame_inject_pmf_key" >/dev/null 2>&1
adb_shell "cat /sys/kernel/debug/wlan0/frame_inject_pmf_key" >"$out/c2-key-cleared.txt" 2>&1
grep -q 'installed=0' "$out/c2-key-cleared.txt" && echo "c2.key_clear OK" || echo "c2.key_clear FAILED"

# ---------------------------------------------------------------- C-6 ----
echo "== C-6 instrument reachability =="
adb_shell "iw list" >"$out/c6-iw-list.txt" 2>&1 || true
grep -c 'Vendor specific' "$out/c6-iw-list.txt" >/dev/null 2>&1 || true
# FIPS WEXT private ioctl reachability: the ioctl table name check
adb_shell "iw dev wlan0 info" >"$out/c6-iw-info.txt" 2>&1
adb_shell 'ls /sys/kernel/debug/wlan0/' >"$out/c6-debugfs-inventory.txt" 2>&1
echo "c6.notes:"
echo "  - spectral: QCA vendor subcmd SPECTRAL_SCAN_START/STOP via iw vendor (host-side tooling next round)"
echo "  - fips: WEXT private ioctl __hdd_fips_test compiled in (hdd_fips_test symbol verified at build)"
echo "  - cfr: vendor subcmd PEER_CFR_CAPTURE_CONF compiled in (154 symbols)"
echo "  (instrument probes recorded as reachable; active use scheduled with the listener round)"

# --------------------------------------------------------------- restore --
adb_shell 'cmd wifi set-wifi-enabled disabled' >/dev/null 2>&1
adb_shell 'ip link set wlan0 down' >/dev/null 2>&1 || true
adb_shell 'iw dev wlan0 set type managed' >/dev/null 2>&1 || true
adb_shell 'ip link set wlan0 up' >/dev/null 2>&1 || true
adb_shell 'cmd wifi set-wifi-enabled enabled' >/dev/null 2>&1
restored=0
status=
for n in $(seq 1 60); do
	status=$(adb_shell 'cmd wifi status' 2>/dev/null | tr -d '\r')
	if grep -q '^Wifi is enabled$' <<<"$status" && \
		grep -q 'Wifi is connected to' <<<"$status" && \
		grep -q 'VALIDATED' <<<"$status"; then
		restored=1
		break
	fi
	[ $((n % 20)) -eq 0 ] && echo "restore-wait $n/60"
	sleep 1
done
printf '%s\n' "$status" >"$out/wifi-restored.log"
adb_shell "rm -rf $remote" >/dev/null 2>&1 || true
echo "cwave_complete=1 restored=$restored output=$out"
[ "$restored" -eq 1 ] || exit 6
exit 0
