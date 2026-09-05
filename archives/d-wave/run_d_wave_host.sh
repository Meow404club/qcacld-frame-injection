#!/usr/bin/env bash

# 4.3 one-shot device closing round (d-wave, v19): everything left in 4.3
# that is observable ON THE DEVICE, in a single invocation.
#
#   gate      build identity + selftests 401 + capabilities v11 probe lines
#   c7        inflight default-8 burst re-verify (v18 default flip check)
#   c2        PMF chain re-verify (install / WFA submit / conflict / clear)
#   b2a       HT self-echo rx audit: inject HT20 frames while capturing,
#             analyzer walk=0 + MCS FEC/STBC known-bit count + on-device
#             tshark malformed count (B-2a final verification)
#   c6tools   FIPS WEXT ioctl invoke (python ctypes) + spectral vendor
#             GET_CAP_INFO invoke (C-6 invoke-level evidence; the effect-
#             level measurement belongs to the stage2 listener round)
#   c5        firmware probe axes, risk-ordered, ONE axis per step with a
#             live-vector banner; crash-risk axes last. If an axis resets
#             the SoC the runner waits for the device to come back,
#             rebuilds the persona and continues (each axis needs its own
#             observation anyway).
#
# Discipline (three-crash lesson): crash-risk vectors go last within c5,
# the banner prints BEFORE the send, and verdicts are read from stats
# deltas + the completion ledger - a reboot mid-axis IS the observation.
# OTA effect adjudication of anything that survives is a stage2 kit
# listener session, never this runner.

set -uo pipefail

here=$(cd -- "$(dirname -- "$0")" && pwd)
kit=$here/../../suites/device-suite-wmi-full-frame-stage2
analyzer=$here/../../suites/rx-radiotap-audit/analyze_radiotap_pcap.py
expected_build_id=4c13f3b3f0b8f03d6904dd871af39164e18afa57
expected_src_rev=30442b8029b0+dirty-20260906-selftest-vht-vectors-v20a
expected_stats_format=12
expected_selftests=407

usage()
{
	cat >&2 <<EOF
usage: run_d_wave_host.sh [--authorized-isolated-lab]
One-shot 4.3 closing round on v19: gate + c7 + c2 + b2a HT rx-audit +
c6 invoke-level tools + c5 firmware probe axes (risk-ordered, crash
continuation built in).
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
case $note in *"$expected_build_id"*) ;; *) echo "build id mismatch (want v19 $expected_build_id)" >&2; exit 3 ;; esac

stamp=$(date -u +%Y%m%dT%H%M%SZ)
out=$here/host-capture-d-wave-$stamp-$$
mkdir "$out"
echo "D_WAVE_OUTPUT_DIR=$out"

stat_value() { awk -F= -v key="$2" '$1 == key {print $2; exit}' "$1"; }

remote=/data/local/tmp/qcacld-dwave-$$
adb_shell "mkdir -p $remote" || exit 3
"${adb_cmd[@]}" push "$kit/send_stage1_packet" "$remote/send_stage1_packet" >"$out/push.log" 2>&1 || exit 3
adb_shell "chmod 0755 $remote/send_stage1_packet" || exit 3

tp=/data/data/com.termux/files/usr
tp_home=/data/data/com.termux/files/home
tool_env="env LD_LIBRARY_PATH=$tp/lib HOME=$tp_home TERM=xterm-256color TERMINFO=$tp/share/terminfo PATH=$tp/bin:/system/bin:/vendor/bin"

stats=/sys/kernel/debug/wlan0/frame_inject_stats

mount_debugfs()
{
	local debugfs_type
	debugfs_type=$(adb_shell 'stat -f -c %T /sys/kernel/debug' | tr -d ' \r\n')
	if [ "$debugfs_type" != 0x64626720 ] && [ "$debugfs_type" != debugfs ]; then
		adb_shell 'mount -t debugfs debugfs /sys/kernel/debug' >"$out/mount.log" 2>&1
	fi
}

# Framework teardown discipline (stage0 golden rule, do not simplify):
# "Wifi is disabled" is only the SETTING bit; the framework tears down
# asynchronously and would destroy the persona mid-run otherwise.
persona_up()
{
	adb_shell 'cmd wifi set-wifi-enabled disabled' >/dev/null 2>&1
	local n off_status off_supp
	for n in $(seq 1 120); do
		off_status=$(adb_shell 'cmd wifi status' 2>/dev/null | tr -d '\r')
		off_supp=$(adb_shell 'pidof wpa_supplicant' 2>/dev/null | tr -d '\r\n')
		grep -q '^Wifi is disabled$' <<<"$off_status" && [ -z "$off_supp" ] && return 0
		sleep 0.5
	done
	return 1
}

monitor_setup()
{
	local n f
	for n in $(seq 1 15); do
		adb_shell 'iw dev wlan0 set type monitor' >/dev/null 2>&1 || { sleep 1; continue; }
		adb_shell 'ip link set wlan0 up' >/dev/null 2>&1 || { sleep 1; continue; }
		for f in $(seq 1 20); do
			adb_shell 'iw dev wlan0 set freq 5745' >/dev/null 2>&1 && break
			sleep 0.3
		done
		adb_shell 'iw dev wlan0 info' 2>/dev/null | tr -d '\r' | grep -q 'channel 149' && return 0
		sleep 1
	done
	return 1
}

persona_alive()
{
	adb_shell "test -r $stats" >/dev/null 2>&1
}

# After a crash-risk send: either the adapter still answers (no crash) or
# the SoC reset is in flight (adb drops, then the phone reboots into the
# same v19 image). Wait, rebuild persona, report - the axis verdict is
# CRASHED either way; this only lets the remaining axes still run.
wait_device_back()
{
	local n state
	for n in $(seq 1 150); do
		state=$(adb get-serialno 2>/dev/null)
		if [ "$state" = "$serial" ] && adb_shell 'true' >/dev/null 2>&1; then
			# adb is back; wait for boot to finish bringing the
			# framework up so the teardown dance has something to do
			for _ in $(seq 1 60); do
				adb_shell 'getprop sys.boot_completed' 2>/dev/null | tr -d '\r' | grep -q '^1$' && return 0
				sleep 2
			done
			return 0
		fi
		[ $((n % 10)) -eq 0 ] && echo "wait_device_back $n/150 (device gone: crash in flight)"
		sleep 2
	done
	return 1
}

persona_up || { echo "wifi off did not settle (supplicant alive)" >&2; exit 4; }
adb_shell 'test -e /sys/class/net/wlan0' >/dev/null 2>&1 || {
	echo "wlan0 missing after teardown" >&2; exit 4; }
mount_debugfs
monitor_setup || { echo "monitor setup failed" >&2; exit 4; }
persona_alive || { echo "persona died before first phase" >&2; exit 4; }

# ------------------------------------------------------------------ gate --
echo "== gate =="
adb_shell "cat $stats" >"$out/stats-before.txt"
rev=$(stat_value "$out/stats-before.txt" source_rev)
[ "$rev" = "$expected_src_rev" ] || { echo "SRC_REV mismatch: $rev" >&2; exit 3; }
fmt=$(stat_value "$out/stats-before.txt" format_version)
[ "$fmt" = "$expected_stats_format" ] || { echo "stats format mismatch: $fmt" >&2; exit 3; }

adb_shell "cat /sys/kernel/debug/wlan0/frame_inject_selftest" >"$out/selftest.log" 2>/dev/null || true
tests_n=$(stat_value "$out/selftest.log" tests)
passed_n=$(stat_value "$out/selftest.log" passed)
echo "gate.selftest tests=$tests_n passed=$passed_n (want $expected_selftests)"
[ "$tests_n" = "$expected_selftests" ] && [ "$passed_n" = "$expected_selftests" ] ||
	echo "gate.selftest MISMATCH (expected $expected_selftests)"

adb_shell "cat /sys/kernel/debug/wlan0/frame_inject_capabilities" >"$out/capabilities.txt" 2>&1
caps_ok=1
grep -q '^capabilities_format_version=14$' "$out/capabilities.txt" || caps_ok=0
grep -q '^probe_tx_cfr_beamform=' "$out/capabilities.txt" || caps_ok=0
grep -q '^fw_default_rate_mode=' "$out/capabilities.txt" || caps_ok=0
grep -q '^peer_fixed_rate_knob=' "$out/capabilities.txt" || caps_ok=0
grep -q '^peer_rssi_knob=' "$out/capabilities.txt" || caps_ok=0
grep -q '^tx_inflight_limit=8$' "$out/capabilities.txt" || caps_ok=0
grep -q '^fw_mgmt_len_cap=between_2048_2304' "$out/capabilities.txt" || caps_ok=0
grep -q '^fw_mgmt_retry_limit=not_honored' "$out/capabilities.txt" || caps_ok=0
grep -q '^monitor_fcs_preserve=.*effect_trim_skip_full_mon_path_only' "$out/capabilities.txt" || caps_ok=0
grep -q '^phy_family_bw_bypass=peer_fixed_rate_fw_default_submit' "$out/capabilities.txt" || caps_ok=0
grep -q '^phy_vht_beamformed=radiotap_flag_to_en_beamforming_tlv_mapped' "$out/capabilities.txt" || caps_ok=0
grep -q '^probe_state_reapply=pmf_key_peer_rate_auto_reapplied_on_helper_rebuild' "$out/capabilities.txt" || caps_ok=0
grep -q '^radiotap_vht_layout=spec_known_u16_flags_u8_bw_u8_mcs_nss_u8x4' "$out/capabilities.txt" || caps_ok=0
grep -q '^phy_family_bw=.*ge80_default_bypass' "$out/capabilities.txt" || caps_ok=0
echo "gate.capabilities v12_probe_lines=$caps_ok lines=$(wc -l <"$out/capabilities.txt") bytes=$(wc -c <"$out/capabilities.txt")"

# ------------------------------------------------------------------- c7 ----
echo "== C-7 default inflight=8 burst =="
persona_alive || { echo "persona died before c7" >&2; exit 4; }
adb_shell "cat /sys/kernel/debug/wlan0/frame_inject_inflight_limit" >"$out/c7-limit.txt" 2>&1
grep -q 'inflight_limit=8' "$out/c7-limit.txt" && echo "c7.default_limit8 OK" || echo "c7.default_limit8 FAILED"

C7_HEX=$(python3 - <<'PY'
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
adb_shell "cat $stats" >"$out/c7-stats-before.txt"
dmesg_mark=$(adb_shell 'dmesg | wc -l')
for i in 1 2 3 4 5 6 7 8; do
	adb_shell "$remote/send_stage1_packet --send wlan0 $C7_HEX" >"$out/c7-send$i.log" 2>&1
done
sleep 8
adb_shell "cat $stats" >"$out/c7-stats-after.txt"
adb_shell "dmesg | tail -n +$((dmesg_mark + 1))" >"$out/c7-dmesg.txt" 2>/dev/null || true
wmi0=$(stat_value "$out/c7-stats-before.txt" wmi_submitted); wmi1=$(stat_value "$out/c7-stats-after.txt" wmi_submitted)
fwc0=$(stat_value "$out/c7-stats-before.txt" fw_completion_events); fwc1=$(stat_value "$out/c7-stats-after.txt" fw_completion_events)
unc0=$(stat_value "$out/c7-stats-before.txt" unexpected_completions); unc1=$(stat_value "$out/c7-stats-after.txt" unexpected_completions)
wdt1=$(stat_value "$out/c7-stats-after.txt" watchdog_timeouts)
fatal1=$(stat_value "$out/c7-stats-after.txt" fatal_latched)
echo "c7.burst wmi_delta=$((wmi1 - wmi0)) fwc_delta=$((fwc1 - fwc0)) unexpected_delta=$((unc1 - unc0)) watchdog=$wdt1 fatal=$fatal1"

# ------------------------------------------------------------------- c2 ----
echo "== C-2 PMF chain =="
persona_alive || { echo "persona died before c2" >&2; exit 4; }
# Warm-up first: the helper auto-tears down ~5s after its last completion
# and the key install needs a live helper (-EAGAIN otherwise).
adb_shell "$remote/send_stage1_packet --send wlan0 $C7_HEX" >"$out/c2-warmup.log" 2>&1
sleep 4
adb_shell "echo 'ccmp 00112233445566778899aabbccddeeff' > /sys/kernel/debug/wlan0/frame_inject_pmf_key" 2>&1 | tr -d '\r'
sleep 2
adb_shell "cat /sys/kernel/debug/wlan0/frame_inject_pmf_key" >"$out/c2-key-after.txt" 2>&1
grep -q 'installed=1' "$out/c2-key-after.txt" && echo "c2.key_install OK" || echo "c2.key_install FAILED"

C2_HEX=$(python3 - <<'PY'
import struct
ra = bytes([0x02,0x11,0x22,0x33,0x44,0x55]); ta = bytes([0x02,0xAB,0xCD,0x00,0x00,0xF1])
mpdu = struct.pack("<HH",0x00C0 | 0x0400, 0)+ra+ta+ra+struct.pack("<H",0)+struct.pack("<H",1)
tx = struct.pack("<H", 0x0800)
hdr = struct.pack("<BBHI",0,0,8+len(tx),1<<15)
pkt = hdr+tx+mpdu
assert (pkt[2] | (pkt[3]<<8)) == 10 and (pkt[8] | (pkt[9]<<8)) == 0x0800
print(pkt.hex())
PY
)
adb_shell "cat $stats" >"$out/c2-stats-before.txt"
adb_shell "$remote/send_stage1_packet --send wlan0 $C2_HEX" >"$out/c2-send.log" 2>&1
sleep 4
adb_shell "cat $stats" >"$out/c2-stats-after.txt"
wmi0=$(stat_value "$out/c2-stats-before.txt" wmi_submitted); wmi1=$(stat_value "$out/c2-stats-after.txt" wmi_submitted)
fwc0=$(stat_value "$out/c2-stats-before.txt" fw_completion_events); fwc1=$(stat_value "$out/c2-stats-after.txt" fw_completion_events)
echo "c2.wfa_submit wmi_delta=$((wmi1 - wmi0)) fwc_delta=$((fwc1 - fwc0))"
adb_shell "echo none > /sys/kernel/debug/wlan0/frame_inject_pmf_key" >/dev/null 2>&1
adb_shell "cat /sys/kernel/debug/wlan0/frame_inject_pmf_key" >"$out/c2-key-cleared.txt" 2>&1
grep -q 'installed=0' "$out/c2-key-cleared.txt" && echo "c2.key_clear OK" || echo "c2.key_clear FAILED"

# N3 re-apply check: reinstall the key, force the helper to idle-teardown,
# rebuild it with one plain frame, and assert the apply_count grew by
# itself (the driver re-applies installed probe state onto every rebuilt
# helper, generation-deduplicated).
adb_shell "echo 'ccmp 00112233445566778899aabbccddeeff' > /sys/kernel/debug/wlan0/frame_inject_pmf_key" >/dev/null 2>&1
sleep 2
adb_shell "cat /sys/kernel/debug/wlan0/frame_inject_pmf_key" >"$out/c2-reapply-before.txt" 2>&1
apply0=$(awk -F= '/^reapply_count=/{print $2}' "$out/c2-reapply-before.txt" | tr -d '\r')
adb_shell "echo 1000 > /sys/kernel/debug/wlan0/frame_inject_helper_idle_ms" >/dev/null 2>&1
sleep 8
adb_shell "echo 5000 > /sys/kernel/debug/wlan0/frame_inject_helper_idle_ms" >/dev/null 2>&1
adb_shell "$remote/send_stage1_packet --send wlan0 $C7_HEX" >"$out/c2-rebuild-send.log" 2>&1
sleep 4
adb_shell "cat /sys/kernel/debug/wlan0/frame_inject_pmf_key" >"$out/c2-reapply-after.txt" 2>&1
apply1=$(awk -F= '/^reapply_count=/{print $2}' "$out/c2-reapply-after.txt" | tr -d '\r')
echo "c2.reapply reapply_delta=$((apply1 - apply0)) last_status=$(awk -F= '/^last_status=/{print $2}' "$out/c2-reapply-after.txt" | tr -d '\r') (want delta 1, status 0)"
adb_shell "echo none > /sys/kernel/debug/wlan0/frame_inject_pmf_key" >/dev/null 2>&1

# ------------------------------------------------------------------ b2a ----
echo "== B-2a HT rx audit (self-echo) =="
persona_alive || { echo "persona died before b2a" >&2; exit 4; }
HT20_HEX=$(python3 - <<'PY'
import struct
# HT20 device-proven vector (bisect 2026-09-05 boot e29e6aa2, status 0):
# MCS known=0x03 (HAVE_BW|HAVE_MCS), flags=0 (BW_20), index 0.
ra = b'\xff'*6; ta = bytes([0x02,0xAB,0xCD,0x00,0x00,0xF1])
mpdu = struct.pack("<HH",0x00C0,0)+ra+ta+ra+struct.pack("<H",0)+struct.pack("<H",7)
field = struct.pack("<BBB", 0x03, 0x00, 0x00)
hdr = struct.pack("<BBHI",0,0,8+len(field),1<<19)
pkt = hdr+field+mpdu
assert (pkt[2] | (pkt[3]<<8)) == 11 and pkt[8] == 0x03 and pkt[10] == 0
print(pkt.hex())
PY
)
b2a_seconds=75
b2a_count=90
"${adb_cmd[@]}" shell su -c "$remote/send_stage1_packet --capture-bssid wlan0 02:11:22:33:44:55 $b2a_seconds $remote/b2a.pcap" >"$out/b2a-capture.log" 2>&1 &
cap_pid=$!
sleep 2
for i in $(seq 1 $b2a_count); do
	adb_shell "$remote/send_stage1_packet --send wlan0 $HT20_HEX" >/dev/null 2>&1
	sleep 0.15
done
wait $cap_pid
grep -o 'capture=PASS packets=[0-9]*' "$out/b2a-capture.log" | head -1 || echo "b2a.capture_banner MISSING"

# On-device tshark malformed count (B-2a tshark leg) before anything is
# removed from the device.
adb_shell "$tool_env tshark -v" >"$out/b2a-tshark-version.txt" 2>&1 | head -1
adb_shell "$tool_env tshark -r $remote/b2a.pcap -Y _ws.malformed 2>/dev/null | wc -l" >"$out/b2a-malformed-count.txt" 2>&1
malformed=$(tr -d ' \r\n' <"$out/b2a-malformed-count.txt")
echo "b2a.tshark malformed_count=${malformed:-unreadable}"

"${adb_cmd[@]}" pull $remote/b2a.pcap "$out/b2a.pcap" >"$out/b2a-pull.log" 2>&1 || echo "b2a.pull FAILED"
if [ -r "$out/b2a.pcap" ]; then
	b2a_counts=$(python3 - "$out/b2a.pcap" "$analyzer" <<'PY'
import importlib.util, struct, sys
spec = importlib.util.spec_from_file_location("a", sys.argv[2])
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
total = walk_bad = ns_bad = mcs_frames = fec_known = stbc_known = fec_set = stbc_set = 0
try:
    pkts = a.parse_pcap(sys.argv[1])
except Exception as e:
    print(f"total=0 walk_bad=0 ns_bad=0 mcs_frames=0 fec_known=0 stbc_known=0 fec_set=0 stbc_set=0 parse_error={e}")
    raise SystemExit(0)
for _, pkt in pkts:
    total += 1
    f, body, _ = a.parse_radiotap(pkt)
    if f.get("walk_end_mismatch"):
        walk_bad += 1
    if f.get("ns_vendor_conflict"):
        ns_bad += 1
    if "mcs_known" in f:
        mcs_frames += 1
        if f["mcs_known"] & 0x10:
            fec_known += 1
            if f["mcs_flags"] & 0x10:
                fec_set += 1
        if f["mcs_known"] & 0x20:
            stbc_known += 1
            if f["mcs_flags"] & 0x20:
                stbc_set += 1
print(f"total={total} walk_bad={walk_bad} ns_bad={ns_bad} mcs_frames={mcs_frames} "
      f"fec_known={fec_known} stbc_known={stbc_known} fec_set={fec_set} stbc_set={stbc_set}")
PY
)
	echo "b2a.analyzer $b2a_counts"
	mcs_n=$(awk '{for(i=1;i<=NF;i++) if($i ~ /^mcs_frames=/) {sub("mcs_frames=","",$i); print $i}}' <<<"$b2a_counts")
	fec_k=$(awk '{for(i=1;i<=NF;i++) if($i ~ /^fec_known=/) {sub("fec_known=","",$i); print $i}}' <<<"$b2a_counts")
	stbc_k=$(awk '{for(i=1;i<=NF;i++) if($i ~ /^stbc_known=/) {sub("stbc_known=","",$i); print $i}}' <<<"$b2a_counts")
	if [ "${mcs_n:-0}" -ge 3 ] && [ $(( ${fec_k:-0} + ${stbc_k:-0} )) -ge 1 ]; then
		echo "b2a.verdict FEC_STBC_KNOWN_BITS_LIVE (mcs_frames=$mcs_n fec_known=$fec_k stbc_known=$stbc_k)"
	else
		echo "b2a.verdict NEEDS_INSPECTION (mcs_frames=${mcs_n:-0} fec_known=${fec_k:-0} stbc_known=${stbc_k:-0} - echo count is environment-dependent)"
	fi
else
	echo "b2a.verdict PCAP_MISSING"
fi

# --------------------------------------------------------------- c6tools --
echo "== C-6 invoke-level tools =="
persona_alive || { echo "persona died before c6tools" >&2; exit 4; }
# FIPS WEXT private ioctl (SIOCIWFIRSTPRIV+8) via python ctypes: request
# {u32 operation=encrypt; u32 mode=AES_CTR; u32 key_len=16; u8 key[32];
#  u32 data_len=16; u8 data[]} - response overwrites the same buffer.
# MEASURED (2026-09-06, first d-wave round): this build compiles the WEXT
# face OUT (WLAN_WEXT_SUPPORT_ENABLE undefined -> hdd_register_wext is an
# empty inline, wlan0 has no wireless_handlers): every WEXT private ioctl
# including SIOCGIWPRIV returns -EOPNOTSUPP. The expected outcome of this
# leg is rc=95 as NEGATIVE evidence (face structurally unreachable); any
# other rc means the face appeared and the log is worth reading.
cat >"$out/fips_invoke.py" <<'PY'
import ctypes, fcntl, socket, struct, sys
SIOCIWFIRSTPRIV = 0x8BE0
CMD = SIOCIWFIRSTPRIV + 8
key = bytes.fromhex("00112233445566778899aabbccddeeff")
data = bytes.fromhex("50000100000000000000000000000001")
req = struct.pack("<III", 0, 0, 16) + key.ljust(32, b"\x00") + struct.pack("<I", len(data)) + data
buf = ctypes.create_string_buffer(req, len(req))
# struct iwreq (64-bit): ifr_name[16] + union; iw_point.pointer is 64-bit
iwreq = ctypes.create_string_buffer(48)
struct.pack_into("16s", iwreq, 0, b"wlan0")
struct.pack_into("<QHH", iwreq, 16, ctypes.addressof(buf), len(req), 0)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    fcntl.ioctl(s, CMD, iwreq, True)
    rc = 0
except OSError as e:
    rc = e.errno
out = bytes(buf)
status, data_len = struct.unpack_from("<II", out, 0)
print(f"fips_invoke rc={rc} status={status} data_len={data_len} "
      f"out16={out[8:8+16].hex() if data_len >= 16 else out[8:8+data_len].hex()}")
sys.exit(0)
PY
"${adb_cmd[@]}" push "$out/fips_invoke.py" "$remote/fips_invoke.py" >/dev/null 2>&1
adb_shell "$tool_env python3 $remote/fips_invoke.py" >"$out/c6-fips.txt" 2>&1 || \
	adb_shell "python3 $remote/fips_invoke.py" >>"$out/c6-fips.txt" 2>&1 || true
cat "$out/c6-fips.txt"
grep -q "rc=95" "$out/c6-fips.txt" && echo "c6.fips NEGATIVE_CONFIRMED (wext face compiled out, measured)" || echo "c6.fips UNEXPECTED_RC (see above)"

# Spectral vendor invoke: GET_CAP_INFO (0xa0) needs no attributes (empty
# stdin via '-'). MEASURED: the vendor face answers, the spectral
# component refuses while disabled (-95, QDF_STATUS_COMP_DISABLED);
# activation is an INI/config-level change outside this round.
printf '' | timeout 30 "${adb_cmd[@]}" shell su -c 'iw dev wlan0 vendor recv 0x001374 0xa0 -' >"$out/c6-spectral-cap.txt" 2>&1
grep -q "Operation not supported" "$out/c6-spectral-cap.txt" && \
	echo "c6.spectral vendor_face_live component_disabled (measured -95)" || \
	cat "$out/c6-spectral-cap.txt"
echo "c6.notes: FIPS=wext face compiled out (negative closed); spectral=vendor face live, component config-gated; CFR=reachability on record, invoke not performed; effect-level = stage2 listener round"

# ------------------------------------------------------------------- c5 ----
# Probe axes, risk-ordered: rssi, fwrate, fixed_ht | cfr, bf, fixed_vht80.
echo "== C-5 probe axes =="

FWRATE_HEX=$(python3 - <<'PY'
import struct
ra = bytes([0x02,0x11,0x22,0x33,0x44,0x55]); ta = bytes([0x02,0xAB,0xCD,0x00,0x00,0xF1])
mpdu = struct.pack("<HH",0x00C0,0)+ra+ta+ra+struct.pack("<H",0)+struct.pack("<H",1)
tx = struct.pack("<H", 0x8000)
hdr = struct.pack("<BBHI",0,0,8+len(tx),1<<15)
pkt = hdr+tx+mpdu
assert (pkt[2] | (pkt[3]<<8)) == 10 and (pkt[8] | (pkt[9]<<8)) == 0x8000
print(pkt.hex())
PY
)
CFR_HEX=$(python3 - <<'PY'
import struct
ra = bytes([0x02,0x11,0x22,0x33,0x44,0x55]); ta = bytes([0x02,0xAB,0xCD,0x00,0x00,0xF1])
mpdu = struct.pack("<HH",0x00C0,0)+ra+ta+ra+struct.pack("<H",0)+struct.pack("<H",1)
tx = struct.pack("<H", 0x2000)
hdr = struct.pack("<BBHI",0,0,8+len(tx),1<<15)
pkt = hdr+tx+mpdu
assert (pkt[8] | (pkt[9]<<8)) == 0x2000
print(pkt.hex())
PY
)
BF_HEX=$(python3 - <<'PY'
import struct
ra = bytes([0x02,0x11,0x22,0x33,0x44,0x55]); ta = bytes([0x02,0xAB,0xCD,0x00,0x00,0xF1])
mpdu = struct.pack("<HH",0x00C0,0)+ra+ta+ra+struct.pack("<H",0)+struct.pack("<H",1)
tx = struct.pack("<H", 0x4000)
hdr = struct.pack("<BBHI",0,0,8+len(tx),1<<15)
pkt = hdr+tx+mpdu
assert (pkt[8] | (pkt[9]<<8)) == 0x4000
print(pkt.hex())
PY
)

# Shared submit-and-observe helper: label hex crash_risk
axis_submit()
{
	local label=$1 hex=$2 crash_risk=$3
	persona_alive || { echo "c5.$label SKIPPED (persona dead)" >&2; return 1; }
	adb_shell "cat $stats" >"$out/c5-$label-stats-before.txt"
	dmesg_mark=$(adb_shell 'dmesg | wc -l')
	echo "C5_LIVE_AXIS=$label"
	adb_shell "$remote/send_stage1_packet --send wlan0 $hex" >"$out/c5-$label-send.log" 2>&1
	sleep 6
	if ! adb_shell "cat $stats" >"$out/c5-$label-stats-after.txt" 2>/dev/null || [ ! -s "$out/c5-$label-stats-after.txt" ]; then
		echo "c5.$label CRASHED (stats unreadable after send)"
		if [ "$crash_risk" = 1 ]; then
			if wait_device_back && persona_up && mount_debugfs && monitor_setup && persona_alive; then
				echo "c5.$label recovered_after_reboot (continuing with remaining axes)"
			else
				echo "c5.$label DEVICE_DID_NOT_COME_BACK - abort remaining axes" >&2
				return 2
			fi
		fi
		return 1
	fi
	adb_shell "dmesg | tail -n +$((dmesg_mark + 1))" >"$out/c5-$label-dmesg.txt" 2>/dev/null || true
	adb_shell "cat /sys/kernel/debug/wlan0/frame_inject_completions" >"$out/c5-$label-ledger.txt" 2>&1 || true
	wmi0=$(stat_value "$out/c5-$label-stats-before.txt" wmi_submitted); wmi1=$(stat_value "$out/c5-$label-stats-after.txt" wmi_submitted)
	fwc0=$(stat_value "$out/c5-$label-stats-before.txt" fw_completion_events); fwc1=$(stat_value "$out/c5-$label-stats-after.txt" fw_completion_events)
	local last_rate
	last_rate=$(awk -F'\t' 'END{print $9}' "$out/c5-$label-ledger.txt" 2>/dev/null)
	echo "c5.$label wmi_delta=$((wmi1 - wmi0)) fwc_delta=$((fwc1 - fwc0)) last_tx_rate_kbps=${last_rate:-none}"
	return 0
}

# --- axis 1: peer_rssi knob (safe) ---
adb_shell "echo -40 > /sys/kernel/debug/wlan0/frame_inject_peer_rssi" 2>&1 | tr -d '\r'
adb_shell "cat /sys/kernel/debug/wlan0/frame_inject_peer_rssi" >"$out/c5-rssi-knob.txt" 2>&1
grep -q 'peer_rssi=-40' "$out/c5-rssi-knob.txt" && echo "c5.rssi knob_write OK" || echo "c5.rssi knob_write FAILED"
axis_submit rssi "$C7_HEX" 0
adb_shell "echo none > /sys/kernel/debug/wlan0/frame_inject_peer_rssi" >/dev/null 2>&1

# --- axis 2: fw-default-rate submission mode (safe) ---
axis_submit fwrate "$FWRATE_HEX" 0

# --- axis 3: fixed HT rate via peer param (low risk) ---
adb_shell "$remote/send_stage1_packet --send wlan0 $C7_HEX" >/dev/null 2>&1
sleep 3
adb_shell "echo 'fixed ht 1 7' > /sys/kernel/debug/wlan0/frame_inject_peer_rate" 2>&1 | tr -d '\r'
adb_shell "cat /sys/kernel/debug/wlan0/frame_inject_peer_rate" >"$out/c5-fixedht-knob.txt" 2>&1
grep -q 'ratecode=0x10000207' "$out/c5-fixedht-knob.txt" && echo "c5.fixedht knob_ratecode OK" || cat "$out/c5-fixedht-knob.txt"
sleep 1
axis_submit fixedht "$FWRATE_HEX" 0
adb_shell "echo none > /sys/kernel/debug/wlan0/frame_inject_peer_rate" >/dev/null 2>&1

# --- axis 4: cfr_enable bit (CRASH RISK) ---
axis_submit cfr "$CFR_HEX" 1
rc=$?
[ $rc -eq 2 ] && { echo "aborting remaining c5 axes" >&2; goto_restore=1; }

# --- axis 5: en_beamforming bit (CRASH RISK) ---
if [ "${goto_restore:-0}" -ne 1 ]; then
	# re-arm helper after any reboot between axes
	adb_shell "$remote/send_stage1_packet --send wlan0 $C7_HEX" >/dev/null 2>&1
	sleep 3
	axis_submit bf "$BF_HEX" 1
	[ $? -eq 2 ] && { echo "aborting remaining c5 axes" >&2; goto_restore=1; }
fi

# --- axis 6: fixed VHT rate + fw-default frame (CRASH RISK, >=80MHz
#     bypass hypothesis: peer ratectrl vs the mgmt rate descriptor) ---
if [ "${goto_restore:-0}" -ne 1 ]; then
	adb_shell "$remote/send_stage1_packet --send wlan0 $C7_HEX" >/dev/null 2>&1
	sleep 3
	adb_shell "echo 'fixed vht 1 9' > /sys/kernel/debug/wlan0/frame_inject_peer_rate" 2>&1 | tr -d '\r'
	adb_shell "cat /sys/kernel/debug/wlan0/frame_inject_peer_rate" >"$out/c5-fixedvht-knob.txt" 2>&1
	grep -q 'ratecode=0x10000309' "$out/c5-fixedvht-knob.txt" && echo "c5.fixedvht knob_ratecode OK" || cat "$out/c5-fixedvht-knob.txt"
	sleep 1
	axis_submit fixedvht "$FWRATE_HEX" 1
	adb_shell "echo none > /sys/kernel/debug/wlan0/frame_inject_peer_rate" >/dev/null 2>&1
fi

# --- axis 7: wide-family request through the DEFAULT bypass (v19b).
# The vht80_nss1_mcs3 vector is the exact class the v13b gate rejected;
# since v19b it must ride the C-5 bypass: peer fixed rate pinned from
# the request + TLV-less submission. Expect wmi+1, fwc+1,
# fw_width_bypassed exactly +1 and drop_reason_fw_width unchanged.
if [ "${goto_restore:-0}" -ne 1 ]; then
	# re-arm helper after any reboot between axes
	adb_shell "$remote/send_stage1_packet --send wlan0 $C7_HEX" >/dev/null 2>&1
	sleep 3
	BYPASS_HEX=000014000000200040000004130000000000000040000000ffffffffffff02abcd0000f1ffffffffffff0000
	adb_shell "cat $stats" >"$out/c5-bypass-stats-before.txt"
	dmesg_mark=$(adb_shell 'dmesg | wc -l')
	echo "C5_LIVE_AXIS=bypassvht80"
	adb_shell "$remote/send_stage1_packet --send wlan0 $BYPASS_HEX" >"$out/c5-bypass-send.log" 2>&1
	sleep 6
	if adb_shell "cat $stats" >"$out/c5-bypass-stats-after.txt" 2>/dev/null && [ -s "$out/c5-bypass-stats-after.txt" ]; then
		adb_shell "dmesg | tail -n +$((dmesg_mark + 1))" >"$out/c5-bypass-dmesg.txt" 2>/dev/null || true
		bw0=$(stat_value "$out/c5-bypass-stats-before.txt" wmi_submitted); bw1=$(stat_value "$out/c5-bypass-stats-after.txt" wmi_submitted)
		bc0=$(stat_value "$out/c5-bypass-stats-before.txt" fw_completion_events); bc1=$(stat_value "$out/c5-bypass-stats-after.txt" fw_completion_events)
		byp0=$(stat_value "$out/c5-bypass-stats-before.txt" fw_width_bypassed); byp1=$(stat_value "$out/c5-bypass-stats-after.txt" fw_width_bypassed)
		brj0=$(stat_value "$out/c5-bypass-stats-before.txt" drop_reason_fw_width); brj1=$(stat_value "$out/c5-bypass-stats-after.txt" drop_reason_fw_width)
		echo "c5.bypassvht80 wmi_delta=$((bw1 - bw0)) fwc_delta=$((bc1 - bc0)) bypass_delta=$((byp1 - byp0)) fw_width_reject_delta=$((brj1 - brj0)) (want 1/1/1/0)"
		grep -q "bypassed to peer fixed rate" "$out/c5-bypass-dmesg.txt" && echo "c5.bypass dmesg_trace OK" || echo "c5.bypass dmesg_trace MISSING"
	else
		echo "c5.bypassvht80 CRASHED (stats unreadable after send)"
		if wait_device_back && persona_up && mount_debugfs && monitor_setup && persona_alive; then
			echo "c5.bypassvht80 recovered_after_reboot"
		else
			echo "c5.bypassvht80 DEVICE_DID_NOT_COME_BACK" >&2
			goto_restore=1
		fi
	fi
fi

# --------------------------------------------------------------- restore --
restore_device()
{
	adb_shell 'cmd wifi set-wifi-enabled disabled' >/dev/null 2>&1
	adb_shell 'ip link set wlan0 down' >/dev/null 2>&1 || true
	adb_shell 'iw dev wlan0 set type managed' >/dev/null 2>&1 || true
	adb_shell 'ip link set wlan0 up' >/dev/null 2>&1 || true
	adb_shell 'cmd wifi set-wifi-enabled enabled' >/dev/null 2>&1
	local n status
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
	echo "dwave_complete=1 restored=$restored output=$out"
	[ "$restored" -eq 1 ] || exit 6
}
restore_device
exit 0
