#!/usr/bin/env bash

set -uo pipefail

# Stage 2 PHY A/B probe (todo 4.3/4.4 PHY rows), kit v10.
#
# Sends a fixed, individually addressed vector set twice: once with the
# frame_inject_experimental_phy module parameter off (frozen Stage 1
# behavior: MCS/VHT/HE/power/antenna requests must be dropped) and once
# with it on. The independent listener capture is the only authority for
# what actually went over the air and at which rate.
#
# v11e contract (measured firmware boundary + v19b default bypass):
#   - A PURE family (HT/VHT/HE) rate request whose bandwidth is 80 MHz or
#     wider still RAMDUMPs the firmware when carried by the mgmt rate
#     descriptor (2026-09-05 bisect). Since v19b the driver defaults this
#     class onto the measured-safe C-5 bypass: the helper peer's fixed
#     rate is pinned to the requested family/MCS/NSS and the frame is
#     submitted WITHOUT the tx_send_params TLV (d-wave axis7 device
#     proof: wmi+1/fwc+1/fw_width_bypassed exactly +1/fw_width reject
#     unchanged). Therefore vht80_nss1_mcs3, vht160_nss2_mcs8 and
#     he_su_mcs7 are POSITIVE in the on phase with the bypass counter as
#     evidence, and knob-gated rejects in the off phase like any other
#     family vector. 20/40 MHz family requests complete with status 0 on
#     the descriptor path and stay positive in both phases.
#
# v9 contract (fixes the 12 defects confirmed in the v8 return audit):
#   - "submitted" is a driver-evidence verdict: per-vector wmi_submitted
#     and drop-reason deltas from the frame_inject_stats debugfs node,
#     NOT the sendto() return code (queue-accept only). Per-phase stats
#     snapshots (state / helper_context_source / histograms) are archived.
#   - The expected submit outcome of every vector in every phase is
#     asserted: knob-gated families reject when the param is off,
#     negative vectors reject in both phases, FCS and declared-channel
#     passthrough are knob-independent (v7+) and must be accepted in
#     both phases. Violations exit 7 after Wi-Fi restore.
#   - The bool module parameter reads back Y/N, not 0/1.
#   - Monitor setup retries with interface down/up and asserts the final
#     iw state (type/channel/width) instead of trusting one attempt.
#   - An EXIT trap best-effort restores the param and the managed
#     persona even when the script dies mid-run.
#   - The verifier return code is surfaced: rc 0 = PASS, rc 1 = UNPROVEN
#     (a legal verdict, reported as-is), rc 2 = harness error (exit 9).
#   - --expected-build-id must be 40 hex chars and both the expected and
#     the loaded build id are recorded into the artifacts.

here=$(cd -- "$(dirname -- "$0")" && pwd)
stage1_dir=$here

expected_build_id=4c13f3b3f0b8f03d6904dd871af39164e18afa57

usage()
{
	cat >&2 <<'EOF'
usage: run_stage2_phy_ab.sh [--serial SERIAL] [--expected-build-id HEX40]
       --capture PCAP --frequency MHZ --channel-width W
       [--center-frequency MHZ] [--vector-set main|offchannel]
       [--offchannel-target MHZ] --authorized-isolated-lab

The capture must already be recording on the target channel (start
run_stage2_listener.sh first, or run under run_stage2_matrix_host.sh). The
phone will be switched to monitor on the same channel and restored to
managed Wi-Fi at the end.

--expected-build-id HEX40 authorizes a self-built module identity for this
run (the default stays the delivered kit build id); both ids land in
ab-contract.txt.

--vector-set offchannel proves off-channel passthrough: the phone monitor
is parked on --frequency while every vector DECLARES --offchannel-target;
the listener must be recording on the TARGET frequency (not --frequency).
Declared-channel transmission is knob-independent since v7, so these
vectors are expected to be submitted in BOTH phases; the A/B knob only
gates the PHY rate families of the main set.
EOF
	exit 2
}

serial=
capture=
frequency=
channel_width=
center_frequency=
vector_set=main
offchannel_target=
authorized=0
while [ "$#" -gt 0 ]; do
	case $1 in
	--serial) [ "$#" -ge 2 ] || usage; serial=$2; shift 2 ;;
	--capture) [ "$#" -ge 2 ] || usage; capture=$2; shift 2 ;;
	--frequency) [ "$#" -ge 2 ] || usage; frequency=$2; shift 2 ;;
	--channel-width) [ "$#" -ge 2 ] || usage; channel_width=$2; shift 2 ;;
	--center-frequency) [ "$#" -ge 2 ] || usage; center_frequency=$2; shift 2 ;;
	--vector-set) [ "$#" -ge 2 ] || usage; vector_set=$2; shift 2 ;;
	--offchannel-target) [ "$#" -ge 2 ] || usage; offchannel_target=$2; shift 2 ;;
	--authorized-isolated-lab) authorized=1; shift ;;
	--expected-build-id)
		[ "$#" -ge 2 ] || usage
		case $2 in
		*[!0-9a-fA-F]*|'') usage ;;
		esac
		[ ${#2} -eq 40 ] || usage
		expected_build_id=$2
		shift 2 ;;
	*) usage ;;
	esac
done
[ "$authorized" -eq 1 ] && [ -n "$capture" ] && [ -n "$frequency" ] && \
	[ -n "$channel_width" ] || usage

case $vector_set in
main) ;;
offchannel) [ -n "$offchannel_target" ] || usage ;;
*) usage ;;
esac
[ -r "$capture" ] || { echo "capture not readable: $capture" >&2; exit 3; }
[ -x "$stage1_dir/send_stage1_packet" ] || exit 3
[ -f "$stage1_dir/verify_stage2_ota.py" ] || exit 3
command -v adb >/dev/null || exit 3
command -v python3 >/dev/null || exit 3
# Same kit-integrity gate as the P1/P2 senders.
(cd "$stage1_dir" && sha256sum -c SHA256SUMS) >/dev/null 2>&1 || \
	{ echo "kit SHA256SUMS integrity check failed" >&2; exit 3; }

sender_hex=$(sha256sum "$stage1_dir/send_stage1_packet" | awk '{print $1}')

# Fixed vector set, generated and self-decoded by
# ../width-probe-320/gen_phy_vectors.py (regenerate there, never hand-edit):
# every probe-request MPDU is a full 24-byte header (fc+dur+3 addrs+seq,
# unique locally-administered SA per vector) so the driver's 24-byte mgmt
# min-length gate is cleared and the PHY semantics are actually reached.
# Radiotap encodings follow the kernel enums (GKI 6.6 reference header):
# MCS known=0x03 (BW|MCS), BW 20/40; VHT known=0x0040 (BANDWIDTH) with the
# spec bandwidth values 0/1/4/11 = 20/40/80/160 MHz (80+80 is not
# expressible in the radiotap VHT field; the former hand-written
# vht80p80_nss1_mcs1 used a non-spec table and was replaced by
# vht40_nss2_mcs9); TX power sets DBM_TX_POWER (bit 10), not
# DBM_ANTSIGNAL (bit 5). Vectors 9-10 must be rejected in BOTH phases and
# carry the negative condition in their known/flags bits (HAVE_STBC+STBC,
# KNOWN_GI+SGI). Vectors 11-16 close the 4.1.1 OTA gap (bytes lifted from
# the device-proven stage1 756 plan, SA rewritten per vector):
#   11 he_su_mcs7        HE minimal mapping - declared bw 80 MHz, so v10
#                        classifies it with the fw_width negatives (the
#                        firmware boundary is the WIDTH, not the family:
#                        he at 20/40 MHz completed status 0 on device)
#   12/13 antenna_zero/three  v7 ANTENNA->chain_mask wiring (A/B = observed ant)
#   14 fcs_caller_valid  caller-FCS preserve - knob-independent since v7, so
#                        BOTH phases must preserve the caller FCS bytes and
#                        the listener decides what was actually on the air
#   15/16 chan_declared_2412/5955  off-channel passthrough (declared freq !=
#                        monitor freq), knob-independent since v7. In the main
#                        set these are expected "missing" on the session
#                        listener when accepted (the frame leaves on the
#                        DECLARED channel); the positive proof is the
#                        offchannel vector-set run with the listener parked
#                        on the declared target.
vectors=(
"ht_mcs0_bw20|00000b000000080003000040000000ffffffffffff02abcd000001ffffffffffff0000"
"ht_mcs7_bw40|00000b000000080003010740000000ffffffffffff02abcd000002ffffffffffff0000"
"ht_mcs9_nss2|00000b000000080003000940000000ffffffffffff02abcd000003ffffffffffff0000"
"vht80_nss1_mcs3|000014000000200040000004130000000000000040000000ffffffffffff02abcd000004ffffffffffff0000"
"vht160_nss2_mcs8|00001400000020004000000b280000000000000040000000ffffffffffff02abcd000005ffffffffffff0000"
"vht40_nss2_mcs9|000014000000200040000001290000000000000040000000ffffffffffff02abcd000006ffffffffffff0000"
"pwr10_legacy6m|00000a00040400000c0a40000000ffffffffffff02abcd000007ffffffffffff0000"
"pwr20_legacy6m|00000a00040400000c1440000000ffffffffffff02abcd000008ffffffffffff0000"
"neg_mcs_stbc|00000b000000080023200040000000ffffffffffff02abcd000009ffffffffffff0000"
"neg_vht_sgi|000014000000200044000404130000000000000040000000ffffffffffff02abcd00000affffffffffff0000"
"he_su_mcs7|00001400000080002040000000070000020002004000452302112233445502abcd00001102a1a2a3a4a51000"
"antenna_zero|0000090000080000004000452302112233445502abcd00001202a1a2a3a4a51000"
"antenna_three|0000090000080000034000452302112233445502abcd00001302a1a2a3a4a51000"
"fcs_caller_valid|0000090002000000104000452302112233445502abcd00001402a1a2a3a4a510005112a79a"
"chan_declared_2412|00000c00080000006c09a0004000452302112233445502abcd00001502a1a2a3a4a51000"
"chan_declared_5955|00000c0008000000431740014000452302112233445502abcd00001602a1a2a3a4a51000"
)

if [ "$vector_set" = offchannel ]; then
	# Channel field (index 3) declares the TARGET; the monitor stays parked
	# on --frequency. Flags follow the stage1 plan convention: 0x00a0 for
	# 2.4 GHz, 0x0140 for 5/6 GHz.
	case $offchannel_target in
	24[1-9][0-9]) oc_flags=a000 ;;
	*) oc_flags=4001 ;;
	esac
	oc_freq=$(printf '%02x%02x' $((offchannel_target & 255)) $(((offchannel_target >> 8) & 255)))
	oc_hdr="00000c0008000000${oc_freq}${oc_flags}"
	vectors=(
	"oc_probe_a|${oc_hdr}4000452302112233445502abcd00002102a1a2a3a4a51000"
	"oc_probe_b|${oc_hdr}4000452302112233445502abcd00002202a1a2a3a4a51000"
	)
	echo "OFFCHANNEL MODE: monitor parked on $frequency, vectors declare $offchannel_target" >&2
	echo "The listener capture MUST be recording on $offchannel_target (not $frequency)." >&2
fi

# Expected submit outcome per phase, mirroring the driver contract:
# the knob gates exactly the five rate families; the fw_width vectors
# (family preamble + declared bandwidth 80/160 MHz) are rejected in BOTH
# phases - off via the knob gate, on via the measured firmware RAMDUMP
# boundary (drop_reason_fw_width, v13b+); negatives (STBC/SGI known-bit
# requests) are precise -EOPNOTSUPP refusals; FCS preserve and
# declared-channel passthrough are unconditional.
expected_submit()
{
	case $2 in
	ht_mcs0_bw20|ht_mcs7_bw40|ht_mcs9_nss2|vht40_nss2_mcs9|pwr10_legacy6m|pwr20_legacy6m|antenna_zero|antenna_three)
		[ "$1" = on ] && echo accept || echo reject ;;
	vht80_nss1_mcs3|vht160_nss2_mcs8|he_su_mcs7)
		[ "$1" = on ] && echo accept || echo reject ;;
	neg_mcs_stbc|neg_vht_sgi)
		echo reject ;;
	fcs_caller_valid|chan_declared_2412|chan_declared_5955|oc_probe_a|oc_probe_b)
		echo accept ;;
	*)
		return 1 ;;
	esac
}

# fw_width vectors: in the ON phase the request must ride the v19b
# bypass - the fw_width_bypassed histogram moves exactly +1 while
# drop_reason_fw_width stays put (a reject there means the loaded module
# predates the v19b bypass and must be rebuilt from the kit source).
fw_width_vector()
{
	case $1 in
	vht80_nss1_mcs3|vht160_nss2_mcs8|he_su_mcs7) return 0 ;;
	*) return 1 ;;
	esac
}

if [ -z "$serial" ]; then
	mapfile -t serials < <(adb devices | awk '$2 == "device" {print $1}')
	[ "${#serials[@]}" -eq 1 ] || exit 3
	serial=${serials[0]}
fi
adb_cmd=(adb -s "$serial")
adb_shell() { "${adb_cmd[@]}" shell su -c "$1" </dev/null; }

session_open=1
param_on=0

# Best-effort emergency restore for mid-run deaths; the normal path uses
# restore_wifi() with the full wait loop and then clears session_open.
emergency_cleanup()
{
	[ "$session_open" -eq 1 ] || return 0
	if [ "$param_on" -eq 1 ]; then
		adb_shell "echo N > /sys/module/qca_cld3_peach_v2/parameters/frame_inject_experimental_phy" \
			>/dev/null 2>&1
	fi
	adb_shell 'cmd wifi set-wifi-enabled disabled' >/dev/null 2>&1
	adb_shell 'ip link set wlan0 down' >/dev/null 2>&1
	adb_shell 'iw dev wlan0 set type managed' >/dev/null 2>&1
	adb_shell 'ip link set wlan0 up' >/dev/null 2>&1
	adb_shell 'cmd wifi set-wifi-enabled enabled' >/dev/null 2>&1
	echo "EMERGENCY_CLEANUP_RAN=1 (verify the phone reconnected to Wi-Fi)" >&2
}
trap 'rc=$?; emergency_cleanup; exit $rc' EXIT

# Kit build gate: the loaded module must match the pinned identity unless
# the operator explicitly overrides it with a self-built module.
note=$("${adb_cmd[@]}" exec-out su -c 'od -An -v -tx1 /sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id' | tr -d ' \r\n')
case $note in *"$expected_build_id"*) ;; *)
	echo "loaded module build id mismatch (want $expected_build_id)" >&2
	exit 3
	;;
esac

# Locate the stats node before anything else: v9 treats the per-vector
# wmi_submitted/drop deltas as the submitted evidence, so an unreadable
# stats node is a hard stop, not a degradation.
mounts=$(adb_shell 'cat /proc/mounts' 2>/dev/null || true)
debug_root=$(awk '$3 == "debugfs" { print $2; exit }' <<<"$mounts")
if [ -z "$debug_root" ] || \
	! adb_shell "test -r $debug_root/wlan0/frame_inject_stats" >/dev/null 2>&1; then
	adb_shell 'mkdir -p /sys/kernel/debug' >/dev/null 2>&1 || true
	adb_shell 'mount -t debugfs debugfs /sys/kernel/debug' >/dev/null 2>&1 || true
	debug_root=/sys/kernel/debug
fi
stats_node=$debug_root/wlan0/frame_inject_stats
adb_shell "test -r $stats_node" >/dev/null 2>&1 || {
	echo "frame_inject_stats not readable at $stats_node (debugfs hidden?)" >&2
	exit 10
	}

param_path=/sys/module/qca_cld3_peach_v2/parameters/frame_inject_experimental_phy
stamp=$(date -u +%Y%m%dT%H%M%SZ)
out=$here/phy-ab-$stamp-$$
mkdir "$out" || exit 3
echo "PHY_AB_OUTPUT_DIR=$out"
printf '%s\n' "${vectors[@]}" >"$out/vectors.txt"
printf 'capture=%s\nsender_sha256=%s\nvector_set=%s\nfrequency=%s\nchannel_width=%s\ncenter_frequency=%s\noffchannel_target=%s\nexpected_build_id=%s\nloaded_build_id_note=%s\nstats_node=%s\n' \
	"$capture" "$sender_hex" "$vector_set" "$frequency" "$channel_width" \
	"${center_frequency:-none}" "${offchannel_target:-none}" \
	"$expected_build_id" "$note" "$stats_node" >"$out/ab-contract.txt"
# record (not gate) the module's stats format + source rev for forensics
adb_shell "cat $stats_node" 2>/dev/null | awk -F= '
	$1 == "format_version" { printf "stats_format_version=%s\n", $2 }
	$1 == "source_rev" { printf "source_rev=%s\n", $2 }' >>"$out/ab-contract.txt"

# Phone prep: managed -> monitor on the listener channel. Golden persona
# discipline (v11): "Wifi is disabled" is only the SETTING bit - the
# framework teardown (supplicant exit, vdev destroy) lands asynchronously
# and would otherwise destroy the monitor persona mid-run. The persona
# flip also races the teardown (-EBUSY/-16), so retry the whole sequence
# and assert the final state instead of trusting a single pass.
adb_shell 'cmd wifi set-wifi-enabled disabled' >/dev/null 2>&1
settled=0
for n in $(seq 1 120); do
	status=$(adb_shell 'cmd wifi status' 2>/dev/null | tr -d '\r')
	supp=$(adb_shell 'pidof wpa_supplicant' 2>/dev/null | tr -d '\r\n')
	grep -q '^Wifi is disabled$' <<<"$status" && [ -z "$supp" ] && { settled=1; break; }
	sleep 0.5
done
[ "$settled" -eq 1 ] || { echo "Wi-Fi framework did not settle off (supplicant alive)" >&2; exit 4; }
if [ "$channel_width" = 20 ]; then
	channel_command="iw dev wlan0 set freq $frequency"
else
	channel_command="iw dev wlan0 set freq $frequency $channel_width $center_frequency"
fi
monitor_ready=0
for _ in $(seq 1 30); do
	adb_shell 'ip link set wlan0 down' >/dev/null 2>&1 || true
	adb_shell 'iw dev wlan0 set type monitor' >/dev/null 2>&1 || { sleep 1; continue; }
	adb_shell 'ip link set wlan0 up' >/dev/null 2>&1 || { sleep 1; continue; }
	adb_shell "$channel_command" >/dev/null 2>&1 || { sleep 1; continue; }
	monitor_ready=1
	break
done
[ "$monitor_ready" -eq 1 ] || { echo "monitor/channel setup failed after retries" >&2; exit 4; }
adb_shell 'iw dev wlan0 info' >"$out/iw-monitor.log" 2>&1
grep -q '^[[:space:]]*type monitor$' "$out/iw-monitor.log" || exit 4
grep -q "channel [0-9][0-9]* ($frequency MHz)" "$out/iw-monitor.log" || exit 4
grep -q "width: $channel_width MHz" "$out/iw-monitor.log" || exit 4

sender_remote=/data/local/tmp/qcacld-phy-ab-$$
adb_shell "mkdir -p $sender_remote" || exit 4
"${adb_cmd[@]}" push "$stage1_dir/send_stage1_packet" \
	"$sender_remote/send_stage1_packet" >"$out/push.log" 2>&1 || exit 4
adb_shell "chmod 0755 $sender_remote/send_stage1_packet" || exit 4

stat_value() { awk -F= -v key="$2" '$1 == key {print $2; exit}' "$1"; }
drop_evidence() {
	awk -F= '/^drop_reason_/ { s += $2 }
		/^parse_failed=/ { s += $2 }
		/^backend_unsupported=/ { s += $2 }
		END { print s + 0 }' "$1"
}

contract_failures=0
note_contract_violation()
{
	echo "CONTRACT_VIOLATION phase=$1 vector=$2 expected=$3 wmi_delta=$4 drop_delta=$5 sendto_rc=$6"
	contract_failures=$((contract_failures + 1))
}

# The bool module parameter reads back Y/N.
phase_param_value() { [ "$1" = on ] && echo Y || echo N; }

# Per-vector settle: the sendto() return only proves queue acceptance, the
# worker parse drop and the WMI submit (+completion) land asynchronously,
# so read stats after a settle pause; the capture window deliberately
# covers send + settle + stats read so late listener copies can bind.
settle_seconds=1

: >"$out/ab-runs.tsv"
printf 'phase\tvector\texpected\tsubmitted\tsendto_rc\twmi_delta\tdrop_delta\tfw_completion_delta\twindow_start_ns\twindow_end_ns\n' \
	>"$out/ab-runs.tsv"
for phase in off on; do
	param_value=$(phase_param_value "$phase")
	adb_shell "echo $param_value > $param_path" || exit 5
	value=$(adb_shell "cat $param_path" | tr -d ' \r\n')
	[ "$value" = "$param_value" ] || \
		{ echo "param readback mismatch (got $value want $param_value)" >&2; exit 5; }
	if [ "$phase" = on ]; then param_on=1; else param_on=0; fi
	prev_snap=$out/stats-$phase-start.txt
	adb_shell "cat $stats_node" >"$prev_snap" || { echo "stats read failed" >&2; exit 10; }
	for entry in "${vectors[@]}"; do
		name=${entry%%|*}
		hex=${entry#*|}
		expected=$(expected_submit "$phase" "$name") || exit 3
		start=$(adb_shell "$sender_remote/send_stage1_packet --clock" | tr -d ' \r\n')
		adb_shell "$sender_remote/send_stage1_packet --send wlan0 $hex" \
			>"$out/send-$phase-$name.log" 2>&1
		rc=$?
		sleep "$settle_seconds"
		snap=$out/stats-$phase-$name.txt
		adb_shell "cat $stats_node" >"$snap" || { echo "stats read failed" >&2; exit 10; }
		end=$(adb_shell "$sender_remote/send_stage1_packet --clock" | tr -d ' \r\n')
		wmi_delta=$(( $(stat_value "$snap" wmi_submitted) -
			$(stat_value "$prev_snap" wmi_submitted) ))
		drop_delta=$(( $(drop_evidence "$snap") - $(drop_evidence "$prev_snap") ))
		fwc_delta=$(( $(stat_value "$snap" fw_completion_events) -
			$(stat_value "$prev_snap" fw_completion_events) ))
		fww_now=$(stat_value "$snap" drop_reason_fw_width)
		fww_prev=$(stat_value "$prev_snap" drop_reason_fw_width)
		fww_delta=$(( ${fww_now:-0} - ${fww_prev:-0} ))
		byp_now=$(stat_value "$snap" fw_width_bypassed)
		byp_prev=$(stat_value "$prev_snap" fw_width_bypassed)
		byp_delta=$(( ${byp_now:-0} - ${byp_prev:-0} ))
		submitted=0
		if [ "$expected" = accept ]; then
			if [ "$wmi_delta" -eq 1 ]; then
				submitted=1
			else
				note_contract_violation "$phase" "$name" "$expected" \
					"$wmi_delta" "$drop_delta" "$rc"
			fi
		else
			if [ "$wmi_delta" -eq 0 ] && [ "$drop_delta" -ge 1 ]; then
				submitted=0
			else
				note_contract_violation "$phase" "$name" "$expected" \
					"$wmi_delta" "$drop_delta" "$rc"
			fi
		fi
		# fw_width vectors must ride the v19b bypass in the on phase:
		# fw_width_bypassed moves exactly +1 and the boundary reject
		# histogram stays put.
		if [ "$phase" = on ] && fw_width_vector "$name"; then
			if [ "$byp_delta" -ne 1 ] || [ "$fww_delta" -ne 0 ]; then
				echo "CONTRACT_VIOLATION phase=$phase vector=$name bypass_delta=$byp_delta fw_width_delta=$fww_delta (want 1/0; module predates the v19b bypass?)"
				contract_failures=$((contract_failures + 1))
			fi
		fi
		printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
			"$phase" "$name" "$expected" "$submitted" "$rc" \
			"$wmi_delta" "$drop_delta" "$fwc_delta" "$start" "$end" \
			>>"$out/ab-runs.tsv"
		prev_snap=$snap
	done
	adb_shell "echo N > $param_path" || true
	param_on=0
	adb_shell "cat $stats_node" >"$out/stats-$phase-end.txt" || \
		{ echo "stats read failed" >&2; exit 10; }
	fatal=$(stat_value "$out/stats-$phase-end.txt" fatal_latched)
	[ "$fatal" -eq 0 ] || {
		echo "CONTRACT_VIOLATION phase=$phase fatal_latched=$fatal"
		contract_failures=$((contract_failures + 1))
	}
done

# Build the schema the owner-aware verifier already consumes, then bind.
# Column layout must match the ab-runs.tsv header above.
python3 - "$out" <<'PY'
import hashlib
import json
import sys
import pathlib

out = pathlib.Path(sys.argv[1])
lines = (out / "ab-runs.tsv").read_text().splitlines()
runs = [line.split("\t") for line in lines[1:]]
vectors = {}
for line in (out / "vectors.txt").read_text().splitlines():
    name, hex_text = line.split("|")
    packet = bytes.fromhex(hex_text)
    radiotap_len = packet[2] | (packet[3] << 8)
    mpdu = packet[radiotap_len:]
    # A vector that declares radiotap FCS carries 4 caller FCS bytes. The
    # verifier matches listener bodies with FCS already stripped (however
    # the listener handled it), so emit the body without the caller FCS;
    # the preserve/regenerate adjudication reads the raw capture instead.
    present = int.from_bytes(packet[4:8], "little")
    if present & 2 and packet[8] & 0x10 and len(mpdu) >= 4:
        mpdu = mpdu[:-4]
    vectors[name] = (packet, mpdu)
manifest_path = out / "ab-manifest.jsonl"
results_path = out / "ab-results.jsonl"
with manifest_path.open("w") as manifest, results_path.open("w") as results:
    for phase, name, _expected, submitted, _rc, _wmi, _drop, _fwc, start, end in runs:
        if not int(submitted):
            continue
        packet, mpdu = vectors[name]
        case_id = f"ab.{phase}.{name}"
        sha = hashlib.sha256(packet).hexdigest()
        manifest.write(json.dumps({
            "case_id": case_id,
            "case_cookie": case_id,
            "mpdu_hex": mpdu.hex(),
            "packet_sha256": sha,
            "stage2_response_policy": "required_if_ack_policy_applies",
        }) + "\n")
        results.write(json.dumps({
            "case_id": case_id,
            "packet_sha256": sha,
            "run_state": "complete",
            "submitted": {"state": "submitted", "request_id": 0,
                "capture_window_wallclock_ns": [int(start), int(end)]},
        }) + "\n")
PY

python3 "$stage1_dir/verify_stage2_ota.py" \
	--manifest "$out/ab-manifest.jsonl" \
	--results "$out/ab-results.jsonl" \
	--capture "$capture" \
	--output "$out/ab-matrix.tsv" >"$out/ab-verify.log" 2>&1
verify_rc=$?
printf '%s\n' "$verify_rc" >"$out/ab-verify.rc"
# rc 0 = PASS, rc 1 = UNPROVEN (a legal verdict), rc 2 = verifier harness
# error. The verdict itself always comes from the independent capture.
sed -n '1,2p' "$out/ab-verify.log" || true

python3 - "$out" "$capture" "$stage1_dir" <<'PY'
import pathlib
import struct
import sys

out = pathlib.Path(sys.argv[1])
capture = pathlib.Path(sys.argv[2])
sys.path.insert(0, sys.argv[3])
import verify_stage2_ota as ota

raw = capture.read_bytes()
packets = ota.classic_pcap(raw)
if packets is None:
    packets = ota.pcapng(raw)
if packets is None:
    raise SystemExit("capture is neither classic pcap nor pcapng")
# Rebuild the verifier's captured indexing (radiotap_mpdu drops bad/invalid
# FCS packets) so matched_packet_index from ab-matrix.tsv lines up.
captured = [packet for _ts, packet in packets
            if ota.radiotap_mpdu(packet)[0] is not None]

vectors = {}
for line in (out / "vectors.txt").read_text().splitlines():
    name, hex_text = line.split("|")
    packet = bytes.fromhex(hex_text)
    radiotap_len = packet[2] | (packet[3] << 8)
    vectors[name] = (packet, packet[radiotap_len:])

# Field size/alignment table copied verbatim from the driver's authoritative
# wlan_hdd_radiotap_sizes[] (wlan_hdd_frame_inject_radiotap.c): the v8 kit
# walked listener radiotap with a hand-guessed table that desynced on
# ANTENNA/DB_ANTSIGNAL (size 1, not 2) and misread DBM_ANTSIGNAL as TX power.
align_size = {
    0: (8, 8), 1: (1, 1), 2: (1, 1), 3: (2, 4), 4: (2, 2), 5: (1, 1),
    6: (1, 1), 7: (2, 2), 8: (2, 2), 9: (2, 2), 10: (1, 1), 11: (1, 1),
    12: (1, 1), 13: (1, 1), 14: (2, 2), 15: (2, 2), 16: (1, 1), 17: (1, 1),
    18: (4, 8), 19: (1, 3), 20: (4, 8), 21: (2, 12), 22: (8, 12),
    23: (2, 12), 24: (2, 12), 25: (2, 6), 26: (1, 1), 27: (2, 4),
    28: (4, 0),
}

def radiotap_phy(packet):
    length = packet[2] | (packet[3] << 8)
    field = 4
    present_masks = []
    while True:
        if field + 4 > length:
            return "malformed"
        present = struct.unpack_from("<I", packet, field)[0]
        present_masks.append(present)
        field += 4
        if not present & (1 << 31):
            break
    parts = []
    family = ""
    reset = False
    for present in present_masks:
        for index in range(32):
            bit = 1 << index
            if not present & bit or index == 31:
                continue
            if index in (29, 30):  # namespace switches carry no data
                if index == 30:
                    reset = True
                continue
            key = 0 if reset else index
            reset = False
            if key not in align_size:
                return "unknown_field"
            align, size = align_size[key]
            field = (field + align - 1) & ~(align - 1)
            if size == 0:  # TLV is variable length; stop walking
                return (family + "+tlv") if family else "tlv"
            if field + size > length:
                return "malformed"
            if index == 2:
                parts.append("legacy_%gmbps" % (packet[field] * 0.5))
            elif index == 10:
                value = packet[field]
                if value > 127:
                    value -= 256
                parts.append("txpower%ddbm" % value)
            elif index == 11:
                parts.append("ant%d" % packet[field])
            elif index == 19:
                known, flags, mcs = packet[field:field + 3]
                bw = {0: "20", 1: "40", 2: "40L", 3: "40U"}.get(
                    flags & 3, "?")
                family = "ht_mcs%d_bw%s" % (mcs, bw)
            elif index == 21:
                bandwidth = packet[field + 4]
                nss = packet[field + 5] >> 4
                mcs = packet[field + 5] & 0xF
                bw = {0: "20", 1: "40", 2: "80", 3: "80p80",
                    4: "160"}.get(bandwidth, "?")
                family = "vht_mcs%d_nss%d_bw%s" % (mcs, nss, bw)
            elif index == 23:
                data1 = struct.unpack_from("<H", packet, field)[0]
                data3 = struct.unpack_from("<H", packet, field + 4)[0]
                data6 = struct.unpack_from("<H", packet, field + 10)[0]
                # mcs bits mirror the host-side v7 HE mapping (data3>>8);
                # nsts is reported raw so A/B compares apples to apples.
                family = "he_fmt%d_mcs%d_nsts%d" % (
                    data1 & 3, (data3 >> 8) & 0xF, data6 & 0x1F)
            field += size
    return family + "+" + "+".join(parts) if family else \
        "+".join(parts) if parts else "unspecified"

rows = ["case_id\tsubmitted\tota_state\tobserved_phy"]
verified = {}
for line in (out / "ab-matrix.tsv").read_text().splitlines()[1:]:
    fields = line.split("\t")
    verified[fields[0]] = fields
for line in (out / "ab-runs.tsv").read_text().splitlines()[1:]:
    fields = line.split("\t")
    phase, name, expected, submitted = fields[0], fields[1], fields[2], fields[3]
    case_id = f"ab.{phase}.{name}"
    row = verified.get(case_id)
    ota_state = "not_submitted"
    phy = ""
    if row:
        ota_state = "observed" if row[2] != "missing" else "missing"
        if ota_state == "observed":
            phy = radiotap_phy(captured[int(row[2])])
    rows.append(f"{case_id}\t{submitted}({expected})\t{ota_state}\t{phy}")

# FCS source adjudication (vector fcs_caller_valid), phase-scoped: only
# copies whose capture timestamp falls inside the send window (with a
# tolerance for clock skew and retransmissions) attribute to a phase.
# Duration/ID is FW-owned, so body matching skips bytes 2-3. A listener
# that strips FCS yields listener_fcs_absent - undeterminable, recorded,
# never guessed. FCS preserve is knob-independent since v7, so BOTH phases
# are expected to preserve the caller bytes.
if "fcs_caller_valid" in vectors:
    packet, mpdu = vectors["fcs_caller_valid"]
    body = mpdu[:-4]
    caller_fcs = mpdu[-4:]
    key = body[:2] + body[4:]

    def copies_in(window, before_s=2.0, after_s=10.0):
        found = []
        for timestamp_ns, p in packets:
            radiotap_len = p[2] | (p[3] << 8)
            frame = p[radiotap_len:]
            for extra in (4, 0):
                if len(frame) == len(body) + extra and \
                        frame[:2] + frame[4:len(body)] == key:
                    if window[0] - before_s * 1e9 <= timestamp_ns <= \
                            window[1] + after_s * 1e9:
                        tail = frame[len(body):len(body) + 4]
                        if extra == 4 and tail == caller_fcs:
                            found.append("caller_fcs_preserved")
                        elif extra == 4:
                            found.append("fw_regenerated_fcs")
                        else:
                            found.append("listener_fcs_absent")
                    break
        return found

    for line in (out / "ab-runs.tsv").read_text().splitlines()[1:]:
        fields = line.split("\t")
        if fields[1] != "fcs_caller_valid" or fields[3] != "1":
            continue
        window = (int(fields[8]), int(fields[9]))
        verdicts = copies_in(window)
        summary = ",".join(sorted(set(verdicts))) if verdicts \
            else "no_in_window_copy"
        rows.append(f"fcs_source.{fields[0]}_phase={summary}"
            "\texpect=caller_fcs_preserved_if_listener_captures_fcs")
(out / "ab-summary.tsv").write_text("\n".join(rows) + "\n")
print((out / "ab-summary.tsv").read_text())
PY
summary_rc=$?
summary_failed=0
[ "$summary_rc" -eq 0 ] || {
	echo "summary block failed rc=$summary_rc" >&2
	summary_failed=1
}

# Restore managed Wi-Fi; a failed restore must be loud, never silent.
restore_wifi()
{
	adb_shell 'cmd wifi set-wifi-enabled disabled' >/dev/null 2>&1
	adb_shell 'ip link set wlan0 down' >/dev/null 2>&1 || true
	adb_shell 'iw dev wlan0 set type managed' >/dev/null 2>&1 || true
	adb_shell 'ip link set wlan0 up' >/dev/null 2>&1 || true
	adb_shell 'cmd wifi set-wifi-enabled enabled' >/dev/null 2>&1
	local restored=0
	for _ in $(seq 1 200); do
		status=$(adb_shell 'cmd wifi status' 2>/dev/null | tr -d '\r')
		if grep -q '^Wifi is enabled$' <<<"$status" &&
			grep -q 'Wifi is connected to' <<<"$status" &&
			grep -q 'VALIDATED' <<<"$status"; then
			restored=1
			break
		fi
		sleep 1
	done
	printf '%s\n' "$status" >"$out/wifi-restored.log" 2>&1
	return $((1 - restored))
}
if ! restore_wifi; then
	session_open=0
	echo "WIFI RESTORE FAILED; manual action required" >&2
	exit 6
fi
session_open=0

# Self-exclusion: hash everything except the sum file itself (the v8
# find|xargs pipeline could race its own output file into the listing).
(cd "$out" && find . -type f ! -name SHA256SUMS -print0 |
	sort -z | xargs -0 sha256sum >SHA256SUMS.new && mv SHA256SUMS.new SHA256SUMS)

echo "contract_failures=$contract_failures"
case $verify_rc in
0) echo "ota_verdict=PASS" ;;
1) echo "ota_verdict=UNPROVEN (legal verdict; report the summary as-is)" ;;
*) echo "ota_verdict=VERIFIER_ERROR rc=$verify_rc" ;;
esac
[ "$summary_failed" -eq 0 ] && echo "summary=ok" || echo "summary=failed"
echo "phy_ab_complete=1 output=$out"
if [ "$verify_rc" -eq 2 ] || [ "$summary_failed" -eq 1 ]; then
	exit 9
fi
[ "$contract_failures" -eq 0 ] || exit 7
exit 0
