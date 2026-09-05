#!/usr/bin/env bash

set -uo pipefail

# Stage 2 PHY A/B probe (todo 4.3/4.4 PHY rows).
#
# Sends a fixed, individually addressed vector set twice: once with the
# frame_inject_experimental_phy module parameter off (frozen Stage 1
# behavior: MCS/VHT/power must be rejected) and once with it on (submit with
# the experimental mapping). The independent listener capture is the only
# authority for what actually went over the air and at which rate.
# Negative vectors must be rejected in both phases. The script restores the
# phone to managed Wi-Fi afterwards and fails loudly if restoration fails.

here=$(cd -- "$(dirname -- "$0")" && pwd)
stage1_dir=$here/../device-suite-wmi-stage1-matrix

usage()
{
	cat >&2 <<'EOF'
usage: run_stage2_phy_ab.sh [--serial SERIAL] --capture PCAP
       --frequency MHZ --channel-width W [--center-frequency MHZ]
       [--vector-set main|offchannel] [--offchannel-target MHZ]
       --authorized-isolated-lab

The capture must already be recording on the target channel (start
run_stage2_listener.sh first, or run under run_stage2_matrix_host.sh). The
phone will be switched to monitor on the same channel and restored to
managed Wi-Fi at the end.

--vector-set offchannel proves off-channel passthrough: the phone monitor
is parked on --frequency while every vector DECLARES --offchannel-target;
the listener must be recording on the TARGET frequency (not --frequency).
off-phase vectors must be refused (pre-v7 same-frequency enforcement);
on-phase vectors accepted and observed on the target listener prove the
declared-channel transmission end to end.
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

sender_hex=$(sha256sum "$stage1_dir/send_stage1_packet" | awk '{print $1}')

# Fixed vector set, generated and decoded off-line: every radiotap header
# length/present bitmap and every MPDU (fc=0x0040 probe request, unique
# locally-administered SA, broadcast DA/BSSID) was verified before embedding.
# Vectors 1-8 are the original positive requests; 9-10 must be rejected in
# BOTH phases. Vectors 11-16 close the 4.1.1 OTA gap (bytes lifted from the
# device-proven stage1 756 plan, SA rewritten to a unique value per vector):
#   11 he_su_mcs7        v7 HE minimal mapping (preamble bit4, mcs/nss/bw)
#   12/13 antenna_zero/three  v7 ANTENNA->chain_mask wiring (A/B = observed ant)
#   14 fcs_caller_valid  v7 caller-FCS preserve (off=strip->FW FCS, on=ours;
#                        the fcs-source verdict line adjudicates preservation)
#   15/16 chan_declared_2412/5955  off-channel passthrough (declared freq !=
#                        monitor freq). In the main set these are expected
#                        "missing" on the session listener when accepted (the
#                        frame leaves on the DECLARED channel); the positive
#                        proof is the offchannel vector-set run with the
#                        listener parked on the declared target.
vectors=(
"ht_mcs0_bw20|00000b000000080002000040000000ffffffffffff02abcd000001ffffffffffff"
"ht_mcs7_bw40|00000b000000080003010740000000ffffffffffff02abcd000002ffffffffffff"
"ht_mcs9_nss2|00000b000000080002000940000000ffffffffffff02abcd000003ffffffffffff"
"vht80_nss1_mcs3|00001800000020004000000002130000000000000000000040000000ffffffffffff02abcd000004ffffffffffff"
"vht160_nss2_mcs8|00001800000020004000000004280000000000000000000040000000ffffffffffff02abcd000005ffffffffffff"
"vht80p80_nss1_mcs1|00001800000020004000000003110000000000000000000040000000ffffffffffff02abcd000006ffffffffffff"
"pwr10_legacy6m|00000a00240000000c0a40000000ffffffffffff02abcd000007ffffffffffff"
"pwr20_legacy6m|00000a00240000000c1440000000ffffffffffff02abcd000008ffffffffffff"
"neg_mcs_stbc|00000b000000080022200040000000ffffffffffff02abcd000009ffffffffffff"
"neg_vht_sgi|00001800000020000400040002130000000000000000000040000000ffffffffffff02abcd00000affffffffffff"
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

if [ -z "$serial" ]; then
	mapfile -t serials < <(adb devices | awk '$2 == "device" {print $1}')
	[ "${#serials[@]}" -eq 1 ] || exit 3
	serial=${serials[0]}
fi
adb_cmd=(adb -s "$serial")
adb_shell() { "${adb_cmd[@]}" shell su -c "$1"; }

param_path=/sys/module/qca_cld3_peach_v2/parameters/frame_inject_experimental_phy
stamp=$(date -u +%Y%m%dT%H%M%SZ)
out=$here/phy-ab-$stamp-$$
mkdir "$out" || exit 3
echo "PHY_AB_OUTPUT_DIR=$out"
printf '%s\n' "$vectors" >"$out/vectors.txt"
printf 'capture=%s\nsender_sha256=%s\n' "$capture" "$sender_hex" \
	>"$out/ab-contract.txt"

# Phone prep: managed -> monitor on the listener channel.
adb_shell 'cmd wifi set-wifi-enabled disabled' >/dev/null 2>&1
sleep 2
adb_shell 'iw dev wlan0 set type monitor' || exit 4
if [ "$channel_width" = 20 ]; then
	adb_shell "iw dev wlan0 set freq $frequency" || exit 4
else
	adb_shell "iw dev wlan0 set freq $frequency $channel_width $center_frequency" || exit 4
fi
adb_shell 'iw dev wlan0 info' >"$out/iw-monitor.log" 2>&1
grep -q '^[[:space:]]*type monitor$' "$out/iw-monitor.log" || exit 4

sender_remote=/data/local/tmp/qcacld-phy-ab-$$
adb_shell "mkdir -p $sender_remote" || exit 4
"${adb_cmd[@]}" push "$stage1_dir/send_stage1_packet" \
	"$sender_remote/send_stage1_packet" >"$out/push.log" 2>&1 || exit 4
adb_shell "chmod 0755 $sender_remote/send_stage1_packet" || exit 4

: >"$out/ab-runs.tsv"
printf 'phase\tvector\tsubmitted\twindow_start_ns\twindow_end_ns\trc\n' >"$out/ab-runs.tsv"
for phase in off on; do
	adb_shell "echo $([ $phase = on ] && echo 1 || echo 0) > $param_path" || exit 5
	value=$(adb_shell "cat $param_path" | tr -d ' \r\n')
	[ "$value" = "$([ $phase = on ] && echo 1 || echo 0)" ] || \
		{ echo "param readback mismatch" >&2; exit 5; }
	for entry in "${vectors[@]}"; do
		name=${entry%%|*}
		hex=${entry#*|}
		start=$(adb_shell "$sender_remote/send_stage1_packet --clock" | tr -d ' \r\n')
		adb_shell "$sender_remote/send_stage1_packet --send wlan0 $hex" \
			>"$out/send-$phase-$name.log" 2>&1
		rc=$?
		end=$(adb_shell "$sender_remote/send_stage1_packet --clock" | tr -d ' \r\n')
		submitted=0
		[ $rc -eq 0 ] && submitted=1
		printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
			"$phase" "$name" "$submitted" "$start" "$end" "$rc" \
			>>"$out/ab-runs.tsv"
	done
done
adb_shell "echo 0 > $param_path" || true

# Build the schema the owner-aware verifier already consumes, then bind.
python3 - "$out" <<'PY'
import hashlib
import json
import sys
import pathlib

out = pathlib.Path(sys.argv[1])
runs = [line.split("\t") for line in
	(out / "ab-runs.tsv").read_text().splitlines()[1:]]
vectors = {}
for line in (out / "vectors.txt").read_text().splitlines():
	name, hex_text = line.split("|")
	packet = bytes.fromhex(hex_text)
	radiotap_len = packet[2] | (packet[3] << 8)
	vectors[name] = (packet, packet[radiotap_len:])
manifest_path = out / "ab-manifest.jsonl"
results_path = out / "ab-results.jsonl"
with manifest_path.open("w") as manifest, results_path.open("w") as results:
	for phase, name, submitted, start, end, rc in runs:
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

set +e
python3 "$stage1_dir/verify_stage2_ota.py" \
	--manifest "$out/ab-manifest.jsonl" \
	--results "$out/ab-results.jsonl" \
	--capture "$capture" \
	--output "$out/ab-matrix.tsv" >"$out/ab-verify.log" 2>&1
rc=$?
set -e
printf '%s\n' "$rc" >"$out/ab-verify.rc"

python3 - "$out" "$capture" <<'PY'
import json
import pathlib
import struct
import sys

out = pathlib.Path(sys.argv[1])
capture = pathlib.Path(sys.argv[2])
data = capture.read_bytes()
packets = []
offset = 24
while offset + 16 <= len(data):
	seconds, fraction, captured, _ = struct.unpack_from("<IIII", data, offset)
	offset += 16
	packets.append(data[offset:offset + captured])
	offset += captured

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
	align_size = {
		0: (8, 8), 1: (1, 1), 2: (1, 1), 3: (2, 4), 4: (2, 2), 5: (1, 1),
		6: (1, 1), 7: (2, 2), 8: (2, 2), 9: (1, 1), 10: (1, 1),
		11: (2, 2), 12: (2, 2), 13: (1, 1), 14: (2, 2), 15: (2, 2),
		16: (1, 1), 17: (1, 1), 18: (4, 8), 19: (1, 3), 20: (4, 8),
		21: (2, 16), 22: (8, 12), 23: (2, 12), 24: (2, 12), 25: (2, 6),
	}
	phy = "unknown"
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
			if field + size > length:
				return "malformed"
			if index == 2:
				phy = "legacy_%gmbps" % (packet[field] * 0.5)
			elif index == 5 and phy != "unknown":
				phy += "+power%ddbm" % packet[field]
			elif index == 5:
				phy = "power%ddbm" % packet[field]
			elif index == 11 and phy != "unknown":
				phy += "+ant%d" % packet[field]
			elif index == 11:
				phy = "ant%d" % packet[field]
			elif index == 19:
				known, flags, mcs = packet[field:field + 3]
				bw = {0: "20", 1: "40", 2: "40L", 3: "40U"}.get(
					flags & 3, "?")
				phy = "ht_mcs%d_bw%s" % (mcs, bw)
			elif index == 21:
				bandwidth = packet[field + 4]
				nss = packet[field + 5] >> 4
				mcs = packet[field + 5] & 0xF
				bw = {0: "20", 1: "40", 2: "80", 3: "80p80",
					4: "160"}.get(bandwidth, "?")
				phy = "vht_mcs%d_nss%d_bw%s" % (mcs, nss, bw)
			elif index == 23:
				data1 = struct.unpack_from("<H", packet, field)[0]
				data3 = struct.unpack_from("<H", packet, field + 4)[0]
				data6 = struct.unpack_from("<H", packet, field + 10)[0]
				# mcs bits mirror the host-side v7 HE mapping (data3>>8);
				# nsts is reported raw so A/B compares apples to apples.
				phy = "he_fmt%d_mcs%d_nsts%d" % (
					data1 & 3, (data3 >> 8) & 0xF, data6 & 0x1F)
			field += size
	return phy

rows = ["case_id\tsubmitted\tota_state\tobserved_phy"]
verified = {}
for line in (out / "ab-matrix.tsv").read_text().splitlines()[1:]:
	fields = line.split("\t")
	verified[fields[0]] = fields
for line in (out / "ab-runs.tsv").read_text().splitlines()[1:]:
	phase, name, submitted, _, _, rc = line.split("\t")
	case_id = f"ab.{phase}.{name}"
	row = verified.get(case_id)
	ota = "not_submitted"
	phy = ""
	if row:
		ota = "observed" if row[2] != "missing" else "missing"
		if ota == "observed":
			phy = radiotap_phy(packets[int(row[2])])
	rows.append(f"{case_id}\t{submitted}\t{ota}\t{phy}")

# FCS source adjudication (vector fcs_caller_valid): compare the trailing
# four bytes the listener captured against the caller-supplied FCS. The v7
# contract passes the caller FCS through; if FW regenerates it the on-air
# bytes differ. A listener that strips FCS (flag absent) yields
# listener_fcs_absent - undeterminable, recorded as such, never guessed.
for name, entry in vectors.items():
	if name != "fcs_caller_valid":
		continue
	mpdu = entry[1]
	body = mpdu[:-4]
	caller_fcs = mpdu[-4:]
	verdicts = []
	for p in packets:
		radiotap_len = p[2] | (p[3] << 8)
		if p[radiotap_len:radiotap_len + len(body)] != body:
			continue
		tail = p[radiotap_len + len(body):radiotap_len + len(body) + 4]
		if len(tail) < 4:
			verdicts.append("listener_fcs_absent")
		elif tail == caller_fcs:
			verdicts.append("caller_fcs_preserved")
		else:
			verdicts.append("fw_regenerated_fcs")
	summary = ",".join(sorted(set(verdicts))) if verdicts else "no_capture_copy"
	rows.append(f"fcs_source.caller_valid\ton_phase={summary}"
		f"\toff_phase_expect=fw_regenerated_or_absent(legacy_strip)")
(out / "ab-summary.tsv").write_text("\n".join(rows) + "\n")
print((out / "ab-summary.tsv").read_text())
PY

# Restore managed Wi-Fi; a failed restore must be loud, never silent.
adb_shell 'cmd wifi set-wifi-enabled enabled' >/dev/null 2>&1
restored=0
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
[ $restored -eq 1 ] || { echo "WIFI RESTORE FAILED; manual action required" >&2; exit 6; }
(cd "$out" && sha256sum ./* >SHA256SUMS 2>/dev/null)
echo "phy_ab_complete=1 output=$out"
