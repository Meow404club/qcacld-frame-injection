#!/usr/bin/env bash
# kit v9 local dry-run (the v8 lesson: never ship a ported script that has
# not been executed end to end).
#
# Runs the rewritten run_stage2_phy_ab.sh four times against the mock adb
# (full main set / offchannel set / contract-violation injection / setup
# failure + EXIT-trap path), plus:
#   - verify_stage2_ota.py selftest (window-over-exactness case)
#   - verify_stage2_ota.py on the v8 return P3 real inputs (zero-packet
#     capture -> clean UNPROVEN, no crash)
#   - verify_stage2_capture.py on the v8 return P1 real inputs
#     (66/67 owner-aware UNPROVEN reproduction)
#   - bash -n on every kit shell script

set -uo pipefail

dryrun_root=$(cd -- "$(dirname -- "$0")" && pwd)
kit=$dryrun_root/../kit
returns=${FI_RETURNS_DIR:-$dryrun_root/returns}
work=$dryrun_root/work
rm -rf "$work"
mkdir -p "$work"

pass=0
fail=0
check() { # name condition-description rc-style
	if eval "$2"; then
		echo "PASS $1"
		pass=$((pass + 1))
	else
		echo "FAIL $1 -- $2"
		fail=$((fail + 1))
	fi
}

# ---- vector classification table for the mock (name<TAB>hex<TAB>class) ----
build_table() { # offchannel-target ('' = main set only)
	local target=$1 tmp block name hex
	tmp=$work/vector-class-table
	: >"$tmp"
	block=$(sed -n '/^vectors=(/,/^)$/p' "$kit/run_stage2_phy_ab.sh")
	while IFS= read -r line; do
		name=${line%%|*}
		hex=${line#*|}
		case $name in
		vht80_nss1_mcs3|vht160_nss2_mcs8|he_su_mcs7)
			class=fw_width ;;
		ht_mcs*|vht*|he_su*|antenna_*|pwr*)
			class=knob_family ;;
		neg_*)
			class=negative ;;
		*)
			class=unconditional ;;
		esac
		printf '%s\t%s\t%s\n' "$name" "$hex" "$class" >>"$tmp"
	done < <(grep -o '"[a-z0-9_]*|[0-9a-f]*"' <<<"$block" | tr -d '"')
	if [ -n "$target" ]; then
		case $target in
		24[1-9][0-9]) flags=a000 ;;
		*) flags=4001 ;;
		esac
		freq_hex=$(printf '%02x%02x' $((target & 255)) $(((target >> 8) & 255)))
		hdr="00000c0008000000${freq_hex}${flags}"
		printf 'oc_probe_a\t%s4000452302112233445502abcd00002102a1a2a3a4a51000\tunconditional\n' "$hdr" >>"$tmp"
		printf 'oc_probe_b\t%s4000452302112233445502abcd00002202a1a2a3a4a51000\tunconditional\n' "$hdr" >>"$tmp"
	fi
	echo "$tmp"
}

init_pcap() { # path -- classic pcap global header, DLT 127
	printf '\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x7f\x00\x00\x00' >"$1"
}

fresh_mock() { # mock-root offchannel-target
	rm -rf "$1"
	mkdir -p "$1"
	cp "$(build_table "$2")" "$1/vector-class-table"
}

# kit v11e: fw_width class vectors (vht80/vht160/he80) ride the v19b
# bypass in the on phase (accept + fw_width_bypassed=3 after case A,
# drop_reason_fw_width stays 0); off-phase knob rejects bump backend:
# 8 knob-family off + 3 fw_width off + 2 negatives x2 phases = 15.

# kit integrity gate must pass with current files
(cd "$kit" && sha256sum -c SHA256SUMS) >/dev/null 2>&1 || {
	echo "kit SHA256SUMS out of date; regenerate first" >&2
	exit 1
}

run_phy_ab() { # mock-root pcap extra-args...
	local mock_root=$1 pcap=$2
	shift 2
	MOCK_ROOT=$mock_root MOCK_CAPTURE=$pcap PATH="$dryrun_root/mock-bin:$PATH" \
		"$kit/run_stage2_phy_ab.sh" --capture "$pcap" --frequency 5745 \
		--channel-width 20 --authorized-isolated-lab "$@"
}

# ---------- vector table sanity ----------
# Catches the vector-defect classes found by the 2026-09-04 scan: truncated
# MPDUs (missing seq-ctl), power in DBM_ANTSIGNAL instead of DBM_TX_POWER,
# non-spec VHT bandwidth values, and negatives whose known/flags do not
# carry the negative condition.
echo '=== vector table sanity ==='
python3 - "$kit/run_stage2_phy_ab.sh" >"$work/vectors.out" 2>&1 <<'PY'
import pathlib
import re
import struct
import sys

text = pathlib.Path(sys.argv[1]).read_text()
block = re.search(r"^vectors=\((.*?)^$", text, re.S | re.M).group(1)
bad = 0
count = 0
for match in re.finditer(r'"([a-z0-9_]+)\|([0-9a-fA-F]*)"', block):
    count += 1
    name, hex_text = match.groups()
    why = []
    if len(hex_text) % 2:
        why.append("odd hex length")
    else:
        packet = bytes.fromhex(hex_text)
        it_len = packet[2] | (packet[3] << 8)
        if packet[0] != 0 or it_len < 8 or it_len > len(packet):
            why.append("bad radiotap bounds")
        else:
            mpdu = packet[it_len:]
            fc = mpdu[0] | (mpdu[1] << 8)
            ftype, subtype = (fc >> 2) & 3, (fc >> 4) & 15
            has_fcs = False
            if it_len >= 9:
                present = int.from_bytes(packet[4:8], "little")
                # flags at bit 1, single-word headers only in this set
                if present & (1 << 1):
                    has_fcs = bool(packet[8] & 0x10)
            hdrlen = 24 if (ftype in (0, 2) and (fc & 0x0300) != 3) else \
                30 if ftype in (0, 2) else 10
            want = hdrlen + (4 if has_fcs else 0)
            if len(mpdu) < want:
                why.append(f"mpdu {len(mpdu)} < {want} (fc={fc:#06x})")
            if name.startswith("ht_"):
                present = int.from_bytes(packet[4:8], "little")
                if present != 1 << 19:
                    why.append("not MCS field")
                else:
                    known = packet[8]
                    if not known & 0x02:
                        why.append("MCS known lacks HAVE_MCS")
            elif name.startswith("vht") or name == "neg_vht_sgi":
                present = int.from_bytes(packet[4:8], "little")
                if present != 1 << 21:
                    why.append("not VHT field")
                else:
                    if it_len < 20:
                        why.append(f"VHT field truncated (it_len {it_len} < 20)")
                    bw = packet[8 + 3]  # spec layout (v20): flags u8@+2, bw u8@+3
                    if bw not in (0, 1, 4, 11):
                        why.append(f"VHT bw {bw} not spec (0/1/4/11)")
            elif name.startswith("he_") or name == "he_mcs7":
                present = int.from_bytes(packet[4:8], "little")
                if present & (1 << 23) and it_len < 20:
                    why.append(f"HE field truncated (it_len {it_len} < 20)")
            elif name.startswith("pwr"):
                present = int.from_bytes(packet[4:8], "little")
                if not present & (1 << 10):
                    why.append("power not DBM_TX_POWER bit10")
                if present & (1 << 5):
                    why.append("uses DBM_ANTSIGNAL bit5")
            elif name == "neg_mcs_stbc":
                known, flags = packet[8], packet[9]
                if not (known & 0x20 and (flags & 0x60) >> 5):
                    why.append("STBC condition not asserted")
    if why:
        print(f"{name}: {'; '.join(why)}")
        bad += 1
print(f"vectors_checked={count} bad={bad}")
sys.exit(1 if bad else 0)
PY
vectors_rc=$?
check vectors.sane '[ "$vectors_rc" -eq 0 ] && grep -q "vectors_checked=16 bad=0" "$work/vectors.out"'

# ---------- case A: full main set, happy path ----------
echo '=== case A: main set happy path ==='
mock=$work/mock-a
pcap=$work/listener-a.pcap
fresh_mock "$mock" ''
init_pcap "$pcap"
stdout=$work/a.stdout
run_phy_ab "$mock" "$pcap" >"$stdout" 2>"$work/a.stderr"
rc=$?
echo "case A rc=$rc"
out_a=$(sed -n 's/^PHY_AB_OUTPUT_DIR=//p' "$stdout" | head -n1)
check A.exit0 '[ $rc -eq 0 ]'
check A.contract0 'grep -q "^contract_failures=0$" "$stdout"'
check A.verdict_pass 'grep -q "^ota_verdict=PASS$" "$stdout"'
check A.complete 'grep -q "^phy_ab_complete=1" "$stdout"'
check A.runs32 '[ "$(wc -l <"$out_a/ab-runs.tsv")" -eq 33 ]'
check A.vectors16 '[ "$(wc -l <"$out_a/vectors.txt")" -eq 16 ]'
check A.accept_rows 'awk -F"\t" "NR>1 && \$3==\"accept\" && \$4!=1 {bad=1} END {exit bad+0}" "$out_a/ab-runs.tsv"'
check A.reject_rows 'awk -F"\t" "NR>1 && \$3==\"reject\" && \$4!=0 {bad=1} END {exit bad+0}" "$out_a/ab-runs.tsv"'
check A.rejections_have_drops 'awk -F"\t" "NR>1 && \$3==\"reject\" && \$7<1 {bad=1} END {exit bad+0}" "$out_a/ab-runs.tsv"'
check A.offphase_phy_rejected 'awk -F"\t" "NR>1 && \$1==\"off\" && (\$2 ~ /^(ht_|vht|he_|antenna_|pwr)/) && \$3!=\"reject\" {bad=1} END {exit bad+0}" "$out_a/ab-runs.tsv"'
check A.fwwidth_off_rejected 'awk -F"\t" "NR>1 && \$1==\"off\" && (\$2 ~ /^(vht80_nss1_mcs3|vht160_nss2_mcs8|he_su_mcs7)$/) && \$3!=\"reject\" {bad=1} END {exit bad+0}" "$out_a/ab-runs.tsv"'
check A.fwwidth_gate_evidence '[ "$(cat "$mock/drop_reason_fw_width")" -eq 0 ] && [ "$(cat "$mock/fw_width_bypassed")" -eq 3 ]'
check A.fwwidth_knob_untouched '[ "$(cat "$mock/drop_reason_backend")" -eq 15 ]'
check A.stats_snaps '[ -f "$out_a/stats-off-start.txt" ] && [ -f "$out_a/stats-on-end.txt" ]'
check A.context_recorded 'grep -q "helper_context_source=constructed" "$out_a/stats-on-start.txt"'
check A.fcs_lines 'grep -qP "^fcs_source\.off_phase=caller_fcs_preserved\t" "$out_a/ab-summary.tsv" && grep -qP "^fcs_source\.on_phase=caller_fcs_preserved\t" "$out_a/ab-summary.tsv"'
check A.sum_no_self '! grep -q " SHA256SUMS$" "$out_a/SHA256SUMS"'
check A.wifi_restored '[ "$(cat "$mock/wifi")" = enabled ]'
check A.pcap_grew '[ "$(stat -c %s "$pcap")" -gt 24 ]'
check A.verifier_rc0 '[ "$(cat "$out_a/ab-verify.rc")" = 0 ]'

# ---------- case B: offchannel set ----------
echo '=== case B: offchannel set ==='
mock=$work/mock-b
pcap=$work/listener-b.pcap
fresh_mock "$mock" 2412
init_pcap "$pcap"
stdout=$work/b.stdout
run_phy_ab "$mock" "$pcap" --vector-set offchannel --offchannel-target 2412 \
	>"$stdout" 2>"$work/b.stderr"
rc=$?
echo "case B rc=$rc"
out_b=$(sed -n 's/^PHY_AB_OUTPUT_DIR=//p' "$stdout" | head -n1)
check B.exit0 '[ $rc -eq 0 ]'
check B.contract0 'grep -q "^contract_failures=0$" "$stdout"'
check B.runs4 '[ "$(wc -l <"$out_b/ab-runs.tsv")" -eq 5 ]'
check B.all_accept 'awk -F"\t" "NR>1 && \$4!=1 {bad=1} END {exit bad+0}" "$out_b/ab-runs.tsv"'
check B.verdict_pass 'grep -q "^ota_verdict=PASS$" "$stdout"'

# ---------- case C: contract-violation injection ----------
echo '=== case C: contract violation ==='
mock=$work/mock-c
pcap=$work/listener-c.pcap
fresh_mock "$mock" ''
init_pcap "$pcap"
fcs_hex=$(awk -F'\t' '$1 == "fcs_caller_valid" {print $2}' "$mock/vector-class-table")
stdout=$work/c.stdout
MOCK_INVERT_HEX=$fcs_hex \
	run_phy_ab "$mock" "$pcap" >"$stdout" 2>"$work/c.stderr"
rc=$?
echo "case C rc=$rc"
out_c=$(sed -n 's/^PHY_AB_OUTPUT_DIR=//p' "$stdout" | head -n1)
check C.exit7 '[ $rc -eq 7 ]'
check C.violations 'grep -q "^CONTRACT_VIOLATION phase=off vector=fcs_caller_valid" "$stdout"'
check C.count2 'grep -q "^contract_failures=2$" "$stdout"'
check C.restore_despite_fail '[ "$(cat "$mock/wifi")" = enabled ]'
check C.sum_written '[ -f "$out_c/SHA256SUMS" ]'

# ---------- case D: setup failure + EXIT trap ----------
echo '=== case D: setup failure / trap ==='
mock=$work/mock-d
pcap=$work/listener-d.pcap
fresh_mock "$mock" ''
init_pcap "$pcap"
stdout=$work/d.stdout
MOCK_FAIL_SETUP=1 \
	run_phy_ab "$mock" "$pcap" >"$stdout" 2>"$work/d.stderr"
rc=$?
echo "case D rc=$rc"
check D.exit4 '[ $rc -eq 4 ]'
check D.emergency_ran 'grep -q "EMERGENCY_CLEANUP_RAN=1" "$work/d.stderr"'
check D.trap_restored '[ "$(cat "$mock/wifi")" = enabled ]'
check D.trap_managed '[ "$(cat "$mock/iface")" = managed ]'

# ---------- verifier selftest (incl. window-over-exactness) ----------
echo '=== verifier selftest ==='
python3 - "$work" <<'PY'
import json
import pathlib
import sys

work = pathlib.Path(sys.argv[1])
records = []
for index in range(3):
    body = bytes([0x40, 0x00, 0x2e, 0x00]) + b"\xff" * 6 + \
        bytes([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x10 + index]) + b"\xff" * 12 + \
        b"\x01\x02\x03\x04\x05"
    records.append({
        "case_id": f"dryrun.{index}",
        "case_cookie": f"dryrun.{index}",
        "mpdu_hex": body.hex(),
        "packet_sha256": "0" * 64,
        "operation": "send_after_continuity_fix",
    })
(work / "selftest-manifest.jsonl").write_text(
    "".join(json.dumps(record) + "\n" for record in records))
PY
selftest_out=$work/selftest.out
python3 "$kit/verify_stage2_ota.py" --selftest \
	--manifest "$work/selftest-manifest.jsonl" >"$selftest_out" 2>&1
check V.selftest 'grep -q "stage2_ota_selftest=PASS.*window_over_exact=1" "$selftest_out"'

# ---------- ota verifier on v8 P3 real inputs (zero-packet capture) ----------
# The v8 author-side return bundle is external-round evidence (kept out of
# the open repo); these regressions run when FI_RETURNS_DIR provides it and
# SKIP portably otherwise.
echo '=== ota verifier P3 real-input regression ==='
v8=$returns/v8-audit/qcacld-stage2-ota-kit-v12-full-v8-20260904-author-bundle
if [ -d "$v8/host-run" ]; then
	p3=$work/p3-ota.out
	python3 "$kit/verify_stage2_ota.py" \
		--manifest "$v8/host-run/p3-offline-adjudication/ab-manifest.jsonl" \
		--results "$v8/host-run/p3-offline-adjudication/ab-results.jsonl" \
		--capture "$v8/host-run/listener-p3-phy-main/ota-capture.pcap" \
		--output "$work/p3-matrix.tsv" >"$p3" 2>&1
	rc=$?
	check V.p3_unproven '[ $rc -eq 1 ] && grep -q "^ota_verdict=UNPROVEN$" "$p3"'
else
	echo "SKIP V.p3_unproven (v8 return bundle not present; set FI_RETURNS_DIR)"
fi

# ---------- capture verifier on v8 P1 real inputs (66/67 reproduction) ----------
echo '=== capture verifier P1 real-input regression ==='
if [ -d "$v8/sender-evidence" ]; then
	token=$(awk -F'\t' 'NR==2 {print $NF}' \
		"$v8/sender-evidence/P1-main/device-output/send-manifest.tsv" | tr -d '\r')
	p1=$work/p1-capture.out
	python3 "$kit/verify_stage2_capture.py" \
		--capture "$v8/host-run/listener-p1/ota-capture.pcap" \
		--sender-output "$v8/sender-evidence/P1-main/device-output" \
		--listener-token "$token" \
		--matrix-out "$work/p1-matrix.tsv" >"$p1" 2>&1
	rc=$?
	check V.p1_66of67 '[ $rc -eq 1 ] && grep -q "owner_aware_ordered_frames=66 " "$p1" && grep -q "missing_owner_aware_frames=1 " "$p1"'
else
	echo "SKIP V.p1_66of67 (v8 return bundle not present; set FI_RETURNS_DIR)"
fi

# ---------- kit v11: decryptor + new sessions ----------
echo '=== kit v11: decrypt_ccmp_pmf + new sessions ==='
dec=$work/decrypt-selftest.out
python3 "$kit/decrypt_ccmp_pmf.py" --selftest >"$dec" 2>&1
check D.selftest 'grep -q "selftest.roundtrip_mic=PASS" "$dec" && grep -q "selftest.tamper_rejected=PASS" "$dec" && grep -q "selftest.wrong_key_rejected=PASS" "$dec"'

# decryptor end-to-end on a synthetic capture: known key proves, wrong
# key fails (built with the decryptor's own encryptor).
decpcap=$work/decrypt-leg.pcap
python3 - "$kit/decrypt_ccmp_pmf.py" "$decpcap" >"$work/decrypt-build.out" 2>&1 <<'PY'
import importlib.util, struct, sys
spec = importlib.util.spec_from_file_location("m", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
key = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
hdr = (struct.pack("<HH", 0x00C0 | 0x0400, 0x0134) + bytes.fromhex("021122334455") +
       bytes.fromhex("02abcd0000f1") + bytes.fromhex("021122334455") +
       struct.pack("<H", 0x0021))
body = struct.pack("<H", 6)
frame = hdr + m.ccmp_encrypt(key, hdr, bytes([9, 8, 7, 6, 5, 4]), body)
pkt = struct.pack("<BBHI", 0, 0, 8, 0) + frame
with open(sys.argv[2], "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 127))
    f.write(struct.pack("<IIII", 0, 0, len(pkt), len(pkt)))
    f.write(pkt)
PY
check D.synthetic_build '[ -s "$decpcap" ]'
python3 "$kit/decrypt_ccmp_pmf.py" "$decpcap" 0f1e2d3c4b5a69788796a5b4c3d2e1f0 --ta 02:ab:cd:00:00:f1 >"$work/decrypt-leg.out" 2>&1
check D.known_key_proven 'grep -q "^verdict=FW_LOCAL_CCMP_PROVEN_WITH_KNOWN_KEY$" "$work/decrypt-leg.out"'
python3 "$kit/decrypt_ccmp_pmf.py" "$decpcap" 112233445566778899aabbccddeeff00 >"$work/decrypt-wrongkey.out" 2>&1
check D.wrong_key_fails 'grep -q "MIC_FAILED_ALL" "$work/decrypt-wrongkey.out"'

# arg gates must refuse before touching any device
"$kit/run_stage2_ccmp_pmf.sh" >"$work/ccmp-noauth.out" 2>&1
check C.noauth '[ $? -eq 2 ]'
"$kit/run_stage2_ccmp_pmf.sh" --authorized-isolated-lab --key 00112233445566778899aabbccddeef >"$work/ccmp-badkey.out" 2>&1
check C.badkey '[ $? -eq 2 ]'
"$kit/run_stage2_peer_rate_ota.sh" >"$work/pr-noauth.out" 2>&1
check P.noauth '[ $? -eq 2 ]'

# extract every shipped python vector builder from the two new sessions
# and decode-assert its output (it_len / presence / tx_flags value /
# protected FC) - this runs the exact shipped code, not a copy.
vcheck=$work/v11-vectors.out
: >"$vcheck"
for script in run_stage2_ccmp_pmf.sh run_stage2_peer_rate_ota.sh; do
	for marker in WARMUP_HEX PROTECTED_HEX FWDEFAULT_HEX; do
		block=$(sed -n "/^${marker}=\$(python3 - <<'PY'/,/^PY$/p" "$kit/$script" |
			sed '1d;$d')
		[ -n "$block" ] || continue
		hex=$(python3 -c "$block") || { echo "$script.$marker BUILD_FAIL" >>"$vcheck"; continue; }
		echo "$script.$marker $hex" >>"$vcheck"
		python3 - "$hex" >>"$vcheck" 2>&1 <<'PY' || true
import sys
pkt = bytes.fromhex(sys.argv[1])
it_len = pkt[2] | (pkt[3] << 8)
present = int.from_bytes(pkt[4:8], "little")
assert it_len == len(pkt) - 26, "radiotap/mpdu bounds"
mpdu = pkt[it_len:]
fc = mpdu[0] | (mpdu[1] << 8)
if present == 1 << 15:  # TX_FLAGS-only vectors
    tx = mpdu and (pkt[8] | (pkt[9] << 8))
    assert tx in (0x0800, 0x8000), hex(tx)
    if tx == 0x0800:
        assert fc & 0x0400, "protected bit missing"
    else:
        assert not fc & 0x0400
elif present == 1 << 2:  # RATE-only vectors
    assert pkt[8] in (12, 2), hex(pkt[8])
print("vector_decode_ok")
PY
	done
done
vbad=$(grep -c -v -e 'vector_decode_ok' -e '^run_stage2' "$vcheck" || true)
vbuilt=$(grep -c 'BUILD_FAIL' "$vcheck" || true)
vok=$(grep -c 'vector_decode_ok' "$vcheck" || true)
check N.v11_vectors '[ "$vbad" -eq 0 ] && [ "$vbuilt" -eq 0 ] && [ "$vok" -ge 3 ]'

# ---------- kit binaries must be Android ARM (the v11a round shipped an
# x86-64 host build and the mock adb - which intercepts sender calls -
# never executed it; five phases died with "not executable") ----------
echo '=== kit binary architecture ==='
for bin in send_stage1_packet send_frame_matrix send_frame_matrix.host; do
	case "$bin" in
	send_frame_matrix.host) want='x86-64' ;;
	*) want='ARM aarch64' ;;
	esac
	check "arch.$bin" "file \"$kit/$bin\" | grep -q '$want'"
done

# ---------- bash -n every kit shell script ----------
echo '=== syntax pass ==='
for script in "$kit"/*.sh; do
	check "syntax.$(basename "$script")" "bash -n \"$script\""
done

echo
echo "dryrun_summary pass=$pass fail=$fail"
[ "$fail" -eq 0 ] || exit 1
exit 0
