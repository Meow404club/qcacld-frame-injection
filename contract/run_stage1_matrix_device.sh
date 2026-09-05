#!/system/bin/sh

# Complete Stage 1 parser/backend/completion runner. Local beacon continuity
# is observational here: a missing beacon is retained as evidence for todo
# 4.2, but does not prevent the rest of the Stage 1 matrix from running.
device_execution_enabled=1
expected_schema=2
expected_build_id=914714cb6f296f35f093bf393bfea47c4982897c
expected_source_rev=698efe09e8b8+dirty-20260906-observability-admin-knobs-v21
expected_common_image_sha256=9f7556fc1a9fabb2f48860455e99eb555b8ca955bf79f77c92dc0265fb81ae2c
expected_common_build_id=e5522979c6bb52bee7aabd589cc4c04c9970e9ef
expected_stats_format=13
expected_device_cases=642
expected_plan_sha256=823900054cd3ee6dbce28875f73f28e78fea607de17da3385e78c8871abf263a
expected_sender_sha256=c2795e6b612c065fd464a97251276ad61c0f7a5484bd7d4767fdd882adc10afc
expected_firmware_sha256=f89a5348a4076d4db062eb335ac97b5fb028397bd3d21c96a837fb138503d84e
expected_bdf_sha256=b95a047cda7ab3d23010f7cdc0dd031bc865fbf369191a55df6a44a574d4cccd

terminal_contract()
{
	accepted_delta=$1
	submitted_delta=$2
	parse_delta=$3
	unsupported_delta=$4
	completion_delta=$5
	previous_request=$6
	terminal_request=$7
	terminal_stage=$8
	terminal_errno=$9
	completion_status=${10}

	[ "$accepted_delta" -eq 1 ] &&
		[ "$terminal_request" -gt "$previous_request" ] || return 1
	contract_request_id=$terminal_request
	contract_completion=NA
	case "$parse_delta:$unsupported_delta:$completion_delta:$submitted_delta" in
	1:0:0:0)
		[ "$terminal_stage" -eq 1 ] && [ "$terminal_errno" -lt 0 ] ||
			return 1
		contract_parser_state=rejected
		contract_parser_errno=$terminal_errno
		;;
	0:1:0:0)
		[ "$terminal_stage" -eq 2 ] && [ "$terminal_errno" -lt 0 ] ||
			return 1
		contract_parser_state=accepted
		contract_parser_errno=0
		;;
	0:0:1:1)
		[ "$terminal_stage" -eq 3 ] && [ "$terminal_errno" -eq 0 ] ||
			return 1
		case $completion_status in 0|1|2|3) ;; *) return 1 ;; esac
		contract_parser_state=accepted
		contract_parser_errno=0
		contract_completion=$completion_status
		;;
	*)
		return 1
		;;
	esac
	return 0
}

terminal_contract_selftest()
{
	terminal_contract 1 0 1 0 0 0 1 1 -22 NA || return 1
	[ "$contract_parser_state:$contract_parser_errno:$contract_request_id" = \
		"rejected:-22:1" ] || return 1
	terminal_contract 1 0 0 1 0 1 2 2 -95 NA || return 1
	[ "$contract_parser_state:$contract_parser_errno:$contract_request_id" = \
		"accepted:0:2" ] || return 1
	terminal_contract 1 1 0 0 1 2 3 3 0 3 || return 1
	[ "$contract_parser_state:$contract_completion:$contract_request_id" = \
		"accepted:3:3" ] || return 1
	if terminal_contract 1 1 1 0 1 3 4 3 0 0; then return 1; fi
	if terminal_contract 1 0 1 0 0 4 4 1 -22 NA; then return 1; fi
	if terminal_contract 1 0 1 0 0 4 5 1 0 NA; then return 1; fi
	echo "terminal_contract_selftest=PASS valid=3 invalid=3"
}

usage()
{
	echo "usage: $0 --plan TSV --sender BIN --target-bssid BSSID --authorized-isolated-lab" >&2
	exit 2
}

if [ "${1:-}" = --selftest-terminal-contract ]; then
	[ "$#" -eq 1 ] || usage
	terminal_contract_selftest || exit 1
	exit 0
fi

plan=
sender=
target_bssid=
authorized=0
while [ "$#" -gt 0 ]; do
	case $1 in
	--plan) [ "$#" -ge 2 ] || usage; plan=$2; shift 2 ;;
	--sender) [ "$#" -ge 2 ] || usage; sender=$2; shift 2 ;;
	--target-bssid) [ "$#" -ge 2 ] || usage; target_bssid=$2; shift 2 ;;
	--authorized-isolated-lab) authorized=1; shift ;;
	*) usage ;;
	esac
done

[ "$device_execution_enabled" -eq 1 ] || {
	echo "stage1_matrix_device_execution=DISABLED" >&2
	echo "reason=device_execution_not_authorized" >&2
	exit 64
}
[ "$authorized" -eq 1 ] && [ -r "$plan" ] && [ -x "$sender" ] || usage
[ -n "$target_bssid" ] || usage

# KernelSU setups may hide /sys/kernel/debug in the su mount namespace; fall
# back to any debugfs mount visible here (e.g. a bind view like /dev/sysdebug).
debug_root=/sys/kernel/debug
[ -r "$debug_root/wlan0/frame_inject_stats" ] ||
	debug_root=$(awk '$3 == "debugfs" { print $2; exit }' /proc/mounts)
stats=$debug_root/wlan0/frame_inject_stats
build_note=/sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id
module_path=/vendor_dlkm/lib/modules/qca_cld3_peach_v2.ko
kernel_notes=/sys/kernel/notes
firmware_path=/vendor/firmware_mnt/image/peach/amss20.bin
bdf_path=/odm/etc/wifi/peach/bdwlan.elf
boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
stamp=$(date -u +%Y%m%dT%H%M%SZ)
out=/data/local/tmp/qcacld-stage1-matrix-$stamp-$$
mkdir "$out" || exit 3
echo "OUTPUT_DIR=$out"
exec >"$out/run.log" 2>&1

fail()
{
	code=$1
	shift
	echo "verdict=FAIL" >"$out/result.txt"
	echo "failure_code=$code" >>"$out/result.txt"
	echo "failure=$*" >>"$out/result.txt"
	dmesg >"$out/failure-dmesg.log" 2>&1
	exit "$code"
}

value()
{
	awk -F= -v key="$2" '$1 == key { print $2 }' "$1" | tail -n 1
}

snapshot()
{
	cat "$stats" >"$out/stats-$1.log" 2>&1 || fail 20 "stats $1 unavailable"
	[ "$(value "$out/stats-$1.log" format_version)" = "$expected_stats_format" ] ||
		fail 21 "stats $1 format mismatch"
}

continuity_passed=0
continuity_missing=0
continuity_check()
{
	label=$1
	if "$sender" --capture-bssid wlan0 "$target_bssid" 6 \
		"$out/continuity-$label.pcap" >"$out/continuity-$label.log" 2>&1; then
		status=present
		continuity_passed=$((continuity_passed + 1))
	else
		status=missing
		continuity_missing=$((continuity_missing + 1))
	fi
	printf '%s\t%s\n' "$label" "$status" >>"$out/continuity-results.tsv"
}

wait_terminal()
{
	terminal_before=$1
	i=0
	while [ "$i" -lt 80 ]; do
		snapshot poll
		terminal_now=$(value "$out/stats-poll.log" last_terminal_request_id)
		active_now=$(value "$out/stats-poll.log" active_request_id)
		[ "$terminal_now" -gt "$terminal_before" ] &&
			[ "$active_now" -eq 0 ] && return 0
		sleep 0.25
		i=$((i + 1))
	done
	return 1
}

[ -n "$boot_id" ] && [ -r "$stats" ] && [ -r "$build_note" ] &&
	[ -r "$module_path" ] && [ -r "$kernel_notes" ] || fail 10 "preconditions missing"
plan_sha256=$(sha256sum "$plan" 2>/dev/null | awk '{print $1}')
sender_sha256=$(sha256sum "$sender" 2>/dev/null | awk '{print $1}')
[ "$plan_sha256" = "$expected_plan_sha256" ] || fail 11 "device plan hash mismatch"
[ "$sender_sha256" = "$expected_sender_sha256" ] || fail 11 "sender hash mismatch"
note=$(od -An -v -tx1 "$build_note" | tr -d ' \r\n')
case $note in *"$expected_build_id"*) ;; *) fail 12 "build ID mismatch" ;; esac
# The loaded module is delivered via the Image-embedded overlay; the
# /vendor_dlkm file is only recorded as audit evidence and is NOT gated on,
# because AK3 flashes never rewrite that partition and the file can lag the
# running build while the build note above proves the runtime identity.
module_sha256=$(sha256sum "$module_path" 2>/dev/null | awk '{print $1}')
file_note=$(od -An -v -tx1 "$module_path" 2>/dev/null | tr -d ' \r\n')
case $file_note in
*"$expected_build_id"*) file_matches_loaded=1 ;;
*) file_matches_loaded=0 ;;
esac
common_note=$(od -An -v -tx1 "$kernel_notes" | tr -d ' \r\n')
case $common_note in *"$expected_common_build_id"*) ;; *) fail 12 "common Build ID mismatch" ;; esac
firmware_sha256=$(sha256sum "$firmware_path" 2>/dev/null | awk '{print $1}')
bdf_sha256=$(sha256sum "$bdf_path" 2>/dev/null | awk '{print $1}')
[ "$firmware_sha256" = "$expected_firmware_sha256" ] || fail 12 "firmware hash mismatch"
[ "$bdf_sha256" = "$expected_bdf_sha256" ] || fail 12 "BDF hash mismatch"
{
	echo "module_build_id=$expected_build_id"
	echo "module_path=$module_path"
	echo "module_sha256=$module_sha256"
	echo "module_file_matches_loaded=$file_matches_loaded"
	echo "common_image_sha256=$expected_common_image_sha256"
	echo "common_build_id=$expected_common_build_id"
	echo "source_rev=$expected_source_rev"
	echo "device_plan_sha256=$plan_sha256"
	echo "sender_sha256=$sender_sha256"
	echo "firmware_path=$firmware_path"
	echo "firmware_sha256=$firmware_sha256"
	echo "bdf_path=$bdf_path"
	echo "bdf_sha256=$bdf_sha256"
} >"$out/runtime-identity.txt"
iw dev wlan0 info >"$out/iw-before.log" 2>&1 || fail 13 "iw failed"
grep -q '^[[:space:]]*type monitor$' "$out/iw-before.log" || fail 14 "not monitor"
snapshot initial
[ "$(value "$out/stats-initial.log" source_rev)" = "$expected_source_rev" ] || fail 15 "source revision mismatch"
dmesg >"$out/dmesg-before.log" 2>&1
before_dmesg_ts=$(sed -n 's/^\[[[:space:]]*\([0-9][0-9.]*\)\].*/\1/p' "$out/dmesg-before.log" | tail -n 1)
printf 'case_id\tcase_cookie\tpacket_sha256\toperation\tparser_state\tparser_errno\tprevious_request_id\trequest_id\tterminal_stage\tterminal_errno\taccepted_delta\tsubmitted_delta\tparse_delta\tbackend_delta\tcompletion_delta\tcompletion_status\twindow_start_ns\twindow_end_ns\n' >"$out/device-results.tsv"
printf 'window\tstatus\n' >"$out/continuity-results.tsv"

sed '1d' "$plan" >"$out/eligible.tsv" || fail 16 "device plan decode failed"
[ "$(wc -l <"$out/eligible.tsv")" -eq "$expected_device_cases" ] ||
	fail 16 "device plan case count mismatch"
continuity_check before

case_number=0

while IFS="	" read -r case_id cookie packet_sha operation expected_state expected_errno packet_hex; do
	case_number=$((case_number + 1))
	snapshot before
	accepted_before=$(value "$out/stats-before.log" netdev_accepted)
	submitted_before=$(value "$out/stats-before.log" wmi_submitted)
	completed_before=$(value "$out/stats-before.log" fw_completion_events)
	unsupported_before=$(value "$out/stats-before.log" backend_unsupported)
	parse_before=$(value "$out/stats-before.log" parse_failed)
	previous_request=$(value "$out/stats-before.log" last_terminal_request_id)
	window_start=$("$sender" --clock) || fail 29 "$case_id wallclock failed"
	"$sender" --send wlan0 "$packet_hex" >"$out/send-$cookie.log" 2>&1 || fail 30 "$case_id sendto failed"
	wait_terminal "$previous_request" || fail 31 "$case_id terminal timeout"
	window_end=$("$sender" --clock) || fail 29 "$case_id wallclock failed"
	snapshot after
	accepted_after=$(value "$out/stats-after.log" netdev_accepted)
	submitted_after=$(value "$out/stats-after.log" wmi_submitted)
	completed_after=$(value "$out/stats-after.log" fw_completion_events)
	unsupported_after=$(value "$out/stats-after.log" backend_unsupported)
	parse_after=$(value "$out/stats-after.log" parse_failed)
	request_id=$(value "$out/stats-after.log" last_terminal_request_id)
	terminal_stage=$(value "$out/stats-after.log" last_terminal_stage)
	terminal_errno=$(value "$out/stats-after.log" last_terminal_errno)
	completion_status=$(value "$out/stats-after.log" last_completion_status)
	accepted_delta=$((accepted_after - accepted_before))
	submitted_delta=$((submitted_after - submitted_before))
	parse_delta=$((parse_after - parse_before))
	backend_delta=$((unsupported_after - unsupported_before))
	completion_delta=$((completed_after - completed_before))
	terminal_contract "$accepted_delta" "$submitted_delta" "$parse_delta" \
		"$backend_delta" "$completion_delta" "$previous_request" \
		"$request_id" "$terminal_stage" "$terminal_errno" \
		"$completion_status" || fail 32 "$case_id ambiguous terminal state"
	parser_state=$contract_parser_state
	parser_errno=$contract_parser_errno
	completion=$contract_completion
	[ "$parser_state" = "$expected_state" ] || fail 33 "$case_id parser contract mismatch"
	[ "$parser_errno" = "$expected_errno" ] || fail 33 "$case_id parser errno mismatch"
	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
		"$case_id" "$cookie" "$packet_sha" "$operation" \
		"$parser_state" "$parser_errno" "$previous_request" \
		"$request_id" "$terminal_stage" "$terminal_errno" \
		"$accepted_delta" "$submitted_delta" "$parse_delta" \
		"$backend_delta" "$completion_delta" "$completion" \
		"$window_start" "$window_end" >>"$out/device-results.tsv"
	if [ $((case_number % 100)) -eq 0 ]; then
		continuity_check "$case_number"
	fi
done <"$out/eligible.tsv"

continuity_check after
snapshot final
for key in fatal_latched mgmt_inflight queue_depth watchdog_timeouts \
	teardown_timeouts; do
	value_final=$(value "$out/stats-final.log" "$key")
	case $key in
	fatal_latched|mgmt_inflight|queue_depth)
		[ "$value_final" -eq 0 ] || fail 36 "dirty final state $key=$value_final"
		;;
	*)
		value_initial=$(value "$out/stats-initial.log" "$key")
		[ "$value_final" = "$value_initial" ] || fail 36 "terminal error counter changed $key"
		;;
	esac
done
{
	echo "state=active_persona_clean"
	echo "helper_present=$(value "$out/stats-final.log" helper_present)"
	echo "helper_wma_owner_mask=$(value "$out/stats-final.log" helper_wma_owner_mask)"
	echo "note=final owner-zero teardown is collected after the monitor persona is stopped"
} >"$out/active-persona-final-state.txt"

[ "$(cat /proc/sys/kernel/random/boot_id)" = "$boot_id" ] || fail 40 "boot ID changed"
dmesg >"$out/dmesg-after.log" 2>&1
sed -n "s/^\[[[:space:]]*\([0-9][0-9.]*\)\].*/\1 &/p" "$out/dmesg-after.log" |
	awk -v baseline="$before_dmesg_ts" '($1 + 0) > (baseline + 0) { $1=""; sub(/^ /,""); print }' >"$out/dmesg-new.log"
grep -Eiq 'CFI: Fatal|Kernel panic|wlan crashed|cnss_recovery_handler|SMMU.*(^|[^[:alnum:]_])fault([^[:alnum:]_]|$)|firmware.*(^|[^[:alnum:]_])assert([^[:alnum:]_]|$)' \
	"$out/dmesg-new.log" && fail 41 "new fatal signature observed"
echo "verdict=PASS" >"$out/result.txt"
echo "scope=stage1-schema-$expected_schema" >>"$out/result.txt"
echo "boot_id=$boot_id" >>"$out/result.txt"
echo "device_cases=$case_number" >>"$out/result.txt"
echo "continuity_windows=$((continuity_passed + continuity_missing))" >>"$out/result.txt"
echo "continuity_present=$continuity_passed" >>"$out/result.txt"
echo "continuity_missing=$continuity_missing" >>"$out/result.txt"
if [ "$continuity_missing" -eq 0 ]; then
	echo "continuity_verdict=PASS" >>"$out/result.txt"
else
	echo "continuity_verdict=KNOWN_ISSUE_TODO_4_2" >>"$out/result.txt"
fi
sha256sum "$out"/* >"$out/SHA256SUMS" 2>/dev/null
exit 0
