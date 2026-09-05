#!/system/bin/sh

set -u

expected_build_id=d0f530a77c382b50e6bf298ce9cbf5eb26f6dd30
expected_source_rev=f32230e2fd7f+dirty-20260808-wmi-synthetic-v33-pv1-selftest-contract
expected_selftests=293
suite_frozen=1

usage()
{
	echo "usage: $0 S --clean-boot --selftest-only" >&2
	exit 2
}

[ "$#" -eq 3 ] || usage
[ "$1" = S ] || usage
[ "$2" = --clean-boot ] || usage
[ "$3" = --selftest-only ] || usage

[ "$suite_frozen" -eq 1 ] || {
	echo "WMI synthetic Stage 0 is not frozen for device execution" >&2
	exit 4
}

stamp=$(date -u +%Y%m%dT%H%M%SZ)
out_base=/data/local/tmp/qcacld-wmi-stage0-${expected_build_id%%????????????????????????????????}-read-only-$stamp-$$
out=$out_base
suffix=0
while ! mkdir "$out" 2>/dev/null; do
	suffix=$((suffix + 1))
	[ "$suffix" -lt 100 ] || exit 3
	out=${out_base}-${suffix}
done
echo "OUTPUT_DIR=$out"
exec >"$out/run.log" 2>&1

result_file=$out/result.txt
stats_node=/sys/kernel/debug/wlan0/frame_inject_stats
selftest_node=/sys/kernel/debug/wlan0/frame_inject_selftest
build_id_node=/sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id
force_wmi_node=/sys/module/qca_cld3_peach_v2/parameters/frame_inject_force_wmi
boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)

capture()
{
	file=$1
	shift
	{
		echo "utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
		echo "command=$*"
		"$@"
		rc=$?
		echo
		echo "rc=$rc"
		return "$rc"
	} >"$file" 2>&1
}

value()
{
	awk -F= -v key="$2" '$1 == key { print $2 }' "$1" | tail -n 1
}

fail()
{
	code=$1
	shift
	{
		echo "verdict=FAIL"
		echo "failure_code=$code"
		echo "failure_message=$*"
		echo "boot_id=$boot_id"
		echo "end_boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
	} >"$result_file"
	dmesg >"$out/failure-dmesg.log" 2>&1
	echo "RESULT_DIR=$out"
	exit "$code"
}

validate_idle_stats()
{
	stats=$1
	[ "$(value "$stats" format_version)" = 6 ] || return 1
	[ "$(value "$stats" source_rev)" = "$expected_source_rev" ] || return 2
	[ "$(value "$stats" state)" = ready ] || return 3
	[ "$(value "$stats" fatal_latched)" = 0 ] || return 4
	[ "$(value "$stats" mgmt_inflight)" = 0 ] || return 5
	[ "$(value "$stats" system_suspend_restore)" = 0 ] || return 12
	[ "$(value "$stats" queue_depth)" = 0 ] || return 6
	[ "$(value "$stats" helper_present)" = 0 ] || return 7
	[ "$(value "$stats" helper_context_source)" = none ] || return 11
	[ "$(value "$stats" helper_wma_owner_mask)" = 0x0 ] || return 8
	[ "$(value "$stats" helper_wma_context_ready)" = 0 ] || return 9
	grep -qx 'helper_wma_owner_bits=helper,started,cdp_peer,fw_peer_explicit,fw_peer_implicit,peer_setup,sta_up,bss_peer,assoc,aid,sta_ps_mode,crypto,start_pending,stop_pending,peer_create_pending,peer_delete_pending,bss_create_pending,assoc_pending,events,packet_powersave,sta_context_stop_active,helper_stop_active' "$stats" || return 10
	return 0
}

[ -n "$boot_id" ] || fail 10 "boot ID unavailable"
[ -r "$build_id_node" ] || fail 11 "module build-id note unavailable"
od -An -v -tx1 "$build_id_node" >"$out/module-build-id.log" 2>&1 ||
	fail 12 "could not read module build-id"
build_note=$(tr -d ' \r\n' <"$out/module-build-id.log")
case "$build_note" in
	*"$expected_build_id"*) ;;
	*) fail 13 "loaded module build-id mismatch" ;;
esac

[ -r "$force_wmi_node" ] || fail 14 "WMI gate node unavailable"
[ "$(tr -d ' \r\n' <"$force_wmi_node")" = Y ] ||
	fail 16 "v33 WMI injection gate is not enabled"

capture "$out/iw-info.log" iw dev wlan0 info || fail 18 "iw info failed"
grep -q '^[[:space:]]*type monitor$' "$out/iw-info.log" ||
	fail 19 "wlan0 is not an idle monitor interface"
[ -r "$stats_node" ] || fail 20 "frame_inject_stats unavailable"
[ -r "$selftest_node" ] || fail 21 "frame_inject_selftest unavailable"

cat "$stats_node" >"$out/stats-before.log" 2>&1 ||
	fail 22 "could not read pre-selftest stats"
validate_idle_stats "$out/stats-before.log" ||
	fail 23 "pre-selftest WMI owner state is not idle"
dmesg >"$out/dmesg-before.log" 2>&1

cat "$selftest_node" >"$out/selftest.log" 2>&1 ||
	fail 24 "could not execute frame injection selftest"
grep -qx 'case_wma_owner_ledger=PASS tests=28 failed=0 status=0' "$out/selftest.log" ||
	fail 25 "WMA owner ledger selftest failed"
grep -qx 'case_wma_context_contract=PASS tests=25 failed=0 status=0' "$out/selftest.log" ||
	fail 37 "WMA synthetic context contract selftest failed"
grep -qx 'case_wma_helper_responses=PASS tests=66 failed=0 status=0' "$out/selftest.log" ||
	fail 26 "WMA response/race selftest failed"
grep -qx 'case_wma_target_quiesce=PASS tests=3 failed=0 status=0' "$out/selftest.log" ||
	fail 27 "WMA target-quiesce selftest failed"
grep -qx 'case_wma_teardown_claim=PASS tests=38 failed=0 status=0' "$out/selftest.log" ||
	fail 28 "WMA teardown/race selftest failed"
grep -qx 'case_suspend_state=PASS tests=6 failed=0 ret=0' "$out/selftest.log" ||
	fail 38 "system-suspend state selftest failed"
grep -qx 'case_runtime_state=PASS tests=50 failed=0 ret=0' "$out/selftest.log" ||
	fail 39 "HDD runtime state selftest failed"
grep -qx 'case_pv0_64_class_matrix=PASS' "$out/selftest.log" ||
	fail 40 "PV0 64-class parser matrix failed"
grep -qx 'case_non_pv0_48_class_matrix=PASS' "$out/selftest.log" ||
	fail 41 "non-PV0 parser matrix failed"
grep -qx "tests=$expected_selftests" "$out/selftest.log" ||
	fail 29 "selftest count mismatch"
grep -qx "passed=$expected_selftests" "$out/selftest.log" ||
	fail 30 "selftest pass count mismatch"
grep -qx 'failed=0' "$out/selftest.log" || fail 31 "selftest reported failures"
grep -qx 'verdict=PASS' "$out/selftest.log" || fail 32 "selftest verdict failed"

cat "$stats_node" >"$out/stats-after.log" 2>&1 ||
	fail 33 "could not read post-selftest stats"
validate_idle_stats "$out/stats-after.log" ||
	fail 34 "post-selftest WMI owner state is not idle"
dmesg >"$out/dmesg-after.log" 2>&1

for key in netdev_accepted worker_dequeued wmi_submitted queue_depth \
	mgmt_inflight fw_completion_events fw_completed fw_failed \
	watchdog_timeouts teardown_timeouts unexpected_completions; do
	before=$(value "$out/stats-before.log" "$key")
	after=$(value "$out/stats-after.log" "$key")
	[ -n "$before" ] && [ "$before" = "$after" ] ||
		fail 35 "selftest changed runtime counter $key"
done

end_boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
[ "$end_boot_id" = "$boot_id" ] || fail 36 "boot ID changed during selftest"
{
	echo "verdict=PASS"
	echo "scope=wmi-synthetic-stage0-read-only-selftest"
	echo "build_id=$expected_build_id"
	echo "source_rev=$expected_source_rev"
	echo "selftests=$expected_selftests"
	echo "boot_id=$boot_id"
	echo "end_boot_id=$end_boot_id"
} >"$result_file"
echo "RESULT_DIR=$out"
sha256sum "$out"/*.log "$result_file" >"$out/SHA256SUMS" 2>/dev/null
exit 0
