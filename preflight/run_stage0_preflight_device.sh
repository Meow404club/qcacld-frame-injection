#!/system/bin/sh

# Zero-TX preflight for the current format-v12 terminal-ledger (superseded headers updated 2026-09-06).
# Build identity is intentionally pinned to the locally compiled candidate;
# flashing/rebooting and execution remain operator-only.
set -u

expected_build_id=914714cb6f296f35f093bf393bfea47c4982897c
expected_source_rev=698efe09e8b8+dirty-20260906-observability-admin-knobs-v21
expected_stats_format=13
expected_selftests=409
expected_firmware_sha256=f89a5348a4076d4db062eb335ac97b5fb028397bd3d21c96a837fb138503d84e
expected_bdf_sha256=b95a047cda7ab3d23010f7cdc0dd031bc865fbf369191a55df6a44a574d4cccd
device_execution_enabled=1

usage()
{
	echo "usage: $0 S --clean-boot --selftest-only" >&2
	exit 2
}

[ "$#" -eq 3 ] || usage
[ "$1" = S ] && [ "$2" = --clean-boot ] &&
	[ "$3" = --selftest-only ] || usage
[ "$device_execution_enabled" -eq 1 ] || {
	echo "stage0_preflight_device_execution=DISABLED" >&2
	echo "reason=candidate_not_packaged_or_authorized_for_device" >&2
	exit 64
}

# KernelSU setups may hide /sys/kernel/debug in the su mount namespace; fall
# back to any debugfs mount visible here (e.g. a bind view like /dev/sysdebug).
debug_root=/sys/kernel/debug
[ -r "$debug_root/wlan0/frame_inject_stats" ] ||
	debug_root=$(awk '$3 == "debugfs" { print $2; exit }' /proc/mounts)
stats=$debug_root/wlan0/frame_inject_stats
selftest=$debug_root/wlan0/frame_inject_selftest
build_note=/sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id
firmware_path=/vendor/firmware_mnt/image/peach/amss20.bin
bdf_path=/odm/etc/wifi/peach/bdwlan.elf
boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
stamp=$(date -u +%Y%m%dT%H%M%SZ)
out=/data/local/tmp/qcacld-stage0-preflight-$stamp-$$
mkdir "$out" || exit 3
echo "OUTPUT_DIR=$out"
exec >"$out/run.log" 2>&1

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
		echo "failure=$*"
		echo "boot_id=$boot_id"
		echo "end_boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
	} >"$out/result.txt"
	dmesg >"$out/failure-dmesg.log" 2>&1
	exit "$code"
}

validate_idle()
{
	file=$1
	[ "$(value "$file" format_version)" = "$expected_stats_format" ] &&
	[ "$(value "$file" source_rev)" = "$expected_source_rev" ] &&
	[ "$(value "$file" state)" = ready ] &&
	[ "$(value "$file" fatal_latched)" -eq 0 ] &&
	[ "$(value "$file" mgmt_inflight)" -eq 0 ] &&
	[ "$(value "$file" queue_depth)" -eq 0 ] &&
	[ "$(value "$file" helper_present)" -eq 0 ] &&
	[ "$(value "$file" helper_wma_owner_mask)" = 0x0 ] &&
	[ "$(value "$file" active_request_id)" -eq 0 ] &&
	[ "$(value "$file" last_terminal_request_id)" -eq 0 ] &&
	[ "$(value "$file" last_terminal_stage)" -eq 0 ] &&
	[ "$(value "$file" last_terminal_errno)" -eq 0 ]
}

[ -n "$boot_id" ] && [ -r "$stats" ] && [ -r "$selftest" ] &&
	[ -r "$build_note" ] || fail 10 "preconditions missing"
note=$(od -An -v -tx1 "$build_note" | tr -d ' \r\n')
case $note in *"$expected_build_id"*) ;; *) fail 11 "build ID mismatch" ;; esac
firmware_sha256=$(sha256sum "$firmware_path" 2>/dev/null | awk '{print $1}')
bdf_sha256=$(sha256sum "$bdf_path" 2>/dev/null | awk '{print $1}')
[ "$firmware_sha256" = "$expected_firmware_sha256" ] || fail 12 "firmware hash mismatch"
[ "$bdf_sha256" = "$expected_bdf_sha256" ] || fail 13 "BDF hash mismatch"
iw dev wlan0 info >"$out/iw-before.log" 2>&1 || fail 14 "iw failed"
grep -q '^[[:space:]]*type monitor$' "$out/iw-before.log" || fail 15 "not monitor"
cat "$stats" >"$out/stats-before.log" || fail 16 "stats unavailable"
validate_idle "$out/stats-before.log" || fail 17 "pre-selftest state is not idle"
dmesg >"$out/dmesg-before.log" 2>&1
before_dmesg_ts=$(sed -n 's/^\[[[:space:]]*\([0-9][0-9.]*\)\].*/\1/p' "$out/dmesg-before.log" | tail -n 1)
cat "$selftest" >"$out/selftest.log" || fail 18 "selftest read failed"
grep -qx 'case_runtime_state=PASS tests=62 failed=0 ret=0' "$out/selftest.log" ||
	fail 19 "runtime terminal-ledger selftest failed"
grep -qx "tests=$expected_selftests" "$out/selftest.log" &&
	grep -qx "passed=$expected_selftests" "$out/selftest.log" &&
	grep -qx 'failed=0' "$out/selftest.log" &&
	grep -qx 'verdict=PASS' "$out/selftest.log" || fail 20 "selftest summary mismatch"
cat "$stats" >"$out/stats-after.log" || fail 21 "post stats unavailable"
validate_idle "$out/stats-after.log" || fail 22 "post-selftest state is not idle"
for key in netdev_accepted worker_dequeued wmi_submitted parse_failed \
	backend_unsupported fw_completion_events queue_depth watchdog_timeouts \
	teardown_timeouts unexpected_completions; do
	[ "$(value "$out/stats-before.log" "$key")" = "$(value "$out/stats-after.log" "$key")" ] ||
		fail 23 "selftest changed runtime counter $key"
done
dmesg >"$out/dmesg-after.log" 2>&1
sed -n "s/^\[[[:space:]]*\([0-9][0-9.]*\)\].*/\1 &/p" "$out/dmesg-after.log" |
	awk -v baseline="$before_dmesg_ts" '($1 + 0) > (baseline + 0) { $1=""; sub(/^ /,""); print }' >"$out/dmesg-new.log"
grep -Eiq 'CFI: Fatal|Kernel panic|wlan crashed|cnss_recovery_handler|SMMU.*(^|[^[:alnum:]_])fault([^[:alnum:]_]|$)|firmware.*(^|[^[:alnum:]_])assert([^[:alnum:]_]|$)' \
	"$out/dmesg-new.log" && fail 24 "new fatal signature observed"
[ "$(cat /proc/sys/kernel/random/boot_id)" = "$boot_id" ] || fail 25 "boot ID changed"
{
	echo "verdict=PASS"
	echo "scope=stage0-format-v7-zero-tx-preflight"
	echo "build_id=$expected_build_id"
	echo "source_rev=$expected_source_rev"
	echo "selftests=$expected_selftests"
	echo "firmware_sha256=$firmware_sha256"
	echo "bdf_sha256=$bdf_sha256"
	echo "boot_id=$boot_id"
} >"$out/result.txt"
sha256sum "$out"/* >"$out/SHA256SUMS" 2>/dev/null
exit 0
