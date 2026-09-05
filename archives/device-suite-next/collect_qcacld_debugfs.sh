#!/system/bin/sh

set -u

[ "$#" -eq 2 ] || {
	echo "usage: $0 <run-token> <expected-boot-id>" >&2
	exit 2
}
run_token=$1
expected_boot_id=$2
safe_token=$(printf '%s' "$run_token" | tr -c 'A-Za-z0-9._-' '_')
stamp=$(date -u +%Y%m%dT%H%M%SZ)
out_base=/data/local/tmp/qcacld-debugfs-${safe_token}-${stamp}-$$
out=$out_base
suffix=0
while ! mkdir "$out" 2>/dev/null; do
	suffix=$((suffix + 1))
	[ "$suffix" -lt 100 ] || exit 3
	out=${out_base}-${suffix}
done
archive=${out}.tar.gz
archive_tmp=${archive}.tmp.$$
file_list=
manifest_tmp=
cleanup_temp()
{
	[ -z "${file_list:-}" ] || rm -f "$file_list"
	[ -z "${manifest_tmp:-}" ] || rm -f "$manifest_tmp"
	rm -f "$archive_tmp"
}
trap cleanup_temp EXIT
trap 'exit 130' HUP INT TERM
required_successes=0
required_failures=0
optional_successes=0
optional_missing=0
optional_failures=0

printf '%s\n' "$run_token" >"$out/run-token.txt"
printf '%s\n' "$expected_boot_id" >"$out/expected-boot-id.txt"
current_boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
printf '%s\n' "$current_boot_id" >"$out/boot-id.txt"
date -u +%Y-%m-%dT%H:%M:%SZ >"$out/start-utc.txt"
[ -n "$current_boot_id" ] || required_failures=$((required_failures + 1))
if [ "$current_boot_id" = "$expected_boot_id" ]; then
	boot_relation=same
else
	boot_relation=changed
fi

capture_node()
{
	node_kind=$1
	node_src=$2
	node_rel=$3
	node_timeout=$4
	node_dst=$out/$node_rel
	mkdir -p "$(dirname "$node_dst")"
	if [ ! -r "$node_src" ]; then
		printf '%s\tmissing\t%s\n' "$node_kind" "$node_src" \
			>>"$out/node-status.tsv"
		case "$node_kind" in
			required) required_failures=$((required_failures + 1)) ;;
			*) optional_missing=$((optional_missing + 1)) ;;
		esac
		return 0
	fi
	{
		echo "source=$node_src"
		echo "utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	} >"$node_dst.meta"
	timeout "$node_timeout" sh -c \
		'cat "$1" | head -c 67108864' sh "$node_src" \
		>"$node_dst" 2>"$node_dst.stderr"
	node_rc=$?
	echo "rc=$node_rc" >>"$node_dst.meta"
	node_size=$(stat -c '%s' "$node_dst" 2>/dev/null)
	case "$node_size" in ''|*[!0-9]*) node_size=0 ;; esac
	if [ "$node_rc" -eq 0 ] && [ "$node_size" -gt 0 ]; then
		printf '%s\tok\t%s\t%s\n' "$node_kind" "$node_size" \
			"$node_src" >>"$out/node-status.tsv"
		case "$node_kind" in
			required) required_successes=$((required_successes + 1)) ;;
			*) optional_successes=$((optional_successes + 1)) ;;
		esac
	else
		printf '%s\tfailed\trc=%s\tsize=%s\t%s\n' "$node_kind" \
			"$node_rc" "$node_size" "$node_src" \
			>>"$out/node-status.tsv"
		case "$node_kind" in
			required) required_failures=$((required_failures + 1)) ;;
			*) optional_failures=$((optional_failures + 1)) ;;
		esac
	fi
}

capture_node required /sys/bus/platform/drivers/cnss2/cnss_debug \
	cnss/cnss_debug.txt 10
capture_node required /sys/bus/platform/drivers/cnss2/device_id \
	cnss/device_id.txt 10
capture_node required /sys/bus/platform/drivers/cnss2/firmware_ready \
	cnss/firmware_ready.txt 10
capture_node optional /sys/kernel/debug/cnss/stats cnss/stats.txt 10
capture_node optional /sys/kernel/debug/cnss/pin_connect_result \
	cnss/pin_connect_result.txt 10

for node_src in /sys/kernel/debug/qca_cld3_peach_v2/WMI_SOC0_PDEV0/*; do
	[ -e "$node_src" ] || continue
	capture_node optional "$node_src" \
		"wmi/$(basename "$node_src").txt" 10
done
for node_name in ini_config mws_coex_antenna_sharing mws_coex_dpwb_state \
	mws_coex_idrx mws_coex_state mws_coex_tdm_state; do
	capture_node optional "/sys/kernel/debug/qca_cld3_peach_v2/$node_name" \
		"qca/$node_name.txt" 10
done
for node_name in dma kmalloc skb; do
	capture_node optional \
		"/sys/kernel/debug/qca_cld3_peach_v2/mem/$node_name" \
		"qca/mem-$node_name.txt" 10
done
capture_node optional \
	/sys/kernel/debug/qca_cld3_peach_v2/wbuff/wbuff_stats \
	qca/wbuff_stats.txt 10
capture_node optional /sys/kernel/debug/wlan0/ll_stats \
	qca/wlan0-ll_stats.txt 10
capture_node optional /sys/kernel/debug/wlan0/mib_stats \
	qca/wlan0-mib_stats.txt 10
for node_src in /sys/kernel/debug/*/frame_inject_stats \
	/sys/kernel/debug/*/frame_inject_selftest; do
	[ -e "$node_src" ] || continue
	node_iface=$(basename "$(dirname "$node_src")")
	node_name=$(basename "$node_src")
	capture_node optional "$node_src" \
		"qca/$node_iface-$node_name.txt" 10
done

for node_name in cnss cnss-long cnss_plat mhi_110e_00.01.00 pcie0-dump \
	pcie0-long pcie0-short; do
	capture_node optional "/sys/kernel/debug/ipc_logging/$node_name/log" \
		"ipc/$node_name.log" 10
done
for node_dir in /sys/kernel/debug/remoteproc/remoteproc*; do
	[ -d "$node_dir" ] || continue
	node_name=$(basename "$node_dir")
	capture_node optional "$node_dir/name" \
		"remoteproc/$node_name-name.txt" 10
	capture_node optional "$node_dir/recovery" \
		"remoteproc/$node_name-recovery.txt" 10
done
capture_node optional \
	/sys/kernel/debug/qca_cld3_peach_v2/cldpeach_v2/dbglog_block \
	qca/fw-dbglog-block.bin 15

collector_rc=0
[ "$required_successes" -eq 3 ] || collector_rc=6
[ "$required_failures" -eq 0 ] || collector_rc=6
[ "$boot_relation" = same ] || collector_rc=6
date -u +%Y-%m-%dT%H:%M:%SZ >"$out/end-utc.txt"
{
	echo "run_token=$run_token"
	echo "expected_boot_id=$expected_boot_id"
	echo "current_boot_id=$current_boot_id"
	echo "boot_relation=$boot_relation"
	echo "required_successes=$required_successes"
	echo "required_failures=$required_failures"
	echo "optional_successes=$optional_successes"
	echo "optional_missing=$optional_missing"
	echo "optional_failures=$optional_failures"
	echo "collector_exit_code=$collector_rc"
} >"$out/result.txt"

file_list=/data/local/tmp/.qcacld-debugfs-files-${safe_token}-$$
manifest_tmp=/data/local/tmp/.qcacld-debugfs-sha-${safe_token}-$$
find "$out" -type f -print | sort >"$file_list" || exit 8
: >"$manifest_tmp" || exit 8
hash_failures=0
while IFS= read -r hash_path; do
	hash_value=$(sha256sum "$hash_path" 2>/dev/null | awk '{print $1}')
	if [ -z "$hash_value" ]; then
		hash_failures=$((hash_failures + 1))
		continue
	fi
	hash_rel=${hash_path#"$out"/}
	printf '%s  %s\n' "$hash_value" "$hash_rel" >>"$manifest_tmp"
done <"$file_list"
rm -f "$file_list"
[ "$hash_failures" -eq 0 ] || {
	rm -f "$manifest_tmp" "$archive_tmp"
	exit 8
}
mv "$manifest_tmp" "$out/SHA256SUMS" || exit 8
tar -C "$(dirname "$out")" -czf "$archive_tmp" "$(basename "$out")" || {
	rm -f "$archive_tmp"
	exit 9
}
mv "$archive_tmp" "$archive" || exit 9
archive_sha=$(sha256sum "$archive" | awk '{print $1}')
[ -n "$archive_sha" ] || exit 9
sync
echo "OUTPUT_DIR=$out"
echo "TAR_PATH=$archive"
echo "TAR_SHA256=$archive_sha"
exit "$collector_rc"
