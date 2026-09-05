#!/system/bin/sh

set -u

[ "$#" -eq 3 ] || {
	echo "usage: $0 <run-token> <pre-test-boot-id> <label>" >&2
	exit 2
}
run_token=$1
pre_boot_id=$2
label=$3
safe_token=$(printf '%s' "$run_token" | tr -c 'A-Za-z0-9._-' '_')
safe_label=$(printf '%s' "$label" | tr -c 'A-Za-z0-9._-' '_')
stamp=$(date -u +%Y%m%dT%H%M%SZ)
out_base=/data/local/tmp/qcacld-post-${safe_token}-${safe_label}-${stamp}-$$
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
required_failures=0
optional_failures=0
copy_attempts=0
copy_successes=0
copy_failures=0
copy_skipped=0
copy_bytes=0
max_file_bytes=$((256 * 1024 * 1024))
max_total_bytes=1073741824
max_files=2048

printf '%s\n' "$run_token" >"$out/run-token.txt"
printf '%s\n' "$pre_boot_id" >"$out/pre-test-boot-id.txt"
printf '%s\n' "$label" >"$out/label.txt"
date -u +%Y-%m-%dT%H:%M:%SZ >"$out/start-utc.txt"
current_boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
printf '%s\n' "$current_boot_id" >"$out/boot-id.txt"
[ -n "$current_boot_id" ] || required_failures=$((required_failures + 1))
if [ "$current_boot_id" = "$pre_boot_id" ]; then
	boot_relation=same
else
	boot_relation=changed
fi
printf '%s\n' "$boot_relation" >"$out/boot-relation.txt"

capture()
{
	capture_kind=$1
	capture_name=$2
	shift 2
	{
		echo "utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
		echo "command=$*"
		timeout 90 "$@"
		capture_rc=$?
		echo
		echo "rc=$capture_rc"
	} >"$out/$capture_name" 2>&1
	if [ "$capture_rc" -ne 0 ]; then
		case "$capture_kind" in
			required) required_failures=$((required_failures + 1)) ;;
			*) optional_failures=$((optional_failures + 1)) ;;
		esac
	fi
}

copy_bounded()
{
	copy_root=$1
	copy_src=$2
	[ -f "$copy_src" ] || return 0
	copy_attempts=$((copy_attempts + 1))
	copy_size=$(stat -c '%s' "$copy_src" 2>/dev/null)
	case "$copy_size" in
		''|*[!0-9]*)
			copy_failures=$((copy_failures + 1))
			printf 'stat_failed\t%s\n' "$copy_src" >>"$out/copy-status.tsv"
			return 0
			;;
	esac
	if awk -v value="$copy_size" -v limit="$max_file_bytes" \
		'BEGIN { exit (value > limit) ? 0 : 1 }' ||
	   [ "$copy_successes" -ge "$max_files" ] ||
	   [ $((copy_bytes + copy_size)) -gt "$max_total_bytes" ]; then
		copy_skipped=$((copy_skipped + 1))
		printf 'bounded_skip\t%s\t%s\n' "$copy_size" "$copy_src" \
			>>"$out/copy-status.tsv"
		return 0
	fi
	case "$copy_src" in
		"$copy_root"/*) copy_rel=${copy_src#"$copy_root"/} ;;
		"$copy_root") copy_rel=$(basename "$copy_src") ;;
		*)
			copy_failures=$((copy_failures + 1))
			return 0
			;;
	esac
	copy_root_rel=${copy_root#/}
	copy_dst=$out/files/$copy_root_rel/$copy_rel
	mkdir -p "$(dirname "$copy_dst")" || {
		copy_failures=$((copy_failures + 1))
		return 0
	}
	if timeout 30 cp -p "$copy_src" "$copy_dst" \
		2>>"$out/copy-errors.log"; then
		copy_successes=$((copy_successes + 1))
		copy_bytes=$((copy_bytes + copy_size))
		printf 'copied\t%s\t%s\n' "$copy_size" "$copy_src" \
			>>"$out/copy-status.tsv"
	else
		copy_failures=$((copy_failures + 1))
		printf 'copy_failed\t%s\t%s\n' "$copy_size" "$copy_src" \
			>>"$out/copy-status.tsv"
	fi
}

copy_scope_files()
{
	copy_scope=$1
	[ -d "$copy_scope" ] || return 0
	copy_list=$out/scope-$(printf '%s' "$copy_scope" | tr '/' '_').list
	find "$copy_scope" -maxdepth 5 -type f -print 2>/dev/null >"$copy_list"
	while IFS= read -r copy_path; do
		copy_bounded "$copy_scope" "$copy_path"
	done <"$copy_list"
}

capture required uptime.txt cat /proc/uptime
capture required uname.txt uname -a
capture required dmesg-current.log dmesg
capture required logcat-all-current.log logcat -b all -d -v threadtime
capture required cmd-wifi-status.log cmd wifi status
capture required dumpsys-wifi.log dumpsys wifi
capture required dumpsys-connectivity.log dumpsys connectivity
capture required iw-dev.log iw dev
capture required iw-wlan0-info.log iw dev wlan0 info
capture required iw-wlan0-link.log iw dev wlan0 link
capture required ip-address.log ip address
capture required ip-route-all.log ip route show table all
capture required getprop.log getprop
capture required module-build-id.log od -An -v -tx1 \
	/sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id
capture required cnss-firmware-ready.log cat \
	/sys/bus/platform/drivers/cnss2/firmware_ready
capture optional pstore-list.log sh -c \
	'find /sys/fs/pstore -maxdepth 1 -type f -print 2>/dev/null | sort'

copy_scope_files /sys/fs/pstore
if [ -d /data/adb ]; then
	adb_log_list=$out/scope-_data_adb-kernel-logs.list
	find /data/adb -maxdepth 4 -type f \
		\( -iname 'dmesg.log' -o -iname 'dmesg.old.log' \
		   -o -iname 'kmsg.log' -o -iname 'console-ramoops*' \
		   -o -iname 'last_kmsg*' -o -iname 'logcat.log' \
		   -o -iname 'logcat.old.log' -o -iname '*kernel*log*' \
		   -o -iname 'modules_info*' \) -print 2>/dev/null \
		>"$adb_log_list"
	while IFS= read -r copy_path; do
		copy_bounded /data/adb "$copy_path"
	done <"$adb_log_list"
fi
copy_scope_files /data/vendor/tombstones/wifi
copy_scope_files /data/vendor/wifi/wlan_logs
copy_scope_files /data/vendor/wifi/logs
copy_bounded /data/debugging /data/debugging/last_kmsg.txt
copy_bounded /proc /proc/last_kmsg

collector_rc=0
[ "$required_failures" -eq 0 ] || collector_rc=6
[ "$copy_failures" -eq 0 ] || collector_rc=7
[ "$copy_skipped" -eq 0 ] || collector_rc=7
[ "$boot_relation" = same ] || collector_rc=6
date -u +%Y-%m-%dT%H:%M:%SZ >"$out/end-utc.txt"
{
	echo "run_token=$run_token"
	echo "pre_test_boot_id=$pre_boot_id"
	echo "current_boot_id=$current_boot_id"
	echo "boot_relation=$boot_relation"
	echo "required_failures=$required_failures"
	echo "optional_failures=$optional_failures"
	echo "copy_attempts=$copy_attempts"
	echo "copy_successes=$copy_successes"
	echo "copy_failures=$copy_failures"
	echo "copy_skipped=$copy_skipped"
	echo "copy_bytes=$copy_bytes"
	echo "collector_exit_code=$collector_rc"
} >"$out/result.txt"

file_list=/data/local/tmp/.qcacld-post-files-${safe_token}-$$
manifest_tmp=/data/local/tmp/.qcacld-post-sha-${safe_token}-$$
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
