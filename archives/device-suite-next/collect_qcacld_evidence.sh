#!/system/bin/sh

set -u

usage()
{
	echo "usage: $0 <run-token> <expected-boot-id> [test-output-dir]" >&2
	exit 2
}

[ "$#" -ge 2 ] && [ "$#" -le 3 ] || usage
run_token=$1
expected_boot_id=$2
test_out=${3:-}
safe_token=$(printf '%s' "$run_token" | tr -c 'A-Za-z0-9._-' '_')
[ -n "$safe_token" ] || usage

stamp=$(date -u +%Y%m%dT%H%M%SZ)
out_base=/data/local/tmp/qcacld-evidence-${safe_token}-${stamp}-$$
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
expected_firmware_sha256=f89a5348a4076d4db062eb335ac97b5fb028397bd3d21c96a837fb138503d84e
expected_bdf_sha256=b95a047cda7ab3d23010f7cdc0dd031bc865fbf369191a55df6a44a574d4cccd

printf '%s\n' "$run_token" >"$out/run-token.txt"
printf '%s\n' "$expected_boot_id" >"$out/expected-boot-id.txt"
printf '%s\n' "$test_out" >"$out/test-output-dir.txt"
date -u +%Y-%m-%dT%H:%M:%SZ >"$out/start-utc.txt"
current_boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
printf '%s\n' "$current_boot_id" >"$out/boot-id.txt"
[ -n "$current_boot_id" ] || required_failures=$((required_failures + 1))
if [ "$current_boot_id" = "$expected_boot_id" ]; then
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
			printf 'scope_error\t%s\n' "$copy_src" >>"$out/copy-status.tsv"
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
capture required bootconfig.txt cat /proc/bootconfig
capture required cmdline.txt cat /proc/cmdline
capture required modules.txt cat /proc/modules
capture required dmesg-raw.log dmesg
capture optional dmesg-human.log dmesg -T
capture required logcat-all.log logcat -b all -d -v threadtime
capture optional logcat-kernel.log logcat -b kernel -d -v threadtime
capture required cmd-wifi-status.txt cmd wifi status
capture required dumpsys-wifi.log dumpsys wifi
capture required dumpsys-connectivity.log dumpsys connectivity
capture optional dumpsys-network-stack.log dumpsys network_stack
capture required getprop.txt getprop
capture required iw-dev.txt iw dev
capture required iw-wlan0-info.txt iw dev wlan0 info
capture required iw-wlan0-link.txt iw dev wlan0 link
capture optional iw-reg-get.txt iw reg get
capture optional iw-phy1-info.txt iw phy phy1 info
capture required ip-link-wlan0.txt ip -s -details link show wlan0
capture required ip-addr-wlan0.txt ip addr show wlan0
capture required ip-route-all.txt ip route show table all
capture optional ethtool-wlan0.txt ethtool wlan0
capture optional ethtool-stats-wlan0.txt ethtool -S wlan0
capture required module-build-id.txt od -An -tx1 -v \
	/sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id
capture required module-parameters.txt sh -c \
	'for f in /sys/module/qca_cld3_peach_v2/parameters/*; do echo ===$f===; cat "$f" 2>&1; done'
capture optional cnss2-parameters.txt sh -c \
	'for f in /sys/module/cnss2/parameters/*; do echo ===$f===; cat "$f" 2>&1; done'
capture required firmware-amss20-sha256.txt sha256sum \
	/vendor/firmware_mnt/image/peach/amss20.bin
capture required board-data-sha256.txt sha256sum \
	/odm/etc/wifi/peach/bdwlan.elf
capture optional firmware-secondary-hashes.txt sh -c \
	'for f in /vendor/firmware_mnt/image/peach/regdb.bin /vendor/firmware_mnt/image/peach/Data20.msc /vendor/firmware_mnt/image/peach/phy_ucode20.elf /vendor/firmware_mnt/image/peach/aux_ucode20.elf /vendor/firmware_mnt/image/peach/qdss_trace_config_v2.cfg; do if [ -f "$f" ]; then sha256sum "$f" || exit 1; fi; done'
actual_firmware_sha256=$(awk 'NR == 3 {print $1}' \
	"$out/firmware-amss20-sha256.txt")
actual_bdf_sha256=$(awk 'NR == 3 {print $1}' \
	"$out/board-data-sha256.txt")
[ "$actual_firmware_sha256" = "$expected_firmware_sha256" ] ||
	required_failures=$((required_failures + 1))
[ "$actual_bdf_sha256" = "$expected_bdf_sha256" ] ||
	required_failures=$((required_failures + 1))
capture required cnss-firmware-ready.txt cat \
	/sys/bus/platform/drivers/cnss2/firmware_ready
capture optional cnss-debug.txt cat \
	/sys/bus/platform/drivers/cnss2/cnss_debug
capture optional debugfs-tree.txt sh -c \
	'find /sys/kernel/debug -maxdepth 6 \( -iname "*cnss*" -o -iname "*wlan*" -o -iname "*mhi*" -o -iname "*ipc*" -o -iname "*wmi*" \) -print 2>/dev/null | sort'
capture optional processes-wifi.txt sh -c \
	'ps -A -o USER,PID,PPID,NAME,ARGS | grep -Ei "wifi|wlan|cnss|wpa|hostapd"'

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

if [ -n "$test_out" ] && [ -d "$test_out" ]; then
	mkdir -p "$out/test-crossref"
	for cross_name in result.txt frame-matrix.tsv phase-matrix.tsv \
		workflow-matrix.tsv iface-probe.tsv iface-probe.stderr \
		iface-probe.rc iface-probe-frequency-matrix.txt \
		iface-probe-sha256.txt sender-sha256.txt \
		pre-monitor-ifindex.txt \
		random-monitor-ifindex-transition.txt \
		random-monitor-mode-poll.log random-monitor-driver-transition.log \
		random-managed-return-ifindex-transition.txt \
		random-managed-return-mode-poll.log \
		random-managed-return-driver-transition.log \
		specified-monitor-ifindex-transition.txt \
		specified-monitor-mode-poll.log \
		specified-monitor-driver-transition.log \
		specified-managed-return-ifindex-transition.txt \
		specified-managed-return-mode-poll.log \
		specified-managed-return-driver-transition.log \
		failure-managed-ifindex-transition.txt \
		failure-managed-mode-poll.log \
			failure-managed-recovery-status.txt run-token.txt boot-id.txt \
			authorized-isolated-bssid.txt baseline-channel.txt \
			post-reconnect-eapol.log post-reconnect-eapol-new.log \
		crash-evidence-pre-test.manifest \
		crash-evidence-post-test.manifest \
		crash-evidence-post-test.delta.tsv \
		crash-evidence-post-failure.manifest \
		crash-evidence-post-failure.delta.tsv; do
		[ -f "$test_out/$cross_name" ] || continue
		cp -p "$test_out/$cross_name" "$out/test-crossref/$cross_name" ||
			copy_failures=$((copy_failures + 1))
	done
	for cross_path in "$test_out"/workflow-frame-*.log \
		"$test_out"/workflow-frame-*.rc \
		"$test_out"/phase-*-gate-*.txt \
		"$test_out"/workflow-gate-*.txt; do
		[ -f "$cross_path" ] || continue
		cross_name=${cross_path##*/}
		cp -p "$cross_path" "$out/test-crossref/$cross_name" ||
			copy_failures=$((copy_failures + 1))
	done
fi

collector_rc=0
[ "$required_failures" -eq 0 ] || collector_rc=6
[ "$copy_failures" -eq 0 ] || collector_rc=7
[ "$copy_skipped" -eq 0 ] || collector_rc=7
[ "$boot_relation" = same ] || collector_rc=6
date -u +%Y-%m-%dT%H:%M:%SZ >"$out/end-utc.txt"
{
	echo "run_token=$run_token"
	echo "expected_boot_id=$expected_boot_id"
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

file_list=/data/local/tmp/.qcacld-evidence-files-${safe_token}-$$
manifest_tmp=/data/local/tmp/.qcacld-evidence-sha-${safe_token}-$$
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
