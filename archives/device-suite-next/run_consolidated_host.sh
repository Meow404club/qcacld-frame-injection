#!/usr/bin/env bash

set -uo pipefail

usage()
{
	cat >&2 <<'EOF'
usage: run_consolidated_host.sh [--serial SERIAL] [--timeout SECONDS]
       --stage 0|3
       --authorized-bssid BSSID --acknowledge-disruptive-test
       [--ota-interface IFACE] [--require-ota]

Stage 0 performs only helper lifecycle and mode/recovery checks and transmits
no research frames. Stage 3 transmits the full fixed/workflow frame matrices.
Run either stage only in an owned or explicitly authorized isolated RF
environment.
The external OTA interface must already be UP in monitor mode on the tested
channel. Its reported frequency must match the device's connected baseline.
--require-ota makes an incomplete exact-frame pcap matrix fatal.
EOF
	exit 2
}

serial=
stage_scope=
ota_interface=
require_ota=false
authorized_bssid=
disruptive_test_ack=false
test_timeout=1800
while [[ "$#" -gt 0 ]]; do
	case "$1" in
		--stage)
			[[ "$#" -ge 2 && "$2" =~ ^(0|3)$ ]] || usage
			stage_scope=$2
			shift 2
			;;
		--serial)
			[[ "$#" -ge 2 ]] || usage
			serial=$2
			shift 2
			;;
		--timeout)
			[[ "$#" -ge 2 && "$2" =~ ^[0-9]+$ && "$2" -ge 600 ]] || usage
			test_timeout=$2
			shift 2
			;;
		--ota-interface)
			[[ "$#" -ge 2 && -n "$2" ]] || usage
			ota_interface=$2
			shift 2
			;;
		--require-ota)
			require_ota=true
			shift
			;;
		--authorized-bssid)
			[[ "$#" -ge 2 && -n "$2" ]] || usage
			authorized_bssid=${2,,}
			shift 2
			;;
		--acknowledge-disruptive-test)
			disruptive_test_ack=true
			shift
			;;
		*) usage ;;
	esac
done
[[ -n "$stage_scope" ]] || usage
[[ "$require_ota" == false || -n "$ota_interface" ]] || usage
[[ "$stage_scope" == 3 || ( "$require_ota" == false && -z "$ota_interface" ) ]] ||
	usage
[[ "$disruptive_test_ack" == true ]] || usage
[[ "$authorized_bssid" =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]] || usage

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
device_script=$script_dir/run_consolidated_device.sh
sender=$script_dir/send_frame_once
iface_probe=$script_dir/hcx_iface_probe
evidence_collector=$script_dir/collect_qcacld_evidence.sh
debugfs_collector=$script_dir/collect_qcacld_debugfs.sh
post_collector=$script_dir/collect_post_boot.sh
ota_verifier=$script_dir/verify_ota_capture.py
group_runner=$script_dir/run_remote_group.sh
control_helper=$script_dir/run_remote_control.sh
kernel_capture=$script_dir/capture_run_kernel.sh
for input in "$device_script" "$sender" "$iface_probe" "$evidence_collector" \
	"$debugfs_collector" "$post_collector" "$ota_verifier" "$group_runner" \
	"$control_helper" "$kernel_capture"; do
	[[ -r "$input" ]] || {
		echo "missing suite input: $input" >&2
		exit 3
	}
done
grep -qx 'suite_frozen=1' "$device_script" || {
	echo "archived AP/RAW suite is incompatible with the active WMI synthetic route" >&2
	exit 4
}
[[ -x "$sender" ]] || {
	echo "sender is not executable: $sender" >&2
	exit 3
}
[[ -x "$iface_probe" ]] || {
	echo "interface probe is not executable: $iface_probe" >&2
	exit 3
}
[[ -x "$group_runner" ]] || {
	echo "remote group runner is not executable: $group_runner" >&2
	exit 3
}
[[ -x "$control_helper" ]] || {
	echo "remote control helper is not executable: $control_helper" >&2
	exit 3
}
[[ -x "$kernel_capture" ]] || {
	echo "kernel event capture helper is not executable: $kernel_capture" >&2
	exit 3
}

stamp=$(date -u +%Y%m%dT%H%M%SZ)
host_token=QCACLD_HOST_${stamp}_$$_${RANDOM}
host_out=$script_dir/host-capture-${stamp}-$$
mkdir "$host_out" || exit 3
echo "HOST_OUTPUT_DIR=$host_out"

failure_count=0
failure_log=$host_out/failures.log
note_failure()
{
	failure_count=$((failure_count + 1))
	printf '%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" \
		>>"$failure_log"
	echo "ERROR: $1" >&2
}

mkdir "$host_out/inputs"
cp -p "$device_script" "$sender" "$iface_probe" "$evidence_collector" \
	"$debugfs_collector" "$post_collector" "$ota_verifier" "$group_runner" \
	"$control_helper" "$kernel_capture" \
	"$host_out/inputs/" || note_failure "could not preserve suite inputs"
(cd "$host_out/inputs" && sha256sum ./* >SHA256SUMS) ||
	note_failure "could not hash suite inputs"
{
	echo "host_token=$host_token"
	echo "host=$(hostname)"
	echo "user=$(id -u):$(id -g)"
	echo "kernel=$(uname -a)"
	echo "test_timeout_seconds=$test_timeout"
	echo "ota_interface=${ota_interface:-none}"
	echo "require_ota=$require_ota"
	echo "authorized_bssid=$authorized_bssid"
	echo "disruptive_test_acknowledged=$disruptive_test_ack"
} >"$host_out/host-preflight.txt"

command -v adb >"$host_out/adb-path.txt" 2>&1 || {
	note_failure "adb is unavailable"
	serial=unavailable
}
if [[ "$serial" != unavailable ]]; then
	adb devices -l >"$host_out/adb-devices.log" 2>&1 ||
		note_failure "adb devices failed"
	if [[ -z "$serial" ]]; then
		mapfile -t device_serials < <(adb devices | awk '$2 == "device" {print $1}')
		if [[ "${#device_serials[@]}" -ne 1 ]]; then
			note_failure "exactly one authorized adb device is required"
			serial=unavailable
		else
			serial=${device_serials[0]}
		fi
	elif [[ "$(adb -s "$serial" get-state 2>/dev/null)" != device ]]; then
		note_failure "requested adb serial is not in device state: $serial"
		serial=unavailable
	fi
fi
printf '%s\n' "$serial" >"$host_out/adb-serial.txt"

declare -a ADB=(adb)
if [[ "$serial" != unavailable ]]; then
	ADB=(adb -s "$serial")
fi
remote_dir=/data/local/tmp/qcacld-${host_token}
remote_test_pidfile=$remote_dir/test.pid
remote_test_rcfile=$remote_dir/test.rc
remote_group_runner=$remote_dir/run_remote_group.sh
remote_control=$remote_dir/run_remote_control.sh
declare -a stream_names=()
declare -a stream_pids=()
declare -a stream_remote_pidfiles=()
declare -a stream_remote_expected=()
pcap_pid=
pcap_path=
cleanup_started=false
cleanup_failure_count=0
active_collector_pidfile=
active_collector_expected=
active_collector_label=
remote_test_stop_confirmed=false
preboot_remote_groups_expired=false

clear_active_collector()
{
	active_collector_pidfile=
	active_collector_expected=
	active_collector_label=
}

remote_stop_pidfile()
{
	local pidfile=$1
	local expected=$2
	local label=$3
	[[ "$serial" != unavailable ]] || return 1
	[[ "$expected" =~ ^[A-Za-z0-9._-]+$ ]] || return 2
	timeout -k 5 45 "${ADB[@]}" shell su -c \
		"$remote_control stop $pidfile $expected" \
		>>"$host_out/stop-$label.log" 2>&1
}

remote_read_rc()
{
	local rcfile=$1
	local label=$2
	local raw
	remote_rc_value=
	raw=$(timeout -k 5 30 "${ADB[@]}" exec-out su -c \
		"$remote_control read-rc $rcfile" \
		2>"$host_out/$label-sidecar.stderr" | tr -d '\r\n')
	printf '%s\n' "$raw" >"$host_out/$label-sidecar.txt"
	[[ "$raw" =~ ^[0-9]+$ && "$raw" -le 255 ]] || return 1
	remote_rc_value=$raw
	return 0
}

retry_active_collector_stop()
{
	local retry_label=$1
	[[ -n "$active_collector_pidfile" ]] || return 0
	if remote_stop_pidfile "$active_collector_pidfile" \
		"$active_collector_expected" \
		"$retry_label-$active_collector_label"; then
		clear_active_collector
		return 0
	fi
	return 1
}

stop_streams()
{
	local i local_pid stream_name remote_pidfile remote_expected
	local local_wait_rc remote_stopped
	local stop_failed=0
	local -a retry_names=()
	local -a retry_pids=()
	local -a retry_remote_pidfiles=()
	local -a retry_remote_expected=()
	for ((i = 0; i < ${#stream_names[@]}; i++)); do
		stream_name=${stream_names[$i]}
		local_pid=${stream_pids[$i]}
		remote_pidfile=${stream_remote_pidfiles[$i]}
		remote_expected=${stream_remote_expected[$i]}
		remote_stopped=true
		if [[ "$preboot_remote_groups_expired" == false ]]; then
			if ! remote_stop_pidfile "$remote_pidfile" "$remote_expected" \
				"stream-$stream_name"; then
				remote_stopped=false
				stop_failed=1
			fi
		else
			printf 'remote_stop=skipped_old_boot\npidfile=%s\n' \
				"$remote_pidfile" >"$host_out/stop-stream-$stream_name.log"
		fi
		if [[ -n "$local_pid" ]]; then
			kill -TERM "$local_pid" 2>/dev/null || true
			for _ in {1..10}; do
				kill -0 "$local_pid" 2>/dev/null || break
				sleep 1
			done
			kill -KILL "$local_pid" 2>/dev/null || true
			local_wait_rc=0
			wait "$local_pid" 2>/dev/null || local_wait_rc=$?
			printf '%s\n' "$local_wait_rc" \
				>"$host_out/live-$stream_name.exit-code"
		fi
		if [[ "$remote_stopped" == false ]]; then
			retry_names+=("$stream_name")
			retry_pids+=("")
			retry_remote_pidfiles+=("$remote_pidfile")
			retry_remote_expected+=("$remote_expected")
		fi
	done
	stream_names=("${retry_names[@]}")
	stream_pids=("${retry_pids[@]}")
	stream_remote_pidfiles=("${retry_remote_pidfiles[@]}")
	stream_remote_expected=("${retry_remote_expected[@]}")
	return "$stop_failed"
}

stop_pcap()
{
	[[ -n "$pcap_pid" ]] || return 0
	kill -INT "$pcap_pid" 2>/dev/null || true
	for _ in {1..10}; do
		kill -0 "$pcap_pid" 2>/dev/null || break
		sleep 1
	done
	kill -TERM "$pcap_pid" 2>/dev/null || true
	for _ in {1..5}; do
		kill -0 "$pcap_pid" 2>/dev/null || break
		sleep 1
	done
	kill -KILL "$pcap_pid" 2>/dev/null || true
	wait "$pcap_pid" 2>/dev/null
	printf '%s\n' "$?" >"$host_out/ota-tcpdump.exit-code"
	pcap_pid=
}

force_gate_off()
{
	local label=$1
	[[ "$serial" != unavailable ]] || return 1
	timeout -k 5 30 "${ADB[@]}" shell su -c \
		"$remote_control gate-off" \
		>"$host_out/force-gate-off-$label.log" 2>&1
}

cleanup()
{
	[[ "$cleanup_started" == false ]] || return 0
	cleanup_started=true
	if [[ -n "$active_collector_pidfile" ]]; then
		retry_active_collector_stop cleanup ||
			cleanup_failure_count=$((cleanup_failure_count + 1))
	fi
	if [[ "$remote_test_stop_confirmed" == false &&
	      "$preboot_remote_groups_expired" == false ]]; then
		remote_stop_pidfile "$remote_test_pidfile" run_consolidated_device.sh \
			remote-test || cleanup_failure_count=$((cleanup_failure_count + 1))
	fi
	force_gate_off cleanup || cleanup_failure_count=$((cleanup_failure_count + 1))
	stop_streams || cleanup_failure_count=$((cleanup_failure_count + 1))
	stop_pcap
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

mark_finalization_failure()
{
	local final_rc=$1
	if [[ -f "$host_out/host-result.txt" ]]; then
		sed -i \
			-e 's/^overall_verdict=.*$/overall_verdict=FAIL/' \
			-e "s/^overall_exit_code=0$/overall_exit_code=$final_rc/" \
			"$host_out/host-result.txt"
		printf 'finalization_failure_exit_code=%s\n' "$final_rc" \
			>>"$host_out/host-result.txt"
	fi
}

final_host_archive=
final_host_archive_sha=
archive_host_output()
{
	local manifest_list manifest_tmp hash_path hash_value hash_rel hash_failed
	local host_archive host_archive_sha
	date -u +%Y-%m-%dT%H:%M:%SZ >"$host_out/end-utc.txt" || return 1
	manifest_list=$(mktemp)
	manifest_tmp=$(mktemp)
	find "$host_out" -type f ! -name SHA256SUMS -print | sort \
		>"$manifest_list" || {
		rm -f "$manifest_list" "$manifest_tmp"
		return 1
	}
	: >"$manifest_tmp" || {
		rm -f "$manifest_list" "$manifest_tmp"
		return 1
	}
	hash_failed=false
	while IFS= read -r hash_path; do
		hash_value=$(sha256sum "$hash_path" 2>/dev/null | awk '{print $1}')
		[[ "$hash_value" =~ ^[0-9a-f]{64}$ ]] || {
			hash_failed=true
			break
		}
		hash_rel=${hash_path#"$host_out"/}
		printf '%s  %s\n' "$hash_value" "$hash_rel" >>"$manifest_tmp"
	done <"$manifest_list"
	if [[ "$hash_failed" == true ]]; then
		rm -f "$manifest_list" "$manifest_tmp"
		return 1
	fi
	mv "$manifest_tmp" "$host_out/SHA256SUMS" || {
		rm -f "$manifest_list" "$manifest_tmp"
		return 1
	}
	rm -f "$manifest_list"
	host_archive=${host_out}.tar.gz
	rm -f "${host_archive}.tmp" "$host_archive" "${host_archive}.sha256"
	tar -C "$script_dir" -czf "${host_archive}.tmp" \
		"$(basename "$host_out")" || return 1
	mv "${host_archive}.tmp" "$host_archive" || return 1
	host_archive_sha=$(sha256sum "$host_archive" 2>/dev/null | awk '{print $1}')
	[[ "$host_archive_sha" =~ ^[0-9a-f]{64}$ ]] || return 1
	printf '%s  %s\n' "$host_archive_sha" "$(basename "$host_archive")" \
		>"${host_archive}.sha256" || return 1
	(cd "$(dirname "$host_archive")" &&
		sha256sum -c "$(basename "$host_archive").sha256") \
		>/dev/null 2>&1 || return 1
	final_host_archive=$host_archive
	final_host_archive_sha=$host_archive_sha
	return 0
}

finalize_host()
{
	local requested_rc=$1
	cleanup
	trap - EXIT
	if [[ "$cleanup_failure_count" -ne 0 ]]; then
		[[ "$requested_rc" -ne 0 ]] || requested_rc=125
		mark_finalization_failure "$requested_rc"
	fi
	{
		echo "requested_exit_code=$requested_rc"
		echo "cleanup_failure_count=$cleanup_failure_count"
		echo "archive_attempt=initial"
	} >"$host_out/finalization-status.txt"
	if ! archive_host_output; then
		requested_rc=125
		mark_finalization_failure "$requested_rc"
		{
			echo "requested_exit_code=$requested_rc"
			echo "cleanup_failure_count=$cleanup_failure_count"
			echo "archive_attempt=retry_after_initial_failure"
		} >"$host_out/finalization-status.txt"
		archive_host_output || {
			echo "HOST_OUTPUT_DIR=$host_out"
			echo "HOST_ARCHIVE=UNAVAILABLE"
			echo "HOST_ARCHIVE_SHA256=UNAVAILABLE"
			exit 125
		}
	fi
	echo "HOST_OUTPUT_DIR=$host_out"
	echo "HOST_ARCHIVE=$final_host_archive"
	echo "HOST_ARCHIVE_SHA256=$final_host_archive_sha"
	exit "$requested_rc"
}

if [[ "$failure_count" -ne 0 || "$serial" == unavailable ]]; then
	{
		echo "overall_verdict=PRECHECK_FAIL"
		echo "failure_count=$failure_count"
	} >"$host_out/host-result.txt"
	finalize_host 4
fi

"${ADB[@]}" shell su -c 'id -u' >"$host_out/pre-root.txt" 2>&1 ||
	note_failure "root preflight command failed"
[[ "$(tr -d '\r\n' <"$host_out/pre-root.txt")" == 0 ]] ||
	note_failure "adb root shell is unavailable"
if "${ADB[@]}" shell su -c \
	'test -d /sys/kernel/debug/qca_cld3_peach_v2' \
	>"$host_out/pre-debugfs-mount.log" 2>&1; then
	echo mount_state=already-mounted >>"$host_out/pre-debugfs-mount.log"
else
	"${ADB[@]}" shell su -c \
		'mount -t debugfs debugfs /sys/kernel/debug' \
		>>"$host_out/pre-debugfs-mount.log" 2>&1 ||
		note_failure "could not mount debugfs on the device"
fi
"${ADB[@]}" shell su -c \
	'test -d /sys/kernel/debug/qca_cld3_peach_v2' \
	>>"$host_out/pre-debugfs-mount.log" 2>&1 ||
	note_failure "WLAN debugfs root is unavailable on the device"
"${ADB[@]}" shell su -c "mkdir -p '$remote_dir' && chmod 0700 '$remote_dir'" \
	>"$host_out/remote-mkdir.log" 2>&1 || note_failure "remote suite directory creation failed"

declare -a push_sources=("$device_script" "$sender" "$iface_probe" \
	"$evidence_collector" "$debugfs_collector" "$post_collector" \
	"$ota_verifier" "$group_runner" "$control_helper" "$kernel_capture")
declare -a push_names=(run_consolidated_device.sh send_frame_once hcx_iface_probe \
	collect_qcacld_evidence.sh collect_qcacld_debugfs.sh collect_post_boot.sh \
	verify_ota_capture.py run_remote_group.sh run_remote_control.sh \
	capture_run_kernel.sh)
for ((push_i = 0; push_i < ${#push_sources[@]}; push_i++)); do
	push_src=${push_sources[$push_i]}
	push_name=${push_names[$push_i]}
	push_dst=$remote_dir/$push_name
	"${ADB[@]}" push "$push_src" "$push_dst" \
		>"$host_out/push-$push_name.log" 2>&1 || {
		note_failure "push failed: $push_name"
		continue
	}
	host_sha=$(sha256sum "$push_src" | awk '{print $1}')
	remote_sha_line=$("${ADB[@]}" shell su -c "sha256sum '$push_dst'" \
		2>"$host_out/remote-sha-$push_name.stderr" | tr -d '\r')
	remote_sha=${remote_sha_line%% *}
	printf 'host=%s\nremote=%s\n' "$host_sha" "$remote_sha" \
		>"$host_out/identity-$push_name.txt"
	[[ "$host_sha" == "$remote_sha" ]] ||
		note_failure "remote input hash mismatch: $push_name"
done
"${ADB[@]}" shell su -c "chmod 0755 '$remote_dir'/*" \
	>"$host_out/remote-chmod.log" 2>&1 || note_failure "remote chmod failed"

expected_build_id=$(sed -n 's/^expected_build_id=//p' "$device_script" | head -n 1)
expected_build_short=${expected_build_id:0:8}
expected_firmware_sha256=$(sed -n 's/^expected_firmware_sha256=//p' \
	"$device_script" | head -n 1)
expected_bdf_sha256=$(sed -n 's/^expected_bdf_sha256=//p' "$device_script" |
	head -n 1)
[[ "$expected_build_id" =~ ^[0-9a-f]{40}$ ]] ||
	note_failure "suite expected build-id is invalid"
[[ "$expected_firmware_sha256" =~ ^[0-9a-f]{64}$ ]] ||
	note_failure "suite expected firmware hash is invalid"
[[ "$expected_bdf_sha256" =~ ^[0-9a-f]{64}$ ]] ||
	note_failure "suite expected board-data hash is invalid"
pre_boot_id=$("${ADB[@]}" shell cat /proc/sys/kernel/random/boot_id 2>/dev/null |
	tr -d '\r\n')
printf '%s\n' "$pre_boot_id" >"$host_out/pre-boot-id.txt"
[[ "$pre_boot_id" =~ ^[0-9a-f-]{36}$ ]] ||
	note_failure "pre-test boot ID is unavailable"
loaded_build_note=$("${ADB[@]}" exec-out su -c \
	'od -An -v -tx1 /sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id' \
	2>"$host_out/pre-module-build-id.stderr" | tr -d ' \r\n')
printf '%s\n' "$loaded_build_note" >"$host_out/pre-module-build-id.txt"
[[ "$loaded_build_note" == *"$expected_build_id"* ]] ||
	note_failure "loaded module build-id does not match the suite"
runtime_firmware_sha=$("${ADB[@]}" shell su -c \
	'sha256sum /vendor/firmware_mnt/image/peach/amss20.bin' 2>/dev/null |
	awk '{print $1}' | tr -d '\r')
runtime_bdf_sha=$("${ADB[@]}" shell su -c \
	'sha256sum /odm/etc/wifi/peach/bdwlan.elf' 2>/dev/null |
	awk '{print $1}' | tr -d '\r')
{
	echo "firmware_sha256=$runtime_firmware_sha"
	echo "expected_firmware_sha256=$expected_firmware_sha256"
	echo "bdf_sha256=$runtime_bdf_sha"
	echo "expected_bdf_sha256=$expected_bdf_sha256"
} >"$host_out/pre-firmware-bdf-identity.txt"
[[ "$runtime_firmware_sha" == "$expected_firmware_sha256" ]] ||
	note_failure "runtime firmware hash does not match the fixed target"
[[ "$runtime_bdf_sha" == "$expected_bdf_sha256" ]] ||
	note_failure "runtime board-data hash does not match the fixed target"
"${ADB[@]}" shell su -c 'cmd wifi status' \
	>"$host_out/pre-cmd-wifi-status.log" 2>&1 ||
	note_failure "pre-test cmd wifi status failed"
"${ADB[@]}" shell su -c 'iw dev wlan0 link' \
	>"$host_out/pre-iw-link.log" 2>&1 ||
	note_failure "pre-test iw link failed"
target_frequency=$(sed -n \
	's/^[[:space:]]*freq: \([0-9][0-9]*\).*/\1/p' \
	"$host_out/pre-iw-link.log" | head -n 1)
printf '%s\n' "$target_frequency" >"$host_out/target-frequency-mhz.txt"
[[ "$target_frequency" =~ ^[0-9]{4,5}$ ]] ||
	note_failure "pre-test target frequency is unavailable"
"${ADB[@]}" shell su -c 'ip -4 addr show dev wlan0' \
	>"$host_out/pre-ipv4.log" 2>&1 ||
	note_failure "pre-test IPv4 capture failed"
probe_pidfile=$remote_dir/setsid-probe.pid
"${ADB[@]}" shell su -c \
	"$remote_control setsid-probe $remote_group_runner $probe_pidfile" \
	>"$host_out/pre-setsid-probe.log" 2>&1 ||
	note_failure "Android setsid process-group support is unavailable"

if [[ "$failure_count" -ne 0 ]]; then
	{
		echo "overall_verdict=PRECHECK_FAIL"
		echo "failure_count=$failure_count"
	} >"$host_out/host-result.txt"
	finalize_host 4
fi

start_stream()
{
	local name=$1
	local remote_command=$2
	local remote_expected=$3
	local remote_pidfile=$remote_dir/$name.pid
	"${ADB[@]}" exec-out su -c \
		"$remote_group_runner $remote_pidfile $remote_command" \
		>"$host_out/live-$name.log" 2>"$host_out/live-$name.stderr" &
	local local_pid=$!
	stream_names+=("$name")
	stream_pids+=("$local_pid")
	stream_remote_pidfiles+=("$remote_pidfile")
	stream_remote_expected+=("$remote_expected")
}

start_stream dmesg 'dmesg -w' dmesg
start_stream logcat 'logcat -b all -v threadtime' logcat
fw_dbglog_node=$("${ADB[@]}" shell su -c \
	'find /sys/kernel/debug -type f -name dbglog_block -print 2>/dev/null | head -n 1' |
	tr -d '\r')
printf '%s\n' "$fw_dbglog_node" >"$host_out/fw-dbglog-node.txt"
if [[ "$fw_dbglog_node" == /sys/kernel/debug/* ]]; then
	start_stream dbglog_block \
		"timeout $((test_timeout + 2400)) cat $fw_dbglog_node" timeout
else
	echo "fw_dbglog_stream=UNAVAILABLE; decoded FW logs remain in live dmesg" \
		>"$host_out/live-dbglog_block.status"
fi
sleep 2
for stream_pid in "${stream_pids[@]}"; do
	kill -0 "$stream_pid" 2>/dev/null ||
		note_failure "a required live adb stream exited during startup"
done

if [[ -n "$ota_interface" ]]; then
	tcpdump_bin=${TCPDUMP_BIN:-/usr/sbin/tcpdump}
	[[ -x "$tcpdump_bin" ]] || note_failure "tcpdump is unavailable: $tcpdump_bin"
	command -v iw >"$host_out/ota-iw-path.txt" 2>&1 ||
		note_failure "host iw is unavailable for OTA preflight"
	ip -details link show "$ota_interface" >"$host_out/ota-interface.log" 2>&1 ||
		note_failure "external OTA interface is unavailable: $ota_interface"
	grep -Eq '<([^>]*,)?UP(,[^>]*)?>' "$host_out/ota-interface.log" ||
		note_failure "external OTA interface is not UP: $ota_interface"
	iw dev "$ota_interface" info >"$host_out/ota-iw-info.log" 2>&1 ||
		note_failure "could not query external OTA interface with iw"
	grep -q '^[[:space:]]*type monitor$' "$host_out/ota-iw-info.log" ||
		note_failure "external OTA interface is not in monitor mode"
	ota_frequency=$(sed -n \
		's/.*(\([0-9][0-9]*\) MHz).*/\1/p' \
		"$host_out/ota-iw-info.log" | head -n 1)
	{
		echo "target_frequency_mhz=${target_frequency:-unavailable}"
		echo "ota_frequency_mhz=${ota_frequency:-unavailable}"
	} >"$host_out/ota-frequency-check.txt"
	[[ -n "$target_frequency" && "$ota_frequency" == "$target_frequency" ]] ||
		note_failure "external OTA frequency does not match the device baseline"
	if [[ "$failure_count" -eq 0 ]]; then
		pcap_path=$host_out/ota-capture.pcap
		"$tcpdump_bin" -i "$ota_interface" -U -s 0 -w "$pcap_path" \
			>"$host_out/ota-tcpdump.stdout" \
			2>"$host_out/ota-tcpdump.stderr" &
		pcap_pid=$!
		sleep 2
		kill -0 "$pcap_pid" 2>/dev/null ||
			note_failure "external tcpdump exited during startup"
	fi
fi

if [[ "$failure_count" -ne 0 ]]; then
	{
		echo "overall_verdict=PRECHECK_FAIL"
		echo "failure_count=$failure_count"
	} >"$host_out/host-result.txt"
	finalize_host 5
fi

remote_device=$remote_dir/run_consolidated_device.sh
remote_sender=$remote_dir/send_frame_once
remote_iface_probe=$remote_dir/hcx_iface_probe
timeout -k 20 "$test_timeout" "${ADB[@]}" shell su -c \
	"$remote_group_runner $remote_test_pidfile $remote_device S $stage_scope --clean-boot --authorized-isolated-test $authorized_bssid $remote_sender $remote_iface_probe $host_token" \
	>"$host_out/test.stdout" 2>"$host_out/test.stderr"
test_transport_rc=$?
printf '%s\n' "$test_transport_rc" >"$host_out/test.transport-exit-code"
[[ "$test_transport_rc" -ne 124 && "$test_transport_rc" -ne 137 ]] ||
	note_failure "device test exceeded host timeout"
if remote_stop_pidfile "$remote_test_pidfile" run_consolidated_device.sh \
	remote-test-immediate; then
	remote_test_stop_confirmed=true
else
	note_failure "remote device test process group was not stopped immediately"
fi
test_rc=255
if remote_read_rc "$remote_test_rcfile" test; then
	test_rc=$remote_rc_value
	test_rc_source=sidecar
else
	test_rc_source=unavailable
	note_failure "device test did not produce a valid atomic exit-code sidecar"
fi
printf '%s\n' "$test_rc" >"$host_out/test.exit-code"
	force_gate_off immediate-post-test ||
		note_failure "could not disable and verify the force-RAW gate immediately after the test"
sleep 2
stop_pcap

wait_rc=0
timeout 240 "${ADB[@]}" wait-for-device >"$host_out/adb-wait.log" 2>&1 || wait_rc=$?
printf '%s\n' "$wait_rc" >"$host_out/adb-wait.exit-code"
[[ "$wait_rc" -eq 0 ]] || note_failure "device did not return to adb"
boot_complete=false
if [[ "$wait_rc" -eq 0 ]]; then
	for ((boot_wait = 0; boot_wait < 240; boot_wait++)); do
		boot_value=$("${ADB[@]}" shell getprop sys.boot_completed 2>/dev/null |
			tr -d '\r\n')
		if [[ "$boot_value" == 1 ]]; then
			boot_complete=true
			break
		fi
		sleep 1
	done
fi
printf 'boot_complete=%s\nwait_seconds=%s\n' "$boot_complete" \
	"${boot_wait:-240}" >"$host_out/post-boot-wait.txt"
[[ "$boot_complete" == true ]] || note_failure "post-test Android boot did not complete"

post_root=$(timeout 30 "${ADB[@]}" shell su -c 'id -u' 2>/dev/null |
	tr -d '\r\n')
printf '%s\n' "$post_root" >"$host_out/post-root.txt"
[[ "$post_root" == 0 ]] || note_failure "post-test root shell is unavailable"
	force_gate_off post-adb-recovery ||
		note_failure "could not disable and verify the force-RAW gate after the test"
post_boot_id=$(timeout 30 "${ADB[@]}" shell cat \
	/proc/sys/kernel/random/boot_id 2>/dev/null | tr -d '\r\n')
printf '%s\n' "$post_boot_id" >"$host_out/post-boot-id.txt"
if [[ ! "$post_boot_id" =~ ^[0-9a-f-]{36}$ ]]; then
	boot_relation=unknown
	note_failure "post-test boot ID is unavailable"
elif [[ "$post_boot_id" == "$pre_boot_id" ]]; then
	boot_relation=same
else
	boot_relation=changed
	preboot_remote_groups_expired=true
	remote_test_stop_confirmed=true
	printf 'old_boot_id=%s\nnew_boot_id=%s\nremote_group_state=expired\n' \
		"$pre_boot_id" "$post_boot_id" \
		>"$host_out/preboot-remote-groups-expired.txt"
	note_failure "device rebooted during the consolidated test"
fi
printf '%s\n' "$boot_relation" >"$host_out/boot-relation.txt"
if [[ "$remote_test_stop_confirmed" == false &&
      "$preboot_remote_groups_expired" == false ]]; then
	if remote_stop_pidfile "$remote_test_pidfile" run_consolidated_device.sh \
		remote-test-post-recovery; then
		remote_test_stop_confirmed=true
	else
		note_failure "remote device test process group remained unconfirmed after adb recovery"
	fi
fi
if [[ "$remote_test_stop_confirmed" == false ]]; then
	note_failure "continuing evidence collection with an unconfirmed remote test group"
fi

device_out=$(sed -n 's/^OUTPUT_DIR=//p' "$host_out/test.stdout" | head -n 1 |
	tr -d '\r')
printf '%s\n' "$device_out" >"$host_out/device-output-path.txt"
pull_device_rc=1
case "$device_out" in
	/data/local/tmp/qcacld-consolidated-${expected_build_short}-*)
		"${ADB[@]}" pull "$device_out" "$host_out/device-output" \
			>"$host_out/pull-device-output.log" 2>&1
		pull_device_rc=$?
		;;
	*) note_failure "device test did not report a valid unique output path" ;;
esac
printf '%s\n' "$pull_device_rc" >"$host_out/pull-device-output.exit-code"
[[ "$pull_device_rc" -eq 0 ]] || note_failure "device test output pull failed"
device_target_frequency=
if [[ "$pull_device_rc" -eq 0 &&
      -f "$host_out/device-output/baseline-frequency-mhz.txt" ]]; then
	device_target_frequency=$(tr -d '\r\n' \
		<"$host_out/device-output/baseline-frequency-mhz.txt")
	printf '%s\n' "$device_target_frequency" \
		>"$host_out/device-target-frequency-mhz.txt"
	[[ "$device_target_frequency" == "$target_frequency" ]] ||
		note_failure "device runtime target frequency changed after host preflight"
	if [[ -n "$ota_interface" ]]; then
		[[ "$device_target_frequency" == "$ota_frequency" ]] ||
			note_failure "OTA interface did not match the device runtime target"
	fi
fi

device_result_rc=
device_result_kind=missing
if [[ "$pull_device_rc" -eq 0 && -f "$host_out/device-output/result.txt" ]]; then
	if grep -q '^result=success$' "$host_out/device-output/result.txt"; then
		device_result_rc=0
		device_result_kind=success
	else
		device_result_rc=$(sed -n 's/^failure_code=//p' \
			"$host_out/device-output/result.txt" | head -n 1)
		if [[ "$device_result_rc" =~ ^[0-9]+$ && "$device_result_rc" -le 255 ]]; then
			device_result_kind=failure
		else
			device_result_rc=
			device_result_kind=invalid
		fi
	fi
fi
printf 'kind=%s\nexit_code=%s\n' "$device_result_kind" \
	"${device_result_rc:-unavailable}" >"$host_out/device-result-status.txt"
if [[ -n "$device_result_rc" ]]; then
	if [[ "$test_rc_source" == unavailable ]]; then
		test_rc=$device_result_rc
		test_rc_source=device-result
	elif [[ "$test_rc" -ne "$device_result_rc" ]]; then
		note_failure "atomic sidecar and device result exit codes disagree"
	fi
fi
printf '%s\n' "$test_rc" >"$host_out/test.exit-code"
printf '%s\n' "$test_rc_source" >"$host_out/test.exit-code-source"
if [[ "$test_rc" -ne 0 ]]; then
	note_failure "device test failed with exit code $test_rc before completing all required checks"
fi

device_run_token=$host_token
if [[ "$pull_device_rc" -eq 0 && -f "$host_out/device-output/run-token.txt" ]]; then
	device_run_token=$(tr -d '\r\n' <"$host_out/device-output/run-token.txt")
fi
case "$device_run_token" in
	''|*[!A-Za-z0-9._-]*)
		note_failure "device run token is invalid"
		device_run_token=$host_token
		;;
esac

collect_and_pull()
{
	local label=$1
	local remote_script=$2
	shift 2
	[[ -z "$active_collector_pidfile" ]] || return 31
	local stdout=$host_out/$label-collector.stdout
	local stderr=$host_out/$label-collector.stderr
	local collector_rc collector_transport_rc tar_path tar_sha local_tar actual_sha
	local verify_tmp archive_root cross_name
	local collector_pidfile collector_expected collector_stop_rc stage_rc
	collector_pidfile=$remote_dir/$label-collector.pid
	collector_expected=$(basename "$remote_script")
	active_collector_pidfile=$collector_pidfile
	active_collector_expected=$collector_expected
	active_collector_label=$label-collector
	timeout -k 20 600 "${ADB[@]}" shell su -c \
		"$remote_group_runner $collector_pidfile $remote_script $*" \
		>"$stdout" 2>"$stderr"
	collector_transport_rc=$?
	printf '%s\n' "$collector_transport_rc" \
		>"$host_out/$label-collector.transport-exit-code"
	collector_stop_rc=0
	remote_stop_pidfile "$collector_pidfile" "$collector_expected" \
		"$label-collector" || collector_stop_rc=$?
	printf '%s\n' "$collector_stop_rc" \
		>"$host_out/$label-collector-stop.exit-code"
	stage_rc=0
	if [[ "$collector_stop_rc" -ne 0 ]]; then
		stage_rc=30
	else
		clear_active_collector
	fi
	collector_rc=255
	if remote_read_rc "${collector_pidfile%.pid}.rc" "$label-collector"; then
		collector_rc=$remote_rc_value
	else
		[[ "$stage_rc" -ne 0 ]] || stage_rc=32
	fi
	printf '%s\n' "$collector_rc" >"$host_out/$label-collector.exit-code"
	tar_path=$(sed -n 's/^TAR_PATH=//p' "$stdout" | tail -n 1 | tr -d '\r')
	tar_sha=$(sed -n 's/^TAR_SHA256=//p' "$stdout" | tail -n 1 | tr -d '\r')
	printf 'path=%s\nsha256=%s\n' "$tar_path" "$tar_sha" \
		>"$host_out/$label-archive-device.txt"
	case "$tar_path" in
		/data/local/tmp/qcacld-*.tar.gz) ;;
		*) return 20 ;;
	esac
	[[ "$tar_path" == *"$(printf '%s' "$device_run_token" | tr -c 'A-Za-z0-9._-' '_')"* ]] ||
		return 21
	[[ "$tar_sha" =~ ^[0-9a-f]{64}$ ]] || return 22
	local_tar=$host_out/$label-device-evidence.tar.gz
	"${ADB[@]}" pull "$tar_path" "$local_tar" \
		>"$host_out/pull-$label.log" 2>&1 || return 23
	actual_sha=$(sha256sum "$local_tar" | awk '{print $1}')
	printf '%s\n' "$actual_sha" >"$host_out/$label-archive-host.sha256"
	[[ "$actual_sha" == "$tar_sha" ]] || return 24
	tar -tzf "$local_tar" >"$host_out/$label-archive-list.txt" || return 25
	verify_tmp=$(mktemp -d)
	tar -xzf "$local_tar" -C "$verify_tmp" || {
		rm -rf -- "$verify_tmp"
		return 26
	}
	archive_root=$(find "$verify_tmp" -mindepth 1 -maxdepth 1 -type d |
		head -n 1)
	[[ -n "$archive_root" && -f "$archive_root/SHA256SUMS" ]] || {
		rm -rf -- "$verify_tmp"
		return 27
	}
	(cd "$archive_root" && sha256sum -c SHA256SUMS) \
		>"$host_out/$label-internal-sha-check.log" 2>&1 || {
		rm -rf -- "$verify_tmp"
		return 28
	}
	if [[ -f "$archive_root/result.txt" ]]; then
		cp -p "$archive_root/result.txt" "$host_out/$label-result.txt" || {
			rm -rf -- "$verify_tmp"
			return 29
		}
	fi
	for cross_name in frame-matrix.tsv workflow-matrix.tsv phase-matrix.tsv \
		sender-sha256.txt iface-probe-sha256.txt run-token.txt \
		random-monitor-ifindex-transition.txt \
		random-managed-return-ifindex-transition.txt \
		specified-monitor-ifindex-transition.txt \
		specified-managed-return-ifindex-transition.txt \
		failure-managed-ifindex-transition.txt \
		failure-managed-recovery-status.txt; do
		if [[ -f "$archive_root/test-crossref/$cross_name" ]]; then
			cp -p "$archive_root/test-crossref/$cross_name" \
				"$host_out/$label-$cross_name" || {
				rm -rf -- "$verify_tmp"
				return 29
			}
		fi
	done
	rm -rf -- "$verify_tmp"
	[[ "$stage_rc" -eq 0 ]] || return "$stage_rc"
	[[ "$collector_rc" -eq 0 ]] || return "$collector_rc"
	return 0
}

debugfs_rc=0
collect_and_pull debugfs "$remote_dir/collect_qcacld_debugfs.sh" \
	"$device_run_token" "$pre_boot_id" || debugfs_rc=$?
printf '%s\n' "$debugfs_rc" >"$host_out/debugfs-stage.exit-code"
[[ "$debugfs_rc" -eq 0 ]] || note_failure "debugfs collector/pull verification failed"
if [[ -n "$active_collector_pidfile" ]] &&
	! retry_active_collector_stop before-evidence; then
	note_failure "debugfs collector remained active; evidence collector was not started"
fi

evidence_rc=31
if [[ -z "$active_collector_pidfile" ]]; then
	evidence_rc=0
	collect_and_pull evidence "$remote_dir/collect_qcacld_evidence.sh" \
		"$device_run_token" "$pre_boot_id" \
		"${device_out:-/data/local/tmp/none}" || evidence_rc=$?
fi
printf '%s\n' "$evidence_rc" >"$host_out/evidence-stage.exit-code"
[[ "$evidence_rc" -eq 0 ]] || note_failure "full evidence collector/pull verification failed"
if [[ -n "$active_collector_pidfile" ]] &&
	! retry_active_collector_stop before-post; then
	note_failure "a prior collector remained active; post collector was not started"
fi

post_rc=31
if [[ -z "$active_collector_pidfile" ]]; then
	post_rc=0
	collect_and_pull post "$remote_dir/collect_post_boot.sh" \
		"$device_run_token" "$pre_boot_id" consolidated || post_rc=$?
fi
printf '%s\n' "$post_rc" >"$host_out/post-stage.exit-code"
[[ "$post_rc" -eq 0 ]] || note_failure "post-boot collector/pull verification failed"
if [[ -n "$active_collector_pidfile" ]] &&
	! retry_active_collector_stop before-final-collection; then
	note_failure "collector process group remained active at the final collection boundary"
fi

for ((stream_i = 0; stream_i < ${#stream_pids[@]}; stream_i++)); do
	stream_pid=${stream_pids[$stream_i]}
	stream_name=${stream_names[$stream_i]}
	if ! kill -0 "$stream_pid" 2>/dev/null; then
		if [[ "$stream_name" == dbglog_block ]]; then
			echo "stream_status=ended-during-driver-reconstruction" \
				>"$host_out/live-$stream_name.status"
		else
			note_failure "live $stream_name evidence stream exited before collectors completed"
		fi
	fi
done
for collector_label in debugfs evidence post; do
	collector_result=$host_out/$collector_label-result.txt
	[[ -f "$collector_result" ]] || {
		note_failure "$collector_label archive lacks result provenance"
		continue
	}
	grep -q '^boot_relation=same$' "$collector_result" ||
		note_failure "$collector_label collector ran on a different boot"
	grep -Fqx "run_token=$device_run_token" "$collector_result" ||
		note_failure "$collector_label collector run token does not match the test"
done
final_boot_id=$(timeout 30 "${ADB[@]}" shell cat \
	/proc/sys/kernel/random/boot_id 2>/dev/null | tr -d '\r\n')
printf '%s\n' "$final_boot_id" >"$host_out/final-boot-id.txt"
[[ "$final_boot_id" == "$pre_boot_id" ]] ||
	note_failure "boot ID changed while collectors were running"
force_gate_off final ||
	note_failure "force-RAW gate was not disabled at final collection boundary"
stop_streams || note_failure "one or more remote evidence stream groups did not stop"

read_runtime_sha_record()
{
	local record_path=$1
	local expected_path=$2
	local parsed_sha
	runtime_record_sha=
	[[ -f "$record_path" ]] || return 1
	parsed_sha=$(awk -v expected_path="$expected_path" '
		NR == 1 && NF == 2 && $2 == expected_path {
			print $1
			valid = 1
			next
		}
		{ invalid = 1 }
		END { exit (NR != 1 || !valid || invalid) ? 1 : 0 }
	' "$record_path") || return 1
	[[ "$parsed_sha" =~ ^[0-9a-f]{64}$ ]] || return 1
	runtime_record_sha=$parsed_sha
}

verify_runtime_helper_hash()
{
	local helper_name=$1
	local input_name=$2
	local remote_path=$3
	local input_path=$host_out/inputs/$input_name
	local identity_path=$host_out/identity-$input_name.txt
	local direct_record=$host_out/device-output/$helper_name-sha256.txt
	local evidence_record=$host_out/evidence-$helper_name-sha256.txt
	local input_sha=unavailable
	local push_host_sha=unavailable
	local push_remote_sha=unavailable
	local direct_sha=unavailable
	local evidence_sha=unavailable
	local record_match=no
	local helper_status=FAIL

	input_sha=$(sha256sum "$input_path" 2>/dev/null | awk '{print $1}')
	if [[ -f "$identity_path" ]]; then
		push_host_sha=$(sed -n 's/^host=//p' "$identity_path")
		push_remote_sha=$(sed -n 's/^remote=//p' "$identity_path")
	fi
	if read_runtime_sha_record "$direct_record" "$remote_path"; then
		direct_sha=$runtime_record_sha
	fi
	if read_runtime_sha_record "$evidence_record" "$remote_path"; then
		evidence_sha=$runtime_record_sha
	fi
	if [[ -f "$direct_record" && -f "$evidence_record" ]] &&
		cmp -s "$direct_record" "$evidence_record"; then
		record_match=yes
	fi
	if [[ "$input_sha" =~ ^[0-9a-f]{64}$ &&
	      "$push_host_sha" =~ ^[0-9a-f]{64}$ &&
	      "$push_remote_sha" =~ ^[0-9a-f]{64}$ &&
	      "$direct_sha" =~ ^[0-9a-f]{64}$ &&
	      "$evidence_sha" =~ ^[0-9a-f]{64}$ &&
	      "$input_sha" == "$push_host_sha" &&
	      "$input_sha" == "$push_remote_sha" &&
	      "$input_sha" == "$direct_sha" &&
	      "$input_sha" == "$evidence_sha" &&
	      "$record_match" == yes ]]; then
		helper_status=PASS
	fi
	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$helper_name" \
		"$input_sha" "$push_host_sha" "$push_remote_sha" "$direct_sha" \
		"$evidence_sha" "$record_match" "$helper_status" \
		>>"$host_out/runtime-helper-hash-crossref.tsv"
	[[ "$helper_status" == PASS ]]
}

printf 'helper\tinput_sha256\tpush_host_sha256\tpush_remote_sha256\tdevice_runtime_sha256\tevidence_runtime_sha256\trecord_match\tstatus\n' \
	>"$host_out/runtime-helper-hash-crossref.tsv"
runtime_helper_hash_rc=0
verify_runtime_helper_hash sender send_frame_once "$remote_sender" ||
	runtime_helper_hash_rc=1
verify_runtime_helper_hash iface-probe hcx_iface_probe "$remote_iface_probe" ||
	runtime_helper_hash_rc=1
if [[ "$runtime_helper_hash_rc" -eq 0 ]]; then
	runtime_helper_hash_status=PASS
else
	runtime_helper_hash_status=FAIL
	note_failure "runtime sender/interface-probe hashes do not match preserved and pushed inputs"
fi
printf '%s\n' "$runtime_helper_hash_rc" \
	>"$host_out/runtime-helper-hash-crossref.exit-code"
printf '%s\n' "$runtime_helper_hash_status" \
	>"$host_out/runtime-helper-hash-crossref.status"

transition_crossref_rc=0
printf 'record\texpected_iftype\texpected_con_mode\tsource_ifindex\ttarget_ifindex\tifindex_changed\tdirect_archive_match\tstatus\n' \
	>"$host_out/ifindex-transition-crossref.tsv"
for transition_spec in \
	'random-monitor-ifindex-transition.txt|monitor|4|' \
	'random-managed-return-ifindex-transition.txt|managed|0|' \
	'specified-monitor-ifindex-transition.txt|monitor|4|' \
	'specified-managed-return-ifindex-transition.txt|managed|0|failure-managed-ifindex-transition.txt'; do
	IFS='|' read -r transition_name transition_type transition_con \
		transition_failure_name \
		<<<"$transition_spec"
	transition_direct=$host_out/device-output/$transition_name
	transition_evidence=$host_out/evidence-$transition_name
	transition_record=$transition_name
	if [[ -n "$transition_failure_name" &&
	      ( ! -f "$transition_direct" || ! -f "$transition_evidence" ) ]]; then
		transition_failure_direct=$host_out/device-output/$transition_failure_name
		transition_failure_evidence=$host_out/evidence-$transition_failure_name
		recovery_direct=$host_out/device-output/failure-managed-recovery-status.txt
		recovery_evidence=$host_out/evidence-failure-managed-recovery-status.txt
		if [[ -f "$transition_failure_direct" &&
		      -f "$transition_failure_evidence" &&
		      -f "$recovery_direct" && -f "$recovery_evidence" ]] &&
		   cmp -s "$recovery_direct" "$recovery_evidence" &&
		   grep -q '^status=PASS$' "$recovery_direct"; then
			transition_direct=$transition_failure_direct
			transition_evidence=$transition_failure_evidence
			transition_record=$transition_failure_name
		fi
	fi
	transition_source=unavailable
	transition_target=unavailable
	transition_changed=unavailable
	transition_match=no
	transition_status=FAIL
	if [[ -f "$transition_direct" && -f "$transition_evidence" ]] &&
	   cmp -s "$transition_direct" "$transition_evidence"; then
		transition_match=yes
		transition_source=$(sed -n 's/^source_ifindex=//p' \
			"$transition_direct")
		transition_target=$(sed -n 's/^target_ifindex=//p' \
			"$transition_direct")
		transition_changed=$(sed -n 's/^ifindex_changed=//p' \
			"$transition_direct")
		if [[ "$transition_source" =~ ^[1-9][0-9]*$ &&
		      "$transition_target" =~ ^[1-9][0-9]*$ &&
		      "$transition_changed" =~ ^[01]$ ]] &&
		   [[ "$(grep -c '^status=ready$' "$transition_direct")" -eq 1 &&
		      "$(grep -c '^interface=wlan0$' "$transition_direct")" -eq 1 &&
		      "$(grep -c "^target_iftype=$transition_type$" \
			"$transition_direct")" -eq 1 &&
		      "$(grep -c '^target_up=1$' "$transition_direct")" -eq 1 &&
		      "$(grep -c "^target_con_mode=$transition_con$" \
			"$transition_direct")" -eq 1 ]]; then
			if [[ "$transition_source" == "$transition_target" ]]; then
				transition_expected_changed=0
			else
				transition_expected_changed=1
			fi
			if [[ "$transition_changed" == \
			      "$transition_expected_changed" ]]; then
				transition_status=PASS
			fi
		fi
	fi
	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
		"$transition_record" "$transition_type" "$transition_con" \
		"$transition_source" "$transition_target" "$transition_changed" \
		"$transition_match" "$transition_status" \
		>>"$host_out/ifindex-transition-crossref.tsv"
	[[ "$transition_status" == PASS ]] || transition_crossref_rc=1
done
if [[ "$transition_crossref_rc" -ne 0 ]]; then
	note_failure "interface transition source/target evidence is missing, malformed, or inconsistent"
fi
printf '%s\n' "$transition_crossref_rc" \
	>"$host_out/ifindex-transition-crossref.exit-code"

lifecycle_status=NOT_APPLICABLE
if [[ "$stage_scope" == 0 ]]; then
	fixed_matrix_rows=0
	workflow_matrix_rows=0
	phase_matrix_rows=0
	phase_matrix_status=NOT_APPLICABLE
	phase_matrix_verifier_rc=not_run
	phase_matrix_verifier_status=NOT_APPLICABLE
	frame_attempt_status=NOT_ATTEMPTED
	device_matrix_rc=not_run
	device_matrix_status=NOT_APPLICABLE
	workflow_matrix_status=NOT_APPLICABLE
	dp_ownership_status=NOT_ATTEMPTED
	dp_event_rows=0
	dp_status_valid_rows=0
	dp_reclaimed_rows=0
	matrix_crossref_rc=not_run
	matrix_crossref_status=NOT_APPLICABLE
	matrix_crossref_checked=0
	matrix_crossref_failed=0
	dp_verdict=NOT_ATTEMPTED
	ota_verdict=NOT_APPLICABLE
	ota_scope=not-applicable
	ota_verify_rc=not_run
	ota_expected_frames=0
	ota_observed_frames=0
	stage0_result=$host_out/device-output/result.txt
	stage0_stats=$host_out/device-output/frame-inject-stats-after.log
	lifecycle_status=FAIL
	if [[ -f "$stage0_result" && -f "$stage0_stats" ]] &&
	   grep -Fqx 'result=success' "$stage0_result" &&
	   grep -Fqx 'stage_scope=0' "$stage0_result" &&
	   grep -Fqx 'fixed_frame_count=0' "$stage0_result" &&
	   grep -Fqx 'workflow_frame_count=0' "$stage0_result" &&
	   grep -Fqx 'total_transmit_count=0' "$stage0_result" &&
	   grep -Fqx 'lifecycle_requested=20' "$stage0_result" &&
	   grep -Fqx 'lifecycle_completed=20' "$stage0_result" &&
	   grep -Fqx 'lifecycle_last_ret=0' "$stage0_result" &&
	   grep -Fqx 'dp_tx_status_events=0' "$stage0_result" &&
	   grep -Fqx 'dp_reclaimed=0' "$stage0_result" &&
	   grep -Fqx 'dp_global_flushes=0' "$stage0_result" &&
	   grep -Fqx 'backend_busy=0' "$stage0_result" &&
	   grep -Fqx 'state=disabled' "$stage0_stats" &&
	   grep -Fqx 'helper_present=0' "$stage0_stats" &&
	   grep -Fqx 'tx_inflight=0' "$stage0_stats" &&
	   grep -Fqx 'submit_pending=0' "$stage0_stats"; then
		lifecycle_status=PASS
	else
		note_failure "Stage 0 lifecycle result is missing or inconsistent"
	fi
	overall_rc=0
	[[ "$lifecycle_status" == PASS && "$test_rc" -eq 0 &&
	   "$boot_relation" == same ]] || overall_rc=10
	[[ "$failure_count" -eq 0 ]] || overall_rc=11
	if [[ "$overall_rc" -eq 0 ]]; then
		overall_verdict=LIFECYCLE_PASS
	else
		overall_verdict=FAIL
	fi
else
matrix_data_rows()
{
	local matrix_path=$1
	if [[ ! -f "$matrix_path" ]]; then
		echo 0
		return 0
	fi
	awk 'END { print (NR > 0 ? NR - 1 : 0) }' "$matrix_path"
}

verify_phase_matrix_rows()
{
	local matrix_path=$1
	awk -F '\t' '
		function decimal(value) { return value ~ /^[0-9]+$/ }
		BEGIN {
			name[1] = "management"; start[1] = 1; end[1] = 18; count[1] = 18
			name[2] = "data"; start[2] = 19; end[2] = 25; count[2] = 7
			name[3] = "long-control"; start[3] = 26; end[3] = 31; count[3] = 6
			name[4] = "cts"; start[4] = 32; end[4] = 32; count[4] = 1
			name[5] = "ack"; start[5] = 33; end[5] = 33; count[5] = 1
		}
		NR == 1 {
			if ($0 != "phase\tstart_index\tend_index\texpected_frames\tcompleted_frames\tgate_on_verified\tgate_off_verified\tstatus")
				bad = 1
			next
		}
		{
			i = NR - 1
			if (i > 5 || NF != 8 || $1 != name[i] ||
			    !decimal($2) || !decimal($3) || !decimal($4) ||
			    !decimal($5) || $2 + 0 != start[i] || $3 + 0 != end[i] ||
			    $4 + 0 != count[i] || $5 + 0 != count[i] ||
			    $6 != "1" || $7 != "1" ||
			    $8 != "PASS")
				bad = 1
		}
		END { exit (NR < 1 || bad) ? 1 : 0 }
	' "$matrix_path"
}

write_phase_status()
{
	local phase_name=$1
	local completed_before=$2
	local expected=$3
	local available=$4
	local completed=0
	local status=NOT_ATTEMPTED
	if [[ "$available" -gt "$completed_before" ]]; then
		completed=$((available - completed_before))
		[[ "$completed" -le "$expected" ]] || completed=$expected
		if [[ "$completed" -eq "$expected" ]]; then
			status=PASS
		else
			status=PARTIAL
		fi
	fi
	printf '%s\t%s\t%s\t%s\n' "$phase_name" "$expected" "$completed" \
		"$status" >>"$host_out/phase-status.tsv"
}

fixed_matrix=$host_out/device-output/frame-matrix.tsv
workflow_matrix=$host_out/device-output/workflow-matrix.tsv
phase_matrix=$host_out/device-output/phase-matrix.tsv
fixed_matrix_rows=$(matrix_data_rows "$fixed_matrix")
workflow_matrix_rows=$(matrix_data_rows "$workflow_matrix")
phase_matrix_rows=$(matrix_data_rows "$phase_matrix")
printf 'phase\texpected_frames\tcompleted_frames\tstatus\n' \
	>"$host_out/phase-status.tsv"
write_phase_status management 0 18 "$fixed_matrix_rows"
write_phase_status data 18 7 "$fixed_matrix_rows"
write_phase_status long-control 25 6 "$fixed_matrix_rows"
write_phase_status cts 31 1 "$fixed_matrix_rows"
write_phase_status ack 32 1 "$fixed_matrix_rows"
write_phase_status hcxdumptool-workflow 0 34 "$workflow_matrix_rows"

phase_matrix_status=NOT_ATTEMPTED
frame_attempt_status=NOT_ATTEMPTED
phase_matrix_verifier_rc=125
phase_matrix_verifier_status=NOT_RUN
if [[ -f "$phase_matrix" ]]; then
	verify_phase_matrix_rows "$phase_matrix" \
		>"$host_out/phase-matrix-verifier.log" \
		2>"$host_out/phase-matrix-verifier.stderr"
	phase_matrix_verifier_rc=$?
	if [[ "$phase_matrix_verifier_rc" -eq 0 ]]; then
		phase_matrix_verifier_status=PASS
	else
		phase_matrix_verifier_status=FAIL
		note_failure "phase matrix rows do not match the fixed phase contract"
	fi
fi
printf '%s\n' "$phase_matrix_verifier_rc" \
	>"$host_out/phase-matrix-verifier.exit-code"
if [[ "$fixed_matrix_rows" -gt 33 || "$workflow_matrix_rows" -gt 34 ||
	  "$phase_matrix_rows" -gt 5 ]]; then
	phase_matrix_status=INVALID
	frame_attempt_status=INVALID
	note_failure "device matrices contain more rows than the fixed test contract"
elif [[ "$phase_matrix_verifier_status" == FAIL ]]; then
	phase_matrix_status=INVALID
	frame_attempt_status=INVALID
elif [[ "$fixed_matrix_rows" -eq 33 && "$workflow_matrix_rows" -eq 34 &&
	    "$phase_matrix_rows" -eq 5 && "$phase_matrix_verifier_status" == PASS ]]; then
	phase_matrix_status=COMPLETE
	frame_attempt_status=COMPLETE
elif [[ "$fixed_matrix_rows" -gt 0 || "$workflow_matrix_rows" -gt 0 ||
	    "$phase_matrix_rows" -gt 0 ]]; then
	phase_matrix_status=PARTIAL
	frame_attempt_status=PARTIAL
fi

device_matrix_rc=125
device_matrix_status=NOT_RUN
workflow_matrix_status=NOT_RUN
dp_ownership_status=NOT_RUN
dp_event_rows=0
dp_status_valid_rows=0
dp_reclaimed_rows=0
declare -a device_verify_args=()
if [[ "$fixed_matrix_rows" -eq 33 ]]; then
	device_verify_args=(device "$host_out/device-output" "$fixed_matrix")
	if [[ "$workflow_matrix_rows" -eq 34 ]]; then
		device_verify_args+=(--workflow-matrix "$workflow_matrix")
	fi
	python3 "$ota_verifier" "${device_verify_args[@]}" \
		>"$host_out/device-matrix-verifier.log" \
		2>"$host_out/device-matrix-verifier.stderr"
	device_matrix_rc=$?
	if [[ "$device_matrix_rc" -eq 0 ]]; then
		device_matrix_status=PASS
		if [[ "$workflow_matrix_rows" -eq 34 ]]; then
			workflow_matrix_status=PASS
		elif [[ "$workflow_matrix_rows" -gt 0 ]]; then
			workflow_matrix_status=PARTIAL
		fi
		dp_event_rows=$(sed -n 's/^dp_event_rows=//p' \
			"$host_out/device-matrix-verifier.log" | tail -n 1)
		dp_status_valid_rows=$(sed -n 's/^dp_status_valid_rows=//p' \
			"$host_out/device-matrix-verifier.log" | tail -n 1)
		dp_reclaimed_rows=$(sed -n 's/^dp_reclaimed_rows=//p' \
			"$host_out/device-matrix-verifier.log" | tail -n 1)
		if [[ "$dp_event_rows" =~ ^[0-9]+$ &&
		      "$dp_status_valid_rows" =~ ^[0-9]+$ &&
		      "$dp_reclaimed_rows" =~ ^[0-9]+$ &&
		      "$dp_event_rows" -eq $((fixed_matrix_rows + workflow_matrix_rows)) &&
		      "$dp_status_valid_rows" -eq "$dp_event_rows" &&
		      "$dp_reclaimed_rows" -eq "$dp_event_rows" ]]; then
			dp_ownership_status=PASS
		else
			dp_ownership_status=INVALID
			device_matrix_status=FAIL
		fi
	else
		device_matrix_status=FAIL
		[[ "$workflow_matrix_rows" -ne 34 ]] || workflow_matrix_status=FAIL
	fi
elif [[ "$fixed_matrix_rows" -gt 0 ]]; then
	device_matrix_status=PARTIAL
fi
if [[ "$workflow_matrix_rows" -gt 0 && "$workflow_matrix_status" == NOT_RUN ]]; then
	workflow_matrix_status=PARTIAL
fi
printf '%s\n' "$device_matrix_rc" >"$host_out/device-matrix-verifier.exit-code"
{
	echo "fixed_verifier=$device_matrix_status"
	echo "workflow_verifier=$workflow_matrix_status"
	echo "fixed_frames=$fixed_matrix_rows"
	echo "workflow_frames=$workflow_matrix_rows"
	echo "phase_rows=$phase_matrix_rows"
	echo "phase_matrix=$phase_matrix_status"
	echo "phase_verifier=$phase_matrix_verifier_status"
	echo "frames=$frame_attempt_status"
	echo "dp_ownership=$dp_ownership_status"
	echo "dp_event_rows=$dp_event_rows"
	echo "dp_status_valid_rows=$dp_status_valid_rows"
	echo "dp_reclaimed_rows=$dp_reclaimed_rows"
} >"$host_out/device-matrix-status.txt"
if [[ "$device_matrix_status" == FAIL || "$workflow_matrix_status" == FAIL ]]; then
	note_failure "the complete generated matrices failed semantic verification"
elif [[ "$test_rc" -eq 0 && "$phase_matrix_status" != COMPLETE ]]; then
	note_failure "device reported success without both complete frame matrices"
fi
if [[ "$dp_ownership_status" == INVALID ]]; then
	note_failure "direct-DP status/reclaim ownership counters are internally inconsistent"
fi

matrix_crossref_rc=125
matrix_crossref_status=NOT_RUN
matrix_crossref_checked=0
matrix_crossref_failed=0
: >"$host_out/frame-matrix-crossref.txt"
for matrix_name in frame-matrix.tsv workflow-matrix.tsv phase-matrix.tsv; do
	direct_matrix=$host_out/device-output/$matrix_name
	evidence_matrix=$host_out/evidence-$matrix_name
	[[ -f "$direct_matrix" ]] || continue
	matrix_crossref_checked=$((matrix_crossref_checked + 1))
	direct_matrix_sha=$(sha256sum "$direct_matrix" | awk '{print $1}')
	evidence_matrix_sha=missing
	if [[ -f "$evidence_matrix" ]]; then
		evidence_matrix_sha=$(sha256sum "$evidence_matrix" | awk '{print $1}')
	fi
	printf '%s_direct=%s\n%s_evidence_archive=%s\n' "$matrix_name" \
		"$direct_matrix_sha" "$matrix_name" "$evidence_matrix_sha" \
		>>"$host_out/frame-matrix-crossref.txt"
	[[ "$direct_matrix_sha" =~ ^[0-9a-f]{64}$ &&
	   "$direct_matrix_sha" == "$evidence_matrix_sha" ]] ||
		matrix_crossref_failed=1
done
if [[ "$matrix_crossref_checked" -gt 0 ]]; then
	direct_run_token=$(tr -d '\r\n' <"$host_out/device-output/run-token.txt" \
		2>/dev/null)
	evidence_run_token=$(tr -d '\r\n' <"$host_out/evidence-run-token.txt" \
		2>/dev/null)
	printf 'direct_run_token=%s\nevidence_run_token=%s\n' "$direct_run_token" \
		"$evidence_run_token" >>"$host_out/frame-matrix-crossref.txt"
	if [[ "$direct_run_token" != "$device_run_token" ||
	      "$evidence_run_token" != "$device_run_token" ]]; then
		matrix_crossref_failed=1
	fi
	if [[ "$matrix_crossref_failed" -eq 0 ]]; then
		matrix_crossref_rc=0
		matrix_crossref_status=PASS
	else
		matrix_crossref_rc=1
		matrix_crossref_status=FAIL
	fi
fi
printf '%s\n' "$matrix_crossref_rc" >"$host_out/frame-matrix-crossref.exit-code"
printf '%s\n' "$matrix_crossref_status" \
	>"$host_out/frame-matrix-crossref.status"
if [[ "$matrix_crossref_status" == FAIL ]]; then
	note_failure "direct and evidence-archive matrices do not match"
elif [[ "$matrix_crossref_status" == NOT_RUN &&
	    "$frame_attempt_status" != NOT_ATTEMPTED ]]; then
	note_failure "frame matrices exist but archive cross-reference was unavailable"
fi

dp_verdict=NOT_ATTEMPTED
if [[ "$device_matrix_status" == FAIL || "$workflow_matrix_status" == FAIL ||
	  "$dp_ownership_status" == INVALID ||
	  "$phase_matrix_status" == INVALID ||
	  "$runtime_helper_hash_status" == FAIL ]]; then
	dp_verdict=FAIL
elif [[ "$phase_matrix_status" == COMPLETE && "$device_matrix_rc" -eq 0 &&
	    "$matrix_crossref_rc" -eq 0 && "$boot_relation" == same ]]; then
	dp_verdict=PASS
elif [[ "$frame_attempt_status" != NOT_ATTEMPTED ]]; then
	dp_verdict=PARTIAL
fi

ota_verdict=UNPROVEN
ota_scope=not-run
ota_verify_rc=not_run
ota_expected_frames=0
ota_observed_frames=0
if [[ -n "$pcap_path" && -s "$pcap_path" &&
	  "$device_matrix_status" == PASS ]]; then
	declare -a ota_verify_args=(ota "$pcap_path" "$host_out/device-output" \
		"$fixed_matrix" "$host_out/ota-frame-matrix.tsv")
	ota_scope=fixed-only
	if [[ "$workflow_matrix_status" == PASS ]]; then
		ota_verify_args+=(--workflow-matrix "$workflow_matrix")
		ota_scope=fixed-and-workflow
	fi
	python3 "$ota_verifier" "${ota_verify_args[@]}" \
		>"$host_out/ota-verifier.log" \
		2>"$host_out/ota-verifier.stderr"
	ota_verify_rc=$?
	ota_expected_frames=$(sed -n 's/^expected_frames=//p' \
		"$host_out/ota-verifier.log" | tail -n 1)
	ota_observed_frames=$(sed -n 's/^exact_frames_observed=//p' \
		"$host_out/ota-verifier.log" | tail -n 1)
	[[ "$ota_expected_frames" =~ ^[0-9]+$ ]] || ota_expected_frames=0
	[[ "$ota_observed_frames" =~ ^[0-9]+$ ]] || ota_observed_frames=0
	if [[ "$ota_verify_rc" -eq 0 && "$ota_scope" == fixed-and-workflow ]]; then
		ota_verdict=PASS
	elif [[ "$ota_verify_rc" -le 1 && "$ota_observed_frames" -gt 0 ]]; then
		ota_verdict=PARTIAL
	elif [[ "$ota_verify_rc" -gt 1 ]]; then
		ota_verdict=FAIL
	fi
fi

if [[ "$ota_verdict" == FAIL ]]; then
	note_failure "external OTA verifier rejected the capture or evidence contract"
fi
overall_rc=0
[[ "$dp_verdict" == PASS ]] || overall_rc=10
[[ "$failure_count" -eq 0 ]] || overall_rc=11
if [[ "$require_ota" == true && "$ota_verdict" != PASS ]]; then
	overall_rc=12
	note_failure "required external OTA matrix did not pass"
fi
overall_verdict=FAIL
if [[ "$overall_rc" -eq 0 ]]; then
	case "$ota_verdict" in
		PASS) overall_verdict=PASS ;;
		PARTIAL) overall_verdict=DP_PASS_OTA_PARTIAL ;;
		UNPROVEN) overall_verdict=DP_PASS_OTA_UNPROVEN ;;
	esac
fi
fi
{
	echo "overall_verdict=$overall_verdict"
	echo "stage_scope=$stage_scope"
	echo "lifecycle_status=$lifecycle_status"
	echo "dp_verdict=$dp_verdict"
	echo "dp_ownership_status=$dp_ownership_status"
	echo "dp_event_rows=$dp_event_rows"
	echo "dp_status_valid_rows=$dp_status_valid_rows"
	echo "dp_reclaimed_rows=$dp_reclaimed_rows"
	echo "ota_verdict=$ota_verdict"
	echo "ota_scope=$ota_scope"
	echo "ota_verifier_exit_code=$ota_verify_rc"
	echo "ota_expected_frames=$ota_expected_frames"
	echo "ota_exact_frames_observed=$ota_observed_frames"
	echo "test_exit_code=$test_rc"
	echo "test_exit_code_source=$test_rc_source"
	echo "pre_boot_id=$pre_boot_id"
	echo "post_boot_id=$post_boot_id"
	echo "boot_relation=$boot_relation"
	echo "device_output_pull_exit_code=$pull_device_rc"
	echo "debugfs_stage_exit_code=$debugfs_rc"
	echo "evidence_stage_exit_code=$evidence_rc"
	echo "post_stage_exit_code=$post_rc"
	echo "device_matrix_verifier_exit_code=$device_matrix_rc"
	echo "device_matrix_status=$device_matrix_status"
	echo "workflow_matrix_status=$workflow_matrix_status"
	echo "fixed_matrix_frames=$fixed_matrix_rows"
	echo "workflow_matrix_frames=$workflow_matrix_rows"
	echo "phase_matrix_rows=$phase_matrix_rows"
	echo "phase_matrix_status=$phase_matrix_status"
	echo "phase_matrix_verifier_exit_code=$phase_matrix_verifier_rc"
	echo "phase_matrix_verifier_status=$phase_matrix_verifier_status"
	echo "frame_attempt_status=$frame_attempt_status"
		echo "frame_matrix_crossref_exit_code=$matrix_crossref_rc"
		echo "frame_matrix_crossref_status=$matrix_crossref_status"
		echo "runtime_helper_hash_crossref_exit_code=$runtime_helper_hash_rc"
		echo "runtime_helper_hash_crossref_status=$runtime_helper_hash_status"
	echo "remote_test_stop_confirmed=$remote_test_stop_confirmed"
	echo "preboot_remote_groups_expired=$preboot_remote_groups_expired"
	echo "failure_count=$failure_count"
	echo "overall_exit_code=$overall_rc"
} >"$host_out/host-result.txt"

finalize_host "$overall_rc"
