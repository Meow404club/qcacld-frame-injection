#!/system/bin/sh

set -u

usage()
{
	echo "usage: $0 S <0|3> --clean-boot --authorized-isolated-test <authorized-bssid> <frame-sender> <iface-probe> [host-run-token]" >&2
	exit 2
}

[ "$#" -ge 7 ] || usage
variant=$1
stage_scope=$2
[ "$3" = "--clean-boot" ] || usage
[ "$4" = "--authorized-isolated-test" ] || usage
authorized_bssid=$(printf '%s' "$5" | tr 'A-F' 'a-f')
sender=$6
iface_probe=$7
host_run_token=${8:-}
case "$host_run_token" in
	*[!A-Za-z0-9._-]*) usage ;;
esac
case "$stage_scope" in
	0|3) ;;
	*) usage ;;
esac
expected_build_id=134d10627e846036f229ee40441691f81eb8756f
suite_frozen=0
expected_firmware_sha256=f89a5348a4076d4db062eb335ac97b5fb028397bd3d21c96a837fb138503d84e
expected_bdf_sha256=b95a047cda7ab3d23010f7cdc0dd031bc865fbf369191a55df6a44a574d4cccd
expected_monitor_mtu=2608
expected_managed_mtu=1500
suite_id=$(printf '%s\n' "$expected_build_id" | cut -c 1-8)

[ "$suite_frozen" -eq 1 ] || {
	echo "archived AP/RAW suite is incompatible with the active WMI synthetic route" >&2
	exit 4
}

case "$variant" in
	S)
		[ "$#" -eq 7 ] || [ "$#" -eq 8 ] || usage
		desired_scan_state=false
		desired_scan_arg=disabled
		previous_boot_id=
		;;
	*)
		usage
		;;
esac

stamp=$(date -u +%Y%m%dT%H%M%SZ)
out_base=/data/local/tmp/qcacld-consolidated-${suite_id}-${stamp}-$$
out=$out_base
suffix=0
while ! mkdir "$out" 2>/dev/null; do
	suffix=$((suffix + 1))
	[ "$suffix" -lt 100 ] || {
		echo "failed to create a unique output directory" >&2
		exit 3
	}
	out=${out_base}-${suffix}
done

echo "OUTPUT_DIR=$out"
exec >"$out/run.log" 2>&1

boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
echo "$boot_id" >"$out/boot-id.txt"
echo "$variant" >"$out/variant.txt"
echo "$stage_scope" >"$out/stage-scope.txt"
echo "$desired_scan_arg" >"$out/requested-scan-always.txt"
last_run_boot_file=/data/local/tmp/qcacld-consolidated-${suite_id}-last-boot-id
force_raw_node=/sys/module/qca_cld3_peach_v2/parameters/frame_inject_force_raw
lifecycle_node=/sys/kernel/debug/wlan0/frame_inject_lifecycle
con_mode_node=/sys/module/qca_cld3_peach_v2/parameters/con_mode
run_nonce=$((($$ + $(date +%s)) & 4095))
[ "$run_nonce" -ne 0 ] || run_nonce=1
if [ -n "$host_run_token" ]; then
	run_token="${host_run_token}_${suite_id}_${boot_id}_${run_nonce}"
else
	run_token="QCACLD_${suite_id}_${boot_id}_${run_nonce}"
fi
suite_remote_dir=${sender%/*}
run_group_helper=$suite_remote_dir/run_remote_group.sh
run_control_helper=$suite_remote_dir/run_remote_control.sh
kernel_capture_helper=$suite_remote_dir/capture_run_kernel.sh
run_kernel_pidfile=$suite_remote_dir/device-kernel-events.pid
run_kernel_log=$out/run-kernel-events.log
run_kernel_stderr=$out/run-kernel-events.stderr
run_kernel_stop_log=$out/run-kernel-events-stop.log
run_kernel_stream_started=0
run_kernel_stream_launcher=
p2p_shell_client_initialized=0
p2p_shell_deinit_rc=0
echo "$sender" >"$out/sender-path.txt"
echo "$iface_probe" >"$out/iface-probe-path.txt"
echo "$run_nonce" >"$out/run-nonce.txt"
echo "$run_token" >"$out/run-token.txt"
fail_active=0
required_capture_failures=0
last_capture_rc=0

marker()
{
	mark_stage=$1
	mark_uptime=$(cut -d ' ' -f 1 /proc/uptime 2>/dev/null)
	mark_message="$run_token stage=$mark_stage uptime=$mark_uptime out=$out"
	printf '%s\n' "$mark_message" >>"$out/markers.log"
	if printf '<6>%s\n' "$mark_message" >/dev/kmsg 2>/dev/null; then
		echo "kmsg_rc=0 stage=$mark_stage" >>"$out/marker-status.log"
	else
		echo "kmsg_rc=1 stage=$mark_stage" >>"$out/marker-status.log"
	fi
	if log -t "QCACLD_$suite_id" "$mark_message" 2>/dev/null; then
		echo "logcat_rc=0 stage=$mark_stage" >>"$out/marker-status.log"
	else
		echo "logcat_rc=1 stage=$mark_stage" >>"$out/marker-status.log"
	fi
	echo "=== $mark_message ==="
}

capture()
{
	cap_file=$1
	shift
	{
		echo "utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
		echo "command=$*"
		timeout 60 "$@"
		cap_rc=$?
		echo
		echo "rc=$cap_rc"
	} >"$cap_file" 2>&1
	last_capture_rc=$cap_rc
	printf '%s\t%s\n' "$cap_rc" "$cap_file" >>"$out/capture-status.tsv"
	return 0
}

capture_required()
{
	capture "$@"
	[ "$last_capture_rc" -eq 0 ] ||
		required_capture_failures=$((required_capture_failures + 1))
}

current_run_dmesg()
{
	if [ "$run_kernel_stream_started" -eq 1 ] &&
	   [ -r "$run_kernel_log" ]; then
		cat "$run_kernel_log"
		return
	fi
	dmesg | awk -v token="$run_token" '
		index($0, token) { seen = 1 }
		seen { print }
	'
}

start_run_kernel_stream()
{
	[ -x "$run_group_helper" ] && [ -x "$run_control_helper" ] &&
	[ -x "$kernel_capture_helper" ] || return 1
	: >"$run_kernel_log"
	: >"$run_kernel_stderr"
	"$run_group_helper" "$run_kernel_pidfile" "$kernel_capture_helper" \
		"$run_token" "$run_kernel_log" "$run_kernel_stderr" &
	run_kernel_stream_launcher=$!
	run_kernel_stream_started=1
	run_kernel_wait_i=0
	while [ ! -s "$run_kernel_pidfile" ]; do
		run_kernel_wait_i=$((run_kernel_wait_i + 1))
		[ "$run_kernel_wait_i" -lt 20 ] || return 2
		kill -0 "$run_kernel_stream_launcher" 2>/dev/null || return 3
		sleep 1
	done
	run_kernel_pid=$(cat "$run_kernel_pidfile" 2>/dev/null)
	case "$run_kernel_pid" in
		''|*[!0-9]*) return 4 ;;
	esac
	kill -0 -"$run_kernel_pid" 2>/dev/null || return 5
	return 0
}

wait_run_kernel_marker()
{
	run_kernel_marker_i=0
	while [ "$run_kernel_marker_i" -lt 20 ]; do
		grep -Fq "$run_token" "$run_kernel_log" 2>/dev/null && return 0
		run_kernel_marker_i=$((run_kernel_marker_i + 1))
		sleep 1
	done
	return 1
}

stop_run_kernel_stream()
{
	[ "$run_kernel_stream_started" -eq 1 ] || return 0
	run_kernel_stop_rc=0
	"$run_control_helper" stop "$run_kernel_pidfile" \
		capture_run_kernel.sh >"$run_kernel_stop_log" 2>&1 ||
		run_kernel_stop_rc=$?
	if [ "$run_kernel_stop_rc" -ne 0 ] &&
	   [ -n "$run_kernel_stream_launcher" ]; then
		kill -TERM -"$run_kernel_stream_launcher" 2>/dev/null ||
			kill -TERM "$run_kernel_stream_launcher" 2>/dev/null || true
		run_kernel_stop_i=0
		while kill -0 "$run_kernel_stream_launcher" 2>/dev/null; do
			run_kernel_stop_i=$((run_kernel_stop_i + 1))
			[ "$run_kernel_stop_i" -lt 5 ] || break
			sleep 1
		done
		kill -KILL -"$run_kernel_stream_launcher" 2>/dev/null ||
			kill -KILL "$run_kernel_stream_launcher" 2>/dev/null || true
	fi
	if [ -n "$run_kernel_stream_launcher" ]; then
		wait "$run_kernel_stream_launcher" 2>/dev/null || true
	fi
	run_kernel_stream_started=0
	return "$run_kernel_stop_rc"
}

release_p2p_shell_client()
{
	[ "$p2p_shell_client_initialized" -eq 1 ] || return 0
	p2p_shell_deinit_rc=0
	cmd wifip2p deinit >"$out/wifip2p-deinit.log" 2>&1 ||
		p2p_shell_deinit_rc=$?
	echo "$p2p_shell_deinit_rc" >"$out/wifip2p-deinit.rc"
	p2p_shell_client_initialized=0
	return "$p2p_shell_deinit_rc"
}

cleanup_exit()
{
	release_p2p_shell_client >/dev/null 2>&1 || true
	stop_run_kernel_stream >/dev/null 2>&1 || true
}

crash_manifest()
{
	manifest_file=$1
	{
		find /sys/fs/pstore -maxdepth 1 -type f -print 2>/dev/null
		find /data/adb -maxdepth 4 -type f \
			\( -iname '*dmesg*' -o -iname '*kmsg*' \
			   -o -iname '*kernel*log*' -o -iname 'console-ramoops*' \
			   -o -iname 'logcat.log' -o -iname 'logcat.old.log' \
			   -o -iname 'modules_info*' \) -print 2>/dev/null
		[ ! -f /data/debugging/last_kmsg.txt ] ||
			printf '%s\n' /data/debugging/last_kmsg.txt
		[ ! -f /proc/last_kmsg ] || printf '%s\n' /proc/last_kmsg
		find /data/vendor/tombstones/wifi -maxdepth 4 -type f -print \
			2>/dev/null
	} | sort -u | while IFS= read -r manifest_path; do
		[ -f "$manifest_path" ] || continue
		manifest_size=$(stat -c '%s' "$manifest_path" 2>/dev/null) ||
			manifest_size=unknown
		manifest_mtime=$(stat -c '%Y' "$manifest_path" 2>/dev/null) ||
			manifest_mtime=unknown
		manifest_mode=$(stat -c '%a' "$manifest_path" 2>/dev/null) ||
			manifest_mode=unknown
		manifest_hash=$(sha256sum "$manifest_path" 2>/dev/null |
			awk '{print $1}')
		[ -n "$manifest_hash" ] || manifest_hash=unreadable
		printf '%s\t%s\t%s\t%s\t%s\n' "$manifest_hash" \
			"$manifest_size" "$manifest_mtime" "$manifest_mode" \
			"$manifest_path"
	done >"$manifest_file"
}

crash_manifest_delta()
{
	delta_pre=$1
	delta_post=$2
	delta_out=$3
	awk -F '\t' '
		FILENAME == ARGV[1] { old[$5] = $0; next }
		{
			seen[$5] = 1
			if (!($5 in old))
				print "new\t" $0
			else if (old[$5] != $0)
				print "changed\told=" old[$5] "\tnew=" $0
			else
				print "unchanged\t" $0
		}
		END {
			for (path in old)
				if (!(path in seen))
					print "missing\t" old[path]
		}
	' "$delta_pre" "$delta_post" | sort >"$delta_out"
}

crash_delta_hard_fault()
{
	delta_file=$1
	awk -F '\t' '
		($1 == "new" || $1 == "changed") &&
		(index($0, "/sys/fs/pstore/") ||
		 index($0, "/data/debugging/last_kmsg.txt") ||
		 index($0, "/proc/last_kmsg")) { hard_fault = 1 }
		END { exit hard_fault ? 0 : 1 }
	' "$delta_file"
}

snapshot()
{
	snap_label=$1
	snap_dir=$out/$snap_label
	mkdir -p "$snap_dir"
	{
		echo "label=$snap_label"
		echo "variant=$variant"
		echo "utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
		echo "boot_id=$boot_id"
		cat /proc/uptime 2>&1
	} >"$snap_dir/meta.txt"

	capture_required "$snap_dir/cmd-wifi-status.log" cmd wifi status
	capture_required "$snap_dir/dumpsys-wifi.log" dumpsys wifi
	capture_required "$snap_dir/dumpsys-connectivity.log" dumpsys connectivity
	capture "$snap_dir/dumpsys-network-stack.log" dumpsys network_stack
	capture_required "$snap_dir/getprop-all.log" getprop
	{
		for snap_prop in \
			init.svc.wpa_supplicant \
			init.svc.wificond \
			init.svc.vendor.wifi_hal_legacy \
			init.svc.vendor.wifi_hal \
			init.svc.wifiserver; do
			echo "[$snap_prop]=$(getprop "$snap_prop")"
		done
	} >"$snap_dir/wifi-properties.log" 2>&1
	capture_required "$snap_dir/iw-dev.log" iw dev
	capture_required "$snap_dir/iw-wlan0-info.log" iw dev wlan0 info
	capture_required "$snap_dir/iw-wlan0-link.log" iw dev wlan0 link
	capture_required "$snap_dir/ip-link-wlan0.log" ip -s -details link show wlan0
	capture_required "$snap_dir/ip-addr-wlan0.log" ip addr show wlan0
	capture_required "$snap_dir/ip-route-all.log" ip route show table all
	capture_required "$snap_dir/ip-rule.log" ip rule show
	capture_required "$snap_dir/proc-net-wireless.log" cat /proc/net/wireless
	capture "$snap_dir/processes-wifi.log" sh -c \
		'ps -A -o USER,PID,PPID,NAME,ARGS | grep -Ei "wifi|wlan|wpa|wificond|cnss"'
	{
		for snap_node in address addr_assign_type type flags operstate carrier \
			dormant mtu; do
			echo "=== $snap_node ==="
			cat "/sys/class/net/wlan0/$snap_node" 2>&1
		done
	} >"$snap_dir/sys-class-wlan0.log" 2>&1
	sync
}

copy_evidence_file()
{
	evidence_src=$1
	evidence_dst_dir=$2
	[ -f "$evidence_src" ] || return 0
	evidence_size=$(stat -c '%s' "$evidence_src" 2>/dev/null)
	case "$evidence_size" in
		''|*[!0-9]*)
			printf 'stat_failed=%s\n' "$evidence_src" \
				>>"$evidence_dst_dir/copied-files.log"
			return 0
			;;
	esac
	if [ "$evidence_size" -gt 134217728 ]; then
		printf 'bounded_skip=%s size=%s\n' "$evidence_src" \
			"$evidence_size" >>"$evidence_dst_dir/copied-files.log"
		return 0
	fi
	evidence_name=$(printf '%s\n' "$evidence_src" |
		sed 's|^/||; s|/|__|g')
	evidence_path_hash=$(printf '%s' "$evidence_src" | sha256sum |
		awk '{print substr($1, 1, 16)}')
	evidence_name=${evidence_path_hash}__${evidence_name}
	if cp -p "$evidence_src" "$evidence_dst_dir/$evidence_name" \
		2>>"$evidence_dst_dir/copy-errors.log"; then
		printf 'source=%s dest=%s\n' "$evidence_src" "$evidence_name" \
			>>"$evidence_dst_dir/copied-files.log"
	else
		printf 'copy_failed=%s\n' "$evidence_src" \
			>>"$evidence_dst_dir/copied-files.log"
	fi
}

failure_evidence()
{
	fail_dir=$out/failure-evidence
	mkdir -p "$fail_dir"
	capture "$fail_dir/dmesg.log" dmesg
	capture "$fail_dir/logcat-all.log" logcat -b all -d -v threadtime
	capture "$fail_dir/pstore-list.log" ls -la /sys/fs/pstore
	find /sys/fs/pstore -maxdepth 1 -type f -print 2>/dev/null \
		>"$fail_dir/pstore-files.list"
	while IFS= read -r evidence_path; do
		copy_evidence_file "$evidence_path" "$fail_dir"
	done <"$fail_dir/pstore-files.list"
	find /data/adb -maxdepth 4 -type f \
		\( -iname '*dmesg*' -o -iname '*kmsg*' \
		   -o -iname '*kernel*log*' -o -iname 'console-ramoops*' \
		   -o -iname 'logcat.log' -o -iname 'logcat.old.log' \
		   -o -iname 'modules_info*' \) -print 2>/dev/null \
		>"$fail_dir/data-adb-kernel-log-list.log"
	while IFS= read -r evidence_path; do
		copy_evidence_file "$evidence_path" "$fail_dir"
	done <"$fail_dir/data-adb-kernel-log-list.log"
	copy_evidence_file /data/debugging/last_kmsg.txt "$fail_dir"
	copy_evidence_file /proc/last_kmsg "$fail_dir"
	find /data/vendor/tombstones/wifi -maxdepth 4 -type f -print \
		2>/dev/null >"$fail_dir/vendor-wifi-tombstones.list"
	while IFS= read -r evidence_path; do
		copy_evidence_file "$evidence_path" "$fail_dir"
	done <"$fail_dir/vendor-wifi-tombstones.list"
	capture "$fail_dir/module-build-id.log" od -An -v -tx1 \
		/sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id
	sync
}

fail()
{
	fail_message=$1
	fail_code=$2
	[ "$fail_active" -eq 0 ] || exit "$fail_code"
	fail_active=1
	trap - HUP INT TERM
	echo "failure_code=$fail_code" >"$out/result.txt"
	echo "failure_message=$fail_message" >>"$out/result.txt"
	if [ -n "${active_phase:-}" ]; then
		if [ "$active_phase" = hcxdumptool-workflow ]; then
			partial_completed=$(awk 'END { print (NR > 0 ? NR - 1 : 0) }' \
				"$out/workflow-matrix.tsv" 2>/dev/null)
		else
			partial_rows=$(awk 'END { print (NR > 0 ? NR - 1 : 0) }' \
				"$out/frame-matrix.tsv" 2>/dev/null)
			partial_completed=$((partial_rows - ${phase_rows_before:-0}))
		fi
		printf 'active_phase=%s\nphase_completed_frames=%s\n' \
			"$active_phase" "$partial_completed" >>"$out/result.txt"
			if [ "$active_phase" != hcxdumptool-workflow ] &&
			   [ -f "$out/phase-matrix.tsv" ]; then
				printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\tPARTIAL\n' \
					"$active_phase" "${phase_start_index:-unknown}" \
					"${phase_end_index:-unknown}" "${phase_expected:-unknown}" \
					"$partial_completed" "${phase_gate_on_verified:-0}" \
					"${phase_gate_off_verified:-0}" >>"$out/phase-matrix.tsv"
			fi
		fi
		if [ -n "${active_workflow_group:-}" ]; then
			{
				echo "active_workflow_group=$active_workflow_group"
				echo "workflow_gate_on_verified=${workflow_gate_on_verified:-0}"
				echo "workflow_gate_off_verified=${workflow_gate_off_verified:-0}"
			} >>"$out/result.txt"
		fi
	cat "$force_raw_node" >"$out/failure-force-raw-before-reset.txt" \
		2>&1 || true
	printf '0\n' >"$force_raw_node" 2>/dev/null || true
	fail_gate_after=$(cat "$force_raw_node" 2>/dev/null | tr -d ' \r\n')
	printf '%s\n' "$fail_gate_after" \
		>"$out/failure-force-raw-after-reset.txt"
	case "$fail_gate_after" in
		N|0) ;;
		*) echo "warning=force RAW gate reset could not be verified" \
			>>"$out/result.txt" ;;
	esac
	echo "failure_state_policy=preserve-then-soft-recover-if-safe" \
		>>"$out/result.txt"
	marker "failure-$fail_code"
	echo "$fail_message" >&2
	current_run_dmesg >"$out/failure-run-dmesg-immediate.log" 2>&1
	capture "$out/failure-cnss-firmware-ready.log" cat \
		/sys/bus/platform/drivers/cnss2/firmware_ready
	crash_manifest "$out/crash-evidence-post-failure.manifest"
	crash_manifest_delta "$out/crash-evidence-pre-test.manifest" \
		"$out/crash-evidence-post-failure.manifest" \
		"$out/crash-evidence-post-failure.delta.tsv"
	sync
	failure_evidence
	snapshot "failure-$fail_code-pre-recovery"
	attempt_failure_managed_recovery
	failure_recovery_rc=$?
	echo "failure_recovery_exit_code=$failure_recovery_rc" \
		>>"$out/result.txt"
	current_run_dmesg >"$out/failure-run-dmesg-after-recovery.log" 2>&1
	crash_manifest "$out/crash-evidence-post-recovery.manifest"
	crash_manifest_delta "$out/crash-evidence-post-failure.manifest" \
		"$out/crash-evidence-post-recovery.manifest" \
		"$out/crash-evidence-recovery.delta.tsv"
	snapshot "failure-$fail_code-post-recovery"
	echo "RESULT_DIR=$out"
	exit "$fail_code"
}

trap 'fail "test interrupted" 98' HUP INT TERM

scan_state_from_dump()
{
	sed -n 's/^ScanAlwaysAvailable[[:space:]]*//p' "$1" | head -n 1
}

verify_scan_always()
{
	verify_expected=$1
	verify_label=$2
	verify_i=0
	verify_actual=
	while [ "$verify_i" -lt 20 ]; do
		cmd wifi status >"$out/$verify_label-cmd-wifi-status.log" 2>&1
		dumpsys wifi >"$out/$verify_label-dumpsys-wifi.log" 2>&1
		verify_actual=$(scan_state_from_dump \
			"$out/$verify_label-dumpsys-wifi.log")
		[ "$verify_actual" = "$verify_expected" ] && return 0
		verify_i=$((verify_i + 1))
		sleep 1
	done
	echo "actual_scan_always=$verify_actual" \
		>"$out/$verify_label-scan-state.txt"
	return 1
}

active_warden_section()
{
	awk '
		$0 == "Dump of WifiActiveModeWarden" { inside = 1 }
		inside && ($0 == "Dump of ActiveModeWarden.Graveyard" ||
			   $0 == "Dump of ConcreteClientModeManager.Graveyard") {
			exit
		}
		inside { print }
	' "$1"
}

manager_block_for_iface()
{
	awk -v target_iface="$2" '
		function emit_if_target() {
			if (block ~ ("\nmClientInterfaceName: " target_iface "\n"))
				printf "%s", block
		}
		/^Dump of ClientModeManager id=/ {
			emit_if_target()
			block = $0 "\n"
			in_manager = 1
			next
		}
		in_manager { block = block $0 "\n" }
		END { emit_if_target() }
	' "$1"
}

valid_mac()
{
	printf '%s\n' "$1" |
		grep -Eq '^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$'
}

wait_wifi_disabled()
{
	disable_i=0
	while [ "$disable_i" -lt 45 ]; do
		cmd wifi status >"$out/wait-disabled-cmd-wifi-status.log" 2>&1
		if grep -q '^Wifi is disabled$' \
			"$out/wait-disabled-cmd-wifi-status.log"; then
			return 0
		fi
		disable_i=$((disable_i + 1))
		sleep 1
	done
	return 1
}

wait_framework_disabled_role()
{
	role_i=0
	while [ "$role_i" -lt 45 ]; do
		dumpsys wifi >"$out/wait-disabled-role-dumpsys-wifi.log" 2>&1
		active_warden_section \
			"$out/wait-disabled-role-dumpsys-wifi.log" \
			>"$out/wait-disabled-role-active-warden.log"
		manager_block_for_iface \
			"$out/wait-disabled-role-active-warden.log" wlan0 \
			>"$out/wait-disabled-role-wlan0-manager.log"
		role_wlan0_count=$(grep -c '^Dump of ClientModeManager id=' \
			"$out/wait-disabled-role-wlan0-manager.log")
		if grep -q '^ScanAlwaysAvailable false$' \
			"$out/wait-disabled-role-dumpsys-wifi.log" &&
		   grep -q '^NumActiveModeManagers: 0$' \
			"$out/wait-disabled-role-active-warden.log" &&
		   ! grep -q '^Dump of ClientModeManager id=' \
			"$out/wait-disabled-role-active-warden.log"; then
			return 0
		fi
		role_i=$((role_i + 1))
		sleep 1
	done
	return 1
}

wait_primary_connect_mode()
{
	primary_i=0
	while [ "$primary_i" -lt 90 ]; do
		dumpsys wifi >"$out/wait-primary-dumpsys-wifi.log" 2>&1
		active_warden_section "$out/wait-primary-dumpsys-wifi.log" \
			>"$out/wait-primary-active-warden.log"
		manager_block_for_iface "$out/wait-primary-active-warden.log" \
			wlan0 >"$out/wait-primary-wlan0-manager.log"
		primary_wlan0_count=$(grep -c '^Dump of ClientModeManager id=' \
			"$out/wait-primary-wlan0-manager.log")
		if [ "$primary_wlan0_count" -eq 1 ] &&
		   grep -q '^mRole: ROLE_CLIENT_PRIMARY$' \
			"$out/wait-primary-wlan0-manager.log" &&
		   grep -q '^current StateMachine mode: ConnectModeState$' \
			"$out/wait-primary-wlan0-manager.log" &&
		   grep -q '^mClientInterfaceName: wlan0$' \
			"$out/wait-primary-wlan0-manager.log"; then
			return 0
		fi
		primary_i=$((primary_i + 1))
		sleep 1
	done
	return 1
}

wait_supplicant()
{
	supplicant_i=0
	while [ "$supplicant_i" -lt 45 ]; do
		supplicant_state=$(getprop init.svc.wpa_supplicant)
		echo "$supplicant_state" >"$out/wait-supplicant-state.txt"
		[ "$supplicant_state" = running ] && return 0
		supplicant_i=$((supplicant_i + 1))
		sleep 1
	done
	return 1
}

wait_link()
{
	link_i=0
	while [ "$link_i" -lt 120 ]; do
		iw dev wlan0 link >"$out/wait-link-iw.log" 2>&1
		if grep -q '^Connected to ' "$out/wait-link-iw.log"; then
			return 0
		fi
		link_i=$((link_i + 1))
		sleep 1
	done
	return 1
}

wait_ipv4()
{
	ipv4_i=0
	while [ "$ipv4_i" -lt 90 ]; do
		ip -4 addr show dev wlan0 >"$out/wait-ipv4-addr.log" 2>&1
		if grep -q ' scope global ' "$out/wait-ipv4-addr.log"; then
			return 0
		fi
		ipv4_i=$((ipv4_i + 1))
		sleep 1
	done
	return 1
}

wait_framework_connected_validated()
{
	validated_i=0
	while [ "$validated_i" -lt 90 ]; do
		cmd wifi status >"$out/wait-validated-cmd-wifi-status.log" 2>&1
		if grep -Eq '^Wifi is connected( to .*)?$' \
			"$out/wait-validated-cmd-wifi-status.log" &&
		   grep -E 'NetworkCapabilities:.*Transports: WIFI.*Capabilities:.*VALIDATED' \
			"$out/wait-validated-cmd-wifi-status.log" >/dev/null; then
			return 0
		fi
		validated_i=$((validated_i + 1))
		sleep 1
	done
	return 1
}

verify_gateway_connectivity()
{
	ip -4 route show table all >"$out/post-reconnect-ipv4-routes.log" 2>&1 ||
		return 1
	gateway=$(awk '
		$1 == "default" {
			for (i = 1; i <= NF; i++) {
				if ($i == "dev" && $(i + 1) == "wlan0")
					wlan = 1
				if ($i == "via")
					gw = $(i + 1)
			}
			if (wlan && gw != "") { print gw; exit }
			wlan = 0
			gw = ""
		}
	' "$out/post-reconnect-ipv4-routes.log")
	[ -n "$gateway" ] || return 2
	printf '%s\n' "$gateway" >"$out/post-reconnect-gateway.txt"
	ping -I wlan0 -c 3 -W 3 "$gateway" \
		>"$out/post-reconnect-gateway-ping.log" 2>&1
}

verify_connected_identity()
{
	identity_label=$1
	iw dev wlan0 link >"$out/$identity_label-iw-link.log" 2>&1 || return 1
	identity_bssid=$(sed -n 's/^Connected to \([^ ]*\).*/\1/p' \
		"$out/$identity_label-iw-link.log" | head -n 1)
	[ "$identity_bssid" = "$peer_mac" ] || return 2
	identity_mac=$(cat /sys/class/net/wlan0/address 2>/dev/null)
	[ "$identity_mac" = "$connected_station_mac" ] || return 3
	post_peer_mac=$identity_bssid
	return 0
}

assert_network_cleared()
{
	clear_label=$1
	iw dev wlan0 link >"$out/$clear_label-iw-link.log" 2>&1
	clear_iw_rc=$?
	echo "$clear_iw_rc" >"$out/$clear_label-iw-link.rc"
	[ "$clear_iw_rc" -eq 0 ] || return 3
	grep -q '^Connected to ' "$out/$clear_label-iw-link.log" && return 1
	ip -4 addr show dev wlan0 >"$out/$clear_label-ipv4.log" 2>&1
	clear_ip_rc=$?
	echo "$clear_ip_rc" >"$out/$clear_label-ipv4.rc"
	[ "$clear_ip_rc" -eq 0 ] || return 4
	grep -q ' scope global ' "$out/$clear_label-ipv4.log" && return 2
	return 0
}

run_log_count()
{
	count_pattern=$1
	current_run_dmesg | awk -v pattern="$count_pattern" '
		index($0, pattern) { count++ }
		END { print count + 0 }
	'
}

fatal_seen()
{
	current_run_dmesg | grep -Eqi \
		'frame injection (backend fatal|DP reclaim watchdog expired|DP reclaim timed out|forced teardown retaining direct-DP)|frame injection helper.*(failed|timed out|timeout|rollback.*fail|state.*unknown|retained)|iw full-mode transition.*(failed|rollback.*fail|state.*unknown|stage=complete.*ret=-?[1-9][0-9]*|stage=rollback-complete.*ret=-?[1-9][0-9]*)|monitor filter reset failed after retry|subsys-restart:.*wlan|wlan crashed|SMMU.*fault|arm-smmu.*fault|MHI.*(SYS ERROR|RDDM|RAMDUMP)|cnss.*device crashed|NOC_error|cmnos_assert|AUX FATAL|Asserted in:|Kernel panic| panic:'
}

health_check()
{
	current_boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
	[ "$current_boot_id" = "$boot_id" ] || return 1
	[ -e /sys/module/qca_cld3_peach_v2 ] || return 2
	[ -e /sys/class/net/wlan0 ] || return 3
	current_run_dmesg | grep -q "$run_token" || return 4
	fatal_seen && return 5
	return 0
}

wait_iw_mode()
{
	wait_mode_type=$1
	wait_mode_con=$2
	wait_mode_label=$3
	wait_mode_source_ifindex=$4
	wait_mode_expected_up=$5
	wait_mode_i=0
	wait_mode_stable=0
	wait_mode_stable_ifindex=
	wait_iw_mode_ifindex=
	wait_mode_ifindex=
	wait_mode_iftype=unavailable
	wait_mode_flags=
	wait_mode_up=unavailable
	wait_mode_con_value=
	wait_mode_status=timeout
	wait_mode_exit=1
	: >"$out/$wait_mode_label-mode-poll.log"
	while [ "$wait_mode_i" -lt 120 ]; do
		wait_mode_boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
		if [ "$wait_mode_boot" != "$boot_id" ]; then
			wait_mode_status=boot-changed
			wait_mode_exit=2
			break
		fi
		if [ ! -e /sys/module/qca_cld3_peach_v2 ]; then
			wait_mode_status=module-missing
			wait_mode_exit=3
			break
		fi
		if fatal_seen; then
			wait_mode_status=fatal-log-seen
			wait_mode_exit=4
			break
		fi
		wait_mode_con_value=$(cat "$con_mode_node" 2>/dev/null |
			tr -d ' \r\n')
		wait_mode_ifindex=$(cat /sys/class/net/wlan0/ifindex 2>/dev/null)
		wait_mode_flags=$(cat /sys/class/net/wlan0/flags 2>/dev/null)
		wait_mode_up=unavailable
		case "$wait_mode_flags" in
			0x[0-9a-fA-F]*)
				if [ $((wait_mode_flags & 1)) -ne 0 ]; then
					wait_mode_up=1
				else
					wait_mode_up=0
				fi
				;;
		esac
		wait_mode_iftype=unavailable
		if [ -e /sys/class/net/wlan0 ] &&
		   iw dev wlan0 info >"$out/$wait_mode_label-iw-info-current.log" \
			2>&1 &&
		   grep -q "^[[:space:]]*type $wait_mode_type$" \
			"$out/$wait_mode_label-iw-info-current.log" &&
		   [ "$wait_mode_con_value" = "$wait_mode_con" ] &&
		   [ "$wait_mode_up" = "$wait_mode_expected_up" ]; then
			wait_mode_iftype=$wait_mode_type
			case "$wait_mode_ifindex" in
				''|*[!0-9]*) wait_mode_stable=0; wait_mode_stable_ifindex= ;;
				*)
					if [ "$wait_mode_ifindex" = "$wait_mode_stable_ifindex" ]; then
						wait_mode_stable=$((wait_mode_stable + 1))
					else
						wait_mode_stable=1
						wait_mode_stable_ifindex=$wait_mode_ifindex
					fi
					;;
			esac
		else
			wait_mode_stable=0
			wait_mode_stable_ifindex=
		fi
		printf '%s\tsource_ifindex=%s\tcurrent_ifindex=%s\tiftype=%s\tflags=%s\tup=%s\tcon_mode=%s\tnetdev=%s\tstable=%s\n' \
			"$wait_mode_i" "$wait_mode_source_ifindex" \
			"${wait_mode_ifindex:-unavailable}" "$wait_mode_iftype" \
			"${wait_mode_flags:-unavailable}" "$wait_mode_up" \
			"${wait_mode_con_value:-unavailable}" \
			"$([ -e /sys/class/net/wlan0 ] && echo present || echo absent)" \
			"$wait_mode_stable" >>"$out/$wait_mode_label-mode-poll.log"
		if [ "$wait_mode_stable" -ge 2 ]; then
			cp "$out/$wait_mode_label-iw-info-current.log" \
				"$out/$wait_mode_label-iw-info-final.log"
			wait_iw_mode_ifindex=$wait_mode_ifindex
			if [ "$wait_mode_source_ifindex" = "$wait_iw_mode_ifindex" ]; then
				wait_mode_ifindex_changed=0
			else
				wait_mode_ifindex_changed=1
			fi
			{
				echo 'status=ready'
				echo "interface=wlan0"
				echo "source_ifindex=$wait_mode_source_ifindex"
				echo "target_ifindex=$wait_iw_mode_ifindex"
				echo "ifindex_changed=$wait_mode_ifindex_changed"
				echo "target_iftype=$wait_mode_type"
				echo "target_up=$wait_mode_up"
				echo "target_con_mode=$wait_mode_con_value"
			} >"$out/$wait_mode_label-ifindex-transition.txt"
			current_run_dmesg | grep -F 'iw full-mode transition' \
				>"$out/$wait_mode_label-driver-transition.log" 2>&1 || true
			return 0
		fi
		wait_mode_i=$((wait_mode_i + 1))
		sleep 1
	done
	{
		echo "status=$wait_mode_status"
		echo "interface=wlan0"
		echo "source_ifindex=$wait_mode_source_ifindex"
		echo "latest_ifindex=${wait_mode_ifindex:-unavailable}"
		echo "latest_iftype=$wait_mode_iftype"
		echo "latest_up=$wait_mode_up"
		echo "latest_con_mode=${wait_mode_con_value:-unavailable}"
	} >"$out/$wait_mode_label-ifindex-transition.txt"
	current_run_dmesg | grep -F 'iw full-mode transition' \
		>"$out/$wait_mode_label-driver-transition.log" 2>&1 || true
	return "$wait_mode_exit"
}

failure_fatal_log_seen()
{
	current_run_dmesg | grep -Eqi \
		'frame injection (DP reclaim watchdog expired|DP reclaim timed out|forced teardown retaining direct-DP)|frame injection helper.*(retained|state.*unknown)|subsys-restart:.*wlan|wlan crashed|SMMU.*fault|arm-smmu.*fault|MHI.*(SYS ERROR|RDDM|RAMDUMP)|cnss.*device crashed|NOC_error|cmnos_assert|AUX FATAL|Asserted in:|Kernel panic| panic:'
}

firmware_ready_value_is_ready()
{
	case "$1" in
		1|fwstatus_ready|fwstatus_ready:*) return 0 ;;
		*) return 1 ;;
	esac
}

wait_failure_recovery_settle()
{
	failure_settle_i=0
	failure_settle_stable=0
	failure_settle_key=
	failure_settle_status=timeout
	: >"$out/failure-recovery-settle-poll.log"
	while [ "$failure_settle_i" -lt 60 ]; do
		failure_settle_boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
		if [ "$failure_settle_boot" != "$boot_id" ]; then
			failure_settle_status=boot-changed
			return 1
		fi
		if [ ! -e /sys/module/qca_cld3_peach_v2 ]; then
			failure_settle_status=module-missing
			return 1
		fi
		if failure_fatal_log_seen; then
			failure_settle_status=fatal-log
			return 1
		fi
		failure_settle_fw=$(cat \
			/sys/bus/platform/drivers/cnss2/firmware_ready 2>/dev/null |
			tr -d ' \r\n')
		failure_settle_con=$(cat "$con_mode_node" 2>/dev/null |
			tr -d ' \r\n')
		failure_settle_ifindex=$(cat /sys/class/net/wlan0/ifindex 2>/dev/null)
		failure_settle_type=$(iw dev wlan0 info 2>/dev/null | sed -n \
			's/^[[:space:]]*type \([^ ]*\).*/\1/p' | head -n 1)
		failure_settle_pair=0
		case "$failure_settle_con:$failure_settle_type" in
			0:managed|4:monitor) failure_settle_pair=1 ;;
		esac
		failure_settle_current_key=$failure_settle_ifindex:$failure_settle_con:$failure_settle_type
		if firmware_ready_value_is_ready "$failure_settle_fw" &&
		   [ "$failure_settle_pair" -eq 1 ] &&
		   [ -n "$failure_settle_ifindex" ]; then
			if [ "$failure_settle_current_key" = "$failure_settle_key" ]; then
				failure_settle_stable=$((failure_settle_stable + 1))
			else
				failure_settle_key=$failure_settle_current_key
				failure_settle_stable=1
			fi
		else
			failure_settle_key=
			failure_settle_stable=0
		fi
		printf '%s\tfirmware_ready=%s\tcon_mode=%s\tifindex=%s\tiftype=%s\tpair=%s\tstable=%s\n' \
			"$failure_settle_i" "${failure_settle_fw:-unavailable}" \
			"${failure_settle_con:-unavailable}" \
			"${failure_settle_ifindex:-unavailable}" \
			"${failure_settle_type:-unavailable}" \
			"$failure_settle_pair" "$failure_settle_stable" \
			>>"$out/failure-recovery-settle-poll.log"
		if [ "$failure_settle_stable" -ge 2 ]; then
			failure_settle_status=ready
			return 0
		fi
		failure_settle_i=$((failure_settle_i + 1))
		sleep 1
	done
	return 1
}

failure_hard_fault_seen()
{
	failure_boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
	[ "$failure_boot" = "$boot_id" ] || return 0
	[ -e /sys/module/qca_cld3_peach_v2 ] || return 0
	failure_fw_ready=$(cat /sys/bus/platform/drivers/cnss2/firmware_ready \
		2>/dev/null | tr -d ' \r\n')
	firmware_ready_value_is_ready "$failure_fw_ready" || return 0
	if [ -f "$out/crash-evidence-post-failure.delta.tsv" ] &&
	   crash_delta_hard_fault \
		"$out/crash-evidence-post-failure.delta.tsv"; then
		return 0
	fi
	failure_fatal_log_seen
}

wait_failure_managed_mode()
{
	failure_mode_source_ifindex=$1
	failure_mode_expected_up=$2
	failure_mode_i=0
	failure_mode_stable=0
	failure_mode_stable_ifindex=
	failure_managed_wait_ifindex=
	failure_mode_ifindex=
	failure_mode_flags=
	failure_mode_up=unavailable
	failure_mode_con=
	failure_mode_status=timeout
	failure_mode_exit=1
	: >"$out/failure-managed-mode-poll.log"
	while [ "$failure_mode_i" -lt 120 ]; do
		failure_mode_boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
		if [ "$failure_mode_boot" != "$boot_id" ]; then
			failure_mode_status=boot-changed
			failure_mode_exit=2
			break
		fi
		if [ ! -e /sys/module/qca_cld3_peach_v2 ]; then
			failure_mode_status=module-missing
			failure_mode_exit=3
			break
		fi
		failure_mode_con=$(cat "$con_mode_node" 2>/dev/null |
			tr -d ' \r\n')
		failure_mode_ifindex=$(cat /sys/class/net/wlan0/ifindex 2>/dev/null)
		failure_mode_flags=$(cat /sys/class/net/wlan0/flags 2>/dev/null)
		failure_mode_up=unavailable
		case "$failure_mode_flags" in
			0x[0-9a-fA-F]*)
				if [ $((failure_mode_flags & 1)) -ne 0 ]; then
					failure_mode_up=1
				else
					failure_mode_up=0
				fi
				;;
		esac
		if [ -e /sys/class/net/wlan0 ] &&
		   iw dev wlan0 info \
			>"$out/failure-managed-iw-info-current.log" 2>&1 &&
		   grep -q '^[[:space:]]*type managed$' \
			"$out/failure-managed-iw-info-current.log" &&
		   [ "$failure_mode_con" = 0 ] &&
		   [ "$failure_mode_up" = "$failure_mode_expected_up" ]; then
			case "$failure_mode_ifindex" in
				''|*[!0-9]*)
					failure_mode_stable=0
					failure_mode_stable_ifindex=
					;;
				*)
					if [ "$failure_mode_ifindex" = \
					     "$failure_mode_stable_ifindex" ]; then
						failure_mode_stable=$((failure_mode_stable + 1))
					else
						failure_mode_stable=1
						failure_mode_stable_ifindex=$failure_mode_ifindex
					fi
					;;
			esac
		else
			failure_mode_stable=0
			failure_mode_stable_ifindex=
		fi
		printf '%s\tsource_ifindex=%s\tcurrent_ifindex=%s\tflags=%s\tup=%s\tcon_mode=%s\tstable=%s\n' \
			"$failure_mode_i" "$failure_mode_source_ifindex" \
			"${failure_mode_ifindex:-unavailable}" \
			"${failure_mode_flags:-unavailable}" "$failure_mode_up" \
			"${failure_mode_con:-unavailable}" "$failure_mode_stable" \
			>>"$out/failure-managed-mode-poll.log"
		if [ "$failure_mode_stable" -ge 2 ]; then
			failure_managed_wait_ifindex=$failure_mode_ifindex
			if [ "$failure_mode_source_ifindex" = \
			     "$failure_managed_wait_ifindex" ]; then
				failure_mode_ifindex_changed=0
			else
				failure_mode_ifindex_changed=1
			fi
			{
				echo 'status=ready'
				echo 'interface=wlan0'
				echo "source_ifindex=$failure_mode_source_ifindex"
				echo "target_ifindex=$failure_managed_wait_ifindex"
				echo "ifindex_changed=$failure_mode_ifindex_changed"
				echo 'target_iftype=managed'
				echo "target_up=$failure_mode_up"
				echo 'target_con_mode=0'
			} >"$out/failure-managed-ifindex-transition.txt"
			return 0
		fi
		failure_mode_i=$((failure_mode_i + 1))
		sleep 1
	done
	{
		echo "status=$failure_mode_status"
		echo "source_ifindex=$failure_mode_source_ifindex"
		echo "latest_ifindex=${failure_mode_ifindex:-unavailable}"
		echo "latest_up=$failure_mode_up"
		echo "latest_con_mode=${failure_mode_con:-unavailable}"
	} >"$out/failure-managed-ifindex-transition.txt"
	return "$failure_mode_exit"
}

attempt_failure_managed_recovery()
{
	failure_recovery_status_file=$out/failure-managed-recovery-status.txt
	: >"$failure_recovery_status_file"
	if ! wait_failure_recovery_settle; then
		echo "status=SKIPPED_UNSETTLED_${failure_settle_status}" \
			>>"$failure_recovery_status_file"
		return 0
	fi
	echo "settle_status=$failure_settle_status" \
		>>"$failure_recovery_status_file"
	if failure_hard_fault_seen; then
		echo 'status=SKIPPED_HARD_FAULT' \
			>>"$failure_recovery_status_file"
		return 0
	fi
	if [ -z "${station_mac:-}" ] || [ -z "${connected_station_mac:-}" ] ||
	   [ -z "${peer_mac:-}" ]; then
		echo 'status=NOT_APPLICABLE_NO_BASELINE_IDENTITY' \
			>>"$failure_recovery_status_file"
		return 0
	fi

	failure_recovery_con=$(cat "$con_mode_node" 2>/dev/null |
		tr -d ' \r\n')
	if ! iw dev wlan0 info >"$out/failure-recovery-pre-iw-info.log" 2>&1; then
		echo 'status=FAIL_NO_WLAN0_INFO' >>"$failure_recovery_status_file"
		return 1
	fi
	failure_recovery_type=$(sed -n \
		's/^[[:space:]]*type \([^ ]*\).*/\1/p' \
		"$out/failure-recovery-pre-iw-info.log" | head -n 1)
	failure_recovery_source_ifindex=$(cat /sys/class/net/wlan0/ifindex 2>/dev/null)
	failure_recovery_pre_flags=$(cat /sys/class/net/wlan0/flags 2>/dev/null)
	failure_recovery_expected_up=0
	case "$failure_recovery_source_ifindex" in
		''|*[!0-9]*)
			echo 'status=FAIL_INVALID_SOURCE_IFINDEX' \
				>>"$failure_recovery_status_file"
			return 1
			;;
	esac
	case "$failure_recovery_pre_flags" in
		0x[0-9a-fA-F]*)
			[ $((failure_recovery_pre_flags & 1)) -eq 0 ] ||
				failure_recovery_expected_up=1
			;;
		*)
			echo 'status=FAIL_INVALID_SOURCE_FLAGS' \
				>>"$failure_recovery_status_file"
			return 1
			;;
	esac
	{
		echo "pre_recovery_con_mode=${failure_recovery_con:-unavailable}"
		echo "pre_recovery_iftype=${failure_recovery_type:-unavailable}"
		echo "pre_recovery_mac=$(cat /sys/class/net/wlan0/address 2>/dev/null)"
		echo "pre_recovery_flags=$failure_recovery_pre_flags"
		echo "pre_recovery_ifindex=$failure_recovery_source_ifindex"
		echo "expected_transition_up=$failure_recovery_expected_up"
	} >>"$failure_recovery_status_file"
	marker failure-soft-recovery-eligible
	if [ "$failure_recovery_con" = 0 ] &&
	   [ "$failure_recovery_type" = managed ]; then
		echo 'already_managed=1' >"$out/failure-iw-set-managed.log"
		failure_iw_rc=0
	else
		iw dev wlan0 set type managed \
			>"$out/failure-iw-set-managed.log" 2>&1
		failure_iw_rc=$?
	fi
	echo "iw_set_managed_rc=$failure_iw_rc" \
		>>"$failure_recovery_status_file"
	[ "$failure_iw_rc" -eq 0 ] || {
		echo 'status=FAIL_IW_REQUEST' >>"$failure_recovery_status_file"
		return 1
	}
	wait_failure_managed_mode "$failure_recovery_source_ifindex" \
		"$failure_recovery_expected_up"
	failure_wait_rc=$?
	echo "wait_managed_rc=$failure_wait_rc" \
		>>"$failure_recovery_status_file"
	[ "$failure_wait_rc" -eq 0 ] || {
		echo 'status=FAIL_IW_TRANSITION' >>"$failure_recovery_status_file"
		return 1
	}
	echo "post_transition_ifindex=$failure_managed_wait_ifindex" \
		>>"$failure_recovery_status_file"

	failure_recovery_failed=0
	failure_managed_mac=$(cat /sys/class/net/wlan0/address 2>/dev/null)
	failure_managed_flags=$(cat /sys/class/net/wlan0/flags 2>/dev/null)
	failure_managed_up=false
	case "$failure_managed_flags" in
		0x[0-9a-fA-F]*)
			[ $((failure_managed_flags & 1)) -eq 0 ] ||
				failure_managed_up=true
			;;
	esac
	if [ "$failure_managed_mac" != "$station_mac" ]; then
		ip link set wlan0 down >"$out/failure-ip-link-down.log" 2>&1
		failure_down_rc=$?
		echo "ip_link_down_rc=$failure_down_rc" \
			>>"$failure_recovery_status_file"
		[ "$failure_down_rc" -eq 0 ] || {
			echo 'status=FAIL_MANAGED_LINK_DOWN' \
				>>"$failure_recovery_status_file"
			return 1
		}
		ip link set wlan0 address "$station_mac" \
			>"$out/failure-ip-restore-sta-mac.log" 2>&1
		failure_mac_rc=$?
		echo "restore_sta_mac_rc=$failure_mac_rc" \
			>>"$failure_recovery_status_file"
		[ "$failure_mac_rc" -eq 0 ] || {
			echo 'status=FAIL_RESTORE_STA_MAC' \
				>>"$failure_recovery_status_file"
			return 1
		}
		failure_managed_up=false
	fi
	if [ "$failure_managed_up" != true ]; then
		ip link set wlan0 up >"$out/failure-ip-link-up.log" 2>&1
		failure_up_rc=$?
		echo "ip_link_up_rc=$failure_up_rc" \
			>>"$failure_recovery_status_file"
		[ "$failure_up_rc" -eq 0 ] || {
			echo 'status=FAIL_MANAGED_LINK_UP' \
				>>"$failure_recovery_status_file"
			return 1
		}
	fi
	failure_managed_mac=$(cat /sys/class/net/wlan0/address 2>/dev/null)
	failure_managed_type=$(cat /sys/class/net/wlan0/type 2>/dev/null)
	failure_managed_flags=$(cat /sys/class/net/wlan0/flags 2>/dev/null)
	{
		echo "expected_sta_mac=$station_mac"
		echo "managed_mac=$failure_managed_mac"
		echo "managed_type=$failure_managed_type"
		echo "managed_flags=$failure_managed_flags"
	} >>"$failure_recovery_status_file"
	[ "$failure_managed_mac" = "$station_mac" ] ||
		failure_recovery_failed=1
	[ "$failure_managed_type" = 1 ] || failure_recovery_failed=1
	case "$failure_managed_flags" in
		0x[0-9a-fA-F]*)
			[ $((failure_managed_flags & 1)) -ne 0 ] ||
				failure_recovery_failed=1
			;;
		*) failure_recovery_failed=1 ;;
	esac
	marker failure-managed-mode-ready

	svc wifi enable >"$out/failure-svc-wifi-enable.log" 2>&1
	failure_enable_rc=$?
	echo "svc_wifi_enable_rc=$failure_enable_rc" \
		>>"$failure_recovery_status_file"
	[ "$failure_enable_rc" -eq 0 ] || failure_recovery_failed=1
	if [ "$failure_enable_rc" -eq 0 ]; then
		wait_primary_connect_mode
		failure_primary_rc=$?
		echo "primary_connect_mode_rc=$failure_primary_rc" \
			>>"$failure_recovery_status_file"
		[ "$failure_primary_rc" -eq 0 ] || failure_recovery_failed=1
		if [ "$failure_primary_rc" -eq 0 ]; then
			wait_supplicant
			failure_supplicant_rc=$?
			echo "supplicant_rc=$failure_supplicant_rc" \
				>>"$failure_recovery_status_file"
			[ "$failure_supplicant_rc" -eq 0 ] ||
				failure_recovery_failed=1
		fi
		if [ "${failure_supplicant_rc:-1}" -eq 0 ]; then
			wait_link
			failure_link_rc=$?
			echo "link_rc=$failure_link_rc" \
				>>"$failure_recovery_status_file"
			[ "$failure_link_rc" -eq 0 ] || failure_recovery_failed=1
		fi
		if [ "${failure_link_rc:-1}" -eq 0 ]; then
			verify_connected_identity failure-recovery-identity
			failure_identity_rc=$?
			echo "identity_rc=$failure_identity_rc" \
				>>"$failure_recovery_status_file"
			[ "$failure_identity_rc" -eq 0 ] ||
				failure_recovery_failed=1
			wait_ipv4
			failure_ipv4_rc=$?
			echo "ipv4_rc=$failure_ipv4_rc" \
				>>"$failure_recovery_status_file"
			[ "$failure_ipv4_rc" -eq 0 ] || failure_recovery_failed=1
		fi
		if [ "${failure_ipv4_rc:-1}" -eq 0 ]; then
			wait_framework_connected_validated
			failure_validated_rc=$?
			echo "validated_rc=$failure_validated_rc" \
				>>"$failure_recovery_status_file"
			[ "$failure_validated_rc" -eq 0 ] ||
				failure_recovery_failed=1
			verify_gateway_connectivity
			failure_gateway_rc=$?
			echo "gateway_rc=$failure_gateway_rc" \
				>>"$failure_recovery_status_file"
			[ "$failure_gateway_rc" -eq 0 ] ||
				failure_recovery_failed=1
		fi
	fi

	case "${initial_scan_state:-}" in
		true) failure_restore_scan_arg=enabled ;;
		false) failure_restore_scan_arg=disabled ;;
		*) failure_restore_scan_arg= ;;
	esac
	if [ -n "$failure_restore_scan_arg" ]; then
		cmd wifi set-scan-always-available "$failure_restore_scan_arg" \
			>"$out/failure-restore-scan-always.log" 2>&1
		failure_restore_scan_rc=$?
		echo "restore_scan_always_rc=$failure_restore_scan_rc" \
			>>"$failure_recovery_status_file"
		[ "$failure_restore_scan_rc" -eq 0 ] ||
			failure_recovery_failed=1
	fi

	if [ "$failure_recovery_failed" -eq 0 ]; then
		echo 'status=PASS' >>"$failure_recovery_status_file"
		marker failure-managed-reconnect-pass
		return 0
	fi
	echo 'status=FAIL_VALIDATION_OR_RECONNECT' \
		>>"$failure_recovery_status_file"
	marker failure-managed-reconnect-fail
	return 1
}

select_probe_frequencies()
{
	iw phy >"$out/iw-phy-for-probe.log" 2>&1 || return 1
	probe_2g=$(awk '
		$1 == "*" && $2 ~ /^[0-9]+$/ && $3 == "MHz" {
			line = tolower($0)
			if ($2 >= 2400 && $2 < 2500 &&
			    line !~ /disabled|no ir|radar detection/) {
				print $2
				exit
			}
		}
	' "$out/iw-phy-for-probe.log")
	probe_5g=$(awk '
		$1 == "*" && $2 ~ /^[0-9]+$/ && $3 == "MHz" {
			line = tolower($0)
			if ($2 >= 5000 && $2 < 5925 &&
			    line !~ /disabled|no ir|radar detection/) {
				print $2
				exit
			}
		}
	' "$out/iw-phy-for-probe.log")
	case "$baseline_freq" in
		24[0-9][0-9]) probe_2g=$baseline_freq ;;
		5[0-8][0-9][0-9]) probe_5g=$baseline_freq ;;
	esac
	case "$probe_2g:$probe_5g" in
		[0-9]*:[0-9]*) ;;
		*) return 2 ;;
	esac
	{
		echo "initial_mhz=$baseline_freq"
		echo "probe_2g_mhz=$probe_2g"
		echo "probe_5g_mhz=$probe_5g"
		echo "hop_1_mhz=$baseline_freq"
		echo "hop_2_mhz=$probe_2g"
		echo "hop_3_mhz=$probe_5g"
		echo "hop_4_mhz=$baseline_freq"
	} >"$out/iface-probe-frequency-matrix.txt"
	return 0
}

frequency_to_channel()
{
	channel_freq=$1
	if [ "$channel_freq" -eq 2484 ]; then
		echo 14
		return 0
	fi
	if [ "$channel_freq" -ge 2412 ] && [ "$channel_freq" -le 2472 ] &&
	   [ $(((channel_freq - 2407) % 5)) -eq 0 ]; then
		echo $(((channel_freq - 2407) / 5))
		return 0
	fi
	if [ "$channel_freq" -ge 5000 ] && [ "$channel_freq" -le 5895 ] &&
	   [ $(((channel_freq - 5000) % 5)) -eq 0 ]; then
		echo $(((channel_freq - 5000) / 5))
		return 0
	fi
	if [ "$channel_freq" -eq 5935 ]; then
		echo 2
		return 0
	fi
	if [ "$channel_freq" -ge 5955 ] && [ "$channel_freq" -le 7115 ] &&
	   [ $(((channel_freq - 5950) % 5)) -eq 0 ]; then
		echo $(((channel_freq - 5950) / 5))
		return 0
	fi
	return 1
}

wait_for_log_increment()
{
	wait_pattern=$1
	wait_before=$2
	wait_limit=$3
	wait_i=0
	while [ "$wait_i" -lt "$wait_limit" ]; do
		wait_after=$(run_log_count "$wait_pattern")
		[ "$wait_after" -gt "$wait_before" ] && return 0
		health_check || return 2
		wait_i=$((wait_i + 1))
		sleep 1
	done
	return 1
}

tx_snapshot()
{
	tx_label=$1
	current_run_dmesg | tail -n 600 >"$out/$tx_label-dmesg.log" 2>&1
	capture_required "$out/$tx_label-iw-info.log" iw dev wlan0 info
	capture_required "$out/$tx_label-cnss-firmware-ready.log" cat \
		/sys/bus/platform/drivers/cnss2/firmware_ready
	cat "$force_raw_node" >"$out/$tx_label-force-raw.txt" 2>&1
	cat /sys/kernel/debug/wlan0/frame_inject_stats \
		>"$out/$tx_label-frame-inject-stats.txt" 2>&1
	sync
}

frame_inject_stat()
{
	stat_key=$1
	awk -F= -v key="$stat_key" '
		$1 == key { print $2; found = 1; exit }
		END { if (!found) exit 1 }
	' /sys/kernel/debug/wlan0/frame_inject_stats 2>/dev/null
}

wait_for_frame_inject_stat_increment()
{
	stat_key=$1
	stat_before=$2
	stat_limit=$3
	stat_i=0
	while [ "$stat_i" -lt "$stat_limit" ]; do
		stat_after=$(frame_inject_stat "$stat_key") || return 2
		[ "$stat_after" -gt "$stat_before" ] && return 0
		health_check || return 3
		stat_i=$((stat_i + 1))
		sleep 1
	done
	return 1
}

verify_gate_n_rejection()
{
	gate_reject_pattern='frame injection RAW gate rejected'
	gate_helper_pattern='frame injection helper'
	gate_raw_pattern='frame injection DP RAW submit'
	gate_status_pattern='frame injection DP TX_STATUS'
	gate_reclaim_pattern='frame injection DP RECLAIM'
	gate_reject_before=$(run_log_count "$gate_reject_pattern")
	gate_helper_before=$(run_log_count "$gate_helper_pattern")
	gate_raw_before=$(run_log_count "$gate_raw_pattern")
	gate_status_before=$(run_log_count "$gate_status_pattern")
	gate_reclaim_before=$(run_log_count "$gate_reclaim_pattern")
	marker gate-n-valid-probe
	"$sender" probe-request "$peer_mac" "$run_nonce" \
		>"$out/gate-n-valid-probe.log" 2>&1
	[ "$?" -eq 0 ] || fail "gate-N probe sendto failed" 60
	wait_for_log_increment "$gate_reject_pattern" "$gate_reject_before" 8 ||
		fail "gate-N probe received no explicit worker rejection" 61
	sleep 2
	health_check || fail "health failure after gate-N rejection" 62
	[ "$(run_log_count "$gate_reject_pattern")" -eq \
	  $((gate_reject_before + 1)) ] ||
		fail "gate-N probe produced a non-unique rejection" 63
	[ "$(run_log_count "$gate_helper_pattern")" -eq "$gate_helper_before" ] ||
		fail "gate-N probe entered helper lifecycle" 64
	[ "$(run_log_count "$gate_raw_pattern")" -eq "$gate_raw_before" ] ||
		fail "gate-N probe reached DP RAW submit" 65
	[ "$(run_log_count "$gate_status_pattern")" -eq "$gate_status_before" ] ||
		fail "gate-N probe produced a DP TX status" 66
	[ "$(run_log_count "$gate_reclaim_pattern")" -eq \
	  "$gate_reclaim_before" ] ||
		fail "gate-N probe produced a DP reclaim" 67
	marker gate-n-explicit-rejection-verified
	tx_snapshot gate-n-verified
}

verify_parser_rejection()
{
	parser_pattern='frame injection parser rejected skb error='
	parser_helper_pattern='frame injection helper'
	parser_raw_pattern='frame injection DP RAW submit'
	parser_status_pattern='frame injection DP TX_STATUS'
	parser_reclaim_pattern='frame injection DP RECLAIM'
	parser_before=$(run_log_count "$parser_pattern")
	parser_helper_before=$(run_log_count "$parser_helper_pattern")
	parser_raw_before=$(run_log_count "$parser_raw_pattern")
	parser_status_before=$(run_log_count "$parser_status_pattern")
	parser_reclaim_before=$(run_log_count "$parser_reclaim_pattern")
	marker gate-y-bad-rate-probe
	"$sender" bad-rate-probe "$peer_mac" "$run_nonce" \
		>"$out/gate-y-bad-rate-probe.log" 2>&1
	[ "$?" -eq 0 ] || fail "bad-rate probe sendto failed" 68
	wait_for_log_increment "$parser_pattern" "$parser_before" 8 ||
		fail "bad-rate probe received no explicit parser rejection" 69
	sleep 2
	health_check || fail "health failure after parser rejection" 70
	[ "$(run_log_count "$parser_pattern")" -eq $((parser_before + 1)) ] ||
		fail "bad-rate probe produced a non-unique parser rejection" 71
	[ "$(run_log_count "$parser_helper_pattern")" -eq \
	  "$parser_helper_before" ] || fail "bad-rate probe created helper" 72
	[ "$(run_log_count "$parser_raw_pattern")" -eq "$parser_raw_before" ] ||
		fail "bad-rate probe reached DP RAW submit" 73
	[ "$(run_log_count "$parser_status_pattern")" -eq "$parser_status_before" ] ||
		fail "bad-rate probe produced a DP TX status" 74
	[ "$(run_log_count "$parser_reclaim_pattern")" -eq \
	  "$parser_reclaim_before" ] ||
		fail "bad-rate probe produced a DP reclaim" 75
	marker parser-rejection-verified
	tx_snapshot parser-rejection-verified
}

force_gate_on()
{
	gate_label=$1
	printf '1\n' >"$force_raw_node" 2>/dev/null || return 1
	gate_value=$(cat "$force_raw_node" 2>/dev/null | tr -d ' \r\n')
	printf 'force_raw_requested=1\nforce_raw_observed=%s\n' "$gate_value" \
		>"$out/$gate_label-gate-on.txt"
	[ "$gate_value" = Y ] || [ "$gate_value" = 1 ]
}

force_gate_off()
{
	gate_label=$1
	gate_write_rc=0
	printf '0\n' >"$force_raw_node" 2>/dev/null || gate_write_rc=$?
	gate_value=$(cat "$force_raw_node" 2>/dev/null | tr -d ' \r\n')
	printf 'force_raw_requested=0\nforce_raw_write_rc=%s\nforce_raw_observed=%s\n' \
		"$gate_write_rc" "$gate_value" \
		>"$out/$gate_label-gate-off.txt"
	[ "$gate_write_rc" -eq 0 ] &&
	([ "$gate_value" = N ] || [ "$gate_value" = 0 ])
}

begin_injection_phase()
{
	phase_name=$1
	phase_start_index=$2
	phase_end_index=$3
	phase_expected=$4
	phase_gate_on_verified=0
	phase_gate_off_verified=0
	active_phase=$phase_name
	health_check || fail "health failure before $phase_name phase" 76
	phase_rows_before=$(awk 'END { print (NR > 0 ? NR - 1 : 0) }' \
		"$out/frame-matrix.tsv")
	marker "phase-$phase_name-gate-on-request"
	force_gate_on "phase-$phase_name" ||
		fail "could not enable force RAW gate for $phase_name phase" 58
	phase_gate_on_verified=1
	marker "phase-$phase_name-gate-on-verified"
}

end_injection_phase()
{
	phase_rows_after=$(awk 'END { print (NR > 0 ? NR - 1 : 0) }' \
		"$out/frame-matrix.tsv")
	phase_completed=$((phase_rows_after - phase_rows_before))
	[ "$phase_completed" -eq "$phase_expected" ] ||
		fail "$phase_name phase completed $phase_completed/$phase_expected frames" 92
	marker "phase-$phase_name-gate-off-request"
	force_gate_off "phase-$phase_name" ||
		fail "could not disable force RAW gate after $phase_name phase" 93
	phase_gate_off_verified=1
	health_check || fail "health failure after $phase_name gate shutdown" 94
	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\tPASS\n' \
		"$phase_name" "$phase_start_index" "$phase_end_index" \
		"$phase_expected" "$phase_completed" "$phase_gate_on_verified" \
		"$phase_gate_off_verified" >>"$out/phase-matrix.tsv"
	active_phase=
	marker "phase-$phase_name-complete-gate-disabled"
	tx_snapshot "phase-$phase_name-complete"
}

send_and_wait()
{
	tx_variant=$1
	tx_index=$2
	tx_first=$3
	tx_raw_pattern='frame injection DP RAW submit'
	tx_status_pattern='frame injection DP TX_STATUS'
	tx_reclaim_pattern='frame injection DP RECLAIM'
	tx_fw_ready_pattern='frame injection helper FW ready'
	tx_ap_ready_pattern='frame injection helper AP ready'
	health_check || fail "pre-send health failure for $tx_variant" 76
	tx_raw_before=$(run_log_count "$tx_raw_pattern")
	tx_status_before=$(run_log_count "$tx_status_pattern")
	tx_reclaim_before=$(run_log_count "$tx_reclaim_pattern")
	tx_fw_ready_before=$(run_log_count "$tx_fw_ready_pattern")
	tx_ap_ready_before=$(run_log_count "$tx_ap_ready_pattern")
	tx_status_stat_before=$(frame_inject_stat dp_tx_status_events) ||
		fail "could not read pre-send DP TX status count" 76
	tx_reclaim_stat_before=$(frame_inject_stat dp_reclaimed) ||
		fail "could not read pre-send DP reclaim count" 76
	tx_no_status_stat_before=$(frame_inject_stat dp_reclaim_without_status) ||
		fail "could not read pre-send reclaim-without-status count" 76
	transmit_order=$((transmit_order + 1))
	tx_index_decimal=$((1$tx_index - 100))
	if [ "$tx_index_decimal" -eq 33 ]; then
		tx_expected_order=67
	else
		tx_expected_order=$tx_index_decimal
	fi
	[ "$transmit_order" -eq "$tx_expected_order" ] ||
		fail "$tx_variant transmit order is $transmit_order, expected $tx_expected_order" 76
	marker "send-$tx_index-$tx_variant-order-$transmit_order"
	"$sender" "$tx_variant" "$peer_mac" "$run_nonce" \
		>"$out/send-$tx_index-$tx_variant.log" 2>&1
	tx_sender_rc=$?
	echo "$tx_sender_rc" >"$out/send-$tx_index-$tx_variant.rc"
	[ "$tx_sender_rc" -eq 0 ] ||
		fail "$tx_variant single sendto failed" 77
	tx_sender_line=$(grep '^variant=' "$out/send-$tx_index-$tx_variant.log" |
		tail -n 1)
	tx_packet_hex=$(sed -n 's/^packet_hex=//p' \
		"$out/send-$tx_index-$tx_variant.log" | head -n 1)
	tx_sender_len=$(printf '%s\n' "$tx_sender_line" |
		sed -n 's/.* frame_len=\([0-9][0-9]*\).*/\1/p')
	tx_sender_fc=$(printf '%s\n' "$tx_sender_line" |
		sed -n 's/.* fc=0x\([[:xdigit:]][[:xdigit:]]*\).*/\1/p')
	[ -n "$tx_packet_hex" ] && [ -n "$tx_sender_len" ] &&
	[ -n "$tx_sender_fc" ] ||
		fail "$tx_variant sender provenance is incomplete" 77
	tx_packet_sha=$(printf '%s' "$tx_packet_hex" | sha256sum |
		awk '{print $1}')
	if [ "$tx_first" = true ]; then
		tx_submit_wait=30
	else
		tx_submit_wait=8
	fi
	wait_for_log_increment "$tx_raw_pattern" "$tx_raw_before" \
		"$tx_submit_wait" ||
		fail "$tx_variant received no DP RAW submit" 78
	[ "$(run_log_count "$tx_raw_pattern")" -eq $((tx_raw_before + 1)) ] ||
		fail "$tx_variant did not produce exactly one DP RAW submit" 79
	tx_raw_line=$(current_run_dmesg | grep -F "$tx_raw_pattern" | tail -n 1)
	printf '%s\n' "$tx_raw_line" >"$out/send-$tx_index-$tx_variant-raw-submit.log"
	tx_vdev=$(printf '%s\n' "$tx_raw_line" |
		sed -n 's/.* vdev=\([0-9][0-9]*\).*/\1/p')
	tx_peer_id=$(printf '%s\n' "$tx_raw_line" |
		sed -n 's/.* peer_id=\([0-9][0-9]*\).*/\1/p')
	tx_generation=$(printf '%s\n' "$tx_raw_line" |
		sed -n 's/.* generation=\([0-9][0-9]*\).*/\1/p')
	tx_cookie=$(printf '%s\n' "$tx_raw_line" |
		sed -n 's/.* cookie=0x\([[:xdigit:]][[:xdigit:]]*\).*/\1/p')
	tx_frequency=$(printf '%s\n' "$tx_raw_line" |
		sed -n 's/.* freq=\([0-9][0-9]*\).*/\1/p')
	tx_raw_len=$(printf '%s\n' "$tx_raw_line" |
		sed -n 's/.* len=\([0-9][0-9]*\).*/\1/p')
	tx_raw_fc=$(printf '%s\n' "$tx_raw_line" |
		sed -n 's/.* fc=0x\([[:xdigit:]][[:xdigit:]]*\).*/\1/p')
	[ -n "$tx_vdev" ] && [ -n "$tx_peer_id" ] &&
	[ -n "$tx_generation" ] && [ -n "$tx_cookie" ] ||
		fail "$tx_variant DP RAW identity is incomplete" 81
	[ "$tx_raw_len" = "$tx_sender_len" ] &&
	[ "$tx_raw_fc" = "$tx_sender_fc" ] &&
	[ "$tx_frequency" = "$baseline_freq" ] ||
		fail "$tx_variant sender/DP RAW provenance mismatch" 81
	if [ "$tx_first" = true ]; then
		phase_vdev=$tx_vdev
		phase_generation=$tx_generation
		phase_peer_id=$tx_peer_id
		[ "$(run_log_count "$tx_fw_ready_pattern")" -eq \
		  $((tx_fw_ready_before + 1)) ] ||
			fail "first frame lacked one helper FW-ready event" 82
		[ "$(run_log_count "$tx_ap_ready_pattern")" -eq \
		  $((tx_ap_ready_before + 1)) ] ||
			fail "first frame lacked one helper AP-ready event" 83
		tx_fw_ready_line=$(current_run_dmesg | grep -F "$tx_fw_ready_pattern" |
			tail -n 1)
		tx_ap_ready_line=$(current_run_dmesg | grep -F "$tx_ap_ready_pattern" |
			tail -n 1)
		printf '%s\n' "$tx_fw_ready_line" >"$out/helper-fw-ready.log"
		printf '%s\n' "$tx_ap_ready_line" >"$out/helper-ap-ready.log"
		printf '%s\n' "$tx_fw_ready_line" | grep -q 'ownership=explicit' ||
			fail "helper FW-ready event did not use the explicit BSS peer" 84
		tx_fw_vdev=$(printf '%s\n' "$tx_fw_ready_line" |
			sed -n 's/.* vdev=\([0-9][0-9]*\).*/\1/p')
		tx_ap_vdev=$(printf '%s\n' "$tx_ap_ready_line" |
			sed -n 's/.* vdev=\([0-9][0-9]*\).*/\1/p')
		tx_ap_generation=$(printf '%s\n' "$tx_ap_ready_line" |
			sed -n 's/.* generation=\([0-9][0-9]*\).*/\1/p')
		[ "$tx_fw_vdev" = "$tx_vdev" ] && [ "$tx_ap_vdev" = "$tx_vdev" ] ||
			fail "helper READY vdev does not match DP RAW vdev" 85
		[ "$tx_ap_generation" = "$tx_generation" ] ||
			fail "helper READY generation does not match DP RAW generation" 85
	else
		[ "$tx_vdev" = "$phase_vdev" ] &&
		[ "$tx_generation" = "$phase_generation" ] &&
		[ "$tx_peer_id" = "$phase_peer_id" ] ||
			fail "$tx_variant helper identity changed within phase" 86
		[ "$(run_log_count "$tx_fw_ready_pattern")" -eq \
		  "$tx_fw_ready_before" ] ||
			fail "$tx_variant unexpectedly rebuilt the helper" 86
		[ "$(run_log_count "$tx_ap_ready_pattern")" -eq \
		  "$tx_ap_ready_before" ] ||
			fail "$tx_variant unexpectedly republished the AP helper" 86
	fi
	wait_for_log_increment "$tx_status_pattern" "$tx_status_before" 6 ||
		fail "$tx_variant received no DP TX status" 87
	wait_for_log_increment "$tx_reclaim_pattern" "$tx_reclaim_before" 6 ||
		fail "$tx_variant received no DP reclaim" 88
	[ "$(run_log_count "$tx_status_pattern")" -eq \
	  $((tx_status_before + 1)) ] ||
		fail "$tx_variant did not produce exactly one DP TX status" 87
	[ "$(run_log_count "$tx_reclaim_pattern")" -eq \
	  $((tx_reclaim_before + 1)) ] ||
		fail "$tx_variant did not produce exactly one DP reclaim" 88
	tx_status_line=$(current_run_dmesg | grep -F "$tx_status_pattern" |
		tail -n 1)
	tx_reclaim_line=$(current_run_dmesg | grep -F "$tx_reclaim_pattern" |
		tail -n 1)
	printf '%s\n' "$tx_status_line" \
		>"$out/send-$tx_index-$tx_variant-dp-status.log"
	printf '%s\n' "$tx_reclaim_line" \
		>"$out/send-$tx_index-$tx_variant-dp-reclaim.log"
	tx_status_vdev=$(printf '%s\n' "$tx_status_line" |
		sed -n 's/.* vdev=\([0-9][0-9]*\).*/\1/p')
	tx_status_generation=$(printf '%s\n' "$tx_status_line" |
		sed -n 's/.* generation=\([0-9][0-9]*\).*/\1/p')
	tx_status_cookie=$(printf '%s\n' "$tx_status_line" |
		sed -n 's/.* cookie=0x\([[:xdigit:]][[:xdigit:]]*\).*/\1/p')
	tx_rate_valid=$(printf '%s\n' "$tx_status_line" |
		sed -n 's/.* valid=\([01]\).*/\1/p')
	tx_status=$(printf '%s\n' "$tx_status_line" |
		sed -n 's/.* status=\([0-9][0-9]*\).*/\1/p')
	tx_release_src=$(printf '%s\n' "$tx_status_line" |
		sed -n 's/.* release_src=\([0-9][0-9]*\).*/\1/p')
	tx_transmit_count=$(printf '%s\n' "$tx_status_line" |
		sed -n 's/.* transmit_count=\([0-9][0-9]*\).*/\1/p')
	tx_ppdu_id=$(printf '%s\n' "$tx_status_line" |
		sed -n 's/.* ppdu_id=\([0-9][0-9]*\).*/\1/p')
	tx_reclaim_vdev=$(printf '%s\n' "$tx_reclaim_line" |
		sed -n 's/.* vdev=\([0-9][0-9]*\).*/\1/p')
	tx_reclaim_generation=$(printf '%s\n' "$tx_reclaim_line" |
		sed -n 's/.* generation=\([0-9][0-9]*\).*/\1/p')
	tx_reclaim_cookie=$(printf '%s\n' "$tx_reclaim_line" |
		sed -n 's/.* cookie=0x\([[:xdigit:]][[:xdigit:]]*\).*/\1/p')
	tx_reclaim_status_seen=$(printf '%s\n' "$tx_reclaim_line" |
		sed -n 's/.* status_seen=\([01]\).*/\1/p')
	[ "$tx_status_vdev" = "$tx_vdev" ] &&
	[ "$tx_status_generation" = "$tx_generation" ] &&
	[ "$tx_status_cookie" = "$tx_cookie" ] &&
	[ "$tx_reclaim_vdev" = "$tx_vdev" ] &&
	[ "$tx_reclaim_generation" = "$tx_generation" ] &&
	[ "$tx_reclaim_cookie" = "$tx_cookie" ] &&
	[ "$tx_reclaim_status_seen" = 1 ] && [ "$tx_status" = 0 ] &&
	[ "$tx_release_src" = 3 ] && [ "$tx_transmit_count" -gt 0 ] &&
	[ "$tx_ppdu_id" -gt 0 ] ||
		fail "$tx_variant DP submit/status/reclaim identity mismatch" 89
	wait_for_frame_inject_stat_increment dp_reclaimed \
		"$tx_reclaim_stat_before" 6 ||
		fail "$tx_variant debugfs reclaim count did not advance" 90
	tx_status_stat_after=$(frame_inject_stat dp_tx_status_events) ||
		fail "$tx_variant final DP status count is unavailable" 90
	tx_reclaim_stat_after=$(frame_inject_stat dp_reclaimed) ||
		fail "$tx_variant final DP reclaim count is unavailable" 90
	tx_no_status_stat_after=$(frame_inject_stat dp_reclaim_without_status) ||
		fail "$tx_variant final no-status count is unavailable" 90
	[ "$tx_status_stat_after" -eq $((tx_status_stat_before + 1)) ] &&
	[ "$tx_reclaim_stat_after" -eq $((tx_reclaim_stat_before + 1)) ] &&
	[ "$tx_no_status_stat_after" -eq "$tx_no_status_stat_before" ] ||
		fail "$tx_variant DP status/reclaim counters are inconsistent" 90
	[ "$(frame_inject_stat tx_inflight)" = 0 ] &&
	[ "$(frame_inject_stat submit_pending)" = 0 ] &&
	[ "$(frame_inject_stat tx_vdev_id)" = "$tx_vdev" ] &&
	[ "$(frame_inject_stat tx_generation)" = "$tx_generation" ] &&
	[ "$(frame_inject_stat tx_cookie)" = "0x$tx_cookie" ] &&
	[ "$(frame_inject_stat last_tx_status)" = 0 ] &&
	[ "$(frame_inject_stat last_tx_release_src)" = 3 ] &&
	[ "$(frame_inject_stat last_tx_transmit_count)" -gt 0 ] &&
	[ "$(frame_inject_stat last_tx_ppdu_id)" -gt 0 ] ||
		fail "$tx_variant format-v3 final state is inconsistent" 90
	health_check || fail "post-reclaim health failure for $tx_variant" 91
	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t1\t%s\t%s\t%s\t%s\t1\t%s\t%s\t%s\t%s\n' \
		"$tx_index" "$tx_variant" "$run_nonce" "$tx_cookie" "$tx_vdev" \
		"$tx_generation" "$tx_peer_id" "$tx_status" "$tx_rate_valid" \
		"$tx_release_src" "$tx_transmit_count" "$tx_ppdu_id" \
		"$tx_sender_fc" "$tx_sender_len" "$tx_packet_sha" "$transmit_order" \
		>>"$out/frame-matrix.tsv"
	marker "complete-$tx_index-$tx_variant-cookie-$tx_cookie-status-$tx_status-reclaimed"
}

verify_unsupported_tx_params()
{
	txp_raw_pattern='frame injection DP RAW submit'
	txp_status_pattern='frame injection DP TX_STATUS'
	txp_reclaim_pattern='frame injection DP RECLAIM'
	case "$baseline_freq" in
		24[0-9][0-9]) txp_rate=22; txp_channel_flags=a0 ;;
		49[0-9][0-9]|5[0-8][0-9][0-9]) txp_rate=108; txp_channel_flags=140 ;;
		*) fail "TX-parameter negative probe has no legacy profile for $baseline_freq MHz" 113 ;;
	esac
	txp_nonce=$((run_nonce % 4095 + 1))
	health_check || fail "health failure before unsupported TX-parameter probe" 113
	txp_raw_before=$(run_log_count "$txp_raw_pattern")
	txp_status_before=$(run_log_count "$txp_status_pattern")
	txp_reclaim_before=$(run_log_count "$txp_reclaim_pattern")
	txp_backend_before=$(frame_inject_stat backend_unsupported) ||
		fail "could not read backend_unsupported before negative test" 113
	marker "tx-params-fail-closed-rate-$txp_rate-freq-$baseline_freq-retries-2"
	"$sender" --tx-params "$txp_rate" "$baseline_freq" \
		"0x$txp_channel_flags" 2 "$peer_mac" "$txp_nonce" \
		>"$out/tx-params-unsupported.log" 2>&1
	[ "$?" -eq 0 ] || fail "unsupported TX-parameter sendto failed" 114
	wait_for_frame_inject_stat_increment backend_unsupported \
		"$txp_backend_before" 8 ||
		fail "unsupported TX parameters were not explicitly rejected" 115
	sleep 1
	[ "$(frame_inject_stat backend_unsupported)" -eq \
	  $((txp_backend_before + 1)) ] ||
		fail "unsupported TX parameters did not increment backend_unsupported once" 116
	[ "$(run_log_count "$txp_raw_pattern")" -eq "$txp_raw_before" ] &&
	[ "$(run_log_count "$txp_status_pattern")" -eq "$txp_status_before" ] &&
	[ "$(run_log_count "$txp_reclaim_pattern")" -eq "$txp_reclaim_before" ] ||
		fail "unsupported TX parameters reached direct DP" 117

	txp_parser_before=$(frame_inject_stat parse_failed) ||
		fail "could not read parse_failed before retry-range test" 118
	marker tx-params-retry-range-negative-127
	"$sender" --tx-params "$txp_rate" "$baseline_freq" \
		"0x$txp_channel_flags" 127 "$peer_mac" "$txp_nonce" \
		>"$out/tx-params-retry-range-negative.log" 2>&1
	[ "$?" -eq 0 ] || fail "retry-range negative sendto failed" 118
	wait_for_frame_inject_stat_increment parse_failed "$txp_parser_before" 8 ||
		fail "DATA_RETRIES=127 was not explicitly rejected" 119
	[ "$(run_log_count "$txp_raw_pattern")" -eq "$txp_raw_before" ] &&
	[ "$(run_log_count "$txp_status_pattern")" -eq "$txp_status_before" ] &&
	[ "$(run_log_count "$txp_reclaim_pattern")" -eq "$txp_reclaim_before" ] ||
		fail "retry-range negative request reached direct DP" 120
	health_check || fail "health failure after TX-parameter rejection" 120
	marker tx-params-negative-complete
	tx_snapshot tx-params-negative-complete
}

send_workflow_frame()
{
	wf_index=$1
	wf_tag=$(printf '%02d' "$wf_index")
	wf_log=$out/workflow-frame-$wf_tag.log
	wf_raw_pattern='frame injection DP RAW submit'
	wf_status_pattern='frame injection DP TX_STATUS'
	wf_reclaim_pattern='frame injection DP RECLAIM'
	wf_helper_pattern='frame injection helper FW ready'
	active_workflow_group=pending-$wf_index
	health_check || fail "health failure before workflow frame $wf_index" 100
	wf_raw_before=$(run_log_count "$wf_raw_pattern")
	wf_status_before=$(run_log_count "$wf_status_pattern")
	wf_reclaim_before=$(run_log_count "$wf_reclaim_pattern")
	wf_helper_before=$(run_log_count "$wf_helper_pattern")
	wf_status_stat_before=$(frame_inject_stat dp_tx_status_events) ||
		fail "could not read workflow pre-send DP status count" 100
	wf_reclaim_stat_before=$(frame_inject_stat dp_reclaimed) ||
		fail "could not read workflow pre-send DP reclaim count" 100
	wf_no_status_stat_before=$(frame_inject_stat dp_reclaim_without_status) ||
		fail "could not read workflow pre-send no-status count" 100
	transmit_order=$((transmit_order + 1))
	wf_expected_order=$((32 + wf_index))
	[ "$transmit_order" -eq "$wf_expected_order" ] ||
		fail "workflow frame $wf_index transmit order is $transmit_order, expected $wf_expected_order" 100

	marker "workflow-frame-$wf_tag-send-order-$transmit_order"
	"$sender" --workflow-frame "$wf_index" "$baseline_channel" \
		"$peer_mac" "$run_nonce" >"$wf_log" 2>&1
	wf_sender_rc=$?
	echo "$wf_sender_rc" >"$out/workflow-frame-$wf_tag.rc"
	[ "$wf_sender_rc" -eq 0 ] ||
		fail "workflow frame $wf_index sender failed" 102
	[ "$(grep -c "^workflow_packet index=$wf_index " "$wf_log")" -eq 1 ] &&
	[ "$(grep -c "^workflow_frame index=$wf_index " "$wf_log")" -eq 1 ] ||
		fail "workflow index $wf_index sender records are not unique" 103
	wf_packet_line=$(grep "^workflow_packet index=$wf_index " "$wf_log")
	wf_frame_line=$(grep "^workflow_frame index=$wf_index " "$wf_log")
	wf_packet_hex=${wf_packet_line##* packet_hex=}
	wf_group=$(printf '%s\n' "$wf_frame_line" |
		sed -n 's/.* group=\([0-9][0-9]*\) .*/\1/p')
	wf_trigger=$(printf '%s\n' "$wf_frame_line" |
		sed -n 's/.* trigger=\([^ ]*\) name=.*/\1/p')
	wf_name=$(printf '%s\n' "$wf_frame_line" |
		sed -n 's/.* name=\([^ ]*\) monotonic_timestamp=.*/\1/p')
	wf_channel=$(printf '%s\n' "$wf_frame_line" |
		sed -n 's/.* channel=\([0-9][0-9]*\) .*/\1/p')
	wf_bytes=$(printf '%s\n' "$wf_frame_line" |
		sed -n 's/.* bytes=\([0-9][0-9]*\) expected=.*/\1/p')
	wf_expected=$(printf '%s\n' "$wf_frame_line" |
		sed -n 's/.* expected=\([0-9][0-9]*\) frame_len=.*/\1/p')
	wf_frame_len=$(printf '%s\n' "$wf_frame_line" |
		sed -n 's/.* frame_len=\([0-9][0-9]*\) fc=.*/\1/p')
	wf_fc=$(printf '%s\n' "$wf_frame_line" |
		sed -n 's/.* fc=0x\([[:xdigit:]][[:xdigit:]]*\) .*/\1/p')
	case "$wf_packet_hex:$wf_group:$wf_trigger:$wf_name:$wf_channel:$wf_bytes:$wf_expected:$wf_frame_len:$wf_fc" in
		:*|*::*|*:) fail "workflow index $wf_index sender provenance is incomplete" 103 ;;
	esac
	active_workflow_group=$wf_group
	grep -q "^workflow_complete frames=1 groups=1 nonce=$run_nonce group_filter=$wf_group frame_filter=$wf_index channel=$baseline_channel serialization=runner-dp-status-reclaim-gate-required$" \
		"$wf_log" || fail "workflow frame $wf_index completion contract mismatch" 103
	printf '%s\n' "$wf_packet_hex" | grep -Eq '^[0-9a-f]+$' ||
		fail "workflow index $wf_index packet hex is not canonical" 103
	[ "$wf_channel" = "$baseline_channel" ] &&
	[ "$wf_bytes" = "$wf_expected" ] &&
	[ "$wf_bytes" -eq $((wf_frame_len + 8)) ] &&
	[ $(( ${#wf_packet_hex} % 2 )) -eq 0 ] &&
	[ $(( ${#wf_packet_hex} / 2 )) -eq "$wf_bytes" ] ||
		fail "workflow index $wf_index sender byte/channel mismatch" 103

	wait_for_log_increment "$wf_raw_pattern" "$wf_raw_before" 8 ||
		fail "workflow frame $wf_index received no DP RAW submit" 104
	[ "$(run_log_count "$wf_raw_pattern")" -eq $((wf_raw_before + 1)) ] ||
		fail "workflow frame $wf_index DP RAW submit count mismatch" 105
	if [ "$wf_index" -eq 1 ]; then
		[ "$(run_log_count "$wf_helper_pattern")" -eq \
		  $((wf_helper_before + 1)) ] ||
			fail "workflow first frame lacked one helper FW-ready event" 107
	else
		[ "$(run_log_count "$wf_helper_pattern")" -eq "$wf_helper_before" ] ||
			fail "workflow frame $wf_index unexpectedly rebuilt the helper" 107
	fi

	wf_raw_line=$(current_run_dmesg | grep -F "$wf_raw_pattern" | tail -n 1)
	printf '%s\n' "$wf_raw_line" >"$out/workflow-frame-$wf_tag-raw-submit.log"
	wf_vdev=$(printf '%s\n' "$wf_raw_line" |
		sed -n 's/.* vdev=\([0-9][0-9]*\).*/\1/p')
	wf_peer_id=$(printf '%s\n' "$wf_raw_line" |
		sed -n 's/.* peer_id=\([0-9][0-9]*\).*/\1/p')
	wf_generation=$(printf '%s\n' "$wf_raw_line" |
		sed -n 's/.* generation=\([0-9][0-9]*\).*/\1/p')
	wf_cookie=$(printf '%s\n' "$wf_raw_line" |
		sed -n 's/.* cookie=0x\([[:xdigit:]][[:xdigit:]]*\).*/\1/p')
	wf_raw_freq=$(printf '%s\n' "$wf_raw_line" |
		sed -n 's/.* freq=\([0-9][0-9]*\).*/\1/p')
	wf_raw_len=$(printf '%s\n' "$wf_raw_line" |
		sed -n 's/.* len=\([0-9][0-9]*\).*/\1/p')
	wf_raw_fc=$(printf '%s\n' "$wf_raw_line" |
		sed -n 's/.* fc=0x\([[:xdigit:]][[:xdigit:]]*\).*/\1/p')
	[ -n "$wf_vdev" ] && [ -n "$wf_peer_id" ] &&
	[ -n "$wf_generation" ] && [ -n "$wf_cookie" ] &&
	[ "$wf_raw_len" = "$wf_frame_len" ] &&
	[ "$wf_raw_fc" = "$wf_fc" ] && [ "$wf_raw_freq" = "$baseline_freq" ] ||
		fail "workflow index $wf_index DP RAW provenance mismatch" 108

	wait_for_log_increment "$wf_status_pattern" "$wf_status_before" 6 ||
		fail "workflow frame $wf_index received no DP TX status" 109
	wait_for_log_increment "$wf_reclaim_pattern" "$wf_reclaim_before" 6 ||
		fail "workflow frame $wf_index received no DP reclaim" 109
	[ "$(run_log_count "$wf_status_pattern")" -eq $((wf_status_before + 1)) ] &&
	[ "$(run_log_count "$wf_reclaim_pattern")" -eq \
	  $((wf_reclaim_before + 1)) ] ||
		fail "workflow frame $wf_index DP event count mismatch" 109
	wf_status_line=$(current_run_dmesg |
		grep -F "$wf_status_pattern" | tail -n 1)
	wf_reclaim_line=$(current_run_dmesg |
		grep -F "$wf_reclaim_pattern" | tail -n 1)
	printf '%s\n' "$wf_status_line" \
		>"$out/workflow-frame-$wf_tag-dp-status.log"
	printf '%s\n' "$wf_reclaim_line" \
		>"$out/workflow-frame-$wf_tag-dp-reclaim.log"
	wf_status_vdev=$(printf '%s\n' "$wf_status_line" |
		sed -n 's/.* vdev=\([0-9][0-9]*\).*/\1/p')
	wf_status_generation=$(printf '%s\n' "$wf_status_line" |
		sed -n 's/.* generation=\([0-9][0-9]*\).*/\1/p')
	wf_status_cookie=$(printf '%s\n' "$wf_status_line" |
		sed -n 's/.* cookie=0x\([[:xdigit:]][[:xdigit:]]*\).*/\1/p')
	wf_rate_valid=$(printf '%s\n' "$wf_status_line" |
		sed -n 's/.* valid=\([01]\).*/\1/p')
	wf_status=$(printf '%s\n' "$wf_status_line" |
		sed -n 's/.* status=\([0-9][0-9]*\).*/\1/p')
	wf_release_src=$(printf '%s\n' "$wf_status_line" |
		sed -n 's/.* release_src=\([0-9][0-9]*\).*/\1/p')
	wf_transmit_count=$(printf '%s\n' "$wf_status_line" |
		sed -n 's/.* transmit_count=\([0-9][0-9]*\).*/\1/p')
	wf_ppdu_id=$(printf '%s\n' "$wf_status_line" |
		sed -n 's/.* ppdu_id=\([0-9][0-9]*\).*/\1/p')
	wf_reclaim_vdev=$(printf '%s\n' "$wf_reclaim_line" |
		sed -n 's/.* vdev=\([0-9][0-9]*\).*/\1/p')
	wf_reclaim_generation=$(printf '%s\n' "$wf_reclaim_line" |
		sed -n 's/.* generation=\([0-9][0-9]*\).*/\1/p')
	wf_reclaim_cookie=$(printf '%s\n' "$wf_reclaim_line" |
		sed -n 's/.* cookie=0x\([[:xdigit:]][[:xdigit:]]*\).*/\1/p')
	wf_reclaim_status_seen=$(printf '%s\n' "$wf_reclaim_line" |
		sed -n 's/.* status_seen=\([01]\).*/\1/p')
	[ "$wf_status_vdev" = "$wf_vdev" ] &&
	[ "$wf_status_generation" = "$wf_generation" ] &&
	[ "$wf_status_cookie" = "$wf_cookie" ] &&
	[ "$wf_reclaim_vdev" = "$wf_vdev" ] &&
	[ "$wf_reclaim_generation" = "$wf_generation" ] &&
	[ "$wf_reclaim_cookie" = "$wf_cookie" ] &&
	[ "$wf_reclaim_status_seen" = 1 ] && [ "$wf_status" = 0 ] &&
	[ "$wf_release_src" = 3 ] && [ "$wf_transmit_count" -gt 0 ] &&
	[ "$wf_ppdu_id" -gt 0 ] ||
		fail "workflow index $wf_index DP status/reclaim mismatch" 110
	wf_status_stat_after=$(frame_inject_stat dp_tx_status_events) ||
		fail "workflow DP status counter unavailable" 111
	wf_reclaim_stat_after=$(frame_inject_stat dp_reclaimed) ||
		fail "workflow DP reclaim counter unavailable" 111
	wf_no_status_stat_after=$(frame_inject_stat dp_reclaim_without_status) ||
		fail "workflow no-status counter unavailable" 111
	[ "$wf_status_stat_after" -eq $((wf_status_stat_before + 1)) ] &&
	[ "$wf_reclaim_stat_after" -eq $((wf_reclaim_stat_before + 1)) ] &&
	[ "$wf_no_status_stat_after" -eq "$wf_no_status_stat_before" ] ||
		fail "workflow index $wf_index DP counters mismatch" 111
	if [ -z "${workflow_vdev:-}" ]; then
		workflow_vdev=$wf_vdev
		workflow_generation=$wf_generation
		workflow_peer_id=$wf_peer_id
	fi
	[ "$wf_vdev" = "$workflow_vdev" ] &&
	[ "$wf_generation" = "$workflow_generation" ] &&
	[ "$wf_peer_id" = "$workflow_peer_id" ] ||
		fail "workflow helper identity changed at index $wf_index" 110
	wf_packet_sha=$(printf '%s' "$wf_packet_hex" | sha256sum | awk '{print $1}')
	printf '%02d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t1\t%s\t%s\t%s\t%s\t1\t%s\t%s\t%s\t%s\t%s\n' \
		"$wf_index" "$wf_group" "$wf_trigger" "$wf_name" "$run_nonce" \
		"$wf_cookie" "$wf_vdev" "$wf_generation" "$wf_peer_id" \
		"$wf_status" "$wf_rate_valid" "$wf_release_src" \
		"$wf_transmit_count" "$wf_ppdu_id" "$wf_fc" "$wf_frame_len" \
		"$wf_packet_sha" "$baseline_channel" "$transmit_order" \
		>>"$out/workflow-matrix.tsv"
	marker "workflow-frame-$wf_tag-complete-cookie-$wf_cookie-status-$wf_status-reclaimed"
	health_check ||
		fail "fatal condition after workflow frame $wf_index" 112
	active_workflow_group=
}

trap cleanup_exit EXIT
run_kernel_start_rc=0
start_run_kernel_stream || run_kernel_start_rc=$?
echo "$run_kernel_start_rc" >"$out/run-kernel-events-start.rc"
[ "$run_kernel_start_rc" -eq 0 ] || {
	echo "could not start the bounded kernel event stream" >&2
	exit 5
}
marker start
run_kernel_marker_rc=0
wait_run_kernel_marker || run_kernel_marker_rc=$?
echo "$run_kernel_marker_rc" >"$out/run-kernel-events-marker.rc"
[ "$run_kernel_marker_rc" -eq 0 ] || {
	echo "kernel event stream did not observe the run marker" >&2
	exit 5
}
echo "start_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "variant=$variant"
echo "boot_id=$boot_id"
echo "clean_boot_acknowledged=true"
echo "authorized_isolated_test_acknowledged=true"
echo "authorized_bssid=$authorized_bssid"

[ -n "$boot_id" ] || fail "could not read the current boot ID" 4
[ -x "$sender" ] || fail "single-frame sender is unavailable" 5
[ -x "$iface_probe" ] || fail "interface probe is unavailable" 5
for required_command in awk cat cmd cp cut date diff dmesg dumpsys find grep head \
	ip iw log logcat mkdir mount od ping sed sha256sum sort stat svc sync tail tar \
	timeout tr; do
	command -v "$required_command" >>"$out/required-commands.log" 2>&1 ||
		fail "required Android command is missing: $required_command" 5
done
if [ -d /sys/kernel/debug/qca_cld3_peach_v2 ]; then
	echo mount_state=already-mounted >"$out/debugfs-mount.log"
elif mount -t debugfs debugfs /sys/kernel/debug \
		>"$out/debugfs-mount.log" 2>&1; then
	echo mount_state=mounted >>"$out/debugfs-mount.log"
else
	fail "debugfs is unavailable" 5
fi
[ -d /sys/kernel/debug/qca_cld3_peach_v2 ] ||
	fail "WLAN debugfs root is not visible" 5
timeout 2 sh -c 'exit 0' >"$out/timeout-probe.log" 2>&1 ||
	fail "Android timeout command failed its functional probe" 5
stat -c '%s %Y %a' /proc/sys/kernel/random/boot_id \
	>"$out/stat-probe.log" 2>&1 ||
	fail "Android stat command failed its functional probe" 5
capture_required "$out/sender-selftest.log" "$sender" --selftest
grep -q '^selftest_passed=34$' "$out/sender-selftest.log" ||
	fail "single-frame sender selftest did not pass all variants" 5
grep -q '^workflow_selftest_passed=34 groups=17$' \
		"$out/sender-selftest.log" ||
	fail "sender workflow selftest did not pass all event groups" 5
grep -q '^unsupported_tx_params_selftest_passed=1$' \
	"$out/sender-selftest.log" ||
	fail "sender unsupported TX-parameter radiotap selftest did not pass" 5
capture_required "$out/iface-probe-selftest.log" "$iface_probe" --selftest
grep -q '^selftest_passed=25$' "$out/iface-probe-selftest.log" ||
	fail "interface probe selftest did not pass" 5
sha256sum "$sender" >"$out/sender-sha256.txt" 2>&1 ||
	fail "could not hash the single-frame sender" 5
sha256sum "$iface_probe" >"$out/iface-probe-sha256.txt" 2>&1 ||
	fail "could not hash the interface probe" 5
crash_manifest "$out/crash-evidence-pre-test.manifest"
capture_required "$out/module-build-id.log" od -An -v -tx1 \
	/sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id
build_note=$(tr -d ' \n' <"$out/module-build-id.log")
case "$build_note" in
	*"$expected_build_id"*) ;;
	*) fail "loaded module build-id does not match $expected_build_id" 5 ;;
esac
firmware_path=/vendor/firmware_mnt/image/peach/amss20.bin
bdf_path=/odm/etc/wifi/peach/bdwlan.elf
[ -f "$firmware_path" ] || fail "runtime Peach firmware is missing" 5
[ -f "$bdf_path" ] || fail "runtime Peach board data is missing" 5
firmware_sha256=$(sha256sum "$firmware_path" 2>/dev/null | awk '{print $1}')
bdf_sha256=$(sha256sum "$bdf_path" 2>/dev/null | awk '{print $1}')
{
	echo "firmware_path=$firmware_path"
	echo "firmware_sha256=$firmware_sha256"
	echo "expected_firmware_sha256=$expected_firmware_sha256"
	echo "bdf_path=$bdf_path"
	echo "bdf_sha256=$bdf_sha256"
	echo "expected_bdf_sha256=$expected_bdf_sha256"
} >"$out/runtime-firmware-bdf-identity.txt"
[ "$firmware_sha256" = "$expected_firmware_sha256" ] ||
	fail "runtime Peach firmware hash does not match the fixed target" 5
[ "$bdf_sha256" = "$expected_bdf_sha256" ] ||
	fail "runtime Peach board-data hash does not match the fixed target" 5
capture_required "$out/pre-test-full-dmesg.log" dmesg
grep -E \
	'frame injection build source_rev=' \
	"$out/pre-test-full-dmesg.log" >"$out/pre-test-frame-inject-build.log"
if grep -q 'frame injection build source_rev=' \
	"$out/pre-test-frame-inject-build.log"; then
	echo present >"$out/pre-test-frame-inject-build.status"
else
	echo deferred-until-monitor-init \
		>"$out/pre-test-frame-inject-build.status"
fi
capture_required "$out/frame-inject-force-raw.log" cat "$force_raw_node"
force_raw=$(cat "$force_raw_node" 2>/dev/null | tr -d ' \r\n')
[ "$force_raw" = N ] || [ "$force_raw" = 0 ] ||
	fail "frame_inject_force_raw must be disabled at test entry" 5

cmd wifi help >"$out/cmd-wifi-help.log" 2>&1
help_rc=$?
echo "$help_rc" >"$out/cmd-wifi-help.rc"
grep -q '^Wi-Fi (wifi) commands:$' "$out/cmd-wifi-help.log" ||
	fail "cmd wifi help did not produce recognizable output" 5
grep -q 'set-scan-always-available' "$out/cmd-wifi-help.log" ||
	fail "set-scan-always-available is not advertised by cmd wifi help" 6

dumpsys wifi >"$out/initial-dumpsys-wifi.log" 2>&1
initial_scan_state=$(scan_state_from_dump "$out/initial-dumpsys-wifi.log")
case "$initial_scan_state" in
	true|false) ;;
	*) fail "could not read the initial ScanAlwaysAvailable state" 7 ;;
esac
echo "$initial_scan_state" >"$out/initial-scan-always.txt"

snapshot 00-baseline
[ -e /sys/class/net/wlan0 ] || fail "baseline wlan0 is absent" 8
grep -Eq '^Wifi is connected( to .*)?$' \
	"$out/00-baseline/cmd-wifi-status.log" ||
	fail "baseline Android Wi-Fi framework is not connected" 10
grep -E 'NetworkCapabilities:.*Transports: WIFI.*Capabilities:.*VALIDATED' \
	"$out/00-baseline/cmd-wifi-status.log" >/dev/null ||
	fail "baseline Wi-Fi NetworkCapabilities are not VALIDATED" 10
iw dev wlan0 info >"$out/baseline-iw-info.log" 2>&1
grep -q '^[[:space:]]*type managed$' "$out/baseline-iw-info.log" ||
	fail "baseline wlan0 is not managed" 9
iw dev wlan0 link >"$out/baseline-iw-link.log" 2>&1
grep -q '^Connected to ' "$out/baseline-iw-link.log" ||
	fail "baseline wlan0 is not connected; wait for known-network autoconnect" 10
peer_mac=$(sed -n 's/^Connected to \([^ ]*\).*/\1/p' \
	"$out/baseline-iw-link.log" | head -n 1)
valid_mac "$peer_mac" || fail "baseline AP BSSID is invalid" 10
[ "$peer_mac" = "$authorized_bssid" ] ||
	fail "baseline BSSID $peer_mac is not the authorized isolated target $authorized_bssid" 10
baseline_freq=$(sed -n 's/^[[:space:]]*freq: \([0-9][0-9]*\).*/\1/p' \
	"$out/baseline-iw-link.log" | head -n 1)
case "$baseline_freq" in
	[0-9][0-9][0-9][0-9]|[0-9][0-9][0-9][0-9][0-9]) ;;
	*) fail "baseline AP frequency is unavailable" 10 ;;
esac
baseline_channel=$(frequency_to_channel "$baseline_freq") ||
	fail "baseline frequency $baseline_freq has no supported channel mapping" 10
case "$baseline_channel" in
	''|*[!0-9]*|0) fail "baseline channel mapping is invalid" 10 ;;
esac
baseline_width=$(sed -n \
	's/.*width: \([0-9+][0-9+]*\) MHz.*/\1/p' \
	"$out/baseline-iw-info.log" | head -n 1)
baseline_center1=$(sed -n \
	's/.*center1: \([0-9][0-9]*\) MHz.*/\1/p' \
	"$out/baseline-iw-info.log" | head -n 1)
baseline_center2=$(sed -n \
	's/.*center2: \([0-9][0-9]*\) MHz.*/\1/p' \
	"$out/baseline-iw-info.log" | head -n 1)
case "$baseline_width" in
	20|40|80|160|320) ;;
	80+80) [ -n "$baseline_center2" ] ||
		fail "baseline 80+80 MHz center2 is unavailable" 10 ;;
	*) fail "baseline channel width is unavailable or unsupported" 10 ;;
esac
[ -n "$baseline_center1" ] ||
	fail "baseline channel center1 is unavailable" 10
echo "$peer_mac" >"$out/baseline-peer-mac.txt"
echo "$baseline_freq" >"$out/baseline-frequency-mhz.txt"
echo "$baseline_channel" >"$out/baseline-channel.txt"
echo "$authorized_bssid" >"$out/authorized-isolated-bssid.txt"
{
	echo "width_mhz=$baseline_width"
	echo "center1_mhz=$baseline_center1"
	echo "center2_mhz=${baseline_center2:-none}"
} >"$out/baseline-channel-width.txt"
ip -4 addr show dev wlan0 >"$out/baseline-ipv4.log" 2>&1
grep -q ' scope global ' "$out/baseline-ipv4.log" ||
	fail "baseline wlan0 has no global IPv4 address" 11
connected_station_mac=$(cat /sys/class/net/wlan0/address)
valid_mac "$connected_station_mac" || fail "connected STA MAC is invalid" 11
echo "$connected_station_mac" >"$out/pre-disable-connected-mac.txt"

last_run_boot_id=$(cat "$last_run_boot_file" 2>/dev/null)
echo "$last_run_boot_id" >"$out/previous-test-boot-id.txt"
[ "$last_run_boot_id" != "$boot_id" ] ||
	fail "the $suite_id consolidated test already ran during this boot" 4
printf '%s\n' "$boot_id" >"$last_run_boot_file" ||
	fail "could not persist the $suite_id consolidated boot gate" 4

marker "set-scan-always-$desired_scan_arg"
cmd wifi set-scan-always-available "$desired_scan_arg" \
	>"$out/set-scan-always.log" 2>&1
set_scan_rc=$?
echo "$set_scan_rc" >"$out/set-scan-always.rc"
[ "$set_scan_rc" -eq 0 ] || fail "cmd wifi set-scan-always-available failed" 12
verify_scan_always "$desired_scan_state" scan-always-configured ||
	fail "ScanAlwaysAvailable did not reach $desired_scan_state" 13
snapshot 01-scan-always-configured

marker p2p-shell-client-init-request
cmd wifip2p init >"$out/wifip2p-init.log" 2>&1
p2p_shell_init_rc=$?
echo "$p2p_shell_init_rc" >"$out/wifip2p-init.rc"
[ "$p2p_shell_init_rc" -eq 0 ] ||
	fail "could not initialize the P2P shell client" 14
p2p_shell_client_initialized=1
cmd wifip2p get-state >"$out/wifip2p-state-after-init.log" 2>&1
p2p_shell_state_rc=$?
echo "$p2p_shell_state_rc" >"$out/wifip2p-state-after-init.rc"
[ "$p2p_shell_state_rc" -eq 0 ] &&
grep -qx 'ENABLED' "$out/wifip2p-state-after-init.log" ||
	fail "P2P shell client did not reach ENABLED" 14
marker p2p-shell-client-ready

marker wifi-disable-request
svc wifi disable >"$out/svc-wifi-disable.log" 2>&1
disable_rc=$?
echo "$disable_rc" >"$out/svc-wifi-disable.rc"
[ "$disable_rc" -eq 0 ] || fail "svc wifi disable failed" 14
wait_wifi_disabled || fail "cmd wifi status did not reach disabled" 15
wait_framework_disabled_role ||
	fail "framework did not reach variant $variant disabled-role prerequisite" 16
verify_scan_always "$desired_scan_state" scan-always-after-disable ||
	fail "ScanAlwaysAvailable changed unexpectedly after Wi-Fi disable" 17
marker wifi-disabled-prerequisite-ready
snapshot 02-wifi-disabled

if [ ! -e /sys/class/net/wlan0 ]; then
	fail "zero active managers removed wlan0; no iw conversion was attempted" 18
fi

assert_network_cleared disabled-prerequisite
cleared_rc=$?
case "$cleared_rc" in
	0) ;;
	1) fail "wlan0 remained associated after Wi-Fi disable" 39 ;;
	2) fail "wlan0 retained a global IPv4 address after Wi-Fi disable" 40 ;;
	*) fail "could not verify cleared network state after Wi-Fi disable" 39 ;;
esac

ip link set wlan0 up >"$out/ip-link-set-up.log" 2>&1
link_up_rc=$?
echo "$link_up_rc" >"$out/ip-link-set-up.rc"
[ "$link_up_rc" -eq 0 ] || fail "failed to keep wlan0 UP" 20

iw dev wlan0 info >"$out/pre-transition-iw-info.log" 2>&1
grep -q '^[[:space:]]*type managed$' "$out/pre-transition-iw-info.log" ||
	fail "wlan0 is not managed before the conversion" 21
station_mac=$(cat /sys/class/net/wlan0/address 2>/dev/null)
valid_mac "$station_mac" || fail "pre-transition STA MAC is invalid" 22
[ "$station_mac" = "$connected_station_mac" ] ||
	fail "framework release changed the STA MAC before iw conversion" 22
[ "$(cat /sys/class/net/wlan0/mtu 2>/dev/null)" = "$expected_managed_mtu" ] ||
	fail "managed MTU is not $expected_managed_mtu before conversion" 22
echo "$station_mac" >"$out/pre-transition-sta-mac.txt"
snapshot 03-pre-monitor

marker monitor-request
random_monitor_source_ifindex=$(cat /sys/class/net/wlan0/ifindex 2>/dev/null)
case "$random_monitor_source_ifindex" in
	''|*[!0-9]*) fail "pre-monitor wlan0 ifindex is invalid" 22 ;;
esac
echo "$random_monitor_source_ifindex" >"$out/pre-monitor-ifindex.txt"
iw dev wlan0 set type monitor >"$out/iw-set-monitor.log" 2>&1
monitor_rc=$?
echo "$monitor_rc" >"$out/iw-set-monitor.rc"
[ "$monitor_rc" -eq 0 ] || fail "iw monitor conversion failed" 23
wait_iw_mode monitor 4 random-monitor "$random_monitor_source_ifindex" 1 ||
	fail "random monitor full-mode transition did not stabilize" 24
random_monitor_ifindex=$wait_iw_mode_ifindex
iw dev wlan0 info >"$out/monitor-iw-info.log" 2>&1
grep -q '^[[:space:]]*type monitor$' "$out/monitor-iw-info.log" ||
	fail "iw returned success but wlan0 is not monitor" 24
monitor_mac=$(cat /sys/class/net/wlan0/address 2>/dev/null)
valid_mac "$monitor_mac" || fail "monitor MAC is invalid" 25
[ "$monitor_mac" != "$station_mac" ] ||
	fail "monitor conversion reused the STA MAC" 25
monitor_octet=${monitor_mac%%:*}
monitor_value=$((0x$monitor_octet))
[ $((monitor_value & 3)) -eq 2 ] ||
	fail "monitor MAC is not a unicast locally administered address" 26
[ "$(cat /sys/class/net/wlan0/addr_assign_type 2>/dev/null)" = 1 ] ||
	fail "monitor MAC is not marked NET_ADDR_RANDOM" 26
monitor_flags=$(cat /sys/class/net/wlan0/flags 2>/dev/null)
[ $((monitor_flags & 1)) -ne 0 ] ||
	fail "UP-state monitor transition did not restore IFF_UP" 26
[ "$(cat /sys/class/net/wlan0/mtu 2>/dev/null)" = "$expected_monitor_mtu" ] ||
	fail "monitor MTU is not $expected_monitor_mtu" 26
echo "$monitor_mac" >"$out/monitor-mac.txt"
marker monitor-ready
snapshot 04-monitor
health_check || fail "health failure after random-MAC monitor conversion" 26

marker managed-request
random_managed_source_ifindex=$(cat /sys/class/net/wlan0/ifindex 2>/dev/null)
case "$random_managed_source_ifindex" in
	''|*[!0-9]*) fail "pre-managed-return wlan0 ifindex is invalid" 27 ;;
esac
iw dev wlan0 set type managed >"$out/iw-set-managed.log" 2>&1
managed_rc=$?
echo "$managed_rc" >"$out/iw-set-managed.rc"
[ "$managed_rc" -eq 0 ] || fail "iw managed conversion failed" 27
wait_iw_mode managed 0 random-managed-return "$random_managed_source_ifindex" 1 ||
	fail "managed full-mode return did not stabilize" 28
random_managed_return_ifindex=$wait_iw_mode_ifindex
iw dev wlan0 info >"$out/restored-managed-iw-info.log" 2>&1
grep -q '^[[:space:]]*type managed$' "$out/restored-managed-iw-info.log" ||
	fail "iw returned success but wlan0 is not managed" 28
[ "$(cat /sys/class/net/wlan0/type 2>/dev/null)" = 1 ] ||
	fail "restored wlan0 does not have ARPHRD_ETHER type" 29
[ "$(cat /sys/class/net/wlan0/address 2>/dev/null)" = "$station_mac" ] ||
	fail "restored managed MAC does not match pre-transition STA MAC" 30
managed_flags=$(cat /sys/class/net/wlan0/flags 2>/dev/null)
printf '%s\n' "$managed_flags" | grep -Eq '^0x[[:xdigit:]]+$' ||
	fail "restored managed interface flags are invalid" 31
[ $((managed_flags & 1)) -ne 0 ] ||
	fail "restored managed interface is not UP" 31
[ "$(cat /sys/class/net/wlan0/mtu 2>/dev/null)" = "$expected_managed_mtu" ] ||
	fail "initial managed return did not restore MTU $expected_managed_mtu" 31
marker managed-ready
snapshot 05-restored-managed
health_check || fail "health failure after initial managed restoration" 31

specified_monitor_mac=02:13:37:5a:11:7d
echo "$specified_monitor_mac" >"$out/requested-monitor-mac.txt"
select_probe_frequencies ||
	fail "could not select enabled 2.4/5 GHz probe frequencies" 43
specified_monitor_source_ifindex=$(cat /sys/class/net/wlan0/ifindex 2>/dev/null)
case "$specified_monitor_source_ifindex" in
	''|*[!0-9]*) fail "pre-probe wlan0 ifindex is invalid" 44 ;;
esac
marker specified-monitor-single-process-probe-request
"$iface_probe" --interface wlan0 --mac "$specified_monitor_mac" \
	--frequency "$baseline_freq" --hop "$baseline_freq" \
	--hop "$probe_2g" --hop "$probe_5g" --hop "$baseline_freq" \
	>"$out/iface-probe.tsv" 2>"$out/iface-probe.stderr"
iface_probe_rc=$?
echo "$iface_probe_rc" >"$out/iface-probe.rc"
[ "$iface_probe_rc" -eq 0 ] ||
	fail "single-process specified-MAC monitor probe failed" 45
specified_monitor_probe_ifindex=$(cat /sys/class/net/wlan0/ifindex 2>/dev/null)
case "$specified_monitor_probe_ifindex" in
	''|*[!0-9]*) fail "post-probe wlan0 ifindex is invalid" 46 ;;
esac
iface_probe_header='step	operation	socket	seq	ifindex	mac	frequency_mhz	send_mono_ns	ack_mono_ns	since_previous_ack_ns	ack_received	clock_failed	kernel_error	result_errno	response_received	observed_ifindex	observed_flags	observed_mac	sysfs_ifindex	addr_assign_type	observed_iftype	observed_frequency_mhz	state_match	state_error'
[ "$(head -n 1 "$out/iface-probe.tsv")" = "$iface_probe_header" ] ||
	fail "interface probe TSV header is invalid" 46
awk -F '\t' -v source_ifindex="$specified_monitor_source_ifindex" \
	-v target_ifindex="$specified_monitor_probe_ifindex" \
	-v expected_mac="$specified_monitor_mac" -v expected_freq="$baseline_freq" '
	NR == 1 { next }
	{
		records++
		if ($6 != expected_mac ||
		    $11 != 1 || $12 != 0 || $13 != 0 || $14 != 0)
			bad = 1
		if ($2 == "down" || $2 == "set-uaa" || $2 == "set-monitor") {
			source_records++
			if ($5 != source_ifindex)
				bad = 1
		} else {
			target_records++
			if ($5 != target_ifindex)
				bad = 1
		}
		if ($2 == "set-monitor")
			set_monitor++
		if ($2 == "up")
			set_up++
		if ($2 ~ /^verify-/ &&
		    ($15 != 1 || $23 != 1 || $24 != 0))
			bad = 1
		if ($2 == "verify-link-hop-04") {
			final_link++
			if ($16 != target_ifindex || $18 != expected_mac ||
			    $19 != target_ifindex || $20 != 3)
				bad = 1
		}
		if ($2 == "verify-interface-hop-04") {
			final_interface++
			if ($16 != target_ifindex || $18 != expected_mac ||
			    $21 != 6 || $22 != expected_freq)
				bad = 1
		}
	}
	END {
		if (records != 19 || source_records != 3 || target_records != 16 ||
		    set_monitor != 1 || set_up != 1 || final_link != 1 ||
		    final_interface != 1 || bad)
			exit 1
	}
' "$out/iface-probe.tsv" || fail "interface probe TSV verification failed" 46
wait_iw_mode monitor 4 specified-monitor "$specified_monitor_source_ifindex" 1 ||
	fail "specified monitor full-mode transition did not stabilize" 47
specified_monitor_ifindex=$wait_iw_mode_ifindex
iw dev wlan0 info >"$out/specified-monitor-iw-info.log" 2>&1
grep -q '^[[:space:]]*type monitor$' \
	"$out/specified-monitor-iw-info.log" ||
	fail "specified-MAC conversion did not create monitor persona" 47
[ "$(cat /sys/class/net/wlan0/address 2>/dev/null)" = \
	"$specified_monitor_mac" ] ||
	fail "specified monitor MAC changed during persona conversion" 48
[ "$(cat /sys/class/net/wlan0/addr_assign_type 2>/dev/null)" = 3 ] ||
	fail "specified monitor MAC is not marked NET_ADDR_SET" 49
specified_monitor_flags=$(cat /sys/class/net/wlan0/flags 2>/dev/null)
[ $((specified_monitor_flags & 1)) -ne 0 ] ||
	fail "single-process probe did not leave specified monitor UP" 50
[ "$(cat /sys/class/net/wlan0/mtu 2>/dev/null)" = "$expected_monitor_mtu" ] ||
	fail "specified monitor MTU is not $expected_monitor_mtu" 50
iw dev wlan0 info >"$out/monitor-frequency-info.log" 2>&1
grep -q "${baseline_freq} MHz" "$out/monitor-frequency-info.log" ||
	fail "monitor did not report the requested baseline frequency" 57
	marker specified-monitor-ready
	marker "monitor-frequency-$baseline_freq-ready"
	snapshot 06a-specified-monitor-channel-ready
	health_check || fail "health failure before injection preflight" 57
	capture_required "$out/frame-inject-selftest.log" cat \
		/sys/kernel/debug/wlan0/frame_inject_selftest
	[ "$last_capture_rc" -eq 0 ] ||
		fail "frame injection parser selftest could not be read" 57
	grep -qx 'case_direct_dp_event_state_machine=PASS tests=15 failed=0' \
		"$out/frame-inject-selftest.log" &&
		grep -qx 'case_direct_dp_worker_races=PASS tests=6 failed=0' \
		"$out/frame-inject-selftest.log" &&
		grep -qx 'failed=0' "$out/frame-inject-selftest.log" &&
		grep -qx 'verdict=PASS' "$out/frame-inject-selftest.log" ||
		fail "frame injection parser/direct-DP selftest failed" 57
	capture_required "$out/frame-inject-stats-before.log" cat \
		/sys/kernel/debug/wlan0/frame_inject_stats
	[ "$last_capture_rc" -eq 0 ] ||
		fail "frame injection preflight stats could not be read" 57
	capture_required "$out/post-monitor-full-dmesg.log" dmesg
	grep -E \
		'frame injection build source_rev=' \
		"$out/post-monitor-full-dmesg.log" \
		>"$out/post-monitor-frame-inject-build.log"
	grep -q 'frame injection build source_rev=' \
		"$out/post-monitor-frame-inject-build.log" ||
		fail "runtime frame-injection build record is missing after monitor init" 57
	grep -qx 'format_version=4' "$out/frame-inject-stats-before.log" &&
		grep -qx 'tx_inflight=0' "$out/frame-inject-stats-before.log" &&
		grep -qx 'submit_pending=0' "$out/frame-inject-stats-before.log" ||
		fail "frame injection format-v3 preflight state is invalid" 57

printf 'index\tvariant\tnonce\tcookie\tvdev\tgeneration\tpeer_id\ttx_status\tstatus_valid\trate_valid\trelease_src\ttransmit_count\tppdu_id\treclaimed\tfc\tframe_len\tpacket_hex_sha256\tsend_order\n' \
	>"$out/frame-matrix.tsv"
printf 'phase\tstart_index\tend_index\texpected_frames\tcompleted_frames\tgate_on_verified\tgate_off_verified\tstatus\n' \
	>"$out/phase-matrix.tsv"
printf 'index\tgroup\ttrigger\tname\tnonce\tcookie\tvdev\tgeneration\tpeer_id\ttx_status\tstatus_valid\trate_valid\trelease_src\ttransmit_count\tppdu_id\treclaimed\tfc\tframe_len\tpacket_hex_sha256\tchannel\tsend_order\n' \
	>"$out/workflow-matrix.tsv"
transmit_order=0
workflow_vdev=
dp_status_delta=0
dp_reclaim_delta=0
dp_no_status_delta=0
dp_unsent_delta=0
dp_contract_delta=0
dp_unexpected_delta=0
dp_global_flush_delta=0
backend_busy_delta=0
result_ota_verdict=UNPROVEN
lifecycle_requested=0
lifecycle_completed=0
lifecycle_last_ret=NOT_APPLICABLE

if [ "$stage_scope" -eq 0 ]; then
	[ -w "$lifecycle_node" ] ||
		fail "Stage 0 lifecycle debugfs control is unavailable" 113
	for lifecycle_stat_key in netdev_accepted worker_dequeued dp_submitted \
		backend_busy \
		dp_tx_status_events dp_reclaimed dp_reclaim_without_status \
		dp_submit_unsent dp_submit_contract_errors dp_unexpected_events \
		dp_global_flushes; do
		lifecycle_stat_before=$(awk -F= -v key="$lifecycle_stat_key" \
			'$1 == key { print $2 }' "$out/frame-inject-stats-before.log")
		case "$lifecycle_stat_before" in
			''|*[!0-9]*)
				fail "missing Stage 0 counter $lifecycle_stat_key" 113
				;;
		esac
		eval "lifecycle_${lifecycle_stat_key}_before=$lifecycle_stat_before"
	done
	marker stage0-lifecycle-gate-on-request
	force_gate_on stage0-lifecycle ||
		fail "could not enable RAW gate for Stage 0 lifecycle" 113
	marker stage0-lifecycle-probe-request
	lifecycle_probe_rc=0
	printf '20\n' >"$lifecycle_node" 2>"$out/stage0-lifecycle.stderr" ||
		lifecycle_probe_rc=$?
	echo "$lifecycle_probe_rc" >"$out/stage0-lifecycle.exit-code"
	marker stage0-lifecycle-gate-off-request
	force_gate_off stage0-lifecycle ||
		fail "could not disable RAW gate after Stage 0 lifecycle" 114
	[ "$lifecycle_probe_rc" -eq 0 ] ||
		fail "Stage 0 lifecycle probe failed" 114
	capture_required "$out/frame-inject-stats-after.log" cat \
		/sys/kernel/debug/wlan0/frame_inject_stats
	[ "$last_capture_rc" -eq 0 ] ||
		fail "Stage 0 final frame injection stats could not be read" 114
	grep -qx 'state=disabled' "$out/frame-inject-stats-after.log" &&
	grep -qx 'helper_present=0' "$out/frame-inject-stats-after.log" &&
	grep -qx 'tx_inflight=0' "$out/frame-inject-stats-after.log" &&
	grep -qx 'submit_pending=0' "$out/frame-inject-stats-after.log" &&
	grep -qx 'lifecycle_last_ret=0' "$out/frame-inject-stats-after.log" &&
	grep -qx 'lifecycle_requested=20' "$out/frame-inject-stats-after.log" &&
	grep -qx 'lifecycle_completed=20' "$out/frame-inject-stats-after.log" ||
		fail "Stage 0 lifecycle ownership state is incomplete" 114
	lifecycle_requested=20
	lifecycle_completed=20
	lifecycle_last_ret=0
	for lifecycle_stat_key in netdev_accepted worker_dequeued dp_submitted \
		backend_busy \
		dp_tx_status_events dp_reclaimed dp_reclaim_without_status \
		dp_submit_unsent dp_submit_contract_errors dp_unexpected_events \
		dp_global_flushes; do
		lifecycle_stat_after=$(awk -F= -v key="$lifecycle_stat_key" \
			'$1 == key { print $2 }' "$out/frame-inject-stats-after.log")
		eval "lifecycle_stat_before=\$lifecycle_${lifecycle_stat_key}_before"
	[ "$lifecycle_stat_after" = "$lifecycle_stat_before" ] ||
			fail "Stage 0 changed TX counter $lifecycle_stat_key" 114
	done
	result_ota_verdict=NOT_APPLICABLE
	marker stage0-lifecycle-complete
	tx_snapshot stage0-lifecycle-complete
	health_check || fail "health failure after Stage 0 lifecycle" 114
else
	verify_gate_n_rejection

	begin_injection_phase management 01 18 18
verify_parser_rejection
send_and_wait probe-request 01 true
verify_unsupported_tx_params
send_and_wait hcx-probe-request 02 false
send_and_wait auth-request 03 false
send_and_wait auth-response 04 false
send_and_wait assoc-request 05 false
send_and_wait assoc-response 06 false
send_and_wait reassoc-request 07 false
send_and_wait reassoc-response 08 false
send_and_wait probe-response 09 false
send_and_wait disassoc 10 false
send_and_wait probe-raw-alt 11 false
send_and_wait probe-fcs 12 false
send_and_wait beacon 13 false
send_and_wait timing-advert 14 false
send_and_wait atim 15 false
send_and_wait action 16 false
send_and_wait action-noack 17 false
send_and_wait deauth 18 false
end_injection_phase

begin_injection_phase data 19 25 7
send_and_wait ordinary-data 19 true
send_and_wait null-data 20 false
send_and_wait qos-null 21 false
send_and_wait eap-request-id 22 false
send_and_wait eapol-start 23 false
send_and_wait eapol-m1-wpa1 24 false
send_and_wait eapol-m1-wpa2 25 false
end_injection_phase

begin_injection_phase long-control 26 31 6
send_and_wait rts 26 true
send_and_wait bar 27 false
send_and_wait block-ack 28 false
send_and_wait ps-poll 29 false
send_and_wait cf-end 30 false
send_and_wait cf-end-ack 31 false
end_injection_phase

begin_injection_phase cts 32 32 1
send_and_wait cts 32 true
end_injection_phase
workflow_vdev=
active_phase=hcxdumptool-workflow
workflow_gate_on_verified=0
workflow_gate_off_verified=0
marker workflow-gate-on-request
force_gate_on workflow ||
	fail "could not enable RAW gate for serialized workflow" 100
workflow_gate_on_verified=1
marker workflow-gate-on-verified
workflow_frame=1
while [ "$workflow_frame" -le 34 ]; do
	send_workflow_frame "$workflow_frame"
	workflow_frame=$((workflow_frame + 1))
done
marker workflow-gate-off-request
force_gate_off workflow ||
	fail "could not disable RAW gate after serialized workflow" 112
workflow_gate_off_verified=1
active_phase=
health_check || fail "health failure after serialized workflow" 112
marker workflow-complete-gate-disabled
tx_snapshot workflow-complete

begin_injection_phase ack 33 33 1
send_and_wait ack 33 true
end_injection_phase

[ "$(awk 'END { print NR - 1 }' "$out/frame-matrix.tsv")" -eq 33 ] ||
	fail "fixed frame matrix is not complete" 112
[ "$(awk 'END { print NR - 1 }' "$out/phase-matrix.tsv")" -eq 5 ] ||
	fail "phase matrix is not complete" 112
[ "$(awk 'END { print NR - 1 }' "$out/workflow-matrix.tsv")" -eq 34 ] ||
	fail "workflow matrix is not complete" 112
[ "$transmit_order" -eq 67 ] ||
	fail "serialized transmit order ended at $transmit_order instead of 67" 112
[ "$(cat "$force_raw_node" 2>/dev/null | tr -d ' \r\n')" = N ] ||
	fail "force RAW gate did not remain disabled after workflow" 112
	marker all-injection-phases-and-workflows-complete
	tx_snapshot all-injection-complete
	capture_required "$out/frame-inject-stats-after.log" cat \
		/sys/kernel/debug/wlan0/frame_inject_stats
	[ "$last_capture_rc" -eq 0 ] ||
		fail "frame injection final stats could not be read" 112
	grep -qx 'format_version=4' "$out/frame-inject-stats-after.log" ||
		fail "frame injection final stats are not format v3" 112
	for dp_stat_key in dp_tx_status_events dp_reclaimed \
		dp_reclaim_without_status dp_submit_unsent \
		dp_submit_contract_errors dp_unexpected_events \
		dp_global_flushes backend_busy; do
		dp_stat_before=$(awk -F= -v key="$dp_stat_key" \
			'$1 == key { print $2 }' "$out/frame-inject-stats-before.log")
		dp_stat_after=$(awk -F= -v key="$dp_stat_key" \
			'$1 == key { print $2 }' "$out/frame-inject-stats-after.log")
		case "$dp_stat_before:$dp_stat_after" in
			''|:*|*:|*[!0-9:]*)
				fail "missing or invalid aggregate DP stat $dp_stat_key" 112
				;;
		esac
		eval "${dp_stat_key}_before=$dp_stat_before"
		eval "${dp_stat_key}_after=$dp_stat_after"
	done
	dp_status_delta=$((dp_tx_status_events_after - dp_tx_status_events_before))
	dp_reclaim_delta=$((dp_reclaimed_after - dp_reclaimed_before))
	dp_no_status_delta=$((dp_reclaim_without_status_after - dp_reclaim_without_status_before))
	dp_unsent_delta=$((dp_submit_unsent_after - dp_submit_unsent_before))
	dp_contract_delta=$((dp_submit_contract_errors_after - dp_submit_contract_errors_before))
	dp_unexpected_delta=$((dp_unexpected_events_after - dp_unexpected_events_before))
	dp_global_flush_delta=$((dp_global_flushes_after - dp_global_flushes_before))
	backend_busy_delta=$((backend_busy_after - backend_busy_before))
	[ "$dp_status_delta" -eq 67 ] && [ "$dp_reclaim_delta" -eq 67 ] &&
	[ "$dp_no_status_delta" -eq 0 ] && [ "$dp_unsent_delta" -eq 0 ] &&
	[ "$dp_contract_delta" -eq 0 ] && [ "$dp_unexpected_delta" -eq 0 ] &&
	[ "$dp_global_flush_delta" -eq 0 ] && [ "$backend_busy_delta" -eq 0 ] ||
		fail "aggregate direct-DP ownership counters are inconsistent" 112
	health_check || fail "health failure after all injection groups" 112
fi

marker specified-monitor-managed-request
specified_managed_source_ifindex=$(cat /sys/class/net/wlan0/ifindex 2>/dev/null)
case "$specified_managed_source_ifindex" in
	''|*[!0-9]*) fail "pre-final-managed wlan0 ifindex is invalid" 51 ;;
esac
iw dev wlan0 set type managed \
	>"$out/iw-set-managed-after-specified-monitor.log" 2>&1
[ "$?" -eq 0 ] || fail "managed conversion after specified MAC failed" 51
wait_iw_mode managed 0 specified-managed-return \
	"$specified_managed_source_ifindex" 1 ||
	fail "specified cycle managed full-mode return did not stabilize" 52
specified_managed_return_ifindex=$wait_iw_mode_ifindex
iw dev wlan0 info >"$out/restored-managed-after-specified-iw-info.log" \
	2>&1
grep -q '^[[:space:]]*type managed$' \
	"$out/restored-managed-after-specified-iw-info.log" ||
	fail "specified-MAC cycle did not restore managed persona" 52
[ "$(cat /sys/class/net/wlan0/type 2>/dev/null)" = 1 ] ||
	fail "specified-MAC cycle did not restore ARPHRD_ETHER" 53
[ "$(cat /sys/class/net/wlan0/address 2>/dev/null)" = "$station_mac" ] ||
	fail "specified-MAC cycle did not restore original STA MAC" 54
specified_managed_flags=$(cat /sys/class/net/wlan0/flags 2>/dev/null)
specified_restored_up=true
[ $((specified_managed_flags & 1)) -ne 0 ] || {
	specified_restored_up=false
	fail "UP monitor return did not restore managed IFF_UP" 55
}
[ "$(cat /sys/class/net/wlan0/mtu 2>/dev/null)" = "$expected_managed_mtu" ] ||
	fail "final managed return did not restore MTU $expected_managed_mtu" 55
marker specified-monitor-managed-ready
snapshot 07-restored-managed-after-specified
health_check || fail "health failure after final managed conversion" 55

marker deterministic-scan-request
iw dev wlan0 scan >"$out/iw-scan.log" 2>&1
scan_rc=$?
echo "$scan_rc" >"$out/iw-scan.rc"
marker "deterministic-scan-complete-rc-$scan_rc"
snapshot 06-post-scan
[ "$scan_rc" -eq 0 ] || fail "deterministic iw scan failed" 95
health_check || fail "health failure after deterministic scan" 95

assert_network_cleared pre-enable
cleared_rc=$?
case "$cleared_rc" in
	0) ;;
	1) fail "wlan0 associated before the explicit Wi-Fi enable request" 41 ;;
	2) fail "wlan0 gained global IPv4 before the explicit Wi-Fi enable request" 42 ;;
	*) fail "could not verify cleared network state before Wi-Fi enable" 41 ;;
esac

eapol1_before=$(run_log_count 'EAPOL-1 RX:')
eapol3_before=$(run_log_count 'EAPOL-3 RX:')
eapol2_before=$(run_log_count 'EAPOL-2 TX:')
eapol4_before=$(run_log_count 'EAPOL-4 TX:')
marker wifi-enable-request
svc wifi enable >"$out/svc-wifi-enable.log" 2>&1
enable_rc=$?
echo "$enable_rc" >"$out/svc-wifi-enable.rc"
[ "$enable_rc" -eq 0 ] || fail "svc wifi enable failed" 32
snapshot 07-wifi-enable-issued

wait_primary_connect_mode ||
	fail "ActiveModeWarden did not reach primary ConnectModeState" 33
marker primary-connect-mode-ready
release_p2p_shell_client || fail "could not release the P2P shell client" 33
marker p2p-shell-client-released
snapshot 08-primary-connect-mode

wait_supplicant || fail "wpa_supplicant did not reach running" 34
marker supplicant-ready
snapshot 09-supplicant-ready

wait_link || fail "wlan0 did not reconnect to an AP" 35
marker wlan-link-connected
verify_connected_identity post-link-identity
identity_rc=$?
case "$identity_rc" in
	0) ;;
	1) fail "could not read wlan0 link identity after reconnect" 35 ;;
	2) fail "wlan0 did not reconnect to baseline BSSID $peer_mac" 35 ;;
	*) fail "framework reconnect did not preserve the baseline STA MAC" 35 ;;
esac
snapshot 10-link-connected

wait_ipv4 || fail "wlan0 reconnected but did not obtain global IPv4" 36
marker ipv4-ready
snapshot 11-ipv4-ready

wait_framework_connected_validated ||
	fail "Android Wi-Fi did not become connected and VALIDATED" 96
marker framework-wifi-validated
capture_required "$out/post-reconnect-cmd-wifi-status.log" cmd wifi status
eapol_wait=0
while [ "$eapol_wait" -lt 15 ]; do
	health_check || fail "health failure while waiting for EAPOL proof" 96
	eapol1_after=$(run_log_count 'EAPOL-1 RX:')
	eapol3_after=$(run_log_count 'EAPOL-3 RX:')
	eapol2_after=$(run_log_count 'EAPOL-2 TX:')
	eapol4_after=$(run_log_count 'EAPOL-4 TX:')
	[ "$eapol1_after" -gt "$eapol1_before" ] &&
	[ "$eapol3_after" -gt "$eapol3_before" ] &&
	[ "$eapol2_after" -gt "$eapol2_before" ] &&
	[ "$eapol4_after" -gt "$eapol4_before" ] && break
	eapol_wait=$((eapol_wait + 1))
	sleep 1
done
current_run_dmesg | grep -E 'EAPOL-[1234] (RX|TX):' \
	>"$out/post-reconnect-eapol.log" 2>&1
[ "${eapol1_after:-0}" -gt "$eapol1_before" ] &&
[ "${eapol3_after:-0}" -gt "$eapol3_before" ] &&
[ "${eapol2_after:-0}" -gt "$eapol2_before" ] &&
[ "${eapol4_after:-0}" -gt "$eapol4_before" ] ||
	fail "managed reconnect lacks a complete EAPOL 1/2/3/4 trace" 96
eapol_new_count=$((eapol1_after - eapol1_before +
	eapol3_after - eapol3_before + eapol2_after - eapol2_before +
	eapol4_after - eapol4_before))
tail -n "$eapol_new_count" "$out/post-reconnect-eapol.log" \
	>"$out/post-reconnect-eapol-new.log"
grep -q 'EAPOL-2 TX:.*status: succ' "$out/post-reconnect-eapol-new.log" &&
grep -q 'EAPOL-4 TX:.*status: succ' "$out/post-reconnect-eapol-new.log" ||
	fail "managed reconnect EAPOL-2/4 TX completion is not successful" 96
marker eapol-four-way-proof-complete
verify_gateway_connectivity
gateway_rc=$?
case "$gateway_rc" in
	0) ;;
	1) fail "could not enumerate post-reconnect IPv4 routes" 97 ;;
	2) fail "post-reconnect wlan0 has no IPv4 default gateway" 97 ;;
	*) fail "post-reconnect default gateway did not answer ping" 98 ;;
esac
marker gateway-ping-verified

final_stable_i=0
while [ "$final_stable_i" -lt 10 ]; do
	sleep 1
	health_check || fail "late health failure after managed reconnect" 99
	verify_connected_identity "stable-$final_stable_i-identity" ||
		fail "managed link identity changed during final stabilization" 99
	final_stable_i=$((final_stable_i + 1))
done

if [ "$initial_scan_state" != "$desired_scan_state" ]; then
	case "$initial_scan_state" in
		true) restore_scan_arg=enabled ;;
		false) restore_scan_arg=disabled ;;
	esac
	marker "restore-scan-always-$restore_scan_arg"
	cmd wifi set-scan-always-available "$restore_scan_arg" \
		>"$out/restore-scan-always.log" 2>&1
	restore_scan_rc=$?
	echo "$restore_scan_rc" >"$out/restore-scan-always.rc"
	[ "$restore_scan_rc" -eq 0 ] ||
		fail "failed to restore the initial scan-always setting" 37
	verify_scan_always "$initial_scan_state" scan-always-restored ||
		fail "initial scan-always state was not restored" 38
fi

snapshot 12-success-candidate
health_check || fail "health failure during final success snapshot" 99
verify_connected_identity final-identity ||
	fail "managed link identity changed before final result" 99
crash_manifest "$out/crash-evidence-post-test.manifest"
crash_manifest_delta "$out/crash-evidence-pre-test.manifest" \
	"$out/crash-evidence-post-test.manifest" \
	"$out/crash-evidence-post-test.delta.tsv"
awk -F '\t' '
		$1 == "unreadable" || $2 == "unknown" ||
		$3 == "unknown" || $4 == "unknown" { invalid = 1 }
		END { exit invalid ? 0 : 1 }
	' "$out/crash-evidence-pre-test.manifest" \
		"$out/crash-evidence-post-test.manifest" &&
		fail "crash-evidence manifest contains unreadable metadata" 99
crash_delta_hard_fault "$out/crash-evidence-post-test.delta.tsv" &&
	fail "new or changed persistent crash evidence appeared during the test" 99
if [ "$required_capture_failures" -ne 0 ]; then
	fail "$required_capture_failures required evidence captures failed" 99
fi
health_check || fail "health failure during final crash-evidence hashing" 99
verify_connected_identity final-precommit-identity ||
	fail "managed link identity changed during final evidence hashing" 99

{
	echo "result=success"
	echo "variant=$variant"
	echo "stage_scope=$stage_scope"
	echo "boot_id=$boot_id"
	echo "initial_scan_always=$initial_scan_state"
	echo "test_scan_always=$desired_scan_state"
		echo "pre_transition_mac=$station_mac"
		echo "monitor_mac=$monitor_mac"
		echo "random_monitor_source_ifindex=$random_monitor_source_ifindex"
		echo "random_monitor_ifindex=$random_monitor_ifindex"
		echo "random_managed_source_ifindex=$random_managed_source_ifindex"
		echo "random_managed_return_ifindex=$random_managed_return_ifindex"
		echo "specified_monitor_mac=$specified_monitor_mac"
		echo "specified_monitor_source_ifindex=$specified_monitor_source_ifindex"
		echo "specified_monitor_probe_ifindex=$specified_monitor_probe_ifindex"
		echo "specified_monitor_ifindex=$specified_monitor_ifindex"
		echo "specified_managed_source_ifindex=$specified_managed_source_ifindex"
		echo "specified_managed_return_ifindex=$specified_managed_return_ifindex"
	echo "iface_probe_rc=$iface_probe_rc"
	echo "probe_2g_mhz=$probe_2g"
	echo "probe_5g_mhz=$probe_5g"
	echo "authorized_bssid=$authorized_bssid"
	echo "baseline_channel=$baseline_channel"
	echo "fixed_frame_count=$(awk 'END { print NR - 1 }' "$out/frame-matrix.tsv")"
	echo "phase_count=$(awk 'END { print NR - 1 }' "$out/phase-matrix.tsv")"
	echo "workflow_frame_count=$(awk 'END { print NR - 1 }' "$out/workflow-matrix.tsv")"
	echo "total_transmit_count=$transmit_order"
	echo "lifecycle_requested=$lifecycle_requested"
	echo "lifecycle_completed=$lifecycle_completed"
	echo "lifecycle_last_ret=$lifecycle_last_ret"
	echo "workflow_vdev=$workflow_vdev"
	echo "specified_cycle_restored_up=$specified_restored_up"
	echo "iw_scan_rc=$scan_rc"
	echo "baseline_bssid=$peer_mac"
	echo "post_reconnect_bssid=$post_peer_mac"
	echo "post_reconnect_sta_mac=$(cat /sys/class/net/wlan0/address 2>/dev/null)"
	echo "post_reconnect_gateway=$gateway"
	echo "post_reconnect_eapol_four_way=PASS"
	echo "dp_tx_status_events=$dp_status_delta"
	echo "dp_reclaimed=$dp_reclaim_delta"
	echo "dp_reclaim_without_status=$dp_no_status_delta"
	echo "dp_submit_unsent=$dp_unsent_delta"
	echo "dp_submit_contract_errors=$dp_contract_delta"
	echo "dp_unexpected_events=$dp_unexpected_delta"
	echo "dp_global_flushes=$dp_global_flush_delta"
	echo "backend_busy=$backend_busy_delta"
	echo "dp_ownership_verdict=PASS"
	echo "ota_verdict=$result_ota_verdict"
	echo "end_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"$out/result.txt"
marker success
sync
health_check || fail "health failure while committing the final result" 99
current_run_dmesg >"$out/final-run-dmesg.log" 2>&1
sync
health_check || fail "health failure after final evidence sync" 99
verify_connected_identity final-committed-identity ||
	fail "managed link identity changed after final evidence sync" 99
echo "RESULT_DIR=$out"
exit 0
