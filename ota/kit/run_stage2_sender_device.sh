#!/system/bin/sh

set -u

expected_build_id=914714cb6f296f35f093bf393bfea47c4982897c
expected_source_rev=698efe09e8b8+dirty-20260906-observability-admin-knobs-v21
suite_frozen=1

usage()
{
	echo "usage: $0 S --authorized-isolated-test PEER CHANNEL NONCE SENDER READY_TOKEN [EXPECTED_BUILD_ID]" >&2
	exit 2
}

[ "$#" -eq 7 ] || [ "$#" -eq 8 ] || usage
[ "$1" = S ] && [ "$2" = --authorized-isolated-test ] || usage
peer=$(printf '%s' "$3" | tr 'A-F' 'a-f')
channel=$4
nonce=$5
sender=$6
ready_token=$7
if [ "$#" -eq 8 ]; then
	case "$8" in
	*[!0-9a-f]*|'') usage ;;
	esac
	[ "${#8}" -eq 40 ] || usage
	expected_build_id=$8
fi
[ "$suite_frozen" -eq 1 ] || { echo "Stage 2 is not frozen" >&2; exit 4; }
case "$ready_token" in READY-[A-Za-z0-9._-]*) ;; *) usage ;; esac

# KernelSU setups may hide /sys/kernel/debug in the su mount namespace; fall
# back to any debugfs mount visible here (e.g. a bind view like /dev/sysdebug).
debug_root=/sys/kernel/debug
[ -r "$debug_root/wlan0/frame_inject_stats" ] ||
	debug_root=$(awk '$3 == "debugfs" { print $2; exit }' /proc/mounts)
stats=$debug_root/wlan0/frame_inject_stats
build_note=/sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id
boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
stamp=$(date -u +%Y%m%dT%H%M%SZ)
out=/data/local/tmp/qcacld-v33-stage2-$stamp-$$
mkdir "$out" || exit 3
echo "OUTPUT_DIR=$out"
exec >"$out/run.log" 2>&1

value() { awk -F= -v key="$2" '$1 == key { print $2 }' "$1" | tail -n 1; }
fail()
{
	code=$1; shift
	printf 'verdict=FAIL\nfailure_code=%s\nfailure=%s\n' "$code" "$*" >"$out/result.txt"
	dmesg >"$out/failure-dmesg.log" 2>&1
	exit "$code"
}
snapshot() { cat "$stats" >"$out/stats-$1.log" 2>&1 || fail 20 "stats $1 unavailable"; }
wait_completion()
{
	before=$1
	i=0
	while [ "$i" -lt 160 ]; do
		cat "$stats" >"$out/stats-poll.log" 2>/dev/null || return 1
		now=$(value "$out/stats-poll.log" fw_completion_events)
		[ "$now" = $((before + 1)) ] && return 0
		case "$now" in ''|*[!0-9]*) return 1 ;; esac
		[ "$now" -le $((before + 1)) ] || return 1
		sleep 0.25
		i=$((i + 1))
	done
	return 1
}

send_fixed()
{
	index=$1; name=$2; order=$3
	tag=$(printf '%02d' "$index")
	snapshot "before-$order"
	before_submit=$(value "$out/stats-before-$order.log" wmi_submitted)
	before_complete=$(value "$out/stats-before-$order.log" fw_completion_events)
	"$sender" "$name" "$peer" "$nonce" >"$out/send-$tag-$name.log" 2>&1 || fail 31 "sender failed: $name"
	wait_completion "$before_complete" || fail 32 "completion timeout: $name"
	snapshot "after-$order"
	[ "$(value "$out/stats-after-$order.log" wmi_submitted)" = $((before_submit + 1)) ] || fail 33 "submit mismatch: $name"
	status=$(value "$out/stats-after-$order.log" last_completion_status)
	packet_hex=$(sed -n 's/^packet_hex=//p' "$out/send-$tag-$name.log" | head -n1)
	packet_hash=$(printf '%s' "$packet_hex" | sha256sum | awk '{print $1}')
	last_desc=$(value "$out/stats-after-$order.log" last_completed_desc_id)
	last_vdev=$(value "$out/stats-after-$order.log" last_completion_vdev_id)
	printf '%s\tfixed\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$order" "$tag" "$name" "$status" "$last_desc" "$last_vdev" "$packet_hash" "$ready_token" >>"$out/send-manifest.tsv"
}

send_workflow()
{
	index=$1; order=$2
	tag=$(printf '%02d' "$index")
	snapshot "before-$order"
	before_submit=$(value "$out/stats-before-$order.log" wmi_submitted)
	before_complete=$(value "$out/stats-before-$order.log" fw_completion_events)
	"$sender" --workflow-frame "$index" "$channel" "$peer" "$nonce" >"$out/workflow-frame-$tag.log" 2>&1 || fail 34 "workflow sender failed: $index"
	wait_completion "$before_complete" || fail 35 "workflow completion timeout: $index"
	snapshot "after-$order"
	[ "$(value "$out/stats-after-$order.log" wmi_submitted)" = $((before_submit + 1)) ] || fail 36 "workflow submit mismatch: $index"
	status=$(value "$out/stats-after-$order.log" last_completion_status)
	packet_hex=$(sed -n 's/^workflow_packet .* packet_hex=//p' "$out/workflow-frame-$tag.log" | head -n1)
	packet_hash=$(printf '%s' "$packet_hex" | sha256sum | awk '{print $1}')
	last_desc=$(value "$out/stats-after-$order.log" last_completed_desc_id)
	last_vdev=$(value "$out/stats-after-$order.log" last_completion_vdev_id)
	name=$(sed -n 's/^workflow_frame .* name=\([^ ]*\) .*/\1/p' "$out/workflow-frame-$tag.log" | head -n1)
	printf '%s\tworkflow\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$order" "$tag" "$name" "$status" "$last_desc" "$last_vdev" "$packet_hash" "$ready_token" >>"$out/send-manifest.tsv"
}

[ -x "$sender" ] && [ -r "$stats" ] && [ -r "$build_note" ] || fail 10 "preconditions missing"
case "$(od -An -v -tx1 "$build_note" | tr -d ' \r\n')" in *"$expected_build_id"*) ;; *) fail 11 "build ID mismatch" ;; esac
"$sender" --selftest >"$out/sender-selftest.log" 2>&1 || fail 12 "sender selftest failed"
iw dev wlan0 info >"$out/iw-before.log" 2>&1 || fail 13 "iw info failed"
grep -q '^[[:space:]]*type monitor$' "$out/iw-before.log" || fail 14 "wlan0 is not monitor"
snapshot initial
[ "$(value "$out/stats-initial.log" source_rev)" = "$expected_source_rev" ] || fail 15 "source revision mismatch"
[ "$(value "$out/stats-initial.log" format_version)" = 12 ] || fail 15 "stats format mismatch"
idle_knob=$debug_root/wlan0/frame_inject_helper_idle_ms
orig_idle=$(cat "$idle_knob" 2>/dev/null)
case "$orig_idle" in ''|*[!0-9]*) orig_idle=5000 ;; esac
trap 'echo "$orig_idle" > "$idle_knob" 2>/dev/null' EXIT HUP INT TERM
echo 600000 > "$idle_knob" 2>/dev/null || fail 15 "idle knob set failed"
printf 'orig_idle_ms=%s\nrun_idle_ms=600000\n' "$orig_idle" > "$out/idle-knob.txt"
printf 'send_order\tkind\tindex\tname\tcompletion_status\tdesc\tvdev\tpacket_hex_sha256\tlistener_token\n' >"$out/send-manifest.tsv"
printf '%s\n' "$ready_token" >"$out/listener-ready-token.txt"
dmesg >"$out/dmesg-before.log" 2>&1

order=1
index=1
for name in probe-request hcx-probe-request auth-request auth-response assoc-request assoc-response reassoc-request reassoc-response probe-response disassoc probe-6m probe-fcs beacon timing-advert atim action action-noack deauth ordinary-data null-data qos-null eap-request-id eapol-start eapol-m1-wpa1 eapol-m1-wpa2 rts bar block-ack ps-poll cf-end cf-end-ack cts; do
	send_fixed "$index" "$name" "$order"
	index=$((index + 1)); order=$((order + 1))
done
workflow=1
while [ "$workflow" -le 34 ]; do
	send_workflow "$workflow" "$order"
	workflow=$((workflow + 1)); order=$((order + 1))
done
send_fixed 33 ack "$order"

[ "$order" -eq 67 ] || fail 40 "send order did not end at 67"
[ "$(awk 'END {print NR - 1}' "$out/send-manifest.tsv")" -eq 67 ] || fail 41 "manifest is incomplete"
[ "$(cat /proc/sys/kernel/random/boot_id)" = "$boot_id" ] || fail 42 "boot ID changed"
snapshot final
dmesg >"$out/dmesg-after.log" 2>&1
grep -Eiq 'CFI: Fatal|Kernel panic|wlan crashed|cnss_recovery_handler|SMMU.*fault|firmware.*assert' "$out/dmesg-after.log" && fail 43 "fatal signature observed"
{
	printf 'verdict=COMPLETE\n'
	printf 'scope=stage2-67-frame-sender-v6\n'
	printf 'build_id=%s\n' "$expected_build_id"
	printf 'frames=67\n'
	printf 'boot_id=%s\n' "$boot_id"
	printf 'listener_token=%s\n' "$ready_token"
	printf 'helper_idle_ms=%s\n' "$(value "$out/stats-final.log" helper_idle_ms)"
	printf 'helper_auto_teardowns=%s\n' "$(value "$out/stats-final.log" helper_auto_teardowns)"
} >"$out/result.txt"
sha256sum "$out"/*.log "$out"/*.tsv "$out"/*.txt >"$out/SHA256SUMS" 2>/dev/null
exit 0
