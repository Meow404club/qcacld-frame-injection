#!/system/bin/sh

# Stage 2c device sender: 12 frozen vectors out of the pure constructed
# hidden-STA context. Hard gate: helper_context_source must be constructed
# after the first frame - a managed_template value means the phone still
# carries a template from an earlier connection this boot and the run is
# invalid for this question (reboot without reconnecting, then rerun).

set -u

expected_build_id=914714cb6f296f35f093bf393bfea47c4982897c
expected_source_rev=698efe09e8b8+dirty-20260906-observability-admin-knobs-v21
suite_frozen=1

usage()
{
	echo "usage: $0 C --authorized-isolated-test PEER CHANNEL NONCE SENDER READY_TOKEN [EXPECTED_BUILD_ID]" >&2
	exit 2
}

[ "$#" -eq 7 ] || [ "$#" -eq 8 ] || usage
[ "$1" = C ] && [ "$2" = --authorized-isolated-test ] || usage
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
[ "$suite_frozen" -eq 1 ] || { echo "Stage 2c is not frozen" >&2; exit 4; }
case "$ready_token" in READY-[A-Za-z0-9._-]*) ;; *) usage ;; esac

debug_root=/sys/kernel/debug
[ -r "$debug_root/wlan0/frame_inject_stats" ] ||
	debug_root=$(awk '$3 == "debugfs" { print $2; exit }' /proc/mounts)
stats=$debug_root/wlan0/frame_inject_stats
build_note=/sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id
boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
stamp=$(date -u +%Y%m%dT%H%M%SZ)
out=/data/local/tmp/qcacld-stage2c-$stamp-$$
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

[ -x "$sender" ] && [ -r "$stats" ] && [ -r "$build_note" ] || fail 10 "preconditions missing"
case "$(od -An -v -tx1 "$build_note" | tr -d ' \r\n')" in *"$expected_build_id"*) ;; *) fail 11 "build ID mismatch" ;; esac
"$sender" --selftest >"$out/sender-selftest.log" 2>&1 || fail 12 "sender selftest failed"
iw dev wlan0 info >"$out/iw-before.log" 2>&1 || fail 13 "iw info failed"
grep -q '^[[:space:]]*type monitor$' "$out/iw-before.log" || fail 14 "wlan0 is not monitor"
grep -q 'width: 20 MHz' "$out/iw-before.log" || fail 14 "constructed contract is 20 MHz only"
snapshot initial
[ "$(value "$out/stats-initial.log" source_rev)" = "$expected_source_rev" ] || fail 15 "source revision mismatch"
[ "$(value "$out/stats-initial.log" format_version)" = 12 ] || fail 15 "stats format mismatch"
idle_knob=$debug_root/wlan0/frame_inject_helper_idle_ms
orig_idle=$(cat "$idle_knob" 2>/dev/null)
case "$orig_idle" in ''|*[!0-9]*) orig_idle=5000 ;; esac
trap 'echo "$orig_idle" > "$idle_knob" 2>/dev/null' EXIT HUP INT TERM
echo 600000 > "$idle_knob" 2>/dev/null || fail 15 "idle knob set failed"
printf 'orig_idle_ms=%s\nrun_idle_ms=600000\n' "$orig_idle" >"$out/idle-knob.txt"
printf 'send_order\tkind\tindex\tname\tcompletion_status\tdesc\tvdev\tpacket_hex_sha256\tlistener_token\n' >"$out/send-manifest.tsv"
printf '%s\n' "$ready_token" >"$out/listener-ready-token.txt"
dmesg >"$out/dmesg-before.log" 2>&1

order=1
index=1
for name in probe-request hcx-probe-request auth-request assoc-request disassoc deauth action null-data qos-null ordinary-data rts ps-poll; do
	send_fixed "$index" "$name" "$order"
	# after the first frame the helper exists; the constructed gate is the
	# whole point of this variant - a managed template invalidates the run
	if [ "$order" -eq 1 ]; then
		ctx=$(value "$out/stats-after-$order.log" helper_context_source)
		[ "$ctx" = constructed ] ||
			fail 16 "helper context is '$ctx', not constructed (managed template still present - reboot without reconnecting Wi-Fi and rerun)"
		printf 'helper_context_source=%s\n' "$ctx" >"$out/context-source.txt"
	fi
	index=$((index + 1)); order=$((order + 1))
done

[ "$order" -eq 13 ] || fail 40 "send order did not end at 13"
[ "$(awk 'END {print NR - 1}' "$out/send-manifest.tsv")" -eq 12 ] || fail 41 "manifest is incomplete"
[ "$(cat /proc/sys/kernel/random/boot_id)" = "$boot_id" ] || fail 42 "boot ID changed"
snapshot final
dmesg >"$out/dmesg-after.log" 2>&1
grep -Eiq 'CFI: Fatal|Kernel panic|wlan crashed|cnss_recovery_handler|SMMU.*fault|firmware.*assert' "$out/dmesg-after.log" && fail 43 "fatal signature observed"
{
	printf 'verdict=COMPLETE\n'
	printf 'scope=stage2c-constructed-12-frame-sender-v6\n'
	printf 'build_id=%s\n' "$expected_build_id"
	printf 'frames=12\n'
	printf 'helper_context_source=constructed\n'
	printf 'boot_id=%s\n' "$boot_id"
	printf 'listener_token=%s\n' "$ready_token"
	printf 'helper_idle_ms=%s\n' "$(value "$out/stats-final.log" helper_idle_ms)"
	printf 'helper_auto_teardowns=%s\n' "$(value "$out/stats-final.log" helper_auto_teardowns)"
} >"$out/result.txt"
sha256sum "$out"/*.log "$out"/*.tsv "$out"/*.txt >"$out/SHA256SUMS" 2>/dev/null
exit 0
