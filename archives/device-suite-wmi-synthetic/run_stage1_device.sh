#!/system/bin/sh

set -u

expected_build_id=d0f530a77c382b50e6bf298ce9cbf5eb26f6dd30
expected_source_rev=f32230e2fd7f+dirty-20260808-wmi-synthetic-v33-pv1-selftest-contract
suite_frozen=1

usage()
{
	echo "usage: $0 S --clean-boot --two-round-continuity SENDER PEER_BSSID" >&2
	exit 2
}

[ "$#" -eq 6 ] || usage
[ "$1" = S ] && [ "$2" = --clean-boot ] &&
[ "$3" = --two-round-continuity ] || usage
sender=$4
managed_bssid=$(printf '%s' "$5" | tr 'A-F' 'a-f')
target=$(printf '%s' "$6" | tr 'A-F' 'a-f')
peer=02:32:5a:a5:00:01
[ "$suite_frozen" -eq 1 ] || { echo "Stage 1 is not frozen" >&2; exit 4; }

stats=/sys/kernel/debug/wlan0/frame_inject_stats
build_note=/sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id
boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
stamp=$(date -u +%Y%m%dT%H%M%SZ)
out=/data/local/tmp/qcacld-v33-stage1-$stamp-$$
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
	while [ "$i" -lt 40 ]; do
		snapshot poll
		now=$(value "$out/stats-poll.log" fw_completion_events)
		[ "$now" = $((before + 1)) ] && return 0
		sleep 0.25
		i=$((i + 1))
	done
	return 1
}
send_one()
{
	kind=$1; nonce=$2; label=$3
	snapshot "$label-before"
	submitted=$(value "$out/stats-$label-before.log" wmi_submitted)
	completed=$(value "$out/stats-$label-before.log" fw_completion_events)
	"$sender" "$kind" "$peer" "$nonce" >"$out/send-$label.log" 2>&1 || fail 31 "$label sender failed"
	wait_completion "$completed" || fail 32 "$label completion timeout"
	snapshot "$label-after"
	[ "$(value "$out/stats-$label-after.log" wmi_submitted)" = $((submitted + 1)) ] || fail 33 "$label submit mismatch"
	[ "$(value "$out/stats-$label-after.log" mgmt_inflight)" = 0 ] || fail 34 "$label remained inflight"
	case "$(value "$out/stats-$label-after.log" last_completion_status)" in 0|3) ;; *) fail 35 "$label completion rejected" ;; esac
}
capture_window()
{
	label=$1
	"$sender" --capture-beacon "$target" 6 "$out/$label.pcap" \
		>"$out/$label-capture.log" 2>&1
}

[ -n "$boot_id" ] && [ -x "$sender" ] && [ -r "$stats" ] && [ -r "$build_note" ] || fail 10 "preconditions missing"
case "$(od -An -v -tx1 "$build_note" | tr -d ' \r\n')" in *"$expected_build_id"*) ;; *) fail 11 "build ID mismatch" ;; esac
"$sender" --selftest >"$out/sender-selftest.log" 2>&1 || fail 12 "sender selftest failed"
iw dev wlan0 info >"$out/iw-before.log" 2>&1 || fail 13 "iw failed"
grep -q '^[[:space:]]*type monitor$' "$out/iw-before.log" || fail 14 "not monitor"
snapshot initial
[ "$(value "$out/stats-initial.log" source_rev)" = "$expected_source_rev" ] || fail 15 "source revision mismatch"

capture_window beacon-before || fail 40 "target beacon absent before TX"
send_one probe 801 round1-probe
send_one data 802 round1-data
send_one cts 803 round1-cts
capture_window beacon-between || fail 41 "target beacon absent after round 1"
[ "$(value "$out/stats-round1-cts-after.log" helper_present)" = 1 ] || fail 42 "helper disappeared after round 1"
send_one probe 811 round2-probe
send_one data 812 round2-data
send_one cts 813 round2-cts
capture_window beacon-after || fail 43 "target beacon absent after round 2"
[ "$(cat /proc/sys/kernel/random/boot_id)" = "$boot_id" ] || fail 44 "boot ID changed"
dmesg >"$out/dmesg-after.log" 2>&1
grep -Eiq 'CFI: Fatal|Kernel panic|wlan crashed|cnss_recovery_handler|SMMU.*fault|firmware.*assert' "$out/dmesg-after.log" && fail 45 "fatal signature observed"
printf 'verdict=PASS\nscope=v33-two-round-continuity\nframes=6\nbeacon_windows=3\nboot_id=%s\n' "$boot_id" >"$out/result.txt"
printf 'managed_bssid=%s\nforeign_peer=%s\ntarget_bssid=%s\n' \
	"$managed_bssid" "$peer" "$target" >>"$out/result.txt"
sha256sum "$out"/*.log "$out"/*.pcap "$out/result.txt" >"$out/SHA256SUMS" 2>/dev/null
exit 0
