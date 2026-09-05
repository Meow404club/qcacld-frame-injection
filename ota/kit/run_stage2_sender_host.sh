#!/usr/bin/env bash

set -uo pipefail

expected_build_id=4c13f3b3f0b8f03d6904dd871af39164e18afa57
suite_frozen=1

usage()
{
	cat >&2 <<'EOF'
usage: run_stage2_sender_host.sh [--serial SERIAL] [--expected-build-id HEX40]
       --peer-mac MAC --listener-ready-token READY-...
       --acknowledge-authorized-isolated-test

Run only after the external listener prints LISTENER_READY_TOKEN. The phone
must already be wlan0 monitor on the same channel. This sends the frozen 67
known vectors, completion-gated one at a time. It does not flash or reboot.
--expected-build-id authorizes a self-built module identity for this run; the
default remains the delivered kit build ID, and result.txt records the gate.
EOF
	exit 2
}

serial=
peer=
ready=
ack=false
while [[ $# -gt 0 ]]; do
	case $1 in
	--serial) [[ $# -ge 2 ]] || usage; serial=$2; shift 2 ;;
	--expected-build-id)
		[[ $# -ge 2 && $2 =~ ^[0-9a-f]{40}$ ]] || usage
		expected_build_id=$2; shift 2 ;;
	--peer-mac) [[ $# -ge 2 ]] || usage; peer=${2,,}; shift 2 ;;
	--listener-ready-token) [[ $# -ge 2 ]] || usage; ready=$2; shift 2 ;;
	--acknowledge-authorized-isolated-test) ack=true; shift ;;
	*) usage ;;
	esac
done
[[ $ack == true && $peer =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ && $ready == READY-* ]] || usage
[[ $suite_frozen -eq 1 ]] || { echo "Stage 2 is not frozen" >&2; exit 4; }

dir=$(cd -- "$(dirname -- "$0")" && pwd)
device=$dir/run_stage2_sender_device.sh
sender=$dir/send_frame_matrix
manifest=$dir/SHA256SUMS
[[ -x $device && -x $sender && -r $manifest ]] || exit 3
(cd "$dir" && sha256sum -c SHA256SUMS) || exit 3
declare -a adb_cmd=(adb)
if [[ -n $serial ]]; then
	adb_cmd=(adb -s "$serial")
else
	mapfile -t devices < <(adb devices | awk '$2 == "device" {print $1}')
	[[ ${#devices[@]} -eq 1 ]] || exit 3
	serial=${devices[0]}; adb_cmd=(adb -s "$serial")
fi
stamp=$(date -u +%Y%m%dT%H%M%SZ)
out=$dir/sender-capture-$stamp-$$
mkdir "$out" || exit 3
echo "HOST_OUTPUT_DIR=$out"
"${adb_cmd[@]}" shell su -c 'iw dev wlan0 info' >"$out/iw-info.log" 2>&1 || exit 5
grep -q '^[[:space:]]*type monitor$' "$out/iw-info.log" || exit 5
channel=$(sed -n 's/^[[:space:]]*channel \([0-9][0-9]*\) .*/\1/p' "$out/iw-info.log" | head -n1)
[[ -n $channel ]] || exit 5
note=$("${adb_cmd[@]}" exec-out su -c 'od -An -v -tx1 /sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id' | tr -d ' \r\n')
[[ $note == *"$expected_build_id"* ]] || exit 5
remote=/data/local/tmp/qcacld-stage2-$stamp-$$
"${adb_cmd[@]}" shell su -c "mkdir -p '$remote'" || exit 5
"${adb_cmd[@]}" push "$device" "$remote/run_stage2_sender_device.sh" >"$out/push-device.log" 2>&1 || exit 5
"${adb_cmd[@]}" push "$sender" "$remote/send_frame_matrix" >"$out/push-sender.log" 2>&1 || exit 5
"${adb_cmd[@]}" shell su -c "chmod 0755 '$remote/'*" || exit 5
nonce=$(( (10#$(date -u +%S) + $$) % 4095 + 1 ))
timeout 900 "${adb_cmd[@]}" shell su -c "'$remote/run_stage2_sender_device.sh' S --authorized-isolated-test '$peer' '$channel' '$nonce' '$remote/send_frame_matrix' '$ready' '$expected_build_id'" >"$out/test.stdout" 2>"$out/test.stderr"
rc=$?
remote_out=$(sed -n 's/^OUTPUT_DIR=//p' "$out/test.stdout" | head -n1 | tr -d '\r')
case $remote_out in
/data/local/tmp/qcacld-stage2-*|/data/local/tmp/qcacld-v33-stage2-*) ;;
*) exit 6 ;;
esac
"${adb_cmd[@]}" pull "$remote_out" "$out/device-output" >"$out/pull.log" 2>&1 || exit 6
[[ $rc -eq 0 ]] && grep -qx 'verdict=COMPLETE' "$out/device-output/result.txt" || exit 7
# Self-exclusion + tmp+mv: the v8 find|xargs pipeline could race its own
# output file into the listing (SHA256SUMS hashing a truncated itself).
(cd "$out" && find . -type f ! -name SHA256SUMS -print0 |
	sort -z | xargs -0 sha256sum >SHA256SUMS.new && mv SHA256SUMS.new SHA256SUMS)
echo "SENDER_OUTPUT_DIR=$out"
echo "Transfer that directory to the listener operator for verification."
