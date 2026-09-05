#!/usr/bin/env bash

# Stage 2c: constructed-context OTA adjudication. The main Stage 2 sender
# requires a recent managed template; this variant answers a narrower
# question - can the pure constructed hidden-STA context (no managed
# template since boot: random local BSSID, AID 1, 11A/11G legacy rates,
# 20 MHz only) actually put caller MPDUs on the air? Only the external
# listener pcap can answer that; this script just performs the send under
# a hard helper_context_source=constructed gate.
#
# The host script itself disables the Wi-Fi framework, enters the monitor
# persona at 20 MHz on the listener's frequency and holds it stable before
# handing off to the device sender.

set -uo pipefail

expected_build_id=4c13f3b3f0b8f03d6904dd871af39164e18afa57
suite_frozen=1

usage()
{
	cat >&2 <<'EOF'
usage: run_stage2c_sender_host.sh [--serial SERIAL] [--expected-build-id HEX40]
       --frequency MHZ --peer-mac MAC --listener-ready-token READY-...
       --acknowledge-authorized-isolated-test

Constructed-context variant. The phone must NOT have connected Wi-Fi since
boot (a managed template would fail the constructed gate by design); the
script disables the framework itself and enters monitor at 20 MHz on
--frequency. Run only after the listener prints LISTENER_READY_TOKEN.
EOF
	exit 2
}

serial=
freq=
peer=
ready=
ack=false
while [[ $# -gt 0 ]]; do
	case $1 in
	--serial) [[ $# -ge 2 ]] || usage; serial=$2; shift 2 ;;
	--expected-build-id)
		[[ $# -ge 2 && $2 =~ ^[0-9a-f]{40}$ ]] || usage
		expected_build_id=$2; shift 2 ;;
	--frequency) [[ $# -ge 2 && $2 =~ ^([0-9]{4})$ ]] || usage; freq=$2; shift 2 ;;
	--peer-mac) [[ $# -ge 2 ]] || usage; peer=${2,,}; shift 2 ;;
	--listener-ready-token) [[ $# -ge 2 ]] || usage; ready=$2; shift 2 ;;
	--acknowledge-authorized-isolated-test) ack=true; shift ;;
	*) usage ;;
	esac
done
[[ $ack == true && -n $freq && $peer =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ && $ready == READY-* ]] || usage
[[ $suite_frozen -eq 1 ]] || { echo "Stage 2c is not frozen" >&2; exit 4; }

dir=$(cd -- "$(dirname -- "$0")" && pwd)
device=$dir/run_stage2c_sender_device.sh
sender=$dir/send_frame_matrix
[[ -x $device && -x $sender ]] || exit 3
(cd "$dir" && sha256sum -c SHA256SUMS) || exit 3
declare -a adb_cmd=(adb)
if [[ -n $serial ]]; then
	adb_cmd=(adb -s "$serial")
else
	mapfile -t devices < <(adb devices | awk '$2 == "device" {print $1}')
	[[ ${#devices[@]} -eq 1 ]] || exit 3
	serial=${devices[0]}; adb_cmd=(adb -s "$serial")
fi

as()
{
	"${adb_cmd[@]}" shell su -c "$1" </dev/null
}

stamp=$(date -u +%Y%m%dT%H%M%SZ)
out=$dir/sender-capture-constructed-$stamp-$$
mkdir "$out" || exit 3
echo "HOST_OUTPUT_DIR=$out"

note=$(as 'od -An -v -tx1 /sys/module/qca_cld3_peach_v2/notes/.note.gnu.build-id' | tr -d ' \r\n')
[[ $note == *"$expected_build_id"* ]] || { echo "build ID mismatch" >&2; exit 5; }
knob=$(as 'cat /sys/module/qca_cld3_peach_v2/parameters/frame_inject_constructed_context' | tr -d ' \r\n')
case "$knob" in Y|1) ;; *) echo "constructed-context knob is off ($knob)" >&2; exit 5 ;; esac
printf 'knob_constructed_context=%s\n' "$knob" >"$out/knob.txt"

# framework off and settled (a still-valid managed template from earlier in
# this boot is caught by the device script's helper_context_source gate)
as 'cmd wifi set-wifi-enabled disabled' >"$out/disable-wifi.log" 2>&1 || exit 5
settled=0
for _ in $(seq 1 120); do
	status=$(as 'cmd wifi status' 2>/dev/null | tr -d '\r')
	supp=$(as 'pidof wpa_supplicant' 2>/dev/null | tr -d '\r\n')
	if grep -q '^Wifi is disabled$' <<<"$status" && [ -z "$supp" ]; then
		settled=1
		break
	fi
	sleep 0.5
done
[ "$settled" -eq 1 ] || { echo "Wi-Fi framework did not settle off" >&2; exit 5; }

as 'iw dev wlan0 set type monitor' >"$out/set-monitor.log" 2>&1 || exit 5
sleep 2
as 'ip link set wlan0 up' >"$out/ifup.log" 2>&1 || exit 5
n=0
until as "iw dev wlan0 set freq $freq" >>"$out/set-freq.log" 2>&1; do
	n=$((n + 1)); [ "$n" -lt 100 ] || { echo "set freq failed" >&2; exit 5; }
	sleep 0.2
done
as 'iw dev wlan0 info' >"$out/iw-info.log" 2>&1 || exit 5
grep -q '^[[:space:]]*type monitor$' "$out/iw-info.log" || exit 5
grep -q "channel [0-9]* ($freq MHz)" "$out/iw-info.log" || exit 5
grep -q 'width: 20 MHz' "$out/iw-info.log" ||
	{ echo "constructed contract is 20 MHz only" >&2; exit 5; }
channel=$(sed -n 's/^[[:space:]]*channel \([0-9][0-9]*\) .*/\1/p' "$out/iw-info.log" | head -n1)
[[ -n $channel ]] || exit 5
# persona stability hold
sleep 5
as 'iw dev wlan0 info' >"$out/iw-hold.log" 2>&1 || exit 5
grep -q '^[[:space:]]*type monitor$' "$out/iw-hold.log" || exit 5

remote=/data/local/tmp/qcacld-stage2c-$stamp-$$
as "mkdir -p '$remote'" || exit 5
"${adb_cmd[@]}" push "$device" "$remote/run_stage2c_sender_device.sh" >"$out/push-device.log" 2>&1 || exit 5
"${adb_cmd[@]}" push "$sender" "$remote/send_frame_matrix" >"$out/push-sender.log" 2>&1 || exit 5
as "chmod 0755 '$remote/'*" || exit 5
nonce=$(( (10#$(date -u +%S) + $$) % 4095 + 1 ))
timeout 600 "${adb_cmd[@]}" shell su -c "'$remote/run_stage2c_sender_device.sh' C --authorized-isolated-test '$peer' '$channel' '$nonce' '$remote/send_frame_matrix' '$ready' '$expected_build_id'" >"$out/test.stdout" 2>"$out/test.stderr"
rc=$?
remote_out=$(sed -n 's/^OUTPUT_DIR=//p' "$out/test.stdout" | head -n1 | tr -d '\r')
case "$remote_out" in
/data/local/tmp/qcacld-stage2c-*) ;;
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
