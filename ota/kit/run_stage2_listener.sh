#!/usr/bin/env bash

set -euo pipefail

usage()
{
	cat >&2 <<'EOF'
usage: run_stage2_listener.sh --interface IFACE --frequency MHZ
       --channel-width WIDTH [--center-frequency MHZ]
       [--duration SECONDS] [--output DIR]

WIDTH is one of 20, 40, 80, or 160. A center frequency is required for every
width other than 20. The external interface must support monitor mode.
The script validates the resulting channel definition before printing READY.
Stop early with Ctrl-C after the sender reports COMPLETE.
EOF
	exit 2
}

iface=
frequency=
channel_width=
center_frequency=
duration=600
output=
while [[ $# -gt 0 ]]; do
	case $1 in
	--interface) [[ $# -ge 2 ]] || usage; iface=$2; shift 2 ;;
	--frequency) [[ $# -ge 2 && $2 =~ ^[0-9]+$ ]] || usage; frequency=$2; shift 2 ;;
	--channel-width) [[ $# -ge 2 ]] || usage; channel_width=$2; shift 2 ;;
	--center-frequency) [[ $# -ge 2 && $2 =~ ^[0-9]+$ ]] || usage; center_frequency=$2; shift 2 ;;
	--duration) [[ $# -ge 2 && $2 =~ ^[0-9]+$ && $2 -ge 30 ]] || usage; duration=$2; shift 2 ;;
	--output) [[ $# -ge 2 ]] || usage; output=$2; shift 2 ;;
	*) usage ;;
	esac
done
[[ -n $iface && -n $frequency && -n $channel_width ]] || usage
case $channel_width in
20) [[ -z $center_frequency ]] || usage ;;
40|80|160) [[ -n $center_frequency ]] || usage ;;
*) usage ;;
esac
command -v iw >/dev/null
command -v ip >/dev/null
command -v tcpdump >/dev/null

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
manifest=$script_dir/SHA256SUMS
[[ -r $manifest ]] || exit 3
(cd "$script_dir" && sha256sum -c SHA256SUMS) || exit 3
stamp=$(date -u +%Y%m%dT%H%M%SZ)
[[ -n $output ]] || output=$script_dir/listener-capture-$stamp-$$
mkdir "$output"
token=READY-${stamp}-$$-${RANDOM}
printf '%s\n' "$token" >"$output/READY_TOKEN.txt"
printf 'interface=%s\nfrequency_mhz=%s\nchannel_width_mhz=%s\ncenter_frequency_mhz=%s\nduration_seconds=%s\nready_token=%s\n' \
	"$iface" "$frequency" "$channel_width" "${center_frequency:-$frequency}" \
	"$duration" "$token" >"$output/listener-contract.txt"

sudo ip link set "$iface" down
sudo iw dev "$iface" set type monitor
sudo ip link set "$iface" up
if [[ $channel_width == 20 ]]; then
	sudo iw dev "$iface" set freq "$frequency"
else
	sudo iw dev "$iface" set freq "$frequency" "$channel_width" "$center_frequency"
fi
iw dev "$iface" info >"$output/iw-info.log"
grep -q '^[[:space:]]*type monitor$' "$output/iw-info.log" || {
	echo "listener channel gate: interface is not monitor" >&2
	exit 4
}
actual_frequency=$(sed -n 's/.*(\([0-9][0-9]*\) MHz).*/\1/p' "$output/iw-info.log" | head -n1)
actual_width=$(sed -n 's/.*width: \([0-9][0-9]*\) MHz.*/\1/p' "$output/iw-info.log" | head -n1)
actual_center=$(sed -n 's/.*center1: \([0-9][0-9]*\) MHz.*/\1/p' "$output/iw-info.log" | head -n1)
[[ -n $actual_frequency && $actual_frequency == "$frequency" ]] || {
	echo "listener channel gate: requested frequency $frequency, observed ${actual_frequency:-missing}" >&2
	exit 4
}
[[ -n $actual_width && $actual_width == "$channel_width" ]] || {
	echo "listener channel gate: requested width $channel_width, observed ${actual_width:-missing}" >&2
	exit 4
}
expected_center=${center_frequency:-$frequency}
[[ -n $actual_center && $actual_center == "$expected_center" ]] || {
	echo "listener channel gate: requested center $expected_center, observed ${actual_center:-missing}" >&2
	exit 4
}
printf 'actual_frequency_mhz=%s\nactual_channel_width_mhz=%s\nactual_center_frequency_mhz=%s\n' \
	"$actual_frequency" "$actual_width" "$actual_center" >>"$output/listener-contract.txt"

echo "LISTENER_READY_TOKEN=$token"
echo "Give that exact token to the sender operator now."
echo "CAPTURE_PATH=$output/ota-capture.pcap"
set +e
sudo timeout --signal=INT --kill-after=5 "$duration" \
	tcpdump -i "$iface" -U -s 0 -w "$output/ota-capture.pcap" \
	>"$output/tcpdump.stdout" 2>"$output/tcpdump.stderr"
rc=$?
set -e
printf '%s\n' "$rc" >"$output/tcpdump.exit-code"
sudo chown "$(id -u):$(id -g)" "$output/ota-capture.pcap" 2>/dev/null || true
tcpdump -n -e -r "$output/ota-capture.pcap" >"$output/capture-summary.txt" 2>&1 || true
(cd "$output" && sha256sum ./* >SHA256SUMS)
echo "LISTENER_OUTPUT_DIR=$output"
