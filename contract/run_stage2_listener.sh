#!/usr/bin/env bash

set -euo pipefail

usage()
{
	cat >&2 <<'EOF'
usage: run_stage2_listener.sh --interface IFACE --frequency MHZ
       [--duration SECONDS] [--output DIR]

Run on an independent Linux monitor adapter in an authorized isolated lab.
Start this before the Stage 2 phone runner. The printed READY token binds the capture.
EOF
	exit 2
}

iface=
frequency=
duration=1800
output=
while [[ $# -gt 0 ]]; do
	case $1 in
	--interface) [[ $# -ge 2 ]] || usage; iface=$2; shift 2 ;;
	--frequency) [[ $# -ge 2 && $2 =~ ^[0-9]+$ ]] || usage; frequency=$2; shift 2 ;;
	--duration) [[ $# -ge 2 && $2 =~ ^[0-9]+$ && $2 -ge 30 ]] || usage; duration=$2; shift 2 ;;
	--output) [[ $# -ge 2 ]] || usage; output=$2; shift 2 ;;
	*) usage ;;
	esac
done
[[ -n $iface && -n $frequency ]] || usage
command -v iw >/dev/null
command -v ip >/dev/null
command -v tcpdump >/dev/null

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
stamp=$(date -u +%Y%m%dT%H%M%SZ)
[[ -n $output ]] || output=$script_dir/listener-capture-stage2-$stamp-$$
mkdir "$output"
token=STAGE2-READY-$stamp-$$-$RANDOM
echo "$token" >"$output/READY_TOKEN.txt"
{
	echo "interface=$iface"
	echo "frequency_mhz=$frequency"
	echo "duration_seconds=$duration"
	echo "ready_token=$token"
} >"$output/listener-contract.txt"

sudo ip link set "$iface" down
sudo iw dev "$iface" set type monitor
sudo ip link set "$iface" up
sudo iw dev "$iface" set freq "$frequency"
iw dev "$iface" info >"$output/iw-info.log"
grep -q '^[[:space:]]*type monitor$' "$output/iw-info.log"
grep -q "$frequency MHz" "$output/iw-info.log"

echo "LISTENER_READY_TOKEN=$token"
echo "CAPTURE_PATH=$output/ota-capture.pcap"
set +e
sudo timeout --signal=INT --kill-after=5 "$duration" \
	tcpdump -i "$iface" -U -s 0 -w "$output/ota-capture.pcap" \
	>"$output/tcpdump.stdout" 2>"$output/tcpdump.stderr"
rc=$?
set -e
echo "$rc" >"$output/tcpdump.exit-code"
sudo chown "$(id -u):$(id -g)" "$output/ota-capture.pcap" 2>/dev/null || true
tcpdump -n -e -r "$output/ota-capture.pcap" >"$output/capture-summary.txt" 2>&1 || true
(cd "$output" && sha256sum ./* >SHA256SUMS)
echo "LISTENER_OUTPUT_DIR=$output"
