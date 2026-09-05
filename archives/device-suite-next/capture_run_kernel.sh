#!/system/bin/sh

set -u

[ "$#" -eq 3 ] || {
	echo "usage: $0 <run-token> <output-log> <stderr-log>" >&2
	exit 2
}

run_token=$1
output_log=$2
stderr_log=$3
case "$run_token" in
	''|*[!A-Za-z0-9._-]*) exit 2 ;;
esac
case "$output_log:$stderr_log" in
	/data/local/tmp/qcacld-consolidated-*/*:/data/local/tmp/qcacld-consolidated-*/*) ;;
	*) exit 2 ;;
esac

dmesg -w 2>"$stderr_log" |
	awk -v token="$run_token" '
		index($0, token) {
			seen = 1
			print
			fflush()
			next
		}
		seen && ($0 ~ /frame injection|iw full-mode transition|monitor filter reset|EAPOL-|subsys-restart|wlan crashed|SMMU|arm-smmu|MHI|cnss.*device crashed|NOC_error|cmnos_assert|AUX FATAL|Asserted in:|Kernel panic| panic:/) {
			print
			fflush()
		}
	' >"$output_log"
