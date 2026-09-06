#!/system/bin/sh
# mac-persist - stable monitor MAC across boots.
# The driver gives the monitor persona a per-boot stable MAC, but it
# changes on reboot. This saves the current persona MAC once and
# re-applies it after every `mon up`, keeping long-running capture
# filters and ledger annotations aligned.
# usage: mac-persist save|apply|show
set -u
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
store=/data/local/tmp/fi-monitor-mac

current_mac()
{
	# monitor mode reports link/ieee80211/radiotap instead of
	# link/ether; the MAC is the next field either way
	ip link show wlan0 2>/dev/null |
		awk '/^    link\// && $2 ~ /:/ {print $2; exit}' | tr -d '\r'
}

case ${1:-} in
save)
	m=$(current_mac)
	[ -n "$m" ] || { echo "no MAC on wlan0 (persona up?)" >&2; exit 4; }
	echo "$m" > "$store"
	echo "saved $m"
	;;
apply)
	[ -f "$store" ] || { echo "no saved MAC; run 'save' first" >&2; exit 4; }
	m=$(cat "$store" | tr -d '\r\n')
	# save the channel: a monitor link restart loses the chandef and
	# the injection helper cannot build without it (precise context
	# reject, errno -22)
	chan=$(iw dev wlan0 info 2>/dev/null | awk '/channel/ {
		for (i = 1; i <= NF; i++) if ($i ~ /MHz/) {
			v = $(i-1); gsub(/[^0-9]/, "", v); print v; exit } }' | tr -d '\r')
	width=$(iw dev wlan0 info 2>/dev/null | awk '/channel/ {
		for (i = 1; i <= NF; i++) if ($i == "width:") { print $(i+1); exit } }' | tr -d '\r')
	# MAC changes need the interface down (errno 524 otherwise)
	ip link set wlan0 down
	ip link set wlan0 address "$m" || { ip link set wlan0 up; echo "set failed" >&2; exit 5; }
	ip link set wlan0 up
	# restore the chandef (320 MHz has no iw set-side word: sysfs code 7)
	if [ -n "$chan" ]; then
		case "$width" in
		320) echo "$chan 7" > /sys/class/net/wlan0/monitor_mode_channel 2>/dev/null ||
			iw dev wlan0 set freq "$chan" >/dev/null 2>&1 ;;
		*) [ -n "$width" ] && iw dev wlan0 set freq "$chan" "$width" >/dev/null 2>&1 ||
			iw dev wlan0 set freq "$chan" >/dev/null 2>&1 ;;
		esac
	fi
	echo "applied $m (channel ${chan:-?} ${width:-} restored)"
	;;
show)
	echo "current: $(current_mac)"
	[ -f "$store" ] && echo "saved:   $(cat "$store" | tr -d '\r\n')" ||
		echo "saved:   (none)"
	;;
*) echo "usage: mac-persist save|apply|show" >&2; exit 2 ;;
esac
