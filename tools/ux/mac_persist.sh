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
	ip link show wlan0 2>/dev/null |
		awk '/link\/ether/ {print $2; exit}' | tr -d '\r'
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
	# MAC changes need the interface down (errno 524 otherwise)
	ip link set wlan0 down
	ip link set wlan0 address "$m" || { ip link set wlan0 up; echo "set failed" >&2; exit 5; }
	ip link set wlan0 up
	echo "applied $m"
	;;
show)
	echo "current: $(current_mac)"
	[ -f "$store" ] && echo "saved:   $(cat "$store" | tr -d '\r\n')" ||
		echo "saved:   (none)"
	;;
*) echo "usage: mac-persist save|apply|show" >&2; exit 2 ;;
esac
