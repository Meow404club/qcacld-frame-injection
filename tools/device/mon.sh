#!/system/bin/sh
# mon - monitor persona quick control (device-side; run as root).
# Install: adb push mon.sh /data/local/tmp/bin/mon && chmod 755 .../mon
#
# Subcommands:
#   mon up                 enter monitor persona (supplicant wait + asserts)
#   mon down               back to managed + Wi-Fi framework on
#   mon status             persona/interface/hop state one-look
#   mon freq <mhz> [width] single-channel set (width: 20|40|80|160|320)
#   mon hop2g|hop5g|hop6g [dwell_ms]   band preset hop via driver scheduler
#   mon hopstop            stop hopping (stays on last channel)
#   mon scan [seconds]     airodump-ng on the monitor persona (termux tools)
#
# Notes:
#   - "Wifi is disabled" settings flip is NOT teardown; this script waits
#     for wpa_supplicant to actually leave (gold-standard discipline).
#   - airodump-ng stdout MUST go to /dev/null (ncurses redraw grows to
#     hundreds of MB when redirected); -c takes channel NUMBERS not MHz.
set -u

WIFI_OFF_WAIT=60
HOP_NODE=/sys/kernel/debug/wlan0/frame_inject_channel_hop
STATS_NODE=/sys/kernel/debug/wlan0/frame_inject_stats

need_root()
{
	[ "$(id -u)" = 0 ] || { echo "run as root (su)" >&2; exit 1; }
}

wifi_framework_off()
{
	cmd wifi set-wifi-enabled disabled >/dev/null 2>&1 || true
	n=0
	while [ $n -lt $((WIFI_OFF_WAIT * 2)) ]; do
		st=$(cmd wifi status 2>/dev/null | tr -d '\r')
		supp=$(pidof wpa_supplicant 2>/dev/null | tr -d '\r\n')
		echo "$st" | grep -q '^Wifi is disabled$' && [ -z "$supp" ] && return 0
		sleep 0.5
		n=$((n + 1))
	done
	echo "wpa_supplicant still present after ${WIFI_OFF_WAIT}s" >&2
	return 1
}

up()
{
	wifi_framework_off || exit 4
	n=0
	while [ $n -lt 15 ]; do
		iw dev wlan0 set type monitor >/dev/null 2>&1 || { sleep 1; n=$((n+1)); continue; }
		ip link set wlan0 up >/dev/null 2>&1 || { sleep 1; n=$((n+1)); continue; }
		f=0
		while [ $f -lt 20 ]; do
			iw dev wlan0 set freq 5745 >/dev/null 2>&1 && break
			sleep 0.3
			f=$((f + 1))
		done
		iw dev wlan0 info 2>/dev/null | tr -d '\r' | grep -q 'channel 149' && {
			echo "monitor persona up @5745/20"
			return 0
		}
		sleep 1
		n=$((n + 1))
	done
	echo "monitor setup failed" >&2
	exit 4
}

down()
{
	echo stop > "$HOP_NODE" 2>/dev/null || true
	cmd wifi set-wifi-enabled disabled >/dev/null 2>&1 || true
	ip link set wlan0 down 2>/dev/null || true
	iw dev wlan0 set type managed >/dev/null 2>&1 || true
	ip link set wlan0 up >/dev/null 2>&1 || true
	cmd wifi set-wifi-enabled enabled >/dev/null 2>&1 || true
	echo "managed restored"
}

status()
{
	echo "== interface"
	iw dev wlan0 info 2>/dev/null | tr -d '\r'
	echo "== persona stats node: $([ -r "$STATS_NODE" ] && echo present || echo ABSENT)"
	if [ -r "$HOP_NODE" ]; then
		echo "== hop"
		cat "$HOP_NODE"
	fi
}

freq()
{
	[ $# -ge 1 ] || { echo "usage: mon freq <mhz> [20|40|80|160|320]" >&2; exit 2; }
	sysfs_chan=/sys/class/net/wlan0/monitor_mode_channel
	# driver width codes: 0=20 1=40 2=80 3=160 4=80p80 7=320
	# (evidence: "5180 0"=HT20 row, "5955 7"=320MHz probe both accepted)
	case ${2:-20} in
	20) code=0 ;; 40) code=1 ;; 80) code=2 ;; 160) code=3 ;;
	80p80) code=4 ;; 320) code=7 ;;
	*) echo "bad width (20|40|80|160|80p80|320)" >&2; exit 2 ;;
	esac
	if [ -w "$sysfs_chan" ]; then
		echo "$1 $code" > "$sysfs_chan" 2>/dev/null ||
			{ echo "sysfs chandef write refused" >&2; exit 5; }
	else
		iw dev wlan0 set freq "$1" >/dev/null 2>&1 ||
			{ echo "iw set freq failed (persona down?)" >&2; exit 5; }
	fi
	iw dev wlan0 info 2>/dev/null | tr -d '\r' | grep -E 'channel|freq'
}

hop_start()
{
	preset=$1; dwell=${2:-400}
	case $preset in
	hop2g) set -- 2412 2437 2462 ;;
	hop5g) set -- 5180 5240 5745 5825 ;;
	hop6g) set -- 5955 6015 6095 ;;
	*) echo "unknown preset" >&2; exit 2 ;;
	esac
	[ -w "$HOP_NODE" ] || { echo "hop node absent (persona down?)" >&2; exit 4; }
	echo "start $dwell $*" > "$HOP_NODE" || exit 5
	echo "hopping: $* @${dwell}ms"
}

scan()
{
	secs=${1:-30}
	tp=/data/data/com.termux/files/usr
	tp_home=/data/data/com.termux/files/home
	[ -x "$tp/bin/airodump-ng" ] || { echo "airodump-ng not in termux" >&2; exit 6; }
	out=/data/local/tmp/mon-scan-$(_date_tag)
	mkdir -p "$out"
	echo "writing $out (csv/cap), ${secs}s"
	env LD_LIBRARY_PATH="$tp/lib" HOME="$tp_home" TERM=xterm-256color \
		TERMINFO="$tp/share/terminfo" PATH="$tp/bin:/system/bin" \
		timeout "$secs" airodump-ng wlan0 -w "$out/scan" \
		>/dev/null 2>"$out/stderr.log" || true
	[ -s "$out/scan-01.csv" ] && head -20 "$out/scan-01.csv" ||
		echo "no csv produced (see $out/stderr.log)"
}

_date_tag()
{
	date +%Y%m%dT%H%M%S
}

need_root
case ${1:-} in
up) up ;;
down) down ;;
status) status ;;
freq) shift; freq "$@" ;;
hop2g|hop5g|hop6g) hop_start "$1" "${2:-}" ;;
hopstop) echo stop > "$HOP_NODE" 2>/dev/null && echo stopped ;;
scan) scan "${2:-}" ;;
*)
	echo "usage: mon up|down|status|freq <mhz> [width]|hop2g|hop5g|hop6g [dwell]|hopstop|scan [secs]" >&2
	exit 2 ;;
esac
