#!/system/bin/sh
# mon-keepawake - keep the device awake for a monitor session.
# Suspend mid-session kills persona state and complicates evidence;
# enable before long captures, disable after.
# usage: mon-keepawake on|off
set -u
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
case ${1:-} in
on)
	svc power stayon true
	# hold the screen off but CPU awake: settings stay persistent
	settings put global wifi_sleep_policy 2 >/dev/null 2>&1 || true
	echo "keepawake on (svc power stayon true; disable with 'off')"
	;;
off)
	svc power stayon false
	echo "keepawake off"
	;;
*) echo "usage: mon-keepawake on|off" >&2; exit 2 ;;
esac
