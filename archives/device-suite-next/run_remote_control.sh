#!/system/bin/sh

set -u

valid_pidfile()
{
	case "$1" in
		/data/local/tmp/qcacld-*/*.pid) return 0 ;;
		*) return 1 ;;
	esac
}

load_identity()
{
	identity_file=$1
	[ -f "$identity_file" ] || return 1
	[ "$(grep -c '^boot_id=' "$identity_file")" -eq 1 ] &&
	[ "$(grep -c '^pid=' "$identity_file")" -eq 1 ] &&
	[ "$(grep -c '^starttime=' "$identity_file")" -eq 1 ] &&
	[ "$(grep -c '^pgid=' "$identity_file")" -eq 1 ] &&
	[ "$(grep -c '^sid=' "$identity_file")" -eq 1 ] &&
	[ "$(grep -c '^command=' "$identity_file")" -eq 1 ] &&
	[ "$(awk 'END { print NR + 0 }' "$identity_file")" -eq 6 ] || return 1
	identity_boot=$(sed -n 's/^boot_id=//p' "$identity_file")
	identity_pid=$(sed -n 's/^pid=//p' "$identity_file")
	identity_starttime=$(sed -n 's/^starttime=//p' "$identity_file")
	identity_pgid=$(sed -n 's/^pgid=//p' "$identity_file")
	identity_sid=$(sed -n 's/^sid=//p' "$identity_file")
	identity_command=$(sed -n 's/^command=//p' "$identity_file")
	case "$identity_boot" in
		''|*[!0-9a-fA-F-]*) return 1 ;;
	esac
	for identity_number in "$identity_pid" "$identity_starttime" \
		"$identity_pgid" "$identity_sid"; do
		case "$identity_number" in
			''|*[!0-9]*) return 1 ;;
		esac
	done
	[ "$identity_pid" = "$identity_pgid" ] &&
	[ "$identity_pid" = "$identity_sid" ] || return 1
	case "$identity_command" in
		''|*[!A-Za-z0-9._-]*) return 1 ;;
	esac
	return 0
}

read_proc_identity()
{
	proc_identity_pid=$1
	proc_stat=$(cat "/proc/$proc_identity_pid/stat" 2>/dev/null) || return 1
	proc_pid=$(printf '%s\n' "$proc_stat" | awk '{ print $1 }')
	proc_pgid=$(printf '%s\n' "$proc_stat" | awk '{ print $5 }')
	proc_sid=$(printf '%s\n' "$proc_stat" | awk '{ print $6 }')
	proc_starttime=$(printf '%s\n' "$proc_stat" | awk '{ print $22 }')
	for proc_number in "$proc_pid" "$proc_pgid" "$proc_sid" \
		"$proc_starttime"; do
		case "$proc_number" in
			''|*[!0-9]*) return 1 ;;
		esac
	done
	return 0
}

stop_group()
{
	pidfile=$1
	expected=$2
	valid_pidfile "$pidfile" || return 2
	case "$expected" in
		''|*[!A-Za-z0-9._-]*) return 2 ;;
	esac
	pid=$(cat "$pidfile" 2>/dev/null)
	case "$pid" in
		''|*[!0-9]*) rm -f "$pidfile"; return 0 ;;
	esac
	commandfile=${pidfile%.pid}.command
	identityfile=${pidfile%.pid}.identity
	command_path=$(cat "$commandfile" 2>/dev/null)
	command_name=${command_path##*/}
	[ "$command_name" = "$expected" ] || {
		echo "process identity mismatch: expected=$expected actual=$command_name" >&2
		return 9
	}
	load_identity "$identityfile" || {
		echo "missing or invalid process identity: $identityfile" >&2
		return 9
	}
	[ "$identity_pid" = "$pid" ] && [ "$identity_command" = "$expected" ] || {
		echo "sidecar identity mismatch for pid=$pid" >&2
		return 9
	}
	current_boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
	if [ "$identity_boot" != "$current_boot" ]; then
		printf 'pid=%s recorded_boot=%s current_boot=%s stale_boot=1 no_signal=1\n' \
			"$pid" "$identity_boot" "${current_boot:-unavailable}"
		rm -f "$pidfile"
		return 0
	fi
	if [ -e "/proc/$pid/stat" ]; then
		if ! read_proc_identity "$pid" ||
		   [ "$proc_pid" != "$identity_pid" ] ||
		   [ "$proc_pgid" != "$identity_pgid" ] ||
		   [ "$proc_sid" != "$identity_sid" ] ||
		   [ "$proc_starttime" != "$identity_starttime" ]; then
			printf 'pid=%s identity_changed=1 no_signal=1\n' "$pid"
			rm -f "$pidfile"
			return 0
		fi
	fi
	if ! kill -0 -"$pid" 2>/dev/null; then
		rm -f "$pidfile"
		return 0
	fi
	printf 'pid=%s command=%s boot_id=%s starttime=%s pgid=%s sid=%s\n' \
		"$pid" "$command_name" "$identity_boot" "$identity_starttime" \
		"$identity_pgid" "$identity_sid"
	kill -TERM -"$pid" 2>/dev/null || return 10
	i=0
	while kill -0 -"$pid" 2>/dev/null; do
		i=$((i + 1))
		[ "$i" -lt 10 ] || break
		sleep 1
	done
	if kill -0 -"$pid" 2>/dev/null; then
		kill -KILL -"$pid" 2>/dev/null || return 11
		i=0
		while kill -0 -"$pid" 2>/dev/null; do
			i=$((i + 1))
			[ "$i" -lt 10 ] || break
			sleep 1
		done
	fi
	kill -0 -"$pid" 2>/dev/null && return 12
	rm -f "$pidfile" || return 13
	echo "pid=$pid group_stopped=1"
}

gate_off()
{
	node=/sys/module/qca_cld3_peach_v2/parameters/frame_inject_force_raw
	write_rc=0
	value=unavailable
	if [ -e "$node" ]; then
		printf '0\n' >"$node" || write_rc=$?
		value=$(tr -d ' \r\n' <"$node")
	else
		write_rc=2
	fi
	printf 'force_raw=%s\n' "$value"
	[ "$write_rc" -eq 0 ] && ([ "$value" = N ] || [ "$value" = 0 ])
}

setsid_probe_cleanup()
{
	cleanup_launcher=$1
	cleanup_pidfile=$2
	if [ -s "$cleanup_pidfile" ]; then
		stop_group "$cleanup_pidfile" sleep >/dev/null 2>&1 || true
	fi
	if kill -0 "$cleanup_launcher" 2>/dev/null; then
		kill -TERM -"$cleanup_launcher" 2>/dev/null ||
			kill -TERM "$cleanup_launcher" 2>/dev/null || true
		cleanup_i=0
		while kill -0 "$cleanup_launcher" 2>/dev/null; do
			cleanup_i=$((cleanup_i + 1))
			[ "$cleanup_i" -lt 5 ] || break
			sleep 1
		done
		kill -KILL -"$cleanup_launcher" 2>/dev/null ||
			kill -KILL "$cleanup_launcher" 2>/dev/null || true
	fi
	wait "$cleanup_launcher" 2>/dev/null || true
}

setsid_probe()
{
	runner=$1
	pidfile=$2
	case "$runner" in
		/data/local/tmp/qcacld-*/run_remote_group.sh) ;;
		*) return 2 ;;
	esac
	valid_pidfile "$pidfile" || return 2
	command -v setsid >/dev/null 2>&1 || return 3
	"$runner" "$pidfile" sleep 30 &
	launcher=$!
	probe_rc=0
	i=0
	while [ ! -s "$pidfile" ]; do
		i=$((i + 1))
		if [ "$i" -ge 10 ]; then
			probe_rc=4
			break
		fi
		sleep 1
	done
	if [ "$probe_rc" -eq 0 ]; then
		pid=$(cat "$pidfile" 2>/dev/null) || probe_rc=5
	fi
	if [ "$probe_rc" -eq 0 ]; then
		identityfile=${pidfile%.pid}.identity
		load_identity "$identityfile" || probe_rc=5
	fi
	if [ "$probe_rc" -eq 0 ] && [ "$identity_pid" != "$pid" ]; then
		probe_rc=5
	fi
	if [ "$probe_rc" -eq 0 ]; then
		current_boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
		[ "$identity_boot" = "$current_boot" ] || probe_rc=5
	fi
	if [ "$probe_rc" -eq 0 ]; then
		read_proc_identity "$pid" || probe_rc=5
	fi
	if [ "$probe_rc" -eq 0 ] &&
		{ [ "$proc_pid" != "$identity_pid" ] ||
		  [ "$proc_pgid" != "$identity_pgid" ] ||
		  [ "$proc_sid" != "$identity_sid" ] ||
		  [ "$proc_starttime" != "$identity_starttime" ]; }; then
		probe_rc=5
	fi
	if [ "$probe_rc" -eq 0 ] && ! kill -0 -"$pid" 2>/dev/null; then
		probe_rc=6
	fi
	if [ "$probe_rc" -eq 0 ] &&
		! stop_group "$pidfile" sleep; then
		probe_rc=7
	fi
	setsid_probe_cleanup "$launcher" "$pidfile"
	return "$probe_rc"
}

read_rc()
{
	case "$1" in
		/data/local/tmp/qcacld-*/*.rc) ;;
		*) return 2 ;;
	esac
	rcfile=$1
	identityfile=${rcfile%.rc}.identity
	load_identity "$identityfile" || return 3
	current_boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
	[ "$identity_boot" = "$current_boot" ] || return 5
	value=$(cat "$rcfile" 2>/dev/null) || return 3
	case "$value" in
		''|*[!0-9]*) return 4 ;;
	esac
	[ "$value" -le 255 ] || return 4
	printf '%s\n' "$value"
}

[ "$#" -ge 1 ] || exit 2
action=$1
shift
case "$action" in
	stop) [ "$#" -eq 2 ] || exit 2; stop_group "$1" "$2" ;;
	gate-off) [ "$#" -eq 0 ] || exit 2; gate_off ;;
	setsid-probe) [ "$#" -eq 2 ] || exit 2; setsid_probe "$1" "$2" ;;
	read-rc) [ "$#" -eq 1 ] || exit 2; read_rc "$1" ;;
	*) echo "unknown remote control action: $action" >&2; exit 2 ;;
esac
