#!/system/bin/sh

set -u

[ "$#" -ge 2 ] || {
	echo "usage: $0 <pidfile> <command> [args...]" >&2
	exit 2
}

pidfile=$1
shift
case "$pidfile" in
	/data/local/tmp/qcacld-*/*.pid) ;;
	*) echo "invalid remote group pidfile: $pidfile" >&2; exit 2 ;;
esac
rcfile=${pidfile%.pid}.rc
commandfile=${pidfile%.pid}.command
identityfile=${pidfile%.pid}.identity
rm -f "$rcfile" "$commandfile" "$identityfile" "$pidfile"

exec setsid sh -c '
	pidfile=$1
	rcfile=$2
	commandfile=$3
	identityfile=$4
	shift 4
	command_path=$1
	command_name=${command_path##*/}
	write_atomic()
	{
		write_path=$1
		write_value=$2
		write_tmp=${write_path}.tmp.$$
		printf "%s\n" "$write_value" >"$write_tmp" || return 1
		mv "$write_tmp" "$write_path"
	}
	finish()
	{
		finish_rc=$?
		trap - EXIT HUP INT TERM
		write_atomic "$rcfile" "$finish_rc" || true
		exit "$finish_rc"
	}
	trap finish EXIT
	trap "exit 129" HUP
	trap "exit 130" INT
	trap "exit 143" TERM
	boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null) || exit 3
	stat_line=$(cat "/proc/$$/stat" 2>/dev/null) || exit 3
	stat_pid=$(printf "%s\n" "$stat_line" | awk "{ print \$1 }")
	stat_pgid=$(printf "%s\n" "$stat_line" | awk "{ print \$5 }")
	stat_sid=$(printf "%s\n" "$stat_line" | awk "{ print \$6 }")
	stat_starttime=$(printf "%s\n" "$stat_line" | awk "{ print \$22 }")
	[ "$stat_pid" = "$$" ] && [ "$stat_pgid" = "$$" ] &&
		[ "$stat_sid" = "$$" ] || exit 3
	identity_value="boot_id=$boot_id
pid=$$
starttime=$stat_starttime
pgid=$stat_pgid
sid=$stat_sid
command=$command_name"
	write_atomic "$commandfile" "$command_path" || exit 3
	write_atomic "$identityfile" "$identity_value" || exit 3
	write_atomic "$pidfile" "$$" || exit 3
	"$@"
	exit $?
' sh "$pidfile" "$rcfile" "$commandfile" "$identityfile" "$@"
