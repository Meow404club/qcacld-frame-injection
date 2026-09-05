#!/system/bin/sh
# mon-sniff - parallel display + full-fidelity capture on the monitor
# persona: airodump-ng for live visibility (stdout to /dev/null - the
# ncurses redirect grows to hundreds of MB) while tcpdump writes a
# complete pcap of the same interface.
# usage: mon-sniff [seconds] (default 30)
set -u
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
secs=${1:-30}
tp=/data/data/com.termux/files/usr
tp_home=/data/data/com.termux/files/home
for b in airodump-ng tcpdump; do
	[ -x "$tp/bin/$b" ] || { echo "$b not in termux" >&2; exit 6; }
done
tag=$(date +%Y%m%dT%H%M%S)
out=/data/local/tmp/mon-sniff-$tag
mkdir -p "$out"
tenv="LD_LIBRARY_PATH=$tp/lib HOME=$tp_home TERM=xterm-256color TERMINFO=$tp/share/terminfo PATH=$tp/bin:/system/bin"

env $tenv tcpdump -i wlan0 -U -w "$out/full.pcap" >/dev/null 2>"$out/tcpdump.err" &
tpid=$!
sleep 1
env $tenv timeout "$secs" airodump-ng wlan0 -w "$out/airodump" \
	>/dev/null 2>"$out/airodump.err" || true
kill $tpid 2>/dev/null
wait $tpid 2>/dev/null
echo "capture: $out/full.pcap ($(stat -c%s "$out/full.pcap" 2>/dev/null || echo ?) bytes)"
[ -s "$out/airodump-01.csv" ] && echo "airodump csv: $out/airodump-01.csv"
[ -s "$out/tcpdump.err" ] && head -3 "$out/tcpdump.err"
