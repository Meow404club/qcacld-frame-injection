#!/bin/bash
# pack_evidence.sh - assemble the final evidence package.
#
# Collects: the capability matrix (capabilities node output from the
# latest round), the evidence-directory inventory (every host-capture
# run with its pinned build id where recorded), the external OTA
# archives (volunteer return bundles), and the suite inventory - into
# one sealed directory with a SHA256SUMS manifest.
#
# usage: pack_evidence.sh [--working-tree DIR] [--out DIR]
#   --working-tree  the project working tree holding tmp/ evidence
#                   (default: the kernel tree this repo lives in)
set -u
here=$(cd -- "$(dirname -- "$0")" && pwd)
repo=$(cd -- "$here/.." && pwd)
wt=$(cd -- "$repo/../.." && pwd)   # vendor/qcom/opensource/wlan by default
wt=$(cd -- "$wt/../.." && pwd)     # kernel tree root
out=${2:-$repo/evidence-pack-$(date -u +%Y%m%dT%H%M%SZ)}

while [ $# -gt 0 ]; do
	case $1 in
	--working-tree) wt=$2; shift 2 ;;
	--out) out=$2; shift 2 ;;
	*) echo "usage: pack_evidence.sh [--working-tree DIR] [--out DIR]" >&2; exit 2 ;;
	esac
done

mkdir -p "$out/capabilities" "$out/runs" "$out/external" "$out/suites" || exit 3

echo "== capability snapshots (latest per suite run)"
find "$wt/tmp/suites" -name capabilities.txt -newer "$wt/tmp/README.md" 2>/dev/null | head -0
latest_cap=$(ls -t "$wt/tmp/suites"/d-wave/host-capture-*/capabilities.txt 2>/dev/null | head -1)
[ -n "$latest_cap" ] && cp "$latest_cap" "$out/capabilities/latest-device-round.txt"

echo "== run inventory"
{
	echo "# evidence-dir build-id-hint verdict-files"
	for d in "$wt/tmp/suites"/*/host-capture-*; do
		[ -d "$d" ] || continue
		bid=$(grep -l . "$d"/stats-before.txt 2>/dev/null | head -1 | xargs -r awk -F= '/^source_rev=/{print $2; exit}' 2>/dev/null)
		echo "$(basename "$d")	${bid:-unknown}	$(ls "$d" | wc -l) files"
	done
} >"$out/runs/inventory.tsv"

echo "== external OTA archives"
for z in "$wt"/tmp/returns/*/; do
	[ -d "$z" ] || continue
	name=$(basename "$z")
	find "$z" -maxdepth 1 -name "*.zip" -exec cp {} "$out/external/$name-{}" \; 2>/dev/null
done

echo "== suite inventory (this repo)"
git -C "$repo" ls-files >"$out/suites/repo-files.txt"
git -C "$repo" log --oneline >"$out/suites/repo-history.txt"

echo "== manifest"
( cd "$out" && find . -type f ! -name SHA256SUMS -print0 |
	xargs -0 sha256sum > /tmp/pack-sums.$$ && mv /tmp/pack-sums.$$ SHA256SUMS )
echo "EVIDENCE_PACK=$out ($(find "$out" -type f | wc -l) files)"
sha256sum "$out/SHA256SUMS"
