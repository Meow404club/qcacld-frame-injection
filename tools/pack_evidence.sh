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
wt=
out=

while [ $# -gt 0 ]; do
	case $1 in
	--working-tree) wt=$2; shift 2 ;;
	--out) out=$2; shift 2 ;;
	*) echo "usage: pack_evidence.sh --working-tree DIR [--out DIR]" >&2; exit 2 ;;
	esac
done
: "${wt:?--working-tree DIR is required (the wlan tree holding tmp/)}"
out=${out:-$repo/evidence-pack-$(date -u +%Y%m%dT%H%M%SZ)}
case "$out/" in "$wt/"*|"$(cd -- "$repo" && pwd)/"*) echo "refusing: --out inside the working tree" >&2; exit 2 ;; esac

mkdir -p "$out/capabilities" "$out/runs" "$out/external" "$out/suites" || exit 3

echo "== capability snapshots (latest per suite run)"
find "$wt/tmp/suites" -name capabilities.txt -newer "$wt/tmp/README.md" 2>/dev/null | head -0
latest_cap=$(ls -t "$wt"/tmp/suites/*/host-capture-*/capabilities.txt 2>/dev/null | head -1)
[ -n "$latest_cap" ] && cp "$latest_cap" "$out/capabilities/latest-device-round.txt"
echo "capability snapshot: ${latest_cap:-none found}"

echo "== run inventory"
{
	echo "# evidence-dir build-id-hint verdict-files"
	for d in "$wt/tmp/suites"/*/host-capture-*; do
		[ -d "$d" ] || continue
		bid=$(grep -h -m1 '^source_rev=' "$d"/stats-*.txt 2>/dev/null | head -1 | cut -d= -f2-)
		echo "$(basename "$d")	${bid:-unknown}	$(ls "$d" | wc -l) files"
	done
}
for d in "$repo"/*/host-capture-* "$repo"/archives/*/host-capture-*; do
	[ -d "$d" ] || continue
	bid=$(grep -h -m1 '^source_rev=' "$d"/stats-*.txt 2>/dev/null | head -1 | cut -d= -f2-)
	echo "repo:$(basename "$(dirname "$d")")/$(basename "$d")	${bid:-unknown}	$(ls "$d" | wc -l) files"
done >>"$out/runs/inventory.tsv"

echo "== external OTA archives"
find "$wt/tmp/returns" -name "*.zip" -size -200M 2>/dev/null | while read -r z; do
	rel=$(basename "$(dirname "$z")")-$(basename "$z")
	cp "$z" "$out/external/$rel"
	echo "archived: $rel"
done

echo "== suite inventory (this repo)"
git -C "$repo" ls-files >"$out/suites/repo-files.txt"
git -C "$repo" log --oneline >"$out/suites/repo-history.txt"

echo "== manifest"
( cd "$out" && find . -type f ! -name SHA256SUMS -print0 |
	xargs -0 sha256sum > /tmp/pack-sums.$$ && mv /tmp/pack-sums.$$ SHA256SUMS )
echo "EVIDENCE_PACK=$out ($(find "$out" -type f | wc -l) files)"
sha256sum "$out/SHA256SUMS"
