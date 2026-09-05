#!/usr/bin/env bash

# Host fuzz for the frame-inject radiotap/MPDU parser (todo 4.4 corpus item).
#
# 1. Builds seed_oracle (plain) and replays the frozen stage-1 manifest:
#    every case's parse errno must match the recorded kernel behavior.
# 2. Builds fuzz_harness with -fsanitize=fuzzer,address,undefined against the
#    SAME production parser source and runs libFuzzer seeded with every
#    manifest packet_hex.
#
# The production file is compiled unmodified; only kernel headers are shimmed
# (linux_shim/, extracted from the shipping kernel tree).

set -uo pipefail

fuzz_seconds=${FUZZ_SECONDS:-60}
keep_corpus=${KEEP_CORPUS:-0}

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
wlan_root=$(cd -- "$script_dir/../../.." && pwd)
parser_src="$wlan_root/qcacld-3.0/core/hdd/src/wlan_hdd_frame_inject_radiotap.c"
inc_dir="$wlan_root/qcacld-3.0/core/hdd/inc"
manifest="$wlan_root/tmp/suites/device-suite-wmi-stage1-matrix/stage1-cases.jsonl"
out_dir="$script_dir/out"
cc=${CC:-clang}

[ -r "$parser_src" ] && [ -r "$manifest" ] || { echo "missing parser or manifest" >&2; exit 3; }
command -v "$cc" >/dev/null || cc=gcc

mkdir -p "$out_dir"

echo "== seed oracle"
"$cc" -std=gnu11 -O2 -Wall -Wextra -Wno-sign-compare -Wno-address-of-packed-member -Werror -DFEATURE_FRAME_INJECTION -I"$script_dir/linux_shim" -I"$inc_dir" \
	-o "$out_dir/seed_oracle" "$script_dir/seed_oracle.c" "$parser_src" || exit 4
"$out_dir/seed_oracle" "$manifest" | tee "$out_dir/seed-oracle.log"
expected_oracle=$(python3 -c '
import json, sys
n = 0
for line in open(sys.argv[1]):
    c = json.loads(line)
    if isinstance(c.get("current_parser_errno"), int):
        n += 1
print(n)' "$manifest")
grep -qx "seed_oracle_cases=$expected_oracle mismatches=0" \
	"$out_dir/seed-oracle.log" || { echo "seed oracle mismatch" >&2; exit 5; }

echo "== corpus extraction"
corpus_dir="$out_dir/corpus"
rm -rf "$corpus_dir"
mkdir -p "$corpus_dir"
python3 - "$manifest" "$corpus_dir" <<'EOF'
import binascii, json, sys
cases = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
for i, c in enumerate(cases):
    data = binascii.unhexlify(c["packet_hex"])
    with open(f"{sys.argv[2]}/{i:05d}.bin", "wb") as f:
        f.write(data)
print(f"corpus_files={len(cases)}")
EOF
[ "$(ls "$corpus_dir" | wc -l)" -ge 700 ] || { echo "corpus too small" >&2; exit 6; }

echo "== libFuzzer (${fuzz_seconds}s)"
"$cc" -std=gnu11 -O2 -Wall -Wextra -Wno-sign-compare -Wno-address-of-packed-member -Werror \
	-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
	-DFEATURE_FRAME_INJECTION -I"$script_dir/linux_shim" -I"$inc_dir" \
	-o "$out_dir/fuzz_harness" "$script_dir/fuzz_harness.c" "$parser_src" || exit 7
"$out_dir/fuzz_harness" -max_total_time="$fuzz_seconds" -rss_limit_mb=4096 \
	-artifact_prefix="$out_dir/crash-" "$corpus_dir" \
	>"$out_dir/fuzz.log" 2>&1
fuzz_rc=$?
tail -n 6 "$out_dir/fuzz.log"
if ls "$out_dir"/crash-* >/dev/null 2>&1; then
	echo "FUZZ_CRASH_ARTIFACTS_PRESENT" >&2
	exit 8
fi
[ "$fuzz_rc" -eq 0 ] || { echo "fuzzer exit $fuzz_rc" >&2; exit 9; }

if [ "$keep_corpus" != 1 ]; then
	rm -rf "$corpus_dir"
fi
echo "verdict=FUZZ_OK seconds=$fuzz_seconds"
