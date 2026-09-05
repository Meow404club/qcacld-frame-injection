#!/usr/bin/env bash

set -euo pipefail

dir=$(cd -- "$(dirname -- "$0")" && pwd)
tmp_dir=$(mktemp -d)
trap 'rm -rf -- "$tmp_dir"' EXIT
cc -O2 -Wall -Wextra -Werror -o "$tmp_dir/sender" "$dir/send_stage1_once.c"
"$tmp_dir/sender" --selftest |
	grep -qx 'selftest_passed=3 variants=probe,data,cts'
bash -n "$dir/run_stage1_host.sh"
sh -n "$dir/run_stage1_device.sh"
grep -qx 'suite_frozen=1' "$dir/run_stage1_host.sh"
grep -qx 'suite_frozen=1' "$dir/run_stage1_device.sh"
grep -q -- '--two-round-continuity' "$dir/run_stage1_device.sh"
grep -q 'capture_window beacon-before' "$dir/run_stage1_device.sh"
grep -q 'capture_window beacon-between' "$dir/run_stage1_device.sh"
grep -q 'capture_window beacon-after' "$dir/run_stage1_device.sh"
grep -q 'send_one probe 801 round1-probe' "$dir/run_stage1_device.sh"
grep -q 'send_one data 812 round2-data' "$dir/run_stage1_device.sh"
grep -q 'send_one cts 813 round2-cts' "$dir/run_stage1_device.sh"
! grep -Eq 'deauth|disassoc|frame_inject_force_control_wmi' \
	"$dir/run_stage1_device.sh" "$dir/run_stage1_host.sh"
echo 'stage1_host_selftest=PASS vectors=6 beacon_windows=3 same_persona=1'
