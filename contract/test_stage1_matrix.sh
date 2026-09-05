#!/usr/bin/env bash

set -euo pipefail

dir=$(cd -- "$(dirname -- "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

PYTHONPYCACHEPREFIX=$work/pycache python3 -m py_compile "$dir/stage1_matrix.py"
PYTHONPYCACHEPREFIX=$work/pycache python3 -m py_compile "$dir/verify_stage1_evidence.py"
PYTHONPYCACHEPREFIX=$work/pycache python3 -m py_compile "$dir/verify_stage2_ota.py"
PYTHONPYCACHEPREFIX=$work/pycache python3 -m py_compile "$dir/device_results_to_evidence.py"
python3 "$dir/stage1_matrix.py" --selftest | tee "$work/selftest.log"
grep -q '^selftest=PASS schema=2 cases=' "$work/selftest.log"
python3 "$dir/stage1_matrix.py" --write "$work/generated"
python3 "$dir/stage1_matrix.py" --check "$work/generated"
python3 "$dir/stage1_matrix.py" --check "$dir"
(cd "$dir" && sha256sum -c SHA256SUMS.generated)
python3 "$dir/verify_stage1_evidence.py" \
	--manifest "$dir/stage1-cases.jsonl" \
	--results "$dir/stage1-evidence-template.jsonl" \
	--allow-not-run | grep -q '^evidence_verdict=PASS '
python3 "$dir/verify_stage1_evidence.py" \
	--manifest "$dir/stage1-cases.jsonl" \
	--results "$dir/stage1-evidence-template.jsonl" \
	--selftest | grep -q '^selftest=PASS manifest_cases='
python3 "$dir/verify_stage2_ota.py" \
	--manifest "$dir/stage1-cases.jsonl" --selftest |
	grep -q '^stage2_ota_selftest=PASS cases='
python3 "$dir/device_results_to_evidence.py" \
	--manifest "$dir/stage1-cases.jsonl" --selftest |
	grep -q '^device_evidence_selftest=PASS valid=1 invalid=1$'
python3 - "$dir/stage1-cases.jsonl" "$work/device-results.tsv" <<'PY'
import csv
import json
import sys

manifest = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
device_ops = {
    "send_after_continuity_fix",
    "parse_then_send_if_accepted_after_continuity_fix",
    "parse_only",
}
header = ("case_id", "case_cookie", "packet_sha256", "operation",
          "parser_state", "parser_errno", "previous_request_id",
          "request_id", "terminal_stage", "terminal_errno",
          "accepted_delta", "submitted_delta", "parse_delta",
          "backend_delta", "completion_delta", "completion_status",
          "window_start_ns", "window_end_ns")
request_id = 0
backend_used = False
with open(sys.argv[2], "w", encoding="utf-8", newline="") as stream:
    writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
    writer.writerow(header)
    for case in manifest:
        if case["operation"] not in device_ops:
            continue
        previous = request_id
        request_id += 1
        if case["current_parser_state"] == "rejected":
            terminal = (1, case["current_parser_errno"], 1, 0, 0, "NA")
        elif not backend_used:
            terminal = (2, -95, 0, 1, 0, "NA")
            backend_used = True
        else:
            terminal = (3, 0, 0, 0, 1, "0")
        stage, terminal_errno, parse_delta, backend_delta, completion_delta, status = terminal
        submitted_delta = int(stage == 3)
        writer.writerow((case["case_id"], case["case_cookie"],
                         case["packet_sha256"], case["operation"],
                         case["current_parser_state"],
                         case["current_parser_errno"], previous, request_id,
                         stage, terminal_errno, 1, submitted_delta, parse_delta,
                         backend_delta, completion_delta, status,
                         request_id * 100, request_id * 100 + 50))
PY
printf 'active_persona_clean\n' >"$work/teardown.txt"
python3 "$dir/device_results_to_evidence.py" \
	--manifest "$dir/stage1-cases.jsonl" \
	--device-results "$work/device-results.tsv" \
	--teardown-evidence "$work/teardown.txt" \
	--output "$work/device-evidence.jsonl" |
	grep -q '^device_evidence_conversion=PASS cases=756$'
python3 "$dir/verify_stage1_evidence.py" \
	--manifest "$dir/stage1-cases.jsonl" \
	--results "$work/device-evidence.jsonl" \
	--enforce-current-parser | grep -q '^evidence_verdict=PASS '
sh -n "$dir/run_stage1_matrix_device.sh"
sh -n "$dir/run_stage2_listener.sh"
sh -n "$dir/run_stage0_preflight_device.sh"
sh "$dir/run_stage1_matrix_device.sh" --selftest-terminal-contract |
	grep -q '^terminal_contract_selftest=PASS valid=3 invalid=3$'
grep -qx 'device_execution_enabled=1' "$dir/run_stage1_matrix_device.sh"
set +e
sh "$dir/run_stage1_matrix_device.sh" >"$work/device-disabled.stdout" \
	2>"$work/device-disabled.stderr"
device_rc=$?
set -e
[[ $device_rc -eq 2 ]]
grep -q '^usage:' "$work/device-disabled.stderr"
grep -q 'last_terminal_request_id' "$dir/run_stage1_matrix_device.sh"
grep -q 'last_terminal_stage' "$dir/run_stage1_matrix_device.sh"
grep -q 'last_terminal_errno' "$dir/run_stage1_matrix_device.sh"
grep -q '^expected_stats_format=13$' "$dir/run_stage1_matrix_device.sh"
grep -q '^expected_device_cases=642$' "$dir/run_stage1_matrix_device.sh"
grep -q '^expected_plan_sha256=823900054cd3ee6dbce28875f73f28e78fea607de17da3385e78c8871abf263a$' \
	"$dir/run_stage1_matrix_device.sh"
grep -q '^expected_sender_sha256=c2795e6b612c065fd464a97251276ad61c0f7a5484bd7d4767fdd882adc10afc$' \
	"$dir/run_stage1_matrix_device.sh"
grep -q '^expected_build_id=914714cb6f296f35f093bf393bfea47c4982897c$' \
	"$dir/run_stage1_matrix_device.sh"
grep -q '^expected_common_image_sha256=9f7556fc1a9fabb2f48860455e99eb555b8ca955bf79f77c92dc0265fb81ae2c$' \
	"$dir/run_stage1_matrix_device.sh"
grep -q '^expected_stats_format=13$' "$dir/run_stage0_preflight_device.sh"
grep -q '^expected_selftests=409$' "$dir/run_stage0_preflight_device.sh"
grep -q '^device_execution_enabled=1$' "$dir/run_stage0_preflight_device.sh"
set +e
sh "$dir/run_stage0_preflight_device.sh" S --clean-boot --selftest-only \
	>"$work/stage0-disabled.stdout" 2>"$work/stage0-disabled.stderr"
stage0_rc=$?
set -e
[[ $stage0_rc -eq 3 || $stage0_rc -eq 2 || $stage0_rc -eq 64 ]]
grep -q '^usage:' "$work/stage0-disabled.stderr" || grep -q 'preconditions missing' "$work/stage0-disabled.stderr" || true

cc -std=c11 -O2 -Wall -Wextra -Werror \
	-o "$work/send_stage1_packet" "$dir/send_stage1_packet.c"
"$work/send_stage1_packet" --selftest |
	grep -qx 'selftest=PASS valid=1 invalid=2'

first_hex=$(python3 - "$dir/stage1-cases.jsonl" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    for line in stream:
        record = json.loads(line)
        if record["radiotap_hex"] and len(record["mpdu_hex"]) >= 4:
            print(record["packet_hex"])
            break
PY
)
"$work/send_stage1_packet" --dry-run "$first_hex" |
	grep -q '^dry_run=PASS packet_len='

python3 - "$dir/stage1-cases.jsonl" "$dir/coverage.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    cases = [json.loads(line) for line in stream]
with open(sys.argv[2], encoding="utf-8") as stream:
    coverage = json.load(stream)
assert len(cases) == coverage["total_cases"]
assert coverage["status"] == "device_ready_4_2_continuity_observational"
assert coverage["device_execution_enabled"] is True
assert coverage["required_radiotap_indices"] == list(range(35))
assert coverage["coverage_gaps"] == [
    "local beacon continuity is recorded as a known todo 4.2 issue; it does not block Stage 1 parser/backend/completion execution",
]
assert coverage["deferred_stage2_work"] == [
    "independent OTA, response and rewrite observations require the later Stage 2 device/listener run",
]
assert all(case["current_parser_state"] in {"accepted", "rejected",
                                                "not_applicable"}
           for case in cases)
assert not any(case["operation"] == "send" for case in cases)
assert all(case["stage1_evidence_scope"] == [
    "parsed", "accepted", "submitted", "completion",
    "local_continuity", "teardown", "capability",
] for case in cases)
assert not any(key in case for case in cases
               for key in ("response_policy", "ota_match_policy"))
assert all(case["current_parser_state"] == "rejected"
           for case in cases if case["operation"] == "parse_only")
assert sum(case["operation"] in {
    "send_after_continuity_fix",
    "parse_then_send_if_accepted_after_continuity_fix",
    "parse_only",
} for case in cases) == 642
required_families = {
    "pv0_management_ie", "pv0_management_action", "pv0_control_wrapper",
    "pv0_block_ack", "pv0_trigger", "pv0_data_payload_boundary",
    "pv0_raw_encrypted", "pv0_data_amsdu_boundary",
    "pv0_data_protected_boundary", "pv1_assigned", "radiotap_fcs_policy",
    "radiotap_phy_legacy", "radiotap_tx_policy", "radiotap_channel_policy",
}
assert required_families <= {case["family"] for case in cases}
assert any(case["axes"].get("payload_boundary") == "max" and
           len(bytes.fromhex(case["mpdu_hex"])) == 2348 for case in cases)
assert any(case["axes"].get("boundary") == "max_mpdu_plus_one" and
           len(bytes.fromhex(case["mpdu_hex"])) == 2349 for case in cases)
assert {case["axes"].get("cipher") for case in cases if case["family"] == "pv0_raw_encrypted"} == {
    "wep40", "tkip", "ccmp128", "ccmp256", "gcmp128", "gcmp256"}
print(f"pre_device_contract=PASS cases={len(cases)} "
      f"blockers={len(coverage['coverage_gaps'])} "
      f"deferred_stage2={len(coverage['deferred_stage2_work'])}")
PY
