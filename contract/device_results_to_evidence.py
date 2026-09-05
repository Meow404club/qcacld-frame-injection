#!/usr/bin/env python3

"""Convert the Android TSV ledger into the strict Stage 1 evidence schema."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import pathlib
import sys
from typing import Any

SCHEMA_VERSION = 2
LAYERS = ("parsed", "accepted", "submitted", "completion", "ota",
          "response", "rewrite", "teardown", "capability")


def read_jsonl(path: pathlib.Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream]


def load_device_rows(path: pathlib.Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        expected = ["case_id", "case_cookie", "packet_sha256", "operation",
                    "parser_state", "parser_errno", "previous_request_id",
                    "request_id", "terminal_stage", "terminal_errno",
                    "accepted_delta", "submitted_delta", "parse_delta",
                    "backend_delta", "completion_delta",
                    "completion_status", "window_start_ns", "window_end_ns"]
        if reader.fieldnames != expected:
            raise ValueError("device TSV header mismatch")
        return list(reader)


def base_result(case: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema": SCHEMA_VERSION, "case_id": case["case_id"],
        "packet_sha256": case["packet_sha256"], "run_state": "complete",
    }
    for layer in LAYERS:
        result[layer] = {"state": "not_applicable"}
    return result


def convert(manifest_path: pathlib.Path, rows_path: pathlib.Path,
            teardown_path: pathlib.Path, output_path: pathlib.Path,
            *, require_all_device_rows: bool = True) -> int:
    manifest = {case["case_id"]: case for case in read_jsonl(manifest_path)}
    rows = load_device_rows(rows_path)
    teardown_sha = hashlib.sha256(teardown_path.read_bytes()).hexdigest()
    results = []
    seen = set()
    seen_request_ids: set[int] = set()
    last_request_id: int | None = None
    for row in rows:
        case_id = row["case_id"]
        if case_id in seen or case_id not in manifest:
            raise ValueError(f"unknown or duplicate case {case_id}")
        seen.add(case_id)
        case = manifest[case_id]
        if row["case_cookie"] != case["case_cookie"] or \
                row["packet_sha256"] != case["packet_sha256"] or \
                row["operation"] != case["operation"]:
            raise ValueError(f"{case_id}: device row identity mismatch")
        parser_errno = int(row["parser_errno"])
        previous_request_id = int(row["previous_request_id"])
        request_id = int(row["request_id"])
        terminal_stage = int(row["terminal_stage"])
        terminal_errno = int(row["terminal_errno"])
        deltas = tuple(int(row[name]) for name in
                       ("accepted_delta", "submitted_delta", "parse_delta",
                        "backend_delta", "completion_delta"))
        if request_id <= previous_request_id or request_id in seen_request_ids:
            raise ValueError(f"{case_id}: terminal request ID is stale or duplicate")
        if last_request_id is not None and previous_request_id != last_request_id:
            raise ValueError(f"{case_id}: terminal request chain is discontinuous")
        if row["parser_state"] != case["current_parser_state"] or \
                parser_errno != case["current_parser_errno"]:
            raise ValueError(f"{case_id}: parser result violates manifest")
        if deltas[0] != 1:
            raise ValueError(f"{case_id}: netdev acceptance is not exactly one")
        if terminal_stage == 1:
            expected_deltas = (1, 0, 1, 0, 0)
            if row["parser_state"] != "rejected" or terminal_errno >= 0:
                raise ValueError(f"{case_id}: invalid parser terminal ledger")
        elif terminal_stage == 2:
            expected_deltas = (1, 0, 0, 1, 0)
            if row["parser_state"] != "accepted" or terminal_errno >= 0:
                raise ValueError(f"{case_id}: invalid backend terminal ledger")
        elif terminal_stage == 3:
            expected_deltas = (1, 1, 0, 0, 1)
            if row["parser_state"] != "accepted" or terminal_errno != 0 or \
                    row["completion_status"] not in {"0", "1", "2", "3"}:
                raise ValueError(f"{case_id}: invalid completion terminal ledger")
        else:
            raise ValueError(f"{case_id}: unknown terminal stage {terminal_stage}")
        if deltas != expected_deltas:
            raise ValueError(f"{case_id}: terminal counters are not mutually exclusive")
        seen_request_ids.add(request_id)
        last_request_id = request_id
        result = base_result(case)
        result["parsed"] = {"state": row["parser_state"],
                            "errno": parser_errno}
        result["accepted"] = {"state": "accepted"}
        if row["parser_state"] == "rejected":
            result["submitted"] = {"state": "not_submitted"}
            result["capability"] = {"state": "precise_unsupported",
                                    "reason": f"parser_errno_{parser_errno}"}
            result["teardown"] = {"state": "clean",
                                  "evidence_sha256": teardown_sha}
        elif row["completion_status"] == "NA":
            result["submitted"] = {"state": "not_submitted"}
            result["capability"] = {"state": "precise_unsupported",
                                    "reason": "backend_rejected_before_submit"}
            result["teardown"] = {"state": "clean",
                                  "evidence_sha256": teardown_sha}
        else:
            result["submitted"] = {
                "state": "submitted", "request_id": request_id,
                "capture_window_wallclock_ns": [int(row["window_start_ns"]),
                                                 int(row["window_end_ns"])],
            }
            result["completion"] = {"state": "completed",
                                    "status": int(row["completion_status"])}
            # Stage 1 has no independent listener. OTA, response and rewrite
            # are deliberately outside its authority and remain Stage 2 work.
            result["ota"] = {"state": "not_applicable"}
            result["response"] = {"state": "not_applicable"}
            result["rewrite"] = {"state": "not_applicable"}
            result["teardown"] = {"state": "clean",
                                  "evidence_sha256": teardown_sha}
            result["capability"] = {"state": "unproven"}
        results.append(result)
    device_operations = {
        "send_after_continuity_fix",
        "parse_then_send_if_accepted_after_continuity_fix",
        "parse_only",
    }
    expected_device_ids = {case_id for case_id, case in manifest.items()
                           if case["operation"] in device_operations}
    if require_all_device_rows and seen != expected_device_ids:
        missing = sorted(expected_device_ids - seen)
        extra = sorted(seen - expected_device_ids)
        raise ValueError(
            f"device row coverage mismatch missing={missing[:3]} extra={extra[:3]}")

    # These cases are intentionally not transmitted.  Assigned S1G/DMG/PV1
    # layouts require a PHY Peach does not provide; reserved cells need only a
    # deterministic classification.  Keep this static evidence distinct from
    # the per-request terminal ledger above.
    for case_id, case in manifest.items():
        if case["operation"] == "capability_only":
            result = base_result(case)
            result["parsed"] = {"state": "not_applicable"}
            result["capability"] = {
                "state": "hardware_unsupported",
                "reason": (f"{case['legality']}:{case['family']}:"
                           f"{case['stage1_requirement']}"),
            }
            results.append(result)
        elif case["operation"] == "classify_only":
            result = base_result(case)
            result["parsed"] = {"state": case["current_parser_state"],
                                "errno": case["current_parser_errno"]}
            results.append(result)
    output_path.write_text("".join(
        json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
        for result in results))
    return len(results)


def selftest(manifest_path: pathlib.Path) -> None:
    case = next(case for case in read_jsonl(manifest_path)
                if case["operation"] == "send_after_continuity_fix")
    import tempfile
    with tempfile.TemporaryDirectory(prefix="stage1-device-evidence-") as root_name:
        root = pathlib.Path(root_name)
        rows = root / "rows.tsv"
        rows.write_text("\t".join(("case_id", "case_cookie", "packet_sha256",
            "operation", "parser_state", "parser_errno", "previous_request_id",
            "request_id", "terminal_stage", "terminal_errno",
            "accepted_delta", "submitted_delta", "parse_delta",
            "backend_delta", "completion_delta", "completion_status",
            "window_start_ns", "window_end_ns")) + "\n" +
            "\t".join((case["case_id"], case["case_cookie"], case["packet_sha256"],
            case["operation"], "accepted", "0", "0", "1", "3", "0",
            "1", "1", "0", "0", "1", "0", "100", "200")) + "\n")
        teardown = root / "teardown.txt"
        teardown.write_text("clean\n")
        output = root / "evidence.jsonl"
        static_count = sum(case["operation"] in
                           {"capability_only", "classify_only"}
                           for case in read_jsonl(manifest_path))
        if convert(manifest_path, rows, teardown, output,
                   require_all_device_rows=False) != 1 + static_count:
            raise AssertionError("conversion count mismatch")
        result = read_jsonl(output)[0]
        if result["submitted"]["capture_window_wallclock_ns"] != [100, 200]:
            raise AssertionError("capture window lost")
        bad_rows = root / "bad-rows.tsv"
        bad_rows.write_text(rows.read_text().replace("\t1\t1\t0\t0\t1\t0\t100",
                                                     "\t1\t1\t1\t0\t1\t0\t100"))
        try:
            convert(manifest_path, bad_rows, teardown, output,
                    require_all_device_rows=False)
        except ValueError:
            pass
        else:
            raise AssertionError("ambiguous terminal deltas were accepted")
    print("device_evidence_selftest=PASS valid=1 invalid=1")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=pathlib.Path)
    parser.add_argument("--device-results", type=pathlib.Path)
    parser.add_argument("--teardown-evidence", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)
    if args.selftest:
        selftest(args.manifest)
        return 0
    if args.device_results is None or args.teardown_evidence is None or args.output is None:
        parser.error("--device-results, --teardown-evidence and --output are required")
    count = convert(args.manifest, args.device_results, args.teardown_evidence, args.output)
    print(f"device_evidence_conversion=PASS cases={count}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, ValueError, KeyError) as error:
        print(f"device_evidence_error={error}", file=sys.stderr)
        raise SystemExit(2)
