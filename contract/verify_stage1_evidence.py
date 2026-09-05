#!/usr/bin/env python3

"""Validate per-case Stage 1 evidence without escalating its authority.

The verifier treats host parse, netdev acceptance, firmware completion, OTA,
response and teardown as separate layers.  In particular a completion record
can never satisfy OTA or response.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
import re
import sys
import tempfile
from collections import Counter
from typing import Any, Iterable

SCHEMA_VERSION = 2
LAYERS = ("parsed", "accepted", "submitted", "completion", "ota",
          "response", "rewrite", "teardown", "capability")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class EvidenceError(ValueError):
    pass


def read_jsonl(path: pathlib.Path) -> list[dict[str, Any]]:
    records = []
    with path.open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise EvidenceError(f"{path}:{number}: {error}") from error
            if not isinstance(record, dict):
                raise EvidenceError(f"{path}:{number}: record is not an object")
            records.append(record)
    return records


def index_unique(records: Iterable[dict[str, Any]], label: str) -> dict[str, dict[str, Any]]:
    indexed = {}
    for record in records:
        case_id = record.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            raise EvidenceError(f"{label}: record has no case_id")
        if case_id in indexed:
            raise EvidenceError(f"{label}: duplicate case_id {case_id}")
        indexed[case_id] = record
    return indexed


def state(layer: Any, name: str, case_id: str) -> str:
    if not isinstance(layer, dict) or not isinstance(layer.get("state"), str):
        raise EvidenceError(f"{case_id}: {name}.state missing")
    return layer["state"]


def require_sha(record: dict[str, Any], key: str, case_id: str) -> None:
    value = record.get(key)
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise EvidenceError(f"{case_id}: {key} must be a lowercase SHA-256")


def validate_not_run(result: dict[str, Any], case_id: str, allow_not_run: bool) -> None:
    if not allow_not_run:
        raise EvidenceError(f"{case_id}: case was not run")
    for name in LAYERS:
        if state(result.get(name), name, case_id) != "not_run":
            raise EvidenceError(f"{case_id}: not_run record has populated {name}")


def validate_parser(manifest: dict[str, Any], result: dict[str, Any],
                    enforce_current_parser: bool) -> str:
    case_id = manifest["case_id"]
    parsed = result["parsed"]
    parsed_state = state(parsed, "parsed", case_id)
    if parsed_state not in {"accepted", "rejected", "not_applicable"}:
        raise EvidenceError(f"{case_id}: invalid parsed state {parsed_state}")
    if parsed_state == "accepted":
        if parsed.get("errno") != 0:
            raise EvidenceError(f"{case_id}: accepted parser result needs errno 0")
    elif parsed_state == "rejected":
        errno = parsed.get("errno")
        if not isinstance(errno, int) or errno >= 0:
            raise EvidenceError(f"{case_id}: rejected parser result needs negative errno")
    elif "errno" in parsed and parsed["errno"] is not None:
        raise EvidenceError(f"{case_id}: not-applicable parser result has errno")

    if enforce_current_parser:
        expected_state = manifest["current_parser_state"]
        expected_errno = manifest["current_parser_errno"]
        if parsed_state != expected_state or parsed.get("errno") != expected_errno:
            raise EvidenceError(
                f"{case_id}: parser result {parsed_state}/{parsed.get('errno')} "
                f"does not match current contract {expected_state}/{expected_errno}")
    return parsed_state


def validate_complete(manifest: dict[str, Any], result: dict[str, Any],
                      enforce_current_parser: bool) -> None:
    case_id = manifest["case_id"]
    operation = manifest["operation"]
    layer_state = {name: state(result[name], name, case_id) for name in LAYERS}

    if operation == "capability_only":
        for name in LAYERS[:-1]:
            if layer_state[name] != "not_applicable":
                raise EvidenceError(f"{case_id}: capability-only {name} must be not_applicable")
        if layer_state["capability"] != "hardware_unsupported":
            raise EvidenceError(f"{case_id}: capability result is not exact hardware_unsupported")
        reason = result["capability"].get("reason")
        if not isinstance(reason, str) or not reason:
            raise EvidenceError(f"{case_id}: capability reason missing")
        return

    parsed_state = validate_parser(manifest, result, enforce_current_parser)

    if operation == "classify_only":
        for name in LAYERS[1:]:
            if layer_state[name] != "not_applicable":
                raise EvidenceError(f"{case_id}: classify-only {name} must be not_applicable")
        return

    if layer_state["accepted"] != "accepted":
        raise EvidenceError(f"{case_id}: device case lacks netdev acceptance")
    if parsed_state == "rejected":
        if layer_state["submitted"] not in {"not_submitted", "not_applicable"}:
            raise EvidenceError(f"{case_id}: parser rejection reached submit")
        for name in ("completion", "ota", "response", "rewrite"):
            if layer_state[name] != "not_applicable":
                raise EvidenceError(f"{case_id}: parser rejection populated {name}")
        if layer_state["teardown"] not in {"clean", "not_applicable"}:
            raise EvidenceError(f"{case_id}: parser rejection has bad teardown state")
        if layer_state["capability"] not in {"not_applicable", "precise_unsupported"}:
            raise EvidenceError(f"{case_id}: parser rejection capability is ambiguous")
        return

    if operation == "parse_only":
        if layer_state["submitted"] != "not_applicable":
            raise EvidenceError(f"{case_id}: parse-only case submitted")
        for name in ("completion", "ota", "response", "rewrite",
                     "teardown", "capability"):
            if layer_state[name] != "not_applicable":
                raise EvidenceError(f"{case_id}: parse-only case populated {name}")
        return

    if operation not in {"send_after_continuity_fix",
                         "parse_then_send_if_accepted_after_continuity_fix"}:
        raise EvidenceError(f"{case_id}: unknown operation {operation}")
    if layer_state["accepted"] != "accepted":
        raise EvidenceError(f"{case_id}: send case lacks netdev acceptance")
    if layer_state["submitted"] == "submitted":
        request_id = result["submitted"].get("request_id")
        if not isinstance(request_id, int) or request_id <= 0:
            raise EvidenceError(f"{case_id}: submitted request_id invalid")
        if layer_state["completion"] != "completed":
            raise EvidenceError(f"{case_id}: submit lacks terminal completion")
        status = result["completion"].get("status")
        if not isinstance(status, int) or status not in range(4):
            raise EvidenceError(f"{case_id}: completion status must be 0..3")
        window = result["submitted"].get("capture_window_wallclock_ns")
        if not isinstance(window, list) or len(window) != 2 or not all(
                isinstance(value, int) and value >= 0 for value in window) or \
                window[0] > window[1]:
            raise EvidenceError(f"{case_id}: invalid capture window")
    elif layer_state["submitted"] != "not_submitted":
        raise EvidenceError(f"{case_id}: invalid submitted state")
    elif layer_state["completion"] != "not_applicable":
        raise EvidenceError(f"{case_id}: non-submitted case has completion")

    for name in ("ota", "response", "rewrite"):
        if layer_state[name] != "not_applicable":
            raise EvidenceError(
                f"{case_id}: Stage 1 must not claim Stage 2 {name} evidence")
    if layer_state["teardown"] != "clean":
        raise EvidenceError(f"{case_id}: send case teardown is not clean")
    require_sha(result["teardown"], "evidence_sha256", case_id)
    if layer_state["capability"] not in {"supported", "precise_unsupported",
                                           "unproven"}:
        raise EvidenceError(f"{case_id}: capability classification missing")


def verify(manifest_records: list[dict[str, Any]],
           result_records: list[dict[str, Any]], *, allow_not_run: bool,
           enforce_current_parser: bool, require_all: bool) -> dict[str, Any]:
    manifest = index_unique(manifest_records, "manifest")
    results = index_unique(result_records, "results")
    unknown = sorted(set(results) - set(manifest))
    missing = sorted(set(manifest) - set(results))
    if unknown:
        raise EvidenceError(f"unknown result cases: {unknown[:3]}")
    if require_all and missing:
        raise EvidenceError(f"missing result cases: {missing[:3]}")

    states = Counter()
    for case_id, result in results.items():
        expected = manifest[case_id]
        if result.get("schema") != SCHEMA_VERSION:
            raise EvidenceError(f"{case_id}: result schema mismatch")
        if result.get("packet_sha256") != expected.get("packet_sha256"):
            raise EvidenceError(f"{case_id}: packet hash does not match manifest")
        run_state = result.get("run_state")
        if run_state == "not_run":
            validate_not_run(result, case_id, allow_not_run)
        elif run_state == "complete":
            validate_complete(expected, result, enforce_current_parser)
        else:
            raise EvidenceError(f"{case_id}: invalid run_state {run_state}")
        states[run_state] += 1
    return {"manifest_cases": len(manifest), "result_cases": len(results),
            "missing_cases": len(missing), "run_states": dict(states)}


def not_applicable_layers(result: dict[str, Any]) -> None:
    for name in LAYERS:
        result[name] = {"state": "not_applicable"}


def run_selftest(manifest_path: pathlib.Path, template_path: pathlib.Path) -> None:
    manifest_records = read_jsonl(manifest_path)
    template_records = read_jsonl(template_path)
    verify(manifest_records, template_records, allow_not_run=True,
           enforce_current_parser=False, require_all=True)
    manifest = index_unique(manifest_records, "manifest")
    template = index_unique(template_records, "template")

    parse_case = next(record for record in manifest_records
                      if record["operation"] == "parse_only" and
                      record["current_parser_state"] == "rejected")
    result = copy.deepcopy(template[parse_case["case_id"]])
    result["run_state"] = "complete"
    not_applicable_layers(result)
    result["parsed"] = {"state": "rejected",
                          "errno": parse_case["current_parser_errno"]}
    result["accepted"] = {"state": "accepted"}
    result["submitted"] = {"state": "not_submitted"}
    result["capability"] = {"state": "precise_unsupported"}
    verify(manifest_records, [result], allow_not_run=False,
           enforce_current_parser=True, require_all=False)

    bad = copy.deepcopy(result)
    bad["submitted"] = {"state": "submitted", "request_id": 1}
    try:
        verify(manifest_records, [bad], allow_not_run=False,
               enforce_current_parser=True, require_all=False)
    except EvidenceError:
        pass
    else:
        raise AssertionError("parser rejection incorrectly permitted submit")

    send_case = next(record for record in manifest_records
                     if record["operation"] == "send_after_continuity_fix")
    bad_ota = copy.deepcopy(template[send_case["case_id"]])
    bad_ota["run_state"] = "complete"
    not_applicable_layers(bad_ota)
    bad_ota["parsed"] = {"state": "accepted", "errno": 0}
    bad_ota["accepted"] = {"state": "accepted"}
    bad_ota["submitted"] = {"state": "submitted", "request_id": 1,
                              "capture_window_wallclock_ns": [100, 200]}
    bad_ota["completion"] = {"state": "completed", "status": 0}
    bad_ota["ota"] = {"state": "observed",
                         "authority": "firmware_completion",
                         "capture_sha256": "0" * 64, "packet_indexes": [1]}
    bad_ota["response"] = {"state": "not_applicable"}
    bad_ota["rewrite"] = {"state": "not_applicable"}
    bad_ota["teardown"] = {"state": "clean",
                              "evidence_sha256": "1" * 64}
    bad_ota["capability"] = {"state": "unproven"}
    try:
        verify(manifest_records, [bad_ota], allow_not_run=False,
               enforce_current_parser=True, require_all=False)
    except EvidenceError:
        pass
    else:
        raise AssertionError("Stage 1 incorrectly accepted Stage 2 OTA evidence")

    print(f"selftest=PASS manifest_cases={len(manifest)} valid=2 invalid=2")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=pathlib.Path, required=True)
    parser.add_argument("--results", type=pathlib.Path)
    parser.add_argument("--allow-not-run", action="store_true")
    parser.add_argument("--enforce-current-parser", action="store_true")
    parser.add_argument("--allow-partial", action="store_true")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)

    try:
        if args.selftest:
            if args.results is None:
                parser.error("--selftest requires --results template")
            run_selftest(args.manifest, args.results)
            return 0
        if args.results is None:
            parser.error("--results is required")
        report = verify(read_jsonl(args.manifest), read_jsonl(args.results),
                        allow_not_run=args.allow_not_run,
                        enforce_current_parser=args.enforce_current_parser,
                        require_all=not args.allow_partial)
    except EvidenceError as error:
        print(f"evidence_verdict=FAIL error={error}", file=sys.stderr)
        return 1
    print("evidence_verdict=PASS " + " ".join(
        f"{key}={json.dumps(value, sort_keys=True)}"
        for key, value in report.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
