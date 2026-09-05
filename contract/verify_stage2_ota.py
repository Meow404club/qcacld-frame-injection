#!/usr/bin/env python3

"""Bind Stage 2 sender evidence to an independent radiotap capture.

Matching is an ordered dynamic-programming alignment. Duration/ID and the
Timestamp field of Beacon/Probe Response frames are compared as explicit
hardware/FW-owned fields instead of making the whole MPDU byte-equal.
"""

from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import pathlib
import struct
import sys
import tempfile
from dataclasses import dataclass
from typing import Any

DLT_IEEE802_11_RADIO = 127
RADIOTAP_F_FCS = 0x10
RADIOTAP_F_BADFCS = 0x40
SCHEMA_VERSION = 2


@dataclass(frozen=True)
class Captured:
    original_index: int
    timestamp_ns: int
    mpdu: bytes
    fcs_state: str


def read_jsonl(path: pathlib.Path) -> list[dict[str, Any]]:
    records = []
    with path.open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"{path}:{number}: {error}") from error
            if not isinstance(record, dict):
                raise ValueError(f"{path}:{number}: not an object")
            records.append(record)
    return records


def classic_pcap(data: bytes) -> list[tuple[int, bytes]] | None:
    magics = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1),
        b"\xa1\xb2\x3c\x4d": (">", 1),
    }
    format_info = magics.get(data[:4])
    if format_info is None:
        return None
    endian, fractional_ns = format_info
    if len(data) < 24 or struct.unpack_from(endian + "I", data, 20)[0] != DLT_IEEE802_11_RADIO:
        raise ValueError("classic pcap is not radiotap")
    packets = []
    offset = 24
    while offset + 16 <= len(data):
        seconds, fraction, captured, _ = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if captured > len(data) - offset:
            raise ValueError("truncated classic pcap packet")
        packets.append((seconds * 1_000_000_000 + fraction * fractional_ns,
                        data[offset:offset + captured]))
        offset += captured
    if offset != len(data):
        raise ValueError("trailing classic pcap bytes")
    return packets


def pcapng(data: bytes) -> list[tuple[int, bytes]] | None:
    if data[:4] != b"\x0a\x0d\x0d\x0a":
        return None
    packets: list[tuple[int, bytes]] = []
    interfaces: list[tuple[int, int]] = []
    endian = None
    offset = 0
    while offset + 12 <= len(data):
        if data[offset:offset + 4] == b"\x0a\x0d\x0d\x0a":
            bom = data[offset + 8:offset + 12]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">" if bom == b"\x1a\x2b\x3c\x4d" else None
            interfaces = []
        if endian is None:
            raise ValueError("invalid pcapng byte order")
        block_type, block_len = struct.unpack_from(endian + "II", data, offset)
        if block_len < 12 or block_len % 4 or block_len > len(data) - offset:
            raise ValueError("invalid pcapng block")
        if struct.unpack_from(endian + "I", data, offset + block_len - 4)[0] != block_len:
            raise ValueError("pcapng block length mismatch")
        if block_type == 1:
            linktype = struct.unpack_from(endian + "H", data, offset + 8)[0]
            interfaces.append((linktype, 1_000))
        elif block_type == 6:
            interface_id, high, low, captured = struct.unpack_from(endian + "IIII", data, offset + 8)
            if interface_id >= len(interfaces) or captured > block_len - 32:
                raise ValueError("invalid pcapng packet")
            linktype, unit_ns = interfaces[interface_id]
            if linktype != DLT_IEEE802_11_RADIO:
                raise ValueError("pcapng packet is not radiotap")
            timestamp = (high << 32 | low) * unit_ns
            packets.append((timestamp, data[offset + 28:offset + 28 + captured]))
        offset += block_len
    if offset != len(data):
        raise ValueError("trailing pcapng bytes")
    return packets


def align(offset: int, alignment: int) -> int:
    return (offset + alignment - 1) & ~(alignment - 1)


def radiotap_mpdu(packet: bytes) -> tuple[bytes | None, str]:
    if len(packet) < 8 or packet[0] != 0:
        raise ValueError("invalid radiotap packet")
    length = int.from_bytes(packet[2:4], "little")
    if length < 8 or length > len(packet):
        raise ValueError("invalid radiotap length")
    bitmap_offset = 4
    bitmaps = []
    while True:
        if bitmap_offset + 4 > length:
            raise ValueError("truncated radiotap bitmap")
        bitmap = int.from_bytes(packet[bitmap_offset:bitmap_offset + 4], "little")
        bitmaps.append(bitmap)
        bitmap_offset += 4
        if not bitmap & (1 << 31):
            break
    field_offset = bitmap_offset
    flags = 0
    if bitmaps[0] & 1:
        field_offset = align(field_offset, 8) + 8
    if bitmaps[0] & 2:
        if field_offset >= length:
            raise ValueError("truncated radiotap flags")
        flags = packet[field_offset]
    if flags & RADIOTAP_F_BADFCS:
        return None, "bad"
    mpdu = packet[length:]
    if flags & RADIOTAP_F_FCS:
        if len(mpdu) < 4:
            raise ValueError("advertised FCS is missing")
        body, captured_fcs = mpdu[:-4], mpdu[-4:]
        expected_fcs = struct.pack("<I", binascii.crc32(body) & 0xffffffff)
        if captured_fcs != expected_fcs:
            return None, "invalid"
        return body, "valid"
    return mpdu, "absent"


def normalize(mpdu: bytes) -> bytes:
    value = bytearray(mpdu)
    if len(value) >= 4:
        value[2:4] = b"\x00\x00"
    if len(value) >= 32:
        fc = int.from_bytes(value[:2], "little")
        if fc & 3 == 0 and (fc >> 2) & 3 == 0 and (fc >> 4) & 15 in {5, 8}:
            header_len = 28 if fc & 0x8000 else 24
            if len(value) >= header_len + 8:
                value[header_len:header_len + 8] = bytes(8)
    return bytes(value)


def field_comparison(expected: bytes, observed: bytes) -> dict[str, str]:
    comparison = {"mpdu_except_owned_fields": "preserved"}
    if len(expected) >= 4 and len(observed) >= 4:
        comparison["duration_id"] = ("preserved" if expected[2:4] == observed[2:4]
                                     else "rewritten")
    fc = int.from_bytes(expected[:2], "little") if len(expected) >= 2 else 0
    if fc & 3 == 0 and (fc >> 2) & 3 == 0 and (fc >> 4) & 15 in {5, 8}:
        header_len = 28 if fc & 0x8000 else 24
        if len(expected) >= header_len + 8 and len(observed) >= header_len + 8:
            comparison["timestamp_tsf"] = ("preserved"
                if expected[header_len:header_len + 8] == observed[header_len:header_len + 8]
                else "rewritten")
    return comparison


def load_expected(manifest_path: pathlib.Path, results_path: pathlib.Path) -> list[dict[str, Any]]:
    manifest = {record["case_id"]: record for record in read_jsonl(manifest_path)}
    results = read_jsonl(results_path)
    expected = []
    seen = set()
    for result in results:
        case_id = result.get("case_id")
        if case_id in seen or case_id not in manifest:
            raise ValueError(f"unknown or duplicate result case {case_id}")
        seen.add(case_id)
        case = manifest[case_id]
        if result.get("packet_sha256") != case.get("packet_sha256"):
            raise ValueError(f"{case_id}: packet hash mismatch")
        if result.get("run_state") != "complete" or result.get("submitted", {}).get("state") != "submitted":
            continue
        window = result["submitted"].get("capture_window_wallclock_ns")
        if not isinstance(window, list) or len(window) != 2 or not all(isinstance(item, int) for item in window):
            raise ValueError(f"{case_id}: capture window missing")
        expected.append({"case": case, "result": result,
                         "mpdu": bytes.fromhex(case["mpdu_hex"]),
                         "window": tuple(window)})
    return expected


def ordered_alignment(expected: list[dict[str, Any]], captured: list[Captured]) -> list[int | None]:
    if not expected:
        return []
    expected_keys = {hashlib.sha256(normalize(item["mpdu"])).digest() for item in expected}
    candidates = [packet for packet in captured
                  if hashlib.sha256(normalize(packet.mpdu)).digest() in expected_keys]
    n, m = len(expected), len(candidates)
    previous = [0] * (m + 1)
    choices = [bytearray(m + 1) for _ in range(n)]
    for row, item in enumerate(expected):
        current = [0] * (m + 1)
        key = normalize(item["mpdu"])
        start, end = item["window"]
        for column, packet in enumerate(candidates, 1):
            skip_expected = previous[column]
            skip_capture = current[column - 1]
            best = skip_expected
            choice = 1
            if skip_capture > best:
                best = skip_capture
                choice = 2
            if normalize(packet.mpdu) == key:
                in_window = start <= packet.timestamp_ns <= end
                exact = packet.mpdu == item["mpdu"]
                score = previous[column - 1] + 1_000_000 + 1_000 * int(exact) + 100 * int(in_window)
                if score > best:
                    best = score
                    choice = 3
            current[column] = best
            choices[row][column] = choice
        previous = current
    matches: list[int | None] = [None] * n
    row, column = n - 1, m
    while row >= 0 and column > 0:
        choice = choices[row][column]
        if choice == 3:
            matches[row] = candidates[column - 1].original_index
            row -= 1
            column -= 1
        elif choice == 2:
            column -= 1
        else:
            row -= 1
    return matches


def find_response(expected_mpdu: bytes, match_index: int | None, captured: list[Captured]) -> list[int]:
    if match_index is None or len(expected_mpdu) < 16:
        return []
    fc = int.from_bytes(expected_mpdu[:2], "little")
    frame_type, subtype = (fc >> 2) & 3, (fc >> 4) & 15
    if frame_type == 1 and subtype in {12, 13}:
        return []
    transmitter = expected_mpdu[10:16]
    source = next((packet for packet in captured if packet.original_index == match_index), None)
    if source is None:
        return []
    found = []
    for packet in captured:
        if packet.original_index <= match_index or packet.timestamp_ns - source.timestamp_ns > 100_000_000:
            continue
        if len(packet.mpdu) < 10:
            continue
        response_fc = int.from_bytes(packet.mpdu[:2], "little")
        response_type, response_subtype = (response_fc >> 2) & 3, (response_fc >> 4) & 15
        if response_type == 1 and response_subtype in {9, 12, 13} and packet.mpdu[4:10] == transmitter:
            found.append(packet.original_index)
    return found[:8]


def verify(manifest: pathlib.Path, results: pathlib.Path, capture: pathlib.Path,
           output: pathlib.Path) -> dict[str, int]:
    expected = load_expected(manifest, results)
    raw = capture.read_bytes()
    packets = classic_pcap(raw)
    if packets is None:
        packets = pcapng(raw)
    if packets is None:
        raise ValueError("capture is neither classic pcap nor pcapng")
    captured = []
    fcs = {"absent": 0, "valid": 0, "invalid": 0, "bad": 0}
    for index, (timestamp_ns, packet) in enumerate(packets):
        mpdu, fcs_state = radiotap_mpdu(packet)
        fcs[fcs_state] += 1
        if mpdu is not None:
            captured.append(Captured(index, timestamp_ns, mpdu, fcs_state))
    matches = ordered_alignment(expected, captured)
    captured_by_index = {packet.original_index: packet for packet in captured}
    rows = ["case_id\tcase_cookie\tmatched_packet_index\texact\tduration_id\ttimestamp_tsf\tresponse_indexes"]
    observed = 0
    exact = 0
    responses = 0
    for item, match in zip(expected, matches):
        case, result = item["case"], item["result"]
        if match is None:
            rows.append(f"{case['case_id']}\t{case['case_cookie']}\tmissing\t0\tunknown\tnot_applicable\t")
            continue
        packet = captured_by_index[match]
        observed += 1
        is_exact = packet.mpdu == item["mpdu"]
        exact += int(is_exact)
        fields = field_comparison(item["mpdu"], packet.mpdu)
        response_indexes = find_response(item["mpdu"], match, captured)
        responses += bool(response_indexes)
        result["ota"] = {"state": "observed", "authority": "independent_listener",
            "capture_sha256": hashlib.sha256(raw).hexdigest(), "packet_indexes": [match]}
        result["rewrite"] = {"state": "compared", "fields": fields}
        if case.get("stage2_response_policy") == "required_if_ack_policy_applies":
            result["response"] = ({"state": "observed", "authority": "independent_listener",
                "capture_sha256": hashlib.sha256(raw).hexdigest(), "packet_indexes": response_indexes}
                if response_indexes else {"state": "not_observed"})
        rows.append(f"{case['case_id']}\t{case['case_cookie']}\t{match}\t{int(is_exact)}\t"
                    f"{fields.get('duration_id', 'not_applicable')}\t"
                    f"{fields.get('timestamp_tsf', 'not_applicable')}\t"
                    f"{','.join(map(str, response_indexes))}")
    output.write_text("\n".join(rows) + "\n")
    output.with_suffix(".evidence.jsonl").write_text("".join(
        json.dumps(item["result"], sort_keys=True, separators=(",", ":")) + "\n"
        for item in expected))
    return {"submitted": len(expected), "ota_observed": observed,
            "exact": exact, "responses": responses, "capture_packets": len(packets),
            **{f"fcs_{key}": value for key, value in fcs.items()}}


def write_test_pcap(path: pathlib.Path, packets: list[tuple[int, bytes]]) -> None:
    data = bytearray(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, DLT_IEEE802_11_RADIO))
    for timestamp_ns, mpdu in packets:
        radiotap = struct.pack("<BBHI", 0, 0, 8, 0)
        packet = radiotap + mpdu
        seconds, nanoseconds = divmod(timestamp_ns, 1_000_000_000)
        data += struct.pack("<IIII", seconds, nanoseconds // 1_000, len(packet), len(packet)) + packet
    path.write_bytes(data)


def selftest(manifest_path: pathlib.Path) -> None:
    manifest = read_jsonl(manifest_path)
    selected = [record for record in manifest if record["operation"] == "send_after_continuity_fix"][:3]
    with tempfile.TemporaryDirectory(prefix="stage2-ota-selftest-") as temporary:
        root = pathlib.Path(temporary)
        results = []
        capture_packets = []
        base = 1_700_000_000_000_000_000
        for index, case in enumerate(selected):
            result = {"schema": SCHEMA_VERSION, "case_id": case["case_id"],
                      "packet_sha256": case["packet_sha256"], "run_state": "complete",
                      "submitted": {"state": "submitted", "request_id": index + 1,
                          "capture_window_wallclock_ns": [base + index * 1_000_000,
                                                            base + index * 1_000_000 + 900_000]},
                      "ota": {"state": "not_observed"},
                      "response": {"state": "not_observed"},
                      "rewrite": {"state": "not_compared"}}
            results.append(result)
            mpdu = bytearray.fromhex(case["mpdu_hex"])
            mpdu[2:4] = struct.pack("<H", 0x9000 + index)
            capture_packets.append((base + index * 1_000_000 + 100_000, bytes(mpdu)))
            if index == 0:
                capture_packets.append((base + 150_000, bytes(mpdu)))
        results_path = root / "results.jsonl"
        results_path.write_text("".join(json.dumps(record) + "\n" for record in results))
        capture_path = root / "capture.pcap"
        write_test_pcap(capture_path, capture_packets)
        report = verify(manifest_path, results_path, capture_path, root / "matrix.tsv")
        if report["ota_observed"] != len(selected):
            raise AssertionError("dynamic ordered matcher lost rewritten/duplicate frames")
    print(f"stage2_ota_selftest=PASS cases={len(selected)} duplicate=1 duration_rewrite={len(selected)}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=pathlib.Path, required=True)
    parser.add_argument("--results", type=pathlib.Path)
    parser.add_argument("--capture", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path("stage2-ota-matrix.tsv"))
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)
    if args.selftest:
        selftest(args.manifest)
        return 0
    if args.results is None or args.capture is None:
        parser.error("--results and --capture are required")
    report = verify(args.manifest, args.results, args.capture, args.output)
    print("ota_verdict=" + ("PASS" if report["ota_observed"] == report["submitted"] else "UNPROVEN"))
    print(" ".join(f"{key}={value}" for key, value in sorted(report.items())))
    return 0 if report["ota_observed"] == report["submitted"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, ValueError) as error:
        print(f"ota_verifier_error={error}", file=sys.stderr)
        raise SystemExit(2)
