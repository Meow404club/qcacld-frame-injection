#!/usr/bin/env python3
"""Bind the frozen Stage 2 sender manifest to an independent radiotap capture.

The listener pcap is the only OTA authority. Matching is ordered and
owner-aware: Duration/ID and Beacon/Probe Response TSF are hardware/FW-owned
fields, while all remaining MPDU bytes must be preserved. Exact byte matches,
capture FCS state, and sender completion status remain separate facts.
"""

from __future__ import annotations

import argparse
import binascii
import hashlib
import pathlib
import re
import struct
import sys
from dataclasses import dataclass

DLT_IEEE802_11_RADIO = 127
RADIOTAP_F_FCS = 0x10
RADIOTAP_F_BADFCS = 0x40
EXPECTED_FRAMES = 67
# Stage 2c constructed-context suite frame count (same manifest format)
EXPECTED_FRAMES_CONSTRUCTED = 12


@dataclass(frozen=True)
class Captured:
    original_index: int
    timestamp_ns: int
    mpdu: bytes
    fcs_state: str


def classic_pcap_packets(data: bytes) -> list[tuple[int, bytes]] | None:
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


def pcapng_packets(data: bytes) -> list[tuple[int, bytes]] | None:
    if data[:4] != b"\x0a\x0d\x0d\x0a":
        return None
    packets: list[tuple[int, bytes]] = []
    interfaces: list[tuple[int, int]] = []
    endian = None
    offset = 0
    while offset + 12 <= len(data):
        if data[offset:offset + 4] == b"\x0a\x0d\x0d\x0a":
            bom = data[offset + 8:offset + 12]
            endian = ("<" if bom == b"\x4d\x3c\x2b\x1a" else
                      ">" if bom == b"\x1a\x2b\x3c\x4d" else None)
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
            interface_id, high, low, captured = struct.unpack_from(
                endian + "IIII", data, offset + 8)
            if interface_id >= len(interfaces) or captured > block_len - 32:
                raise ValueError("invalid pcapng packet")
            linktype, unit_ns = interfaces[interface_id]
            # A capture may bundle extra interfaces (e.g. the listener's own
            # Ethernet stack records). Only radiotap interfaces carry capture
            # evidence; skip the rest instead of rejecting the whole file.
            if linktype == DLT_IEEE802_11_RADIO:
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
    first_present = None
    while True:
        if bitmap_offset + 4 > length:
            raise ValueError("truncated radiotap bitmap")
        present = int.from_bytes(packet[bitmap_offset:bitmap_offset + 4], "little")
        if first_present is None:
            first_present = present
        bitmap_offset += 4
        if not present & (1 << 31):
            break
    field_offset = bitmap_offset
    flags = 0
    if first_present & 1:
        field_offset = align(field_offset, 8) + 8
    if first_present & 2:
        if field_offset >= length:
            raise ValueError("truncated radiotap flags")
        flags = packet[field_offset]
    if flags & RADIOTAP_F_BADFCS:
        return None, "bad_fcs"
    mpdu = packet[length:]
    if flags & RADIOTAP_F_FCS:
        if len(mpdu) < 4:
            raise ValueError("missing advertised FCS")
        body, captured_fcs = mpdu[:-4], mpdu[-4:]
        expected_fcs = struct.pack("<I", binascii.crc32(body) & 0xffffffff)
        if captured_fcs != expected_fcs:
            return None, "invalid_fcs"
        return body, "valid"
    return mpdu, "absent"


def packet_hex_from_log(path: pathlib.Path, kind: str) -> tuple[bytes, str]:
    text = path.read_text(errors="replace")
    pattern = (r"^packet_hex=([0-9a-f]+)$" if kind == "fixed" else
               r"^workflow_packet .* packet_hex=([0-9a-f]+)$")
    matches = re.findall(pattern, text, re.M)
    if len(matches) != 1:
        raise ValueError(f"{path.name}: expected one packet hex")
    packet = bytes.fromhex(matches[0])
    if len(packet) < 9:
        raise ValueError(f"{path.name}: short sender packet")
    radiotap_len = int.from_bytes(packet[2:4], "little")
    if radiotap_len < 8 or radiotap_len > len(packet):
        raise ValueError(f"{path.name}: invalid radiotap length")
    mpdu = packet[radiotap_len:]
    if path.name.endswith("-probe-fcs.log"):
        if len(mpdu) < 4:
            raise ValueError(f"{path.name}: missing caller FCS")
        return mpdu[:-4], "caller_present"
    return mpdu, "not_present"


def load_expected(sender_output: pathlib.Path) -> tuple[list[dict], str]:
    manifest = sender_output / "send-manifest.tsv"
    lines = manifest.read_text(errors="replace").splitlines()
    expected_header = ("send_order\tkind\tindex\tname\tcompletion_status\tdesc\t"
                       "vdev\tpacket_hex_sha256\tlistener_token")
    if not lines or lines[0] != expected_header or len(lines) not in (
            EXPECTED_FRAMES + 1, EXPECTED_FRAMES_CONSTRUCTED + 1):
        raise ValueError("invalid or incomplete sender manifest")
    expected = []
    tokens = set()
    for order, line in enumerate(lines[1:], 1):
        fields = line.split("\t")
        if len(fields) != 9 or int(fields[0]) != order or fields[4] not in {"0", "3"}:
            raise ValueError(f"invalid manifest row {order}")
        if not fields[5].isdigit() or not fields[6].isdigit():
            raise ValueError(f"invalid descriptor identity at row {order}")
        kind, index, name, token = fields[1], fields[2], fields[3], fields[8]
        tokens.add(token)
        path = sender_output / (
            f"send-{index}-{name}.log" if kind == "fixed" else
            f"workflow-frame-{index}.log")
        mpdu, input_fcs = packet_hex_from_log(path, kind)
        packet_text = path.read_text(errors="replace")
        packet_match = re.search(
            r"^packet_hex=([0-9a-f]+)$" if kind == "fixed" else
            r"^workflow_packet .* packet_hex=([0-9a-f]+)$", packet_text, re.M)
        if packet_match is None or hashlib.sha256(
                packet_match.group(1).encode("ascii")).hexdigest() != fields[7]:
            raise ValueError(f"packet hash mismatch at row {order}")
        expected.append({
            "order": order,
            "kind": kind,
            "index": index,
            "name": name,
            "completion_status": int(fields[4]),
            "completion_result": "fw_ok" if fields[4] == "0" else "fw_no_ack",
            "mpdu": mpdu,
            "input_fcs": input_fcs,
        })
    if len(tokens) != 1:
        raise ValueError("sender manifest has multiple listener tokens")
    return expected, tokens.pop()


def normalize(mpdu: bytes) -> bytes:
    value = bytearray(mpdu)
    if len(value) >= 4:
        value[2:4] = b"\x00\x00"
    if len(value) >= 32:
        fc = int.from_bytes(value[:2], "little")
        frame_type = (fc >> 2) & 3
        subtype = (fc >> 4) & 15
        if fc & 3 == 0 and frame_type == 0 and subtype in {5, 8}:
            header_len = 28 if fc & 0x8000 else 24
            if len(value) >= header_len + 8:
                value[header_len:header_len + 8] = bytes(8)
    return bytes(value)


def field_comparison(expected: bytes, observed: bytes) -> dict[str, str]:
    comparison = {}
    if len(expected) >= 4 and len(observed) >= 4:
        comparison["duration_id"] = ("preserved" if expected[2:4] == observed[2:4]
                                      else "rewritten")
    else:
        comparison["duration_id"] = "not_applicable"
    fc = int.from_bytes(expected[:2], "little") if len(expected) >= 2 else 0
    frame_type = (fc >> 2) & 3
    subtype = (fc >> 4) & 15
    if fc & 3 == 0 and frame_type == 0 and subtype in {5, 8}:
        header_len = 28 if fc & 0x8000 else 24
        if len(expected) >= header_len + 8 and len(observed) >= header_len + 8:
            comparison["timestamp_tsf"] = (
                "preserved" if expected[header_len:header_len + 8] ==
                observed[header_len:header_len + 8] else "rewritten")
        else:
            comparison["timestamp_tsf"] = "not_applicable"
    else:
        comparison["timestamp_tsf"] = "not_applicable"
    left = bytearray(expected)
    right = bytearray(observed)
    if len(left) >= 4 and len(right) >= 4:
        left[2:4] = right[2:4] = b"\x00\x00"
    if comparison["timestamp_tsf"] != "not_applicable":
        header_len = 28 if fc & 0x8000 else 24
        left[header_len:header_len + 8] = right[header_len:header_len + 8] = bytes(8)
    comparison["mpdu_except_owned_fields"] = (
        "preserved" if bytes(left) == bytes(right) else "changed")
    return comparison


def ordered_alignment(expected: list[dict], captured: list[Captured]) -> list[int | None]:
    if not expected:
        return []
    expected_keys = {hashlib.sha256(normalize(item["mpdu"])).digest()
                     for item in expected}
    candidates = [packet for packet in captured if
                  hashlib.sha256(normalize(packet.mpdu)).digest() in expected_keys]
    n, m = len(expected), len(candidates)
    previous = [0] * (m + 1)
    choices = [bytearray(m + 1) for _ in range(n)]
    for row, item in enumerate(expected):
        current = [0] * (m + 1)
        key = normalize(item["mpdu"])
        for column, packet in enumerate(candidates, 1):
            best = previous[column]
            choice = 1
            if current[column - 1] > best:
                best = current[column - 1]
                choice = 2
            if normalize(packet.mpdu) == key:
                score = (previous[column - 1] + 1_000_000 +
                         1_000 * int(packet.mpdu == item["mpdu"]))
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


def response_class(mpdu: bytes) -> str | None:
    if len(mpdu) < 2:
        return None
    fc = int.from_bytes(mpdu[:2], "little")
    if fc & 3 or ((fc >> 2) & 3) != 1:
        return None
    return {11: "RTS", 12: "CTS", 13: "ACK", 8: "BAR", 9: "BA"}.get(
        (fc >> 4) & 15)


def find_responses(expected_mpdu: bytes, match_index: int | None,
                   captured: list[Captured]) -> list[int]:
    if match_index is None or len(expected_mpdu) < 16:
        return []
    fc = int.from_bytes(expected_mpdu[:2], "little")
    if ((fc >> 2) & 3) == 1 and ((fc >> 4) & 15) in {12, 13}:
        return []
    transmitter = expected_mpdu[10:16]
    source = next((packet for packet in captured
                   if packet.original_index == match_index), None)
    if source is None:
        return []
    found = []
    for packet in captured:
        if packet.original_index <= match_index:
            continue
        if packet.timestamp_ns - source.timestamp_ns > 100_000_000:
            continue
        if len(packet.mpdu) < 10:
            continue
        response_fc = int.from_bytes(packet.mpdu[:2], "little")
        response_type = (response_fc >> 2) & 3
        response_subtype = (response_fc >> 4) & 15
        if response_type == 1 and response_subtype in {9, 12, 13}:
            if packet.mpdu[4:10] == transmitter:
                found.append(packet.original_index)
    return found[:8]


def duplicate_expected_frames(expected: list[dict], captured: list[Captured]) -> int:
    expected_counts = {}
    for item in expected:
        key = normalize(item["mpdu"])
        expected_counts[key] = expected_counts.get(key, 0) + 1
    captured_counts = {}
    for packet in captured:
        key = normalize(packet.mpdu)
        if key in expected_counts:
            captured_counts[key] = captured_counts.get(key, 0) + 1
    return sum(max(0, captured_counts.get(key, 0) - count)
               for key, count in expected_counts.items())


def verify(capture: pathlib.Path, sender_output: pathlib.Path,
           output: pathlib.Path) -> dict[str, int | str]:
    expected, listener_token = load_expected(sender_output)
    raw = capture.read_bytes()
    packets = classic_pcap_packets(raw)
    capture_format = "pcap"
    if packets is None:
        packets = pcapng_packets(raw)
        capture_format = "pcapng"
    if packets is None:
        raise ValueError("capture is neither pcap nor pcapng")
    captured: list[Captured] = []
    fcs = {"absent": 0, "valid": 0, "bad_fcs": 0, "invalid_fcs": 0}
    responses = {name: 0 for name in ("RTS", "CTS", "ACK", "BAR", "BA")}
    skipped_non_radiotap = 0
    for index, (timestamp_ns, packet) in enumerate(packets):
        try:
            mpdu, fcs_state = radiotap_mpdu(packet)
        except ValueError:
            # Records that are not parseable radiotap (e.g. the listener's own
            # IGMP/MLD frames bundled by its capture stack) are not capture
            # evidence for our vectors; skip and count them.
            skipped_non_radiotap += 1
            continue
        fcs[fcs_state] += 1
        if mpdu is None:
            continue
        captured.append(Captured(index, timestamp_ns, mpdu, fcs_state))
        response = response_class(mpdu)
        if response:
            responses[response] += 1
    matches = ordered_alignment(expected, captured)
    captured_by_index = {packet.original_index: packet for packet in captured}
    rows = [
        "send_order\tkind\tname\tcompletion_status\tcompletion_result\t"
        "input_fcs\tota_state\tmatched_packet_index\texact\tduration_id\t"
        "timestamp_tsf\tmpdu_except_owned_fields\tcapture_fcs\tresponse_indexes"
    ]
    observed = 0
    exact = 0
    matched_responses = 0
    for item, match in zip(expected, matches):
        if match is None:
            rows.append("\t".join([
                str(item["order"]), item["kind"], item["name"],
                str(item["completion_status"]), item["completion_result"],
                item["input_fcs"], "missing", "missing", "0", "unknown",
                "not_applicable", "not_applicable", "not_observed", "",
            ]))
            continue
        packet = captured_by_index[match]
        observed += 1
        is_exact = packet.mpdu == item["mpdu"]
        exact += int(is_exact)
        fields = field_comparison(item["mpdu"], packet.mpdu)
        response_indexes = find_responses(item["mpdu"], match, captured)
        matched_responses += bool(response_indexes)
        rows.append("\t".join([
            str(item["order"]), item["kind"], item["name"],
            str(item["completion_status"]), item["completion_result"],
            item["input_fcs"], "observed", str(match), str(int(is_exact)),
            fields["duration_id"], fields["timestamp_tsf"],
            fields["mpdu_except_owned_fields"], packet.fcs_state,
            ",".join(map(str, response_indexes)),
        ]))
    output.write_text("\n".join(rows) + "\n")
    report: dict[str, int | str] = {
        "submitted": len(expected),
        "owner_aware_ordered_frames": observed,
        "exact_ordered_frames": exact,
        "missing_owner_aware_frames": len(expected) - observed,
        "matched_vectors_with_responses": matched_responses,
        "capture_packets": len(packets),
        "skipped_non_radiotap": skipped_non_radiotap,
        "valid_mpdus": len(captured),
        "duplicate_expected_frames": duplicate_expected_frames(expected, captured),
        "listener_token": listener_token,
    }
    report.update({f"fcs_{key}": value for key, value in fcs.items()})
    report.update({f"responses_{key}": value for key, value in responses.items()})
    report["capture_format"] = capture_format
    return report


def selftest() -> None:
    probe = bytearray(32)
    probe[0:2] = struct.pack("<H", 0x0040)
    beacon = bytearray(40)
    beacon[0:2] = struct.pack("<H", 0x0080)
    beacon[24:32] = struct.pack("<Q", 0x1122334455667788)
    expected = [{"mpdu": bytes(probe)}, {"mpdu": bytes(beacon)}]
    rewritten_probe = bytearray(probe)
    rewritten_probe[2:4] = b"\x34\x12"
    rewritten_beacon = bytearray(beacon)
    rewritten_beacon[2:4] = b"\x78\x56"
    rewritten_beacon[24:32] = struct.pack("<Q", 0x8877665544332211)
    captured = [
        Captured(0, 1, bytes(rewritten_probe), "absent"),
        Captured(1, 2, bytes(rewritten_beacon), "absent"),
        Captured(2, 3, bytes(rewritten_probe), "absent"),
    ]
    matches = ordered_alignment(expected, captured)
    if matches != [0, 1] or field_comparison(bytes(probe), bytes(rewritten_probe))["duration_id"] != "rewritten":
        raise AssertionError("owner-aware ordered match selftest failed")
    if field_comparison(bytes(beacon), bytes(rewritten_beacon))["timestamp_tsf"] != "rewritten":
        raise AssertionError("TSF ownership selftest failed")
    body = bytes(probe)
    valid = struct.pack("<BBHI B", 0, 0, 9, 2, RADIOTAP_F_FCS) + body
    valid += struct.pack("<I", binascii.crc32(body) & 0xffffffff)
    if radiotap_mpdu(valid) != (body, "valid"):
        raise AssertionError("valid FCS selftest failed")
    bad = valid[:-1] + bytes([valid[-1] ^ 1])
    if radiotap_mpdu(bad) != (None, "invalid_fcs"):
        raise AssertionError("invalid FCS selftest failed")
    badfcs = struct.pack("<BBHI B", 0, 0, 9, 2, RADIOTAP_F_BADFCS) + body
    if radiotap_mpdu(badfcs) != (None, "bad_fcs"):
        raise AssertionError("bad FCS selftest failed")
    print("stage2_verifier_selftest=PASS")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", type=pathlib.Path)
    parser.add_argument("--sender-output", type=pathlib.Path)
    parser.add_argument("--listener-token", required=False)
    parser.add_argument("--matrix-out", type=pathlib.Path,
                        default=pathlib.Path("stage2-ota-matrix.tsv"))
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)
    if args.selftest:
        selftest()
        return 0
    if args.capture is None or args.sender_output is None or not args.listener_token:
        parser.error("--capture, --sender-output, and --listener-token are required")
    expected, token = load_expected(args.sender_output)
    if token != args.listener_token:
        raise ValueError("listener READY token does not match sender evidence")
    report = verify(args.capture, args.sender_output, args.matrix_out)
    verdict = "PASS" if report["owner_aware_ordered_frames"] == report["submitted"] else "UNPROVEN"
    print(" ".join(f"{key}={value}" for key, value in sorted(report.items())))
    print(f"ota_verdict={verdict}")
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, ValueError) as error:
        print(f"stage2_verifier_error={error}", file=sys.stderr)
        raise SystemExit(2)
