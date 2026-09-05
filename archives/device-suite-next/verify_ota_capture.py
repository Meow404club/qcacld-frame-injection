#!/usr/bin/env python3

import argparse
import binascii
import hashlib
import pathlib
import re
import struct
import sys
import tempfile
from array import array
from collections import Counter

DLT_IEEE802_11_RADIO = 127
RADIOTAP_F_FCS = 0x10
RADIOTAP_F_BADFCS = 0x40
RADIOTAP_FIELD_LAYOUT = {
    0: (8, 8),  # TSFT
    1: (1, 1),  # FLAGS
    2: (1, 1),  # RATE
    3: (2, 4),  # CHANNEL
    4: (2, 2),  # FHSS
    5: (1, 1),  # DBM_ANTSIGNAL
    6: (1, 1),  # DBM_ANTNOISE
    7: (2, 2),  # LOCK_QUALITY
    8: (2, 2),  # TX_ATTENUATION
    9: (2, 2),  # DB_TX_ATTENUATION
    10: (1, 1),  # DBM_TX_POWER
    11: (1, 1),  # ANTENNA
    12: (1, 1),  # DB_ANTSIGNAL
    13: (1, 1),  # DB_ANTNOISE
    14: (2, 2),  # RX_FLAGS
    15: (2, 2),  # TX_FLAGS
    16: (1, 1),  # RTS_RETRIES
    17: (1, 1),  # DATA_RETRIES
}
EXPECTED_VARIANTS = (
    "probe-request",
    "hcx-probe-request",
    "auth-request",
    "auth-response",
    "assoc-request",
    "assoc-response",
    "reassoc-request",
    "reassoc-response",
    "probe-response",
    "disassoc",
    "probe-raw-alt",
    "probe-fcs",
    "beacon",
    "timing-advert",
    "atim",
    "action",
    "action-noack",
    "deauth",
    "ordinary-data",
    "null-data",
    "qos-null",
    "eap-request-id",
    "eapol-start",
    "eapol-m1-wpa1",
    "eapol-m1-wpa2",
    "rts",
    "bar",
    "block-ack",
    "ps-poll",
    "cf-end",
    "cf-end-ack",
    "cts",
    "ack",
)
EXPECTED_FIXED_TYPE_SUBTYPE = {
    "probe-request": (0, 4),
    "hcx-probe-request": (0, 4),
    "auth-request": (0, 11),
    "auth-response": (0, 11),
    "assoc-request": (0, 0),
    "assoc-response": (0, 1),
    "reassoc-request": (0, 2),
    "reassoc-response": (0, 3),
    "probe-response": (0, 5),
    "disassoc": (0, 10),
    "probe-raw-alt": (0, 4),
    "probe-fcs": (0, 4),
    "beacon": (0, 8),
    "timing-advert": (0, 6),
    "atim": (0, 9),
    "action": (0, 13),
    "action-noack": (0, 14),
    "deauth": (0, 12),
    "ordinary-data": (2, 0),
    "null-data": (2, 4),
    "qos-null": (2, 12),
    "eap-request-id": (2, 0),
    "eapol-start": (2, 0),
    "eapol-m1-wpa1": (2, 0),
    "eapol-m1-wpa2": (2, 0),
    "rts": (1, 11),
    "bar": (1, 8),
    "block-ack": (1, 9),
    "ps-poll": (1, 10),
    "cf-end": (1, 14),
    "cf-end-ack": (1, 15),
    "cts": (1, 12),
    "ack": (1, 13),
}
DEVICE_MATRIX_HEADER = (
    "index",
    "variant",
    "nonce",
    "cookie",
    "vdev",
    "generation",
    "peer_id",
    "tx_status",
    "status_valid",
    "rate_valid",
    "release_src",
    "transmit_count",
    "ppdu_id",
    "reclaimed",
    "fc",
    "frame_len",
    "packet_hex_sha256",
    "send_order",
)
EXPECTED_WORKFLOW_STEPS = (
    (1, "beacon-or-probe-response", "assoc-request-broadcast", 0, 0, 93),
    (1, "beacon-or-probe-response", "auth-request", 0, 11, 30),
    (2, "auth-response", "ack-to-ap", 1, 13, 10),
    (2, "auth-response", "assoc-request-directed", 0, 0, 93),
    (3, "auth-request", "ack-to-client", 1, 13, 10),
    (3, "auth-request", "auth-response", 0, 11, 30),
    (4, "assoc-request-wpa2", "ack-to-client", 1, 13, 10),
    (4, "assoc-request-wpa2", "assoc-response", 0, 1, 46),
    (4, "assoc-request-wpa2", "eapol-m1-wpa2", 2, 0, 131),
    (5, "assoc-request-wpa1", "ack-to-client", 1, 13, 10),
    (5, "assoc-request-wpa1", "assoc-response", 0, 1, 46),
    (5, "assoc-request-wpa1", "eapol-m1-wpa1", 2, 0, 131),
    (6, "reassoc-request-wpa2", "ack-to-client", 1, 13, 10),
    (6, "reassoc-request-wpa2", "reassoc-response", 0, 3, 46),
    (6, "reassoc-request-wpa2", "eapol-m1-wpa2", 2, 0, 131),
    (7, "reassoc-request-wpa1", "ack-to-client", 1, 13, 10),
    (7, "reassoc-request-wpa1", "reassoc-response", 0, 3, 46),
    (7, "reassoc-request-wpa1", "eapol-m1-wpa1", 2, 0, 131),
    (8, "assoc-or-reassoc-response", "ack-to-ap", 1, 13, 10),
    (8, "assoc-or-reassoc-response", "null-data", 2, 4, 26),
    (9, "null-data", "ack-to-client", 1, 13, 10),
    (9, "null-data", "eapol-m1-wpa2", 2, 0, 131),
    (10, "qos-null", "ack-to-client", 1, 13, 10),
    (10, "qos-null", "eapol-m1-wpa1", 2, 0, 131),
    (11, "probe-request", "probe-response", 0, 5, 91),
    (12, "eapol-start", "eap-request-id", 2, 0, 41),
    (13, "periodic-scan", "probe-request", 0, 4, 42),
    (14, "beacon-disassoc-path", "disassoc", 0, 10, 26),
    (15, "beacon-new-ap-path", "assoc-request-broadcast", 0, 0, 93),
    (15, "beacon-new-ap-path", "disassoc", 0, 10, 26),
    (16, "null-data-wpa1", "ack-to-client", 1, 13, 10),
    (16, "null-data-wpa1", "eapol-m1-wpa1", 2, 0, 131),
    (17, "qos-null-wpa2", "ack-to-client", 1, 13, 10),
    (17, "qos-null-wpa2", "eapol-m1-wpa2", 2, 0, 131),
)
WORKFLOW_MATRIX_HEADER = (
    "index",
    "group",
    "trigger",
    "name",
    "nonce",
    "cookie",
    "vdev",
    "generation",
    "peer_id",
    "tx_status",
    "status_valid",
    "rate_valid",
    "release_src",
    "transmit_count",
    "ppdu_id",
    "reclaimed",
    "fc",
    "frame_len",
    "packet_hex_sha256",
    "channel",
    "send_order",
)
WORKFLOW_GROUP_COUNT = 17
WORKFLOW_FRAME_COUNT = 34
TOTAL_FRAME_COUNT = len(EXPECTED_VARIANTS) + WORKFLOW_FRAME_COUNT
WORKFLOW_RADIOTAP = bytes.fromhex("0000080000000000")


def classic_pcap_packets(data: bytes):
    magics = {
        b"\xd4\xc3\xb2\xa1": "<",
        b"\xa1\xb2\xc3\xd4": ">",
        b"\x4d\x3c\xb2\xa1": "<",
        b"\xa1\xb2\x3c\x4d": ">",
    }
    endian = magics.get(data[:4])
    if endian is None or len(data) < 24:
        return None
    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    if linktype != DLT_IEEE802_11_RADIO:
        raise ValueError(f"classic pcap linktype {linktype} is not radiotap")
    packets = []
    offset = 24
    while offset + 16 <= len(data):
        _, _, captured_len, _ = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if captured_len > len(data) - offset:
            raise ValueError("truncated classic pcap packet")
        packets.append((linktype, data[offset : offset + captured_len]))
        offset += captured_len
    if offset != len(data):
        raise ValueError("trailing bytes in classic pcap")
    return packets


def pcapng_packets(data: bytes):
    if data[:4] != b"\x0a\x0d\x0d\x0a":
        return None
    packets = []
    offset = 0
    endian = None
    interfaces = []
    while offset + 12 <= len(data):
        block_type_raw = data[offset : offset + 4]
        if block_type_raw == b"\x0a\x0d\x0d\x0a":
            if offset + 12 > len(data):
                raise ValueError("truncated pcapng section header")
            byte_order = data[offset + 8 : offset + 12]
            if byte_order == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif byte_order == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise ValueError("invalid pcapng byte-order magic")
            interfaces = []
        if endian is None:
            raise ValueError("pcapng block before section header")
        block_type, block_len = struct.unpack_from(endian + "II", data, offset)
        if block_len < 12 or block_len % 4 or block_len > len(data) - offset:
            raise ValueError("invalid pcapng block length")
        trailer_len = struct.unpack_from(endian + "I", data, offset + block_len - 4)[0]
        if trailer_len != block_len:
            raise ValueError("pcapng block length mismatch")
        if block_type == 1:
            if block_len < 20:
                raise ValueError("short interface description block")
            linktype = struct.unpack_from(endian + "H", data, offset + 8)[0]
            if linktype != DLT_IEEE802_11_RADIO:
                raise ValueError(f"pcapng linktype {linktype} is not radiotap")
            interfaces.append(linktype)
        elif block_type == 6:
            if block_len < 32:
                raise ValueError("short enhanced packet block")
            interface_id = struct.unpack_from(endian + "I", data, offset + 8)[0]
            if interface_id >= len(interfaces):
                raise ValueError("enhanced packet references an unknown interface")
            captured_len = struct.unpack_from(endian + "I", data, offset + 20)[0]
            packet_offset = offset + 28
            if captured_len > block_len - 32:
                raise ValueError("truncated enhanced packet")
            packets.append(
                (
                    interfaces[interface_id],
                    data[packet_offset : packet_offset + captured_len],
                )
            )
        elif block_type == 3:
            if block_len < 16:
                raise ValueError("short simple packet block")
            original_len = struct.unpack_from(endian + "I", data, offset + 8)[0]
            captured_len = min(original_len, block_len - 16)
            if not interfaces:
                raise ValueError("simple packet block has no interface")
            packets.append(
                (interfaces[0], data[offset + 12 : offset + 12 + captured_len])
            )
        offset += block_len
    if offset != len(data):
        raise ValueError("trailing bytes in pcapng")
    return packets


def align(offset: int, alignment: int) -> int:
    return (offset + alignment - 1) & ~(alignment - 1)


def signed_byte(value: int) -> int:
    return value - 256 if value & 0x80 else value


def radiotap_header(packet: bytes):
    """Return (header length, selected standard metadata)."""
    if len(packet) < 8 or packet[0] != 0:
        raise ValueError("invalid radiotap header")
    radiotap_len = int.from_bytes(packet[2:4], "little")
    if radiotap_len < 8 or radiotap_len > len(packet):
        raise ValueError("invalid captured radiotap length")

    present_offset = 4
    present_words = []
    while True:
        if present_offset + 4 > radiotap_len:
            raise ValueError("truncated radiotap present bitmap")
        present = int.from_bytes(packet[present_offset : present_offset + 4], "little")
        present_words.append(present)
        present_offset += 4
        if not present & (1 << 31):
            break

    metadata = {}
    field_offset = present_offset
    first_word = present_words[0]
    for field_index, (alignment, size) in RADIOTAP_FIELD_LAYOUT.items():
        if not first_word & (1 << field_index):
            continue
        field_offset = align(field_offset, alignment)
        if field_offset + size > radiotap_len:
            raise ValueError(f"truncated radiotap field {field_index}")
        value = packet[field_offset : field_offset + size]
        if field_index == 0:
            metadata["tsft"] = int.from_bytes(value, "little")
        elif field_index == 1:
            metadata["flags"] = value[0]
        elif field_index == 2:
            metadata["rate_500kbps"] = value[0]
        elif field_index == 3:
            metadata["channel_frequency_mhz"] = int.from_bytes(value[:2], "little")
            metadata["channel_flags"] = int.from_bytes(value[2:], "little")
        elif field_index == 5:
            metadata["signal_dbm"] = signed_byte(value[0])
        elif field_index == 6:
            metadata["noise_dbm"] = signed_byte(value[0])
        elif field_index == 10:
            metadata["tx_power_dbm"] = signed_byte(value[0])
        elif field_index == 11:
            metadata["antenna"] = value[0]
        elif field_index == 14:
            metadata["rx_flags"] = int.from_bytes(value, "little")
        elif field_index == 15:
            metadata["tx_flags"] = int.from_bytes(value, "little")
        elif field_index == 16:
            metadata["rts_retries"] = value[0]
        elif field_index == 17:
            metadata["data_retries"] = value[0]
        field_offset += size

    metadata["radiotap_len"] = radiotap_len
    metadata["present_words"] = tuple(present_words)
    return radiotap_len, metadata


def radiotap_record(linktype: int, packet: bytes):
    if linktype != DLT_IEEE802_11_RADIO:
        raise ValueError(f"packet linktype {linktype} is not radiotap")
    radiotap_len, metadata = radiotap_header(packet)
    flags = metadata.get("flags", 0)
    if flags & RADIOTAP_F_BADFCS:
        return None

    mpdu = packet[radiotap_len:]
    metadata["fcs_present"] = bool(flags & RADIOTAP_F_FCS)
    metadata["fcs_valid"] = None
    if flags & RADIOTAP_F_FCS:
        if len(mpdu) < 4:
            raise ValueError("radiotap advertises a missing FCS")
        payload, captured_fcs = mpdu[:-4], mpdu[-4:]
        expected_fcs = struct.pack("<I", binascii.crc32(payload) & 0xFFFFFFFF)
        if captured_fcs != expected_fcs:
            return None
        mpdu = payload
        metadata["fcs_valid"] = True
    return {"mpdu": mpdu, "metadata": metadata}


def radiotap_mpdu(linktype: int, packet: bytes):
    record = radiotap_record(linktype, packet)
    return None if record is None else record["mpdu"]


def parse_sender_log(path: pathlib.Path):
    packet_hex = None
    metadata = {}
    for line in path.read_text(errors="replace").splitlines():
        if line.startswith("packet_hex="):
            if packet_hex is not None:
                raise ValueError(f"duplicate packet_hex in {path.name}")
            packet_hex = line.partition("=")[2].strip()
        elif line.startswith("variant="):
            if metadata:
                raise ValueError(f"duplicate sender metadata in {path.name}")
            for field in line.split():
                key, separator, value = field.partition("=")
                if separator:
                    metadata[key] = value
    required = {
        "variant",
        "nonce",
        "sendto_count",
        "bytes",
        "expected",
        "frame_len",
        "fc",
        "type",
        "subtype",
        "signature",
        "interface_mac",
        "peer_mac",
    }
    if not packet_hex or not required.issubset(metadata):
        raise ValueError(f"incomplete sender log: {path.name}")
    try:
        packet = bytes.fromhex(packet_hex)
    except ValueError as error:
        raise ValueError(f"invalid packet hex in {path.name}: {error}") from error
    if packet.hex() != packet_hex:
        raise ValueError(f"non-canonical packet hex in {path.name}")
    if len(packet) < 12 or packet[0] != 0:
        raise ValueError(f"short or invalid sender packet: {path.name}")
    if metadata["sendto_count"] != "1":
        raise ValueError(f"sender count is not one in {path.name}")
    if metadata["bytes"] != metadata["expected"]:
        raise ValueError(f"short sender write in {path.name}")
    if int(metadata["bytes"]) != len(packet):
        raise ValueError(f"sender byte count mismatch in {path.name}")
    radiotap_len = int.from_bytes(packet[2:4], "little")
    if radiotap_len < 8 or radiotap_len >= len(packet):
        raise ValueError(f"invalid sender radiotap length: {path.name}")
    parsed_radiotap_len, injection_radiotap = radiotap_header(packet)
    if parsed_radiotap_len != radiotap_len:
        raise ValueError(f"sender radiotap parser mismatch: {path.name}")
    frame_with_optional_fcs = packet[radiotap_len:]
    frame = frame_with_optional_fcs
    if metadata["variant"] == "probe-fcs":
        if len(frame) < 5:
            raise ValueError(f"short FCS sender frame: {path.name}")
        frame = frame[:-4]
    if int(metadata["frame_len"]) != len(frame):
        raise ValueError(f"sender frame length mismatch in {path.name}")
    frame_control = int.from_bytes(frame[:2], "little")
    if metadata["fc"].lower() != f"0x{frame_control:04x}":
        raise ValueError(f"sender frame control mismatch in {path.name}")
    return {
        "path": path,
        "packet_hex": packet_hex,
        "packet": packet,
        "frame": frame,
        "metadata": metadata,
        "injection_radiotap": injection_radiotap,
    }


def parse_ascii_decimal(value: str, label: str, minimum: int, maximum: int) -> int:
    if not re.fullmatch(r"[0-9]+", value):
        raise ValueError(f"{label} is not an unsigned decimal integer")
    parsed = int(value)
    if not minimum <= parsed <= maximum:
        raise ValueError(f"{label} is outside {minimum}..{maximum}")
    return parsed


def parse_key_value_record(
    line: str, prefix: str, path: pathlib.Path, line_number: int
):
    fields = {}
    tokens = line.split()
    if not tokens or tokens[0] != prefix:
        raise ValueError(f"invalid {prefix} record in {path.name}:{line_number}")
    for token in tokens[1:]:
        key, separator, value = token.partition("=")
        if not separator or not key or not value or key in fields:
            raise ValueError(f"invalid {prefix} field in {path.name}:{line_number}")
        fields[key] = value
    return fields


def validate_workflow_identity(fields, path: pathlib.Path, line_number: int):
    required = {"index", "group", "trigger", "name"}
    if not required.issubset(fields):
        raise ValueError(f"incomplete workflow identity in {path.name}:{line_number}")
    index = parse_ascii_decimal(
        fields["index"],
        f"workflow index in {path.name}:{line_number}",
        1,
        WORKFLOW_FRAME_COUNT,
    )
    group = parse_ascii_decimal(
        fields["group"],
        f"workflow group in {path.name}:{line_number}",
        1,
        WORKFLOW_GROUP_COUNT,
    )
    expected_group, expected_trigger, expected_name, _, _, _ = EXPECTED_WORKFLOW_STEPS[
        index - 1
    ]
    if (
        group != expected_group
        or fields["trigger"] != expected_trigger
        or fields["name"] != expected_name
    ):
        raise ValueError(f"workflow identity mismatch in {path.name}:{line_number}")
    return index, group


def parse_workflow_log(path: pathlib.Path):
    packet_fields = {}
    frame_fields = {}
    record_order = []
    completion = None
    for line_number, line in enumerate(
        path.read_text(errors="replace").splitlines(), 1
    ):
        if line.startswith("workflow_packet "):
            if completion is not None:
                raise ValueError(f"workflow packet follows completion in {path.name}")
            fields = parse_key_value_record(line, "workflow_packet", path, line_number)
            if set(fields) != {
                "index",
                "group",
                "trigger",
                "name",
                "channel",
                "packet_hex",
            }:
                raise ValueError(
                    f"unexpected workflow_packet fields in {path.name}:{line_number}"
                )
            index, _ = validate_workflow_identity(fields, path, line_number)
            if index in packet_fields:
                raise ValueError(
                    f"duplicate workflow packet index {index} in {path.name}"
                )
            packet_fields[index] = fields
            record_order.append(("packet", index))
        elif line.startswith("workflow_frame "):
            if completion is not None:
                raise ValueError(f"workflow frame follows completion in {path.name}")
            fields = parse_key_value_record(line, "workflow_frame", path, line_number)
            expected_fields = {
                "index",
                "group",
                "trigger",
                "name",
                "monotonic_timestamp",
                "channel",
                "sendto_count",
                "bytes",
                "expected",
                "frame_len",
                "fc",
                "type",
                "subtype",
            }
            if set(fields) != expected_fields:
                raise ValueError(
                    f"unexpected workflow_frame fields in {path.name}:{line_number}"
                )
            index, _ = validate_workflow_identity(fields, path, line_number)
            if index in frame_fields:
                raise ValueError(
                    f"duplicate workflow frame index {index} in {path.name}"
                )
            frame_fields[index] = fields
            record_order.append(("frame", index))
        elif line.startswith("workflow_complete "):
            if completion is not None:
                raise ValueError(f"duplicate workflow completion in {path.name}")
            completion = parse_key_value_record(
                line, "workflow_complete", path, line_number
            )
            expected_fields = {
                "frames",
                "groups",
                "nonce",
                "group_filter",
                "frame_filter",
                "channel",
                "serialization",
            }
            if set(completion) != expected_fields:
                raise ValueError(
                    f"unexpected workflow_complete fields in {path.name}:{line_number}"
                )

    if completion is None:
        raise ValueError(f"missing workflow completion in {path.name}")
    group = parse_ascii_decimal(
        completion["group_filter"],
        f"workflow group_filter in {path.name}",
        1,
        WORKFLOW_GROUP_COUNT,
    )
    index = parse_ascii_decimal(
        completion["frame_filter"],
        f"workflow frame_filter in {path.name}",
        1,
        WORKFLOW_FRAME_COUNT,
    )
    expected_group = EXPECTED_WORKFLOW_STEPS[index - 1][0]
    if group != expected_group:
        raise ValueError(f"workflow frame {index} has unexpected group {group}")
    expected_indices = [index]
    if completion["frames"] != "1":
        raise ValueError(f"workflow frame count is not one in {path.name}")
    if completion["groups"] != "1":
        raise ValueError(f"workflow group count is not one in {path.name}")
    nonce = parse_ascii_decimal(
        completion["nonce"], f"workflow nonce in {path.name}", 1, 4095
    )
    completion_channel = parse_ascii_decimal(
        completion["channel"], f"workflow channel in {path.name}", 1, 255
    )
    if completion["serialization"] != "runner-dp-status-reclaim-gate-required":
        raise ValueError(f"workflow serialization metadata mismatch in {path.name}")
    if (
        sorted(packet_fields) != expected_indices
        or sorted(frame_fields) != expected_indices
    ):
        raise ValueError(f"workflow frame {index} does not match its fixed step")
    expected_order = [
        item
        for index in expected_indices
        for item in (("packet", index), ("frame", index))
    ]
    if record_order != expected_order:
        raise ValueError(f"workflow records are out of order in {path.name}")

    records = []
    for index in expected_indices:
        packet_metadata = packet_fields[index]
        metadata = frame_fields[index]
        try:
            packet = bytes.fromhex(packet_metadata["packet_hex"])
        except ValueError as error:
            raise ValueError(
                f"invalid workflow packet hex for index {index} in {path.name}: {error}"
            ) from error
        if packet.hex() != packet_metadata["packet_hex"]:
            raise ValueError(
                f"non-canonical workflow packet hex for index {index} in {path.name}"
            )
        if not packet.startswith(WORKFLOW_RADIOTAP):
            raise ValueError(
                f"workflow radiotap mismatch for index {index} in {path.name}"
            )
        frame = packet[len(WORKFLOW_RADIOTAP) :]
        _, injection_radiotap = radiotap_header(packet)
        if len(frame) < 2:
            raise ValueError(f"short workflow frame for index {index} in {path.name}")
        sent_bytes = parse_ascii_decimal(
            metadata["bytes"], f"workflow bytes for index {index}", 1, 65535
        )
        expected_bytes = parse_ascii_decimal(
            metadata["expected"],
            f"workflow expected bytes for index {index}",
            1,
            65535,
        )
        frame_len = parse_ascii_decimal(
            metadata["frame_len"],
            f"workflow frame_len for index {index}",
            1,
            65535,
        )
        expected_group, trigger, name, expected_type, expected_subtype, expected_len = (
            EXPECTED_WORKFLOW_STEPS[index - 1]
        )
        if sent_bytes != expected_bytes or sent_bytes != len(packet):
            raise ValueError(f"workflow sender byte count mismatch for index {index}")
        if frame_len != len(frame) or frame_len != expected_len:
            raise ValueError(f"workflow sender frame length mismatch for index {index}")
        if metadata["sendto_count"] != "1":
            raise ValueError(f"workflow sender count is not one for index {index}")
        if not re.fullmatch(r"[0-9]+\.[0-9]{9}", metadata["monotonic_timestamp"]):
            raise ValueError(f"workflow timestamp is invalid for index {index}")
        frame_channel = parse_ascii_decimal(
            metadata["channel"], f"workflow frame channel for index {index}", 1, 255
        )
        packet_channel = parse_ascii_decimal(
            packet_metadata["channel"],
            f"workflow packet channel for index {index}",
            1,
            255,
        )
        if frame_channel != completion_channel or packet_channel != completion_channel:
            raise ValueError(f"workflow channel metadata mismatch for index {index}")
        frame_control = int.from_bytes(frame[:2], "little")
        if metadata["fc"] != f"0x{frame_control:04x}":
            raise ValueError(f"workflow frame control mismatch for index {index}")
        if (
            parse_ascii_decimal(
                metadata["type"], f"workflow type for index {index}", 0, 3
            )
            != expected_type
            or parse_ascii_decimal(
                metadata["subtype"], f"workflow subtype for index {index}", 0, 15
            )
            != expected_subtype
        ):
            raise ValueError(f"workflow type/subtype mismatch for index {index}")
        if ((frame_control >> 2) & 3) != expected_type or (
            (frame_control >> 4) & 15
        ) != expected_subtype:
            raise ValueError(f"workflow packet type/subtype mismatch for index {index}")
        if name == "probe-response" and (
            len(frame) <= 62 or frame[62] != completion_channel
        ):
            raise ValueError(
                f"workflow probe-response DS channel mismatch for index {index}"
            )
        records.append(
            {
                "sender_log": path.name,
                "variant": f"workflow-{index:02d}-g{expected_group:02d}-{name}",
                "frame": frame,
                "packet_hex": packet_metadata["packet_hex"],
                "index": index,
                "group": expected_group,
                "trigger": trigger,
                "name": name,
                "nonce": nonce,
                "fc": metadata["fc"],
                "frame_len": frame_len,
                "channel": completion_channel,
                "send_order": 32 + index,
                "injection_radiotap": injection_radiotap,
            }
        )
    return group, records


def validate_device_matrix(matrix: pathlib.Path, expected):
    lines = matrix.read_text(errors="replace").splitlines()
    if not lines or tuple(lines[0].split("\t")) != DEVICE_MATRIX_HEADER:
        raise ValueError("device frame matrix has an unexpected header")
    if len(lines) != len(EXPECTED_VARIANTS) + 1:
        raise ValueError(
            f"device frame matrix has {len(lines) - 1} rows, expected "
            f"{len(EXPECTED_VARIANTS)}"
        )
    nonces = set()
    for row_number, (line, sender) in enumerate(zip(lines[1:], expected), 1):
        fields = line.split("\t")
        if len(fields) != len(DEVICE_MATRIX_HEADER):
            raise ValueError(f"device matrix row {row_number} has invalid width")
        row = dict(zip(DEVICE_MATRIX_HEADER, fields))
        variant = EXPECTED_VARIANTS[row_number - 1]
        if row["index"] != f"{row_number:02d}" or row["variant"] != variant:
            raise ValueError(f"device matrix row {row_number} identity mismatch")
        metadata = sender["metadata"]
        if row["nonce"] != metadata["nonce"] or not row["nonce"].isdigit():
            raise ValueError(f"device matrix nonce mismatch for {variant}")
        nonce = int(row["nonce"])
        if not 1 <= nonce <= 4095:
            raise ValueError(f"device matrix nonce is out of range for {variant}")
        nonces.add(nonce)
        if not re.fullmatch(r"[0-9a-fA-F]+", row["cookie"]):
            raise ValueError(f"device matrix cookie is invalid for {variant}")
        parse_ascii_decimal(row["vdev"], f"device matrix vdev for {variant}", 0, 255)
        parse_ascii_decimal(
            row["generation"],
            f"device matrix generation for {variant}",
            1,
            (1 << 32) - 1,
        )
        parse_ascii_decimal(
            row["peer_id"], f"device matrix peer for {variant}", 0, 65535
        )
        tx_status = parse_ascii_decimal(
            row["tx_status"], f"device matrix DP status for {variant}", 0, (1 << 32) - 1
        )
        if tx_status != 0:
            raise ValueError(f"device matrix TX was not ACKed for {variant}")
        if row["status_valid"] != "1" or row["rate_valid"] not in {"0", "1"}:
            raise ValueError(f"device matrix completion proof is invalid for {variant}")
        release_src = parse_ascii_decimal(
            row["release_src"], f"device matrix release source for {variant}", 0, 3
        )
        if release_src != 3:
            raise ValueError(f"device matrix completion was not FW-released for {variant}")
        parse_ascii_decimal(
            row["transmit_count"], f"device matrix transmit count for {variant}", 1, 127
        )
        parse_ascii_decimal(
            row["ppdu_id"], f"device matrix PPDU id for {variant}", 1, (1 << 24) - 1
        )
        if row["reclaimed"] != "1":
            raise ValueError(f"device matrix DP ownership is incomplete for {variant}")
        if row["fc"].lower() != metadata["fc"].lower().removeprefix("0x"):
            raise ValueError(f"device matrix frame control mismatch for {variant}")
        if row["frame_len"] != metadata["frame_len"]:
            raise ValueError(f"device matrix frame length mismatch for {variant}")
        expected_hash = hashlib.sha256(sender["packet_hex"].encode("ascii")).hexdigest()
        if row["packet_hex_sha256"] != expected_hash:
            raise ValueError(f"device matrix packet hash mismatch for {variant}")
        send_order = parse_ascii_decimal(
            row["send_order"], f"fixed send order for {variant}", 1, TOTAL_FRAME_COUNT
        )
        expected_order = (
            row_number if row_number < len(EXPECTED_VARIANTS) else TOTAL_FRAME_COUNT
        )
        if send_order != expected_order:
            raise ValueError(
                f"fixed send order mismatch for {variant}: {send_order} != {expected_order}"
            )
        sender["send_order"] = send_order
    if len(nonces) != 1:
        raise ValueError("device frame matrix does not use one run nonce")


def validate_workflow_matrix(matrix: pathlib.Path, expected, fixed_nonce: int):
    lines = matrix.read_text(errors="replace").splitlines()
    if not lines or tuple(lines[0].split("\t")) != WORKFLOW_MATRIX_HEADER:
        raise ValueError("workflow matrix has an unexpected header")
    if len(lines) != WORKFLOW_FRAME_COUNT + 1:
        raise ValueError(
            f"workflow matrix has {len(lines) - 1} rows, expected "
            f"{WORKFLOW_FRAME_COUNT}"
        )
    nonces = set()
    vdevs = set()
    generations = set()
    peers = set()
    for row_number, (line, sender) in enumerate(zip(lines[1:], expected), 1):
        fields = line.split("\t")
        if len(fields) != len(WORKFLOW_MATRIX_HEADER):
            raise ValueError(f"workflow matrix row {row_number} has invalid width")
        row = dict(zip(WORKFLOW_MATRIX_HEADER, fields))
        if (
            row["index"] != f"{row_number:02d}"
            or row["group"] != str(sender["group"])
            or row["trigger"] != sender["trigger"]
            or row["name"] != sender["name"]
        ):
            raise ValueError(f"workflow matrix row {row_number} identity mismatch")
        nonce = parse_ascii_decimal(
            row["nonce"], f"workflow matrix nonce at row {row_number}", 1, 4095
        )
        if nonce != sender["nonce"]:
            raise ValueError(f"workflow matrix nonce mismatch at row {row_number}")
        nonces.add(nonce)
        if not re.fullmatch(r"[0-9a-fA-F]+", row["cookie"]):
            raise ValueError(f"workflow cookie is invalid at row {row_number}")
        vdev = parse_ascii_decimal(
            row["vdev"], f"workflow vdev at row {row_number}", 0, 255
        )
        vdevs.add(vdev)
        parse_ascii_decimal(
            row["generation"],
            f"workflow generation at row {row_number}",
            1,
            (1 << 32) - 1,
        )
        parse_ascii_decimal(
            row["peer_id"], f"workflow peer at row {row_number}", 0, 65535
        )
        tx_status = parse_ascii_decimal(
            row["tx_status"],
            f"workflow DP status at row {row_number}",
            0,
            (1 << 32) - 1,
        )
        if tx_status != 0:
            raise ValueError(f"workflow TX was not ACKed at row {row_number}")
        if row["status_valid"] != "1" or row["rate_valid"] not in {"0", "1"}:
            raise ValueError(f"workflow completion proof is invalid at row {row_number}")
        release_src = parse_ascii_decimal(
            row["release_src"], f"workflow release source at row {row_number}", 0, 3
        )
        if release_src != 3:
            raise ValueError(f"workflow completion was not FW-released at row {row_number}")
        parse_ascii_decimal(
            row["transmit_count"], f"workflow transmit count at row {row_number}", 1, 127
        )
        parse_ascii_decimal(
            row["ppdu_id"], f"workflow PPDU id at row {row_number}", 1, (1 << 24) - 1
        )
        if row["reclaimed"] != "1":
            raise ValueError(f"workflow DP ownership is incomplete at row {row_number}")
        generations.add(int(row["generation"]))
        peers.add(int(row["peer_id"]))
        if not re.fullmatch(r"[0-9a-fA-F]{4}", row["fc"]) or row[
            "fc"
        ].lower() != sender["fc"].removeprefix("0x"):
            raise ValueError(f"workflow frame control mismatch at row {row_number}")
        if row["frame_len"] != str(sender["frame_len"]):
            raise ValueError(f"workflow frame length mismatch at row {row_number}")
        expected_hash = hashlib.sha256(sender["packet_hex"].encode("ascii")).hexdigest()
        if row["packet_hex_sha256"] != expected_hash:
            raise ValueError(f"workflow packet hash mismatch at row {row_number}")
        channel = parse_ascii_decimal(
            row["channel"], f"workflow channel at row {row_number}", 1, 255
        )
        if channel != sender["channel"]:
            raise ValueError(f"workflow channel mismatch at row {row_number}")
        send_order = parse_ascii_decimal(
            row["send_order"],
            f"workflow send order at row {row_number}",
            1,
            TOTAL_FRAME_COUNT,
        )
        if send_order != 32 + row_number or send_order != sender["send_order"]:
            raise ValueError(f"workflow send order mismatch at row {row_number}")
    if nonces != {fixed_nonce}:
        raise ValueError("workflow and fixed matrices do not use one shared nonce")
    if len(vdevs) != 1:
        raise ValueError("workflow matrix uses more than one helper vdev")
    if len(generations) != 1 or len(peers) != 1:
        raise ValueError("workflow matrix changes helper generation or peer")


def load_workflow_frames(
    device_output: pathlib.Path, workflow_matrix: pathlib.Path, fixed_nonce: int
):
    paths = []
    for path in sorted(device_output.glob("workflow-frame-[0-9][0-9].log")):
        if not path.is_file():
            continue
        text = path.read_text(errors="replace")
        if "workflow_packet " in text and "workflow_complete " in text:
            paths.append(path)
    if len(paths) != WORKFLOW_FRAME_COUNT:
        raise ValueError(
            f"found {len(paths)} workflow-frame logs, expected {WORKFLOW_FRAME_COUNT}"
        )
    records_by_index = {}
    for path in paths:
        _, records = parse_workflow_log(path)
        if len(records) != 1:
            raise ValueError(f"workflow log {path.name} is not single-frame")
        record = records[0]
        if record["index"] in records_by_index:
            raise ValueError(f"duplicate workflow frame {record['index']}")
        records_by_index[record["index"]] = record
    expected = [records_by_index[index] for index in sorted(records_by_index)]
    if len(expected) != WORKFLOW_FRAME_COUNT or [
        record["index"] for record in expected
    ] != list(range(1, WORKFLOW_FRAME_COUNT + 1)):
        raise ValueError("workflow logs do not cover global indexes 1..34")
    if {record["group"] for record in expected} != set(
        range(1, WORKFLOW_GROUP_COUNT + 1)
    ):
        raise ValueError("workflow logs do not cover groups 1..17")
    if {record["nonce"] for record in expected} != {fixed_nonce}:
        raise ValueError("workflow logs and fixed matrix do not use one shared nonce")
    validate_workflow_matrix(workflow_matrix, expected, fixed_nonce)
    return expected


def load_expected_frames(device_output: pathlib.Path, device_matrix: pathlib.Path):
    if set(EXPECTED_FIXED_TYPE_SUBTYPE) != set(EXPECTED_VARIANTS):
        raise ValueError("fixed type/subtype oracle does not cover exactly 33 variants")
    expected_names = [
        f"send-{index:02d}-{variant}.log"
        for index, variant in enumerate(EXPECTED_VARIANTS, 1)
    ]
    actual_paths = []
    for path in sorted(device_output.glob("send-[0-9][0-9]-*.log")):
        text = path.read_text(errors="replace")
        if text.startswith("packet_hex=") and "\nvariant=" in text:
            actual_paths.append(path)
    if [path.name for path in actual_paths] != expected_names:
        raise ValueError("sender log names do not match the fixed 33-frame matrix")
    parsed = [parse_sender_log(path) for path in actual_paths]
    for variant, sender in zip(EXPECTED_VARIANTS, parsed):
        metadata = sender["metadata"]
        if metadata["variant"] != variant:
            raise ValueError(f"sender variant mismatch for {sender['path'].name}")
        expected_type, expected_subtype = EXPECTED_FIXED_TYPE_SUBTYPE[variant]
        reported_type = parse_ascii_decimal(
            metadata["type"], f"fixed sender type for {variant}", 0, 3
        )
        reported_subtype = parse_ascii_decimal(
            metadata["subtype"], f"fixed sender subtype for {variant}", 0, 15
        )
        frame_control = int.from_bytes(sender["frame"][:2], "little")
        if (
            reported_type != expected_type
            or reported_subtype != expected_subtype
            or ((frame_control >> 2) & 3) != expected_type
            or ((frame_control >> 4) & 15) != expected_subtype
        ):
            raise ValueError(f"fixed type/subtype oracle mismatch for {variant}")
        signature_offset = 2 if expected_type == 1 else 22
        signature = int.from_bytes(
            sender["frame"][signature_offset : signature_offset + 2], "little"
        )
        if metadata["signature"].lower() != f"0x{signature:04x}":
            raise ValueError(f"fixed sender signature mismatch for {variant}")
    if len({sender["packet"] for sender in parsed}) != len(parsed):
        raise ValueError("the fixed sender matrix contains duplicate packets")
    if len({sender["metadata"]["interface_mac"] for sender in parsed}) != 1:
        raise ValueError("sender interface MAC changed during the matrix")
    if len({sender["metadata"]["peer_mac"] for sender in parsed}) != 1:
        raise ValueError("sender peer MAC changed during the matrix")
    validate_device_matrix(device_matrix, parsed)
    expected = [
        {
            "sender_log": sender["path"].name,
            "variant": variant,
            "frame": sender["frame"],
            "nonce": int(sender["metadata"]["nonce"]),
            "send_order": sender["send_order"],
            "injection_radiotap": sender["injection_radiotap"],
        }
        for variant, sender in zip(EXPECTED_VARIANTS, parsed)
    ]
    return expected


def direct_dp_ownership_counts(*matrices: pathlib.Path):
    counts = {"rows": 0, "status_valid": 0, "reclaimed": 0}
    for matrix in matrices:
        if matrix is None:
            continue
        lines = matrix.read_text(errors="replace").splitlines()
        header = lines[0].split("\t")
        status_index = header.index("status_valid")
        reclaim_index = header.index("reclaimed")
        for line in lines[1:]:
            fields = line.split("\t")
            counts["rows"] += 1
            counts["status_valid"] += fields[status_index] == "1"
            counts["reclaimed"] += fields[reclaim_index] == "1"
    return counts


def maximum_ordered_matches(expected, captured_mpdus):
    expected_frames = [record["frame"] for record in expected]
    scores = array("B", [0]) * (len(expected_frames) + 1)
    paths = [None] * (len(expected_frames) + 1)

    # Keep one LCS row. A path node is created only when a score strictly
    # improves, so reconstruction storage is bounded by the small expected set.
    for packet_index, mpdu in enumerate(captured_mpdus):
        diagonal_score = 0
        diagonal_path = None
        for expected_position, frame in enumerate(expected_frames, 1):
            previous_score = scores[expected_position]
            previous_path = paths[expected_position]
            best_score = previous_score
            best_path = previous_path

            if scores[expected_position - 1] > best_score:
                best_score = scores[expected_position - 1]
                best_path = paths[expected_position - 1]
            if mpdu == frame and diagonal_score + 1 > best_score:
                best_score = diagonal_score + 1
                best_path = (
                    diagonal_path,
                    expected_position - 1,
                    packet_index,
                )

            scores[expected_position] = best_score
            paths[expected_position] = best_path
            diagonal_score = previous_score
            diagonal_path = previous_path

    matched_packet_indexes = [None] * len(expected_frames)
    path = paths[-1]
    while path is not None:
        path, expected_index, packet_index = path
        matched_packet_indexes[expected_index] = packet_index

    matched_indexes = [
        packet_index
        for packet_index in matched_packet_indexes
        if packet_index is not None
    ]
    if len(matched_indexes) != scores[-1] or any(
        left >= right for left, right in zip(matched_indexes, matched_indexes[1:])
    ):
        raise ValueError("internal ordered frame matching invariant failed")
    return matched_packet_indexes


def expected_legacy_rate(record, frequency_mhz: int):
    requested_rate = record["injection_radiotap"].get("rate_500kbps")
    if requested_rate is None:
        return None
    raise ValueError(
        f"sender {record['sender_log']} requested RATE, but AP/RAW direct-DP "
        "has no proven per-packet rate mapping"
    )


def matrix_metadata(metadata, key, *, hexadecimal=False):
    value = metadata.get(key)
    if value is None:
        return "unavailable"
    return f"0x{value:x}" if hexadecimal else str(value)


def phy_metadata_verdict(record, capture_metadata, frequency_mhz, matched):
    expected_rate = expected_legacy_rate(record, frequency_mhz)
    if expected_rate is None:
        return None, "RATE_UNSPECIFIED"
    if not matched:
        return expected_rate, "MISSING_MPDU"
    if (
        capture_metadata.get("rate_500kbps") is None
        or capture_metadata.get("channel_frequency_mhz") is None
    ):
        return expected_rate, "METADATA_UNAVAILABLE"
    if (
        capture_metadata["rate_500kbps"] != expected_rate
        or capture_metadata["channel_frequency_mhz"] != frequency_mhz
    ):
        return expected_rate, "MISMATCH"
    return expected_rate, "PASS"


def selftest_expect_value_error(label, function):
    try:
        function()
    except ValueError:
        return
    raise ValueError(f"selftest {label} did not reject malformed input")


def selftest_classic_capture(packet, endian="<", linktype=DLT_IEEE802_11_RADIO):
    magic = b"\xd4\xc3\xb2\xa1" if endian == "<" else b"\xa1\xb2\xc3\xd4"
    header = magic + struct.pack(endian + "HHIIII", 2, 4, 0, 0, 65535, linktype)
    record = struct.pack(endian + "IIII", 1, 2, len(packet), len(packet))
    return header + record + packet


def selftest_pcapng_capture(packet, endian="<"):
    def block(block_type, body):
        block_len = 12 + len(body)
        return (
            struct.pack(endian + "II", block_type, block_len)
            + body
            + struct.pack(endian + "I", block_len)
        )

    section = block(0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1))
    interface = block(1, struct.pack(endian + "HHI", DLT_IEEE802_11_RADIO, 0, 65535))
    padding = b"\0" * ((-len(packet)) & 3)
    enhanced = block(
        6,
        struct.pack(endian + "IIIII", 0, 0, 1, len(packet), len(packet))
        + packet
        + padding,
    )
    return section + interface + enhanced


def run_selftest():
    tests = 0

    def check(label, condition):
        nonlocal tests
        if not condition:
            raise ValueError(f"selftest {label} failed")
        tests += 1

    mpdu_a = bytes.fromhex("40000000ffffffffffff0213375a117dffffffffffff1000")
    mpdu_b = bytes.fromhex("d40000000213375a117d")
    plain_radiotap = bytes.fromhex("0000080000000000") + mpdu_a

    classic_le = selftest_classic_capture(plain_radiotap, "<")
    classic_be = selftest_classic_capture(plain_radiotap, ">")
    check("classic-le", classic_pcap_packets(classic_le) == [(127, plain_radiotap)])
    check("classic-be", classic_pcap_packets(classic_be) == [(127, plain_radiotap)])
    check("classic-detection", classic_pcap_packets(b"not-a-pcap") is None)
    selftest_expect_value_error(
        "classic-truncation", lambda: classic_pcap_packets(classic_le[:-1])
    )
    tests += 1
    selftest_expect_value_error(
        "classic-linktype",
        lambda: classic_pcap_packets(
            selftest_classic_capture(plain_radiotap, "<", 105)
        ),
    )
    tests += 1

    pcapng_le = selftest_pcapng_capture(plain_radiotap, "<")
    pcapng_be = selftest_pcapng_capture(plain_radiotap, ">")
    check("pcapng-le", pcapng_packets(pcapng_le) == [(127, plain_radiotap)])
    check("pcapng-be", pcapng_packets(pcapng_be) == [(127, plain_radiotap)])
    check("pcapng-detection", pcapng_packets(b"not-a-pcapng") is None)
    broken_pcapng = pcapng_le[:-1] + bytes([pcapng_le[-1] ^ 1])
    selftest_expect_value_error("pcapng-trailer", lambda: pcapng_packets(broken_pcapng))
    tests += 1

    check(
        "radiotap-plain",
        radiotap_mpdu(DLT_IEEE802_11_RADIO, plain_radiotap) == mpdu_a,
    )
    rich_header = bytearray(25)
    rich_header[2:4] = (25).to_bytes(2, "little")
    rich_header[4:8] = sum(1 << field for field in (0, 1, 2, 3, 5, 6, 11)).to_bytes(
        4, "little"
    )
    rich_header[8:16] = (0x1122334455667788).to_bytes(8, "little")
    rich_header[16] = 0
    rich_header[17] = 12
    rich_header[18:20] = (5745).to_bytes(2, "little")
    rich_header[20:22] = (0x0140).to_bytes(2, "little")
    rich_header[22] = (-42) & 0xFF
    rich_header[23] = (-95) & 0xFF
    rich_header[24] = 1
    rich_record = radiotap_record(DLT_IEEE802_11_RADIO, bytes(rich_header) + mpdu_a)
    check(
        "radiotap-rich-metadata",
        rich_record is not None
        and rich_record["mpdu"] == mpdu_a
        and rich_record["metadata"]["tsft"] == 0x1122334455667788
        and rich_record["metadata"]["rate_500kbps"] == 12
        and rich_record["metadata"]["channel_frequency_mhz"] == 5745
        and rich_record["metadata"]["channel_flags"] == 0x0140
        and rich_record["metadata"]["signal_dbm"] == -42
        and rich_record["metadata"]["noise_dbm"] == -95
        and rich_record["metadata"]["antenna"] == 1,
    )
    selftest_expect_value_error(
        "radiotap-truncated-metadata",
        lambda: radiotap_record(
            DLT_IEEE802_11_RADIO,
            bytes(rich_header[:2] + (24).to_bytes(2, "little") + rich_header[4:])
            + mpdu_a,
        ),
    )
    tests += 1
    fcs = struct.pack("<I", binascii.crc32(mpdu_a) & 0xFFFFFFFF)
    fcs_radiotap = bytes.fromhex("000009000200000010") + mpdu_a + fcs
    check(
        "radiotap-valid-fcs",
        radiotap_mpdu(DLT_IEEE802_11_RADIO, fcs_radiotap) == mpdu_a,
    )
    bad_fcs = fcs[:-1] + bytes([fcs[-1] ^ 1])
    check(
        "radiotap-invalid-fcs",
        radiotap_mpdu(
            DLT_IEEE802_11_RADIO,
            bytes.fromhex("000009000200000010") + mpdu_a + bad_fcs,
        )
        is None,
    )
    check(
        "radiotap-badfcs-flag",
        radiotap_mpdu(
            DLT_IEEE802_11_RADIO,
            bytes.fromhex("000009000200000040") + mpdu_a,
        )
        is None,
    )
    selftest_expect_value_error(
        "radiotap-missing-fcs",
        lambda: radiotap_mpdu(
            DLT_IEEE802_11_RADIO, bytes.fromhex("0000090002000000100001")
        ),
    )
    tests += 1
    selftest_expect_value_error(
        "radiotap-version",
        lambda: radiotap_mpdu(
            DLT_IEEE802_11_RADIO, bytes.fromhex("0100080000000000") + mpdu_a
        ),
    )
    tests += 1
    selftest_expect_value_error(
        "radiotap-length",
        lambda: radiotap_mpdu(
            DLT_IEEE802_11_RADIO, bytes.fromhex("0000070000000000") + mpdu_a
        ),
    )
    tests += 1

    expected = [{"frame": mpdu_a}, {"frame": mpdu_b}, {"frame": mpdu_a}]
    check(
        "ordered-match",
        maximum_ordered_matches(
            expected, [b"noise", mpdu_a, b"noise-2", mpdu_b, mpdu_a]
        )
        == [1, 3, 4],
    )
    check(
        "ordered-missing",
        maximum_ordered_matches(expected, [mpdu_b]) == [None, 0, None],
    )
    check(
        "expected-rate-not-requested",
        expected_legacy_rate({"sender_log": "selftest", "injection_radiotap": {}}, 5745)
        is None,
    )
    selftest_expect_value_error(
        "expected-rate-fail-closed",
        lambda: expected_legacy_rate(
            {
                "sender_log": "selftest",
                "injection_radiotap": {"rate_500kbps": 2},
            },
            5745,
        ),
    )
    tests += 1
    phy_record = {
        "sender_log": "selftest",
        "injection_radiotap": {},
    }
    check(
        "phy-metadata-rate-unspecified",
        phy_metadata_verdict(
            phy_record,
            {"rate_500kbps": 12, "channel_frequency_mhz": 5745},
            5745,
            True,
        )
        == (None, "RATE_UNSPECIFIED"),
    )

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = pathlib.Path(temp_dir)
        fixed_expected = []
        fixed_rows = ["\t".join(DEVICE_MATRIX_HEADER)]
        for row_number, variant in enumerate(EXPECTED_VARIANTS, 1):
            frame_type, subtype = EXPECTED_FIXED_TYPE_SUBTYPE[variant]
            fc = (frame_type << 2) | (subtype << 4)
            packet_hex = f"{row_number:02x}"
            metadata = {
                "nonce": "321",
                "fc": f"0x{fc:04x}",
                "frame_len": "24",
            }
            fixed_expected.append({"metadata": metadata, "packet_hex": packet_hex})
            send_order = row_number if row_number < len(EXPECTED_VARIANTS) else 67
            fixed_rows.append(
                "\t".join(
                    (
                        f"{row_number:02d}",
                        variant,
                        "321",
                        f"{0xF000 | row_number:04x}",
                        "7",
                        str(1 + (row_number >= 19) + (row_number >= 26)),
                        "42",
                        "0",
                        "1",
                        "0",
                        "3",
                        "1",
                        str(2048 + row_number),
                        "1",
                        f"{fc:04x}",
                        "24",
                        hashlib.sha256(packet_hex.encode("ascii")).hexdigest(),
                        str(send_order),
                    )
                )
            )
        fixed_matrix = temp_path / "fixed.tsv"
        fixed_matrix.write_text("\n".join(fixed_rows) + "\n")
        validate_device_matrix(fixed_matrix, fixed_expected)
        check(
            "direct-dp-fixed-matrix",
            direct_dp_ownership_counts(fixed_matrix)
            == {"rows": 33, "status_valid": 33, "reclaimed": 33},
        )
        bad_fixed = temp_path / "fixed-bad.tsv"
        bad_fixed_rows = fixed_rows.copy()
        bad_fields = bad_fixed_rows[1].split("\t")
        bad_fields[DEVICE_MATRIX_HEADER.index("reclaimed")] = "0"
        bad_fixed_rows[1] = "\t".join(bad_fields)
        bad_fixed.write_text("\n".join(bad_fixed_rows) + "\n")
        selftest_expect_value_error(
            "direct-dp-fixed-missing-reclaim",
            lambda: validate_device_matrix(bad_fixed, fixed_expected),
        )
        tests += 1
        bad_fixed_rows = fixed_rows.copy()
        bad_fields = bad_fixed_rows[1].split("\t")
        bad_fields[DEVICE_MATRIX_HEADER.index("transmit_count")] = "0"
        bad_fixed_rows[1] = "\t".join(bad_fields)
        bad_fixed.write_text("\n".join(bad_fixed_rows) + "\n")
        selftest_expect_value_error(
            "direct-dp-fixed-no-transmit",
            lambda: validate_device_matrix(bad_fixed, fixed_expected),
        )
        tests += 1
        bad_fixed_rows = fixed_rows.copy()
        bad_fields = bad_fixed_rows[1].split("\t")
        bad_fields[DEVICE_MATRIX_HEADER.index("release_src")] = "0"
        bad_fixed_rows[1] = "\t".join(bad_fields)
        bad_fixed.write_text("\n".join(bad_fixed_rows) + "\n")
        selftest_expect_value_error(
            "direct-dp-fixed-non-fw-release",
            lambda: validate_device_matrix(bad_fixed, fixed_expected),
        )
        tests += 1

        workflow_expected = []
        workflow_rows = ["\t".join(WORKFLOW_MATRIX_HEADER)]
        for row_number, step in enumerate(EXPECTED_WORKFLOW_STEPS, 1):
            group, trigger, name, frame_type, subtype, frame_len = step
            fc = (frame_type << 2) | (subtype << 4)
            packet_hex = f"aa{row_number:02x}"
            workflow_expected.append(
                {
                    "group": group,
                    "trigger": trigger,
                    "name": name,
                    "nonce": 321,
                    "fc": f"0x{fc:04x}",
                    "frame_len": frame_len,
                    "packet_hex": packet_hex,
                    "channel": 149,
                    "send_order": 32 + row_number,
                }
            )
            workflow_rows.append(
                "\t".join(
                    (
                        f"{row_number:02d}",
                        str(group),
                        trigger,
                        name,
                        "321",
                        f"{0xF080 | row_number:04x}",
                        "8",
                        "9",
                        "43",
                        "0",
                        "1",
                        "0",
                        "3",
                        "1",
                        str(4096 + row_number),
                        "1",
                        f"{fc:04x}",
                        str(frame_len),
                        hashlib.sha256(packet_hex.encode("ascii")).hexdigest(),
                        "149",
                        str(32 + row_number),
                    )
                )
            )
        workflow_matrix = temp_path / "workflow.tsv"
        workflow_matrix.write_text("\n".join(workflow_rows) + "\n")
        validate_workflow_matrix(workflow_matrix, workflow_expected, 321)
        check(
            "direct-dp-workflow-matrix",
            direct_dp_ownership_counts(workflow_matrix)
            == {"rows": 34, "status_valid": 34, "reclaimed": 34},
        )
        bad_workflow = temp_path / "workflow-bad.tsv"
        bad_workflow_rows = workflow_rows.copy()
        bad_fields = bad_workflow_rows[2].split("\t")
        bad_fields[WORKFLOW_MATRIX_HEADER.index("generation")] = "10"
        bad_workflow_rows[2] = "\t".join(bad_fields)
        bad_workflow.write_text("\n".join(bad_workflow_rows) + "\n")
        selftest_expect_value_error(
            "direct-dp-workflow-generation-drift",
            lambda: validate_workflow_matrix(bad_workflow, workflow_expected, 321),
        )
        tests += 1

    print(f"selftest_passed={tests}")
    return 0


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="mode", required=True)
    device_parser = subparsers.add_parser("device")
    device_parser.add_argument("device_output", type=pathlib.Path)
    device_parser.add_argument("device_matrix", type=pathlib.Path)
    device_parser.add_argument("--workflow-matrix", type=pathlib.Path)
    ota_parser = subparsers.add_parser("ota")
    ota_parser.add_argument("pcap", type=pathlib.Path)
    ota_parser.add_argument("device_output", type=pathlib.Path)
    ota_parser.add_argument("device_matrix", type=pathlib.Path)
    ota_parser.add_argument("ota_matrix", type=pathlib.Path)
    ota_parser.add_argument("--workflow-matrix", type=pathlib.Path)
    ota_parser.add_argument("--expected-frequency-mhz", type=int)
    ota_parser.add_argument("--require-phy-metadata", action="store_true")
    subparsers.add_parser("selftest")
    args = parser.parse_args()

    if args.mode == "selftest":
        return run_selftest()

    expected = load_expected_frames(args.device_output, args.device_matrix)
    fixed_nonces = {record["nonce"] for record in expected}
    if len(fixed_nonces) != 1:
        raise ValueError("fixed sender logs do not use one run nonce")
    workflow_expected = []
    if args.workflow_matrix is not None:
        workflow_expected = load_workflow_frames(
            args.device_output, args.workflow_matrix, fixed_nonces.pop()
        )
        expected.extend(workflow_expected)
        expected.sort(key=lambda record: record["send_order"])
        if [record["send_order"] for record in expected] != list(
            range(1, TOTAL_FRAME_COUNT + 1)
        ):
            raise ValueError("fixed/workflow send order is not exactly 1..67")
    if args.mode == "device":
        ownership_counts = direct_dp_ownership_counts(
            args.device_matrix, args.workflow_matrix
        )
        print(f"expected_frames={len(expected)}")
        if workflow_expected:
            print(f"workflow_expected_frames={len(workflow_expected)}")
            print("workflow_matrix_verdict=PASS")
        print(f"dp_event_rows={ownership_counts['rows']}")
        print(f"dp_status_valid_rows={ownership_counts['status_valid']}")
        print(f"dp_reclaimed_rows={ownership_counts['reclaimed']}")
        if ownership_counts["rows"] != len(expected):
            raise ValueError("DP matrix row count does not match expected frames")
        if ownership_counts["status_valid"] != len(expected):
            raise ValueError("DP matrix has a frame without valid TX status")
        if ownership_counts["reclaimed"] != len(expected):
            raise ValueError("DP matrix has a frame without reclaim")
        print("dp_ownership_verdict=PASS")
        print("device_matrix_verdict=PASS")
        return 0

    capture = args.pcap.read_bytes()
    packets = classic_pcap_packets(capture)
    capture_format = "pcap"
    if packets is None:
        packets = pcapng_packets(capture)
        capture_format = "pcapng"
    if packets is None:
        raise ValueError("capture is neither classic pcap nor pcapng")
    if args.require_phy_metadata and args.expected_frequency_mhz is None:
        raise ValueError("--require-phy-metadata requires --expected-frequency-mhz")
    if args.expected_frequency_mhz is not None and not (
        2300 <= args.expected_frequency_mhz <= 7125
    ):
        raise ValueError("expected frequency is outside 2300..7125 MHz")
    captured_records = []
    captured_mpdus = []
    rejected_packets = 0
    for linktype, packet in packets:
        record = radiotap_record(linktype, packet)
        if record is None:
            rejected_packets += 1
        else:
            captured_records.append(record)
            captured_mpdus.append(record["mpdu"])

    matched_packet_indexes = maximum_ordered_matches(expected, captured_mpdus)
    found = sum(index is not None for index in matched_packet_indexes)
    occurrence_counts = Counter(captured_mpdus)
    phy_failures = 0
    rows = [
        "send_order\tsender_log\tvariant\tframe_len\tmatched_packet_index"
        "\texact_mpdu_occurrences\texpected_rate_500kbps"
        "\tcaptured_rate_500kbps\texpected_frequency_mhz"
        "\tcaptured_frequency_mhz\tcaptured_channel_flags"
        "\tcaptured_signal_dbm\tcaptured_noise_dbm\tcaptured_antenna"
        "\tcaptured_fcs_present\tcaptured_fcs_valid"
        "\tcaptured_data_retries\tphy_metadata_verdict"
    ]
    for record, matched_index in zip(expected, matched_packet_indexes):
        sender_log = record["sender_log"]
        variant = record["variant"]
        frame = record["frame"]
        expected_rate = "not-requested"
        expected_frequency = (
            str(args.expected_frequency_mhz)
            if args.expected_frequency_mhz is not None
            else "not-requested"
        )
        capture_metadata = {}
        phy_verdict = "NOT_REQUESTED"
        if matched_index is not None:
            capture_metadata = captured_records[matched_index]["metadata"]
        if args.expected_frequency_mhz is not None:
            expected_rate_value, phy_verdict = phy_metadata_verdict(
                record,
                capture_metadata,
                args.expected_frequency_mhz,
                matched_index is not None,
            )
            expected_rate = (
                "not-requested"
                if expected_rate_value is None
                else str(expected_rate_value)
            )
            if args.require_phy_metadata and phy_verdict != "PASS":
                phy_failures += 1
        rows.append(
            f"{record['send_order']}\t{sender_log}\t{variant}\t{len(frame)}\t"
            f"{matched_index if matched_index is not None else 'missing'}\t"
            f"{occurrence_counts[frame]}\t{expected_rate}\t"
            f"{matrix_metadata(capture_metadata, 'rate_500kbps')}\t"
            f"{expected_frequency}\t"
            f"{matrix_metadata(capture_metadata, 'channel_frequency_mhz')}\t"
            f"{matrix_metadata(capture_metadata, 'channel_flags', hexadecimal=True)}\t"
            f"{matrix_metadata(capture_metadata, 'signal_dbm')}\t"
            f"{matrix_metadata(capture_metadata, 'noise_dbm')}\t"
            f"{matrix_metadata(capture_metadata, 'antenna')}\t"
            f"{matrix_metadata(capture_metadata, 'fcs_present')}\t"
            f"{matrix_metadata(capture_metadata, 'fcs_valid')}\t"
            f"{matrix_metadata(capture_metadata, 'data_retries')}\t"
            f"{phy_verdict}"
        )
    args.ota_matrix.write_text("\n".join(rows) + "\n")
    verdict = "PASS" if found == len(expected) and not phy_failures else "UNPROVEN"
    print(f"capture_format={capture_format}")
    print(f"captured_packets={len(packets)}")
    print(f"valid_radiotap_mpdus={len(captured_mpdus)}")
    print(f"bad_fcs_or_rejected_packets={rejected_packets}")
    print(f"expected_frames={len(expected)}")
    print(f"exact_frames_observed={found}")
    print(f"strict_phy_metadata_failures={phy_failures}")
    print(f"ota_verdict={verdict}")
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        print(f"ota_verifier_error={error}", file=sys.stderr)
        sys.exit(2)
