#!/usr/bin/env python3

"""Generate the offline Stage 1 frame/radiotap contract.

This file deliberately separates three questions which older test tools mixed:

* whether an input is structurally representable by a monitor packet;
* what the current v33 host parser is expected to do with it; and
* what evidence the final implementation still owes.

It does not access a device and it does not turn host acceptance into an OTA
claim.  Every generated packet is deterministic so a later device runner and
an independent-listener verifier can bind their evidence to the same case ID.
"""

from __future__ import annotations

import argparse
import binascii
import dataclasses
import hashlib
import json
import pathlib
import struct
import sys
import tempfile
from collections import Counter
from typing import Any, Iterable

SCHEMA_VERSION = 2
MAX_MPDU_LEN = 2348
BASE_RATE = 12  # 6 Mbps, valid on 2.4/5/6 GHz OFDM channels.
BASE_TX_FLAGS = 0
LEGACY_RATES = (2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108)
ACTION_CATEGORIES = tuple(range(19)) + (20, 21, 22, 23, 126, 127)
IE_BEARING_MGMT_SUBTYPES = {0, 1, 2, 3, 4, 5, 8, 10, 11, 12}
PAYLOAD_BOUNDARIES = ("empty", "one", "llc_snap", "max")

MGMT_NAMES = {
    0: "association_request",
    1: "association_response",
    2: "reassociation_request",
    3: "reassociation_response",
    4: "probe_request",
    5: "probe_response",
    6: "timing_advertisement",
    8: "beacon",
    9: "atim",
    10: "disassociation",
    11: "authentication",
    12: "deauthentication",
    13: "action",
    14: "action_no_ack",
}

MGMT_BODY_LENGTH = {
    0: 4, 1: 6, 2: 10, 3: 6, 4: 0, 5: 12, 6: 10,
    8: 12, 9: 0, 10: 2, 11: 6, 12: 2, 13: 2, 14: 2,
}

CONTROL_NAMES = {
    2: "trigger",
    3: "twt_ack",
    4: "beamforming_report_poll",
    5: "vht_he_eht_ranging_ndp_announcement",
    6: "control_extension",
    7: "control_wrapper",
    8: "block_ack_request",
    9: "block_ack",
    10: "ps_poll",
    11: "rts",
    12: "cts",
    13: "ack",
    14: "cf_end",
    15: "cf_end_cf_ack",
}

CONTROL_LENGTH = {2: 24, 3: 22, 4: 17, 5: 19, 6: 16, 7: 16, 8: 20,
                  9: 28, 10: 16, 11: 16, 12: 10, 13: 10, 14: 16, 15: 16}

CONTROL_EXTENSION = {
    2: "poll",
    3: "spr",
    4: "grant",
    5: "dmg_cts",
    6: "dmg_dts",
    7: "grant_ack",
    8: "ssw",
    9: "ssw_feedback",
    10: "ssw_ack",
}

CONTROL_EXTENSION_LENGTH = {2: 18, 3: 23, 4: 23, 5: 16, 6: 22,
                            7: 23, 8: 22, 9: 24, 10: 24}

DATA_NAMES = {
    0: "data", 1: "data_cf_ack", 2: "data_cf_poll",
    3: "data_cf_ack_cf_poll", 4: "null", 5: "cf_ack",
    6: "cf_poll", 7: "cf_ack_cf_poll", 8: "qos_data",
    9: "qos_data_cf_ack", 10: "qos_data_cf_poll",
    11: "qos_data_cf_ack_cf_poll", 12: "qos_null",
    13: "qos_cf_ack", 14: "qos_cf_poll",
    15: "qos_cf_ack_cf_poll",
}

DATA_PAYLOAD_SUBTYPES = {0, 1, 2, 3, 8, 9, 10, 11}

# Fixed radiotap fields: alignment, size, semantic direction.  Index 28 is a
# variable TLV stream and indices 29..31 are structural control bits.
RADIOTAP_FIXED: dict[int, tuple[int, int, str, str]] = {
    0: (8, 8, "rx_metadata", "tsft"),
    1: (1, 1, "bidirectional", "flags"),
    2: (1, 1, "bidirectional", "rate"),
    3: (2, 4, "bidirectional", "channel"),
    4: (2, 2, "rx_metadata", "fhss"),
    5: (1, 1, "rx_metadata", "dbm_antsignal"),
    6: (1, 1, "rx_metadata", "dbm_antnoise"),
    7: (2, 2, "rx_metadata", "lock_quality"),
    8: (2, 2, "tx_control", "tx_attenuation"),
    9: (2, 2, "tx_control", "db_tx_attenuation"),
    10: (1, 1, "tx_control", "dbm_tx_power"),
    11: (1, 1, "bidirectional", "antenna"),
    12: (1, 1, "rx_metadata", "db_antsignal"),
    13: (1, 1, "rx_metadata", "db_antnoise"),
    14: (2, 2, "rx_metadata", "rx_flags"),
    15: (2, 2, "tx_control_status", "tx_flags"),
    16: (1, 1, "tx_control", "rts_retries"),
    17: (1, 1, "tx_control", "data_retries"),
    18: (4, 8, "bidirectional", "xchannel"),
    19: (1, 3, "bidirectional", "mcs"),
    20: (4, 8, "rx_metadata", "ampdu_status"),
    21: (2, 12, "bidirectional", "vht"),
    22: (8, 12, "rx_metadata", "timestamp"),
    23: (2, 12, "bidirectional", "he"),
    24: (2, 12, "bidirectional", "he_mu"),
    25: (2, 6, "rx_metadata", "he_mu_other_user"),
    26: (1, 1, "rx_metadata", "zero_len_psdu"),
    27: (2, 4, "rx_metadata", "lsig"),
}

CURRENT_ACCEPTED_FIELDS = {1, 2, 3, 10, 11, 15, 17, 19, 21, 23}
CURRENT_EXPECTATION = {
    "parser_accept_backend_candidate": ("accepted", 0),
    "parser_accepts_opaque_non_pv0": ("accepted", 0),
    "parse_reject_eopnotsupp": ("rejected", -95),
    "parse_reject_eopnotsupp_before_vendor_decode": ("rejected", -95),
    "parse_reject_einval": ("rejected", -22),
    "parse_reject_ebadmsg": ("rejected", -74),
    "parse_reject_erange": ("rejected", -34),
    "parse_reject_emsgsize": ("rejected", -90),
    "not_representable_as_monitor_mpdu": ("not_applicable", None),
}
ADDR1 = bytes.fromhex("021122334455")
ADDR2 = bytes.fromhex("0266778899aa")
ADDR3 = bytes.fromhex("02a1a2a3a4a5")
ADDR4 = bytes.fromhex("02b1b2b3b4b5")
BROADCAST = b"\xff" * 6


@dataclasses.dataclass(frozen=True)
class Case:
    case_id: str
    suite: str
    operation: str
    legality: str
    family: str
    current_expectation: str
    final_requirement: str
    axes: dict[str, Any]
    radiotap: bytes = b""
    mpdu: bytes = b""
    packet_suffix: bytes = b""

    def as_json(self) -> dict[str, Any]:
        packet = self.radiotap + self.mpdu + self.packet_suffix
        parser_state, parser_errno = CURRENT_EXPECTATION[self.current_expectation]
        if self.operation == "capability_only":
            stage1_requirement = "static_hardware_unsupported"
        elif self.operation == "classify_only":
            stage1_requirement = "precise_static_classification"
        elif parser_state == "rejected":
            stage1_requirement = "precise_parser_reject_without_submit"
        else:
            stage1_requirement = (
                "terminal_completion_or_precise_backend_reject")
        # Stage 1 deliberately has no external listener. These policies are
        # carried forward for the Stage 2 OTA/response/rewrite closure only.
        stage2_response_policy = "not_applicable"
        if self.mpdu and self.operation in {
                "send_after_continuity_fix",
                "parse_then_send_if_accepted_after_continuity_fix"}:
            fc = struct.unpack_from("<H", self.mpdu)[0]
            frame_type = (fc >> 2) & 0x3 if (fc & 0x3) == 0 else None
            subtype = (fc >> 4) & 0xf if frame_type is not None else None
            if (frame_type != 1 or subtype not in {12, 13}) and \
                    len(self.mpdu) >= 10 and self.mpdu[4:10] != BROADCAST:
                stage2_response_policy = "required_if_ack_policy_applies"
        return {
            "schema": SCHEMA_VERSION,
            "case_id": self.case_id,
            "suite": self.suite,
            "operation": self.operation,
            "legality": self.legality,
            "family": self.family,
            "current_expectation": self.current_expectation,
            "current_parser_state": parser_state,
            "current_parser_errno": parser_errno,
            "stage1_requirement": stage1_requirement,
            "stage2_requirement": self.final_requirement,
            "axes": self.axes,
            "radiotap_hex": self.radiotap.hex(),
            "mpdu_hex": self.mpdu.hex(),
            "packet_suffix_hex": self.packet_suffix.hex(),
            "packet_hex": packet.hex(),
            "packet_sha256": hashlib.sha256(packet).hexdigest(),
            "case_cookie": hashlib.sha256(
                ("stage1-v2:" + self.case_id).encode()).hexdigest()[:16],
            "stage1_evidence_scope": [
                "parsed", "accepted", "submitted", "completion",
                "local_continuity", "teardown", "capability",
            ],
            "stage2_response_policy": stage2_response_policy,
            "stage2_ota_match_policy": {
                "algorithm": "ordered_dynamic_programming",
                "wildcard_fields": ["duration_id", "beacon_or_probe_tsf"],
                "fcs": "compare_only_when_listener_provides_valid_fcs",
            },
        }


def align(offset: int, alignment: int) -> int:
    return (offset + alignment - 1) & ~(alignment - 1)


def radiotap_fixed(fields: dict[int, bytes]) -> bytes:
    if not fields:
        return struct.pack("<BBHI", 0, 0, 8, 0)
    if any(index < 0 or index > 27 for index in fields):
        raise ValueError("fixed radiotap builder accepts indices 0..27")
    bitmap = sum(1 << index for index in fields)
    buf = bytearray(struct.pack("<BBHI", 0, 0, 0, bitmap))
    for index in sorted(fields):
        alignment, size, _, _ = RADIOTAP_FIXED[index]
        value = fields[index]
        if len(value) != size:
            raise ValueError(f"radiotap {index} needs {size} bytes")
        buf.extend(b"\x00" * (align(len(buf), alignment) - len(buf)))
        buf.extend(value)
    struct.pack_into("<H", buf, 2, len(buf))
    return bytes(buf)


def radiotap_single_truncated(index: int) -> bytes:
    alignment, size, _, _ = RADIOTAP_FIXED[index]
    buf = bytearray(struct.pack("<BBHI", 0, 0, 0, 1 << index))
    buf.extend(b"\x00" * (align(len(buf), alignment) - len(buf)))
    buf.extend(b"\x5a" * (size - 1))
    struct.pack_into("<H", buf, 2, len(buf))
    return bytes(buf)


def radiotap_extended_presence(global_index: int) -> bytes:
    if not 32 <= global_index <= 62:
        raise ValueError("global extended index out of test range")
    return struct.pack("<BBHII", 0, 0, 12, 1 << 31,
                       1 << (global_index - 32))


def radiotap_namespace_reset_rate(rate: int = BASE_RATE) -> bytes:
    # First word: radiotap namespace reset + extension.  The second bitmap
    # starts again at namespace index zero and selects RATE (bit 2).
    return struct.pack("<BBHIIB", 0, 0, 13, (1 << 29) | (1 << 31),
                       1 << 2, rate)


def radiotap_vendor(oui: bytes, selector: int, payload: bytes,
                     declared_length: int | None = None) -> bytes:
    if len(oui) != 3:
        raise ValueError("vendor OUI must be three bytes")
    declared = len(payload) if declared_length is None else declared_length
    body = oui + bytes([selector]) + struct.pack("<H", declared) + payload
    buf = bytearray(struct.pack("<BBHI", 0, 0, 0, 1 << 30))
    buf.extend(b"\x00" * (align(len(buf), 2) - len(buf)))
    buf.extend(body)
    struct.pack_into("<H", buf, 2, len(buf))
    return bytes(buf)


def tlv_record(tlv_type: int, payload: bytes, declared: int | None = None,
               include_padding: bool = True) -> bytes:
    length = len(payload) if declared is None else declared
    record = bytearray(struct.pack("<HH", tlv_type, length))
    record.extend(payload)
    if include_padding:
        record.extend(b"\x00" * (align(len(payload), 4) - len(payload)))
    return bytes(record)


def radiotap_tlv(records: Iterable[bytes]) -> bytes:
    buf = bytearray(struct.pack("<BBHI", 0, 0, 0, 1 << 28))
    buf.extend(b"\x00" * (align(len(buf), 4) - len(buf)))
    for record in records:
        buf.extend(record)
    struct.pack_into("<H", buf, 2, len(buf))
    return bytes(buf)


def default_radiotap() -> bytes:
    return radiotap_fixed({2: bytes([BASE_RATE]),
                           15: struct.pack("<H", BASE_TX_FLAGS)})


def mac_header(fc: int, length: int, seq: int) -> bytearray:
    if length < 24:
        raise ValueError("three-address header is 24 bytes")
    frame = bytearray(length)
    struct.pack_into("<HH", frame, 0, fc, 0x2345)
    frame[4:10] = ADDR1
    frame[10:16] = ADDR2
    frame[16:22] = ADDR3
    struct.pack_into("<H", frame, 22, (seq & 0xFFF) << 4)
    return frame


def information_element(element_id: int, payload: bytes) -> bytes:
    if element_id not in range(256) or len(payload) > 255:
        raise ValueError("invalid information element")
    return bytes([element_id, len(payload)]) + payload


def management_frame(subtype: int, seq: int, tail: bytes = b"",
                     *, order: bool = False, body_override: bytes | None = None,
                     to_ds: bool = False, from_ds: bool = False) -> bytes:
    body_len = (len(body_override) if body_override is not None
                else MGMT_BODY_LENGTH[subtype])
    fc = subtype << 4 | (0x8000 if order else 0)
    fc |= 0x0100 if to_ds else 0
    fc |= 0x0200 if from_ds else 0
    a4 = to_ds and from_ds
    htc = b"\x01\x23\x45\x67" if order else b""
    hdr_len = 30 if a4 else 24
    frame = mac_header(fc, hdr_len + len(htc) + body_len, seq)
    if a4:
        frame[24:30] = ADDR4
    body = memoryview(frame)[hdr_len + len(htc):]
    if body_override is not None:
        body[:] = body_override
    elif subtype in {5, 8}:
        body[:8] = struct.pack("<Q", 0x1122334455667788)
        body[8:12] = struct.pack("<HH", 100, 0x0431)
    elif subtype == 6:
        body[:8] = struct.pack("<Q", 0x1020304050607080)
        body[8:10] = b"\x01\x00"
    elif subtype in {0}:
        body[:] = struct.pack("<HH", 0x0431, 10)
    elif subtype == 2:
        body[:4] = struct.pack("<HH", 0x0431, 10)
        body[4:10] = ADDR3
    elif subtype in {1, 3}:
        body[:] = struct.pack("<HHH", 0x0431, 0, 0xC001)
    elif subtype == 11:
        body[:] = struct.pack("<HHH", 0, 1, 0)
    elif subtype in {10, 12}:
        body[:] = struct.pack("<H", 7)
    elif subtype in {13, 14}:
        body[:] = b"\x7f\x01"
    return bytes(frame) + tail


def management_ie_fixtures() -> dict[str, bytes]:
    return {
        "ssid_empty": information_element(0, b""),
        "ssid_max": information_element(0, b"S" * 32),
        "supported_rates": information_element(1, b"\x82\x84\x8b\x96"),
        "rsn": information_element(48, bytes.fromhex(
            "0100000fac040100000fac040100000fac020000")),
        "vendor": information_element(221, bytes.fromhex("0050f20401000000")),
        "extension_he": information_element(255, b"\x23" + bytes(16)),
        "extension_eht": information_element(255, b"\x6c" + bytes(16)),
            "max_len": information_element(221, bytes(i & 0xff for i in range(255))),
    }


def control_frame(subtype: int, variant: int = 0, body: bytes | None = None) -> bytes:
    length = (CONTROL_EXTENSION_LENGTH[variant]
              if subtype == 6 and variant else CONTROL_LENGTH[subtype])
    fc = 0x0004 | subtype << 4
    if subtype == 6 and variant:
        fc |= variant << 12
    frame = bytearray(length)
    struct.pack_into("<HH", frame, 0, fc, 0x3456)
    frame[4:10] = ADDR1
    if length >= 16:
        frame[10:16] = ADDR2
    for offset in range(16, length):
        frame[offset] = (offset * 17 + subtype) & 0xFF
    if subtype == 10:
        struct.pack_into("<H", frame, 2, 0xC123)
    if body is not None:
        if len(body) < 10:
            raise ValueError("control body override is shorter than common header")
        return body
    return bytes(frame)


def block_ack_frame(request: bool, kind: str, tid_count: int = 1) -> bytes:
    subtype = 8 if request else 9
    prefix = bytearray(control_frame(subtype))[:16]
    kind_value = {
        "basic": 0, "extended_compressed": 1, "compressed": 2,
        "multi_tid": 3, "gcr": 6, "glk_gcr": 10, "multi_sta": 11,
    }[kind]
    control = kind_value << 1
    if kind == "multi_tid":
        if tid_count not in {1, 2, 16}:
            raise ValueError("invalid multi-TID count")
        control |= (tid_count - 1) << 12
    body = bytearray(struct.pack("<H", control))
    if kind == "basic":
        body += struct.pack("<H", 0x1230)
        if not request:
            body += bytes([0x5a]) * 128
    elif kind in {"compressed", "extended_compressed"}:
        body += struct.pack("<H", 0x1230)
        if not request:
            body += bytes([0xa5]) * (9 if kind == "extended_compressed" else 8)
    elif kind == "multi_tid":
        for tid in range(tid_count):
            body += struct.pack("<HH", tid, (0x100 + tid) << 4)
            if not request:
                body += bytes([1 << (tid & 7)]) * 8
    elif kind in {"gcr", "glk_gcr"}:
        body += struct.pack("<H", 0x2340) + ADDR3
        if not request:
            body += b"\x01" * 8
    elif kind == "multi_sta":
        body += struct.pack("<HH", 1, 0x3450)
        if not request:
            body += b"\x03" * 8
    return bytes(prefix + body)


def trigger_frame(trigger_type: int, users: int, padding: int = 0) -> bytes:
    if trigger_type not in range(9) or users not in {0, 1, 2, 4}:
        raise ValueError("invalid trigger fixture")
    frame = bytearray(control_frame(2))
    frame[16:24] = struct.pack("<Q", trigger_type | 0x100)
    for user in range(users):
        frame += struct.pack("<I", 1 + user) + bytes([user & 1])
    frame += b"\x00" * padding
    return bytes(frame)


def control_wrapper(carried_subtype: int) -> bytes:
    wrapper = bytearray(control_frame(7))
    carried_fc = 0x0004 | carried_subtype << 4
    struct.pack_into("<H", wrapper, 10, carried_fc)
    wrapper[12:16] = b"\x10\x32\x54\x76"
    carried = control_frame(carried_subtype)
    return bytes(wrapper) + carried[10:]


def data_frame(subtype: int, ds: int, ordered: bool, seq: int,
               *, fragment: int = 0, more_fragments: bool = False,
               protected: bool = False, mesh_ae: int | None = None,
               payload_override: bytes | None = None,
               crypto_fixture: tuple[str, bytes, bytes] | None = None,
               amsdu: bool = False,
               protected_raw: bytes | None = None) -> bytes:
    qos = subtype >= 8
    if protected_raw is not None:
        protected = True
    if crypto_fixture is not None:
        protected = True
    fc = 0x0008 | subtype << 4 | ((ds & 1) << 8) | ((ds & 2) << 8)
    if more_fragments:
        fc |= 0x0400
    if protected:
        fc |= 0x4000
    if ordered:
        fc |= 0x8000
    header_len = 24 + (6 if ds == 3 else 0) + (2 if qos else 0)
    if qos and ordered:
        header_len += 4
    payload = b""
    if payload_override is not None:
        payload = payload_override
    elif subtype in DATA_PAYLOAD_SUBTYPES:
        payload = b"S1M" + bytes([subtype, ds, fragment])
    frame = mac_header(fc, header_len, seq)
    struct.pack_into("<H", frame, 22, ((seq & 0xFFF) << 4) | fragment)
    cursor = 24
    if ds == 3:
        frame[cursor:cursor + 6] = ADDR4
        cursor += 6
    if qos:
        qos_control = 5
        if mesh_ae is not None:
            qos_control |= 0x0100
        if amsdu:
            qos_control |= 0x0080
        struct.pack_into("<H", frame, cursor, qos_control)
        cursor += 2
    if qos and ordered:
        frame[cursor:cursor + 4] = b"\xa5\x5a\xc3\x3c"
    if mesh_ae is not None:
        mesh_length = {0: 6, 1: 12, 2: 18}[mesh_ae]
        mesh = bytearray(mesh_length)
        mesh[0] = mesh_ae
        for i in range(1, mesh_length):
            mesh[i] = 0x80 + i
        payload = bytes(mesh) + payload
    if crypto_fixture is not None:
        cipher, crypto_header, trailer = crypto_fixture
        payload = crypto_header + payload + trailer
    elif protected_raw is not None:
        payload = protected_raw
    elif protected:
        payload = b"\x01\x00\x00\x20\x00\x00\x00\x00" + payload + b"\x6d" * 8
    return bytes(frame) + payload


def extension_frame(subtype: int) -> bytes:
    fc = 0x000C | subtype << 4
    if subtype == 0:  # DMG beacon host-boundary minimum.
        return struct.pack("<HH", fc, 0x1111)
    if subtype == 1:  # S1G beacon through change sequence.
        return (struct.pack("<HH", fc, 0x2222) + ADDR2 +
                struct.pack("<I", 0x55667788) + b"\x01")
    raise ValueError("only assigned extension subtypes are generated")


def pv1_frame(pv1_type: int, subtype: int, *, from_ds: bool = False,
              a3: bool = False, a4: bool = False, amsdu: bool = False) -> bytes:
    if pv1_type not in range(4):
        raise ValueError("reserved PV1 frame type")
    fc = 1 | pv1_type << 2 | subtype << 5 | (0x0100 if from_ds else 0)
    frame = bytearray(struct.pack("<H", fc))
    sid = 0x0123 | (0x2000 if a3 else 0) | (0x4000 if a4 else 0) | \
        (0x8000 if amsdu else 0)
    if pv1_type == 2:
        frame += struct.pack("<H", sid) + ADDR2
    elif pv1_type == 1 and subtype == 2:
        frame += ADDR1 + ADDR2
    elif pv1_type == 3:
        frame += ADDR1 + ADDR2
    elif from_ds:
        frame += struct.pack("<H", sid) + ADDR2
    else:
        frame += ADDR1 + struct.pack("<H", sid)
    if pv1_type in {0, 3} or (pv1_type == 1 and subtype != 2):
        frame += struct.pack("<H", 0x1230)
    if a3:
        frame += ADDR3
    if a4:
        frame += ADDR4
    if pv1_type in {0, 3}:
        frame += b"PV1DATA"
    elif pv1_type == 1 and subtype in {0, 1}:
        frame += b"\x7f\x01PV1A"
    elif pv1_type == 1 and subtype in {2, 3}:
        frame += b"PV1MGMT"
    elif pv1_type == 2 and subtype == 0:
        frame += b"\x11\x22\x33\x44"
    elif pv1_type == 2 and subtype == 1:
        frame += bytes(range(22))
    return bytes(frame)


def base_probe() -> bytes:
    return management_frame(4, 1)


def frame_cases() -> list[Case]:
    cases: list[Case] = []
    rtap = default_radiotap()
    seq = 100

    for subtype, name in MGMT_NAMES.items():
        cases.append(Case(
            f"frame.pv0.mgmt.{subtype:02d}.{name}.minimal", "frame",
            "send_after_continuity_fix", "assigned", "pv0_management",
            "parser_accept_backend_candidate",
            "ota_or_precise_firmware_unsupported",
            {"protocol_version": 0, "type": 0, "subtype": subtype,
             "layout": "three_address_minimal"},
            rtap, management_frame(subtype, seq)))
        seq += 1
        cases.append(Case(
            f"frame.pv0.mgmt.{subtype:02d}.{name}.minimum_minus_one",
            "frame", "parse_only", "malformed", "pv0_management_boundary",
            "parse_reject_einval", "reject_without_submit",
            {"protocol_version": 0, "type": 0, "subtype": subtype,
             "boundary": "minimum_minus_one"}, rtap,
            management_frame(subtype, seq)[:-1]))

    for subtype in sorted(IE_BEARING_MGMT_SUBTYPES):
        name = MGMT_NAMES[subtype]
        for fixture_name, tail in management_ie_fixtures().items():
            cases.append(Case(
                f"frame.pv0.mgmt.{subtype:02d}.{name}.ie.{fixture_name}",
                "frame", "send_after_continuity_fix", "assigned",
                "pv0_management_ie", "parser_accept_backend_candidate",
                "ota_or_precise_firmware_unsupported",
                {"protocol_version": 0, "type": 0, "subtype": subtype,
                 "ie_fixture": fixture_name, "variable_body": True},
                rtap, management_frame(subtype, seq, tail)))
            seq += 1

    for subtype in (13, 14):
        for category in ACTION_CATEGORIES:
            cases.append(Case(
                f"frame.pv0.mgmt.{subtype:02d}.{MGMT_NAMES[subtype]}.category.{category:03d}",
                "frame", "send_after_continuity_fix", "assigned",
                "pv0_management_action", "parser_accept_backend_candidate",
                "ota_or_precise_firmware_unsupported",
                {"protocol_version": 0, "type": 0, "subtype": subtype,
                 "action_category": category, "action_code": 1},
                rtap, management_frame(subtype, seq,
                    body_override=bytes([category, 1, 0x5a]))))
            seq += 1

    for subtype in MGMT_NAMES:
        cases.append(Case(
            f"frame.pv0.mgmt.{subtype:02d}.{MGMT_NAMES[subtype]}.ht_control",
            "frame", "send_after_continuity_fix", "assigned",
            "pv0_management_ht_control", "parser_accept_backend_candidate",
            "ota_or_precise_firmware_unsupported",
            {"protocol_version": 0, "type": 0, "subtype": subtype,
             "ht_control": True}, rtap,
            management_frame(subtype, seq, order=True)))
        seq += 1

    # Maxsqueeze: management frames carrying DS bits are legal inputs now
    # that the submit-time refusal is removed; FW behaviour stays an A/B
    # question (both bits set makes the four-address management layout).
    for ds_label, ds_kwargs in (("tods", {"to_ds": True}),
                                ("fromds", {"from_ds": True}),
                                ("tods_fromds_a4",
                                 {"to_ds": True, "from_ds": True})):
        cases.append(Case(
            f"frame.pv0.mgmt.ds.{ds_label}", "frame",
            "send_after_continuity_fix", "assigned", "pv0_management_ds",
            "parser_accept_backend_candidate",
            "ota_or_precise_firmware_unsupported",
            {"protocol_version": 0, "type": 0, "subtype": 4,
             "ds_bits": ds_label}, rtap,
            management_frame(4, seq, **ds_kwargs)))
        seq += 1

    for subtype, name in CONTROL_NAMES.items():
        cases.append(Case(
            f"frame.pv0.control.{subtype:02d}.{name}.minimal", "frame",
            "send_after_continuity_fix", "assigned", "pv0_control",
            "parser_accept_backend_candidate",
            "ota_or_precise_firmware_unsupported",
            {"protocol_version": 0, "type": 1, "subtype": subtype,
             "layout": f"length_{CONTROL_LENGTH[subtype]}"},
            rtap, control_frame(subtype)))
        structural_minimum = {2: 24, 6: 16, 7: 16, 8: 20, 9: 28,
                              10: 16, 11: 16, 12: 10, 13: 10,
                              14: 16, 15: 16}.get(subtype, 10)
        full = control_frame(subtype)
        malformed = full[:structural_minimum - 1]
        cases.append(Case(
            f"frame.pv0.control.{subtype:02d}.{name}.minimum_minus_one",
            "frame", "parse_only", "malformed", "pv0_control_boundary",
            "parse_reject_einval", "reject_without_submit",
            {"protocol_version": 0, "type": 1, "subtype": subtype,
             "boundary": "host_structural_minimum_minus_one"}, rtap, malformed))
    for ext, name in CONTROL_EXTENSION.items():
        cases.append(Case(
            f"frame.pv0.control.06.control_extension.{ext:02d}.{name}",
            "frame", "send_after_continuity_fix", "assigned",
            "pv0_control_extension", "parser_accept_backend_candidate",
            "ota_or_precise_firmware_unsupported",
            {"protocol_version": 0, "type": 1, "subtype": 6,
             "control_extension": ext}, rtap, control_frame(6, ext)))

    for carried_subtype in sorted(CONTROL_NAMES):
        if carried_subtype == 7:
            continue
        cases.append(Case(
            f"frame.pv0.control.07.control_wrapper.carried_{carried_subtype:02d}",
            "frame", "send_after_continuity_fix", "assigned",
            "pv0_control_wrapper", "parser_accept_backend_candidate",
            "ota_or_precise_firmware_unsupported",
            {"protocol_version": 0, "type": 1, "subtype": 7,
             "carried_subtype": carried_subtype}, rtap,
            control_wrapper(carried_subtype)))

    for request, subtype in ((True, 8), (False, 9)):
        for kind in ("basic", "extended_compressed", "compressed",
                     "multi_tid", "gcr", "glk_gcr", "multi_sta"):
            counts = (1, 2, 16) if kind == "multi_tid" else (1,)
            for tid_count in counts:
                cases.append(Case(
                    f"frame.pv0.control.{subtype:02d}.block_ack.{kind}.n{tid_count}",
                    "frame", "send_after_continuity_fix", "assigned",
                    "pv0_block_ack", "parser_accept_backend_candidate",
                    "ota_or_precise_firmware_unsupported",
                    {"protocol_version": 0, "type": 1, "subtype": subtype,
                     "block_ack_type": kind, "tid_count": tid_count},
                    rtap, block_ack_frame(request, kind, tid_count)))

    for trigger_type in range(9):
        for users in (0, 1, 2, 4):
            cases.append(Case(
                f"frame.pv0.control.02.trigger.type{trigger_type}.users{users}",
                "frame", "send_after_continuity_fix", "assigned",
                "pv0_trigger", "parser_accept_backend_candidate",
                "ota_or_precise_firmware_unsupported",
                {"protocol_version": 0, "type": 1, "subtype": 2,
                 "trigger_type": trigger_type, "user_count": users},
                rtap, trigger_frame(trigger_type, users, users & 1)))

    for subtype in (3, 4, 5):
        for extra_len in (0, 1, 8, 32):
            cases.append(Case(
                f"frame.pv0.control.{subtype:02d}.{CONTROL_NAMES[subtype]}.extra{extra_len}",
                "frame", "send_after_continuity_fix", "assigned",
                "pv0_variable_control", "parser_accept_backend_candidate",
                "ota_or_precise_firmware_unsupported",
                {"protocol_version": 0, "type": 1, "subtype": subtype,
                 "variable_body_extra": extra_len}, rtap,
                control_frame(subtype) + bytes([0x80 | subtype]) * extra_len))

    for subtype, name in DATA_NAMES.items():
        for ds in range(4):
            cases.append(Case(
                f"frame.pv0.data.{subtype:02d}.{name}.ds{ds}.base",
                "frame", "send_after_continuity_fix", "assigned",
                "pv0_data", "parser_accept_backend_candidate",
                "ota_or_precise_firmware_unsupported",
                {"protocol_version": 0, "type": 2, "subtype": subtype,
                 "to_ds": bool(ds & 1), "from_ds": bool(ds & 2),
                 "qos": subtype >= 8, "ht_control": False},
                rtap, data_frame(subtype, ds, False, seq)))
            seq += 1
            if subtype >= 8:
                cases.append(Case(
                    f"frame.pv0.data.{subtype:02d}.{name}.ds{ds}.ht_control",
                    "frame", "send_after_continuity_fix", "assigned",
                    "pv0_data", "parser_accept_backend_candidate",
                    "ota_or_precise_firmware_unsupported",
                    {"protocol_version": 0, "type": 2,
                     "subtype": subtype, "to_ds": bool(ds & 1),
                     "from_ds": bool(ds & 2), "qos": True,
                     "ht_control": True},
                    rtap, data_frame(subtype, ds, True, seq)))
                seq += 1

    for subtype, ds, ordered in ((0, 0, False), (0, 3, False),
                                 (8, 0, False), (8, 3, True)):
        frame = data_frame(subtype, ds, ordered, seq, payload_override=b"")
        cases.append(Case(
            f"frame.pv0.data.{subtype:02d}.ds{ds}.ht{int(ordered)}.minimum_minus_one",
            "frame", "parse_only", "malformed", "pv0_data_boundary",
            "parse_reject_einval", "reject_without_submit",
            {"protocol_version": 0, "type": 2, "subtype": subtype,
             "to_ds": bool(ds & 1), "from_ds": bool(ds & 2),
             "ht_control": ordered, "boundary": "header_minus_one"},
            rtap, frame[:-1]))

    for mesh_ae in range(3):
        cases.append(Case(
            f"frame.pv0.data.08.qos_data.mesh_ae{mesh_ae}", "frame",
            "send_after_continuity_fix", "assigned", "pv0_mesh_data",
            "parser_accept_backend_candidate",
            "ota_or_precise_firmware_unsupported",
            {"protocol_version": 0, "type": 2, "subtype": 8,
             "mesh_control": True, "mesh_ae": mesh_ae},
            rtap, data_frame(8, 0, False, seq, mesh_ae=mesh_ae)))
        seq += 1

    for subtype in sorted(DATA_PAYLOAD_SUBTYPES):
        header_len = len(data_frame(subtype, 3, subtype >= 8, seq,
                                    payload_override=b""))
        payloads = {
            "empty": b"",
            "one": b"P",
            "llc_snap": bytes.fromhex("aaaa03000000888e") + b"S1MATRIX",
            "max": bytes([subtype ^ 0x5a]) * (MAX_MPDU_LEN - header_len),
        }
        for boundary, payload in payloads.items():
            cases.append(Case(
                f"frame.pv0.data.{subtype:02d}.{DATA_NAMES[subtype]}.payload.{boundary}",
                "frame", "send_after_continuity_fix", "assigned",
                "pv0_data_payload_boundary", "parser_accept_backend_candidate",
                "ota_or_precise_firmware_unsupported",
                {"protocol_version": 0, "type": 2, "subtype": subtype,
                 "payload_boundary": boundary, "mpdu_length": header_len + len(payload)},
                rtap, data_frame(subtype, 3, subtype >= 8, seq,
                                 payload_override=payload)))
            seq += 1

    for subtype in sorted(DATA_PAYLOAD_SUBTYPES):
        for amsdu in (False, True):
            subframe = ADDR1 + ADDR2 + struct.pack("!H", 8) + \
                bytes.fromhex("aaaa030000000800")
            cases.append(Case(
                f"frame.pv0.data.{subtype:02d}.{DATA_NAMES[subtype]}.amsdu_{int(amsdu)}",
                "frame", "send_after_continuity_fix", "assigned",
                "pv0_data_amsdu", "parser_accept_backend_candidate",
                "ota_or_precise_firmware_unsupported",
                {"protocol_version": 0, "type": 2, "subtype": subtype,
                 "amsdu_present": amsdu}, rtap,
                data_frame(subtype, 0, False, seq, payload_override=subframe,
                           amsdu=amsdu)))
            seq += 1

    # A-MSDU structural boundary (todo 4.4): the parser validates the
    # subframe sequence whenever the A-MSDU present bit is set on non-mesh
    # QoS data. Subframe length is big-endian per 802.11.
    amsdu_boundaries = {
        "multi_subframes_padded": (
            ADDR1 + ADDR2 + struct.pack("!H", 4) + b"\x11" * 4 + b"\x00\x00" +
            ADDR1 + ADDR2 + struct.pack("!H", 6) + b"\x22" * 6,
            "parser_accept_backend_candidate"),
        "subframe_truncated": (
            ADDR1 + ADDR2 + struct.pack("!H", 9) + b"\x33" * 8,
            "parse_reject_einval"),
        "tail_not_padding": (
            ADDR1 + ADDR2 + struct.pack("!H", 4) + b"\x44" * 4 + b"\x55" * 6,
            "parse_reject_einval"),
    }
    for boundary, (payload, expectation) in amsdu_boundaries.items():
        cases.append(Case(
            f"frame.pv0.data.08.qos_data.amsdu_boundary.{boundary}",
            "frame",
            "send_after_continuity_fix"
            if expectation == "parser_accept_backend_candidate"
            else "parse_only",
            "assigned", "pv0_data_amsdu_boundary", expectation,
            "ota_or_precise_firmware_unsupported",
            {"protocol_version": 0, "type": 2, "subtype": 8,
             "amsdu_boundary": boundary}, rtap,
            data_frame(8, 0, False, seq, payload_override=payload,
                       amsdu=True)))
        seq += 1
    cases.append(Case(
        "frame.pv0.data.08.qos_data.amsdu_boundary.ht_control_order",
        "frame", "send_after_continuity_fix", "assigned",
        "pv0_data_amsdu_boundary", "parser_accept_backend_candidate",
        "ota_or_precise_firmware_unsupported",
        {"protocol_version": 0, "type": 2, "subtype": 8,
         "amsdu_boundary": "ht_control_order"}, rtap,
        data_frame(8, 0, True, seq,
                   payload_override=ADDR1 + ADDR2 +
                   struct.pack("!H", 8) + b"\x66" * 8,
                   amsdu=True)))
    seq += 1

    # Protected-frame structural boundary (todo 4.4): the parser requires
    # space for the smallest IV (4 bytes) behind the header.
    protected_boundaries = {
        "min_iv": (b"\x77" * 4, "parser_accept_backend_candidate"),
        "short_iv": (b"\x88" * 2, "parse_reject_einval"),
    }
    for boundary, (payload, expectation) in protected_boundaries.items():
        cases.append(Case(
            f"frame.pv0.data.00.data.protected_boundary.{boundary}",
            "frame",
            "send_after_continuity_fix"
            if expectation == "parser_accept_backend_candidate"
            else "parse_only",
            "assigned", "pv0_data_protected_boundary", expectation,
            "ota_or_precise_firmware_unsupported",
            {"protocol_version": 0, "type": 2, "subtype": 0,
             "protected_boundary": boundary}, rtap,
            data_frame(0, 0, False, seq, protected_raw=payload)))
        seq += 1

    for fragment, more in ((0, True), (1, True), (15, False)):
        cases.append(Case(
            f"frame.pv0.data.00.fragment.{fragment:02d}", "frame",
            "send_after_continuity_fix", "assigned", "pv0_data_fragment",
            "parser_accept_backend_candidate",
            "ota_or_precise_firmware_unsupported",
            {"protocol_version": 0, "type": 2, "subtype": 0,
             "fragment": fragment, "more_fragments": more},
            rtap, data_frame(0, 0, False, seq, fragment=fragment,
                             more_fragments=more)))
        seq += 1

    crypto_fixtures = {
        "wep40": (b"\x01\x02\x03\x00", b"I" * 4),
        "tkip": (b"\x01\x21\x00\x20\x00\x00\x00\x00", b"M" * 12),
        "ccmp128": (b"\x01\x00\x00\x20\x00\x00\x00\x00", b"C" * 8),
        "ccmp256": (b"\x02\x00\x00\x20\x00\x00\x00\x00", b"D" * 16),
        "gcmp128": (b"\x03\x00\x00\x20\x00\x00\x00\x00", b"G" * 16),
        "gcmp256": (b"\x04\x00\x00\x20\x00\x00\x00\x00", b"H" * 16),
    }
    for subtype in (0, 8):
        for cipher, (crypto_header, trailer) in crypto_fixtures.items():
            for pn_class, pn in (("zero", 0), ("one", 1),
                                 ("max48", (1 << 48) - 1)):
                header = bytearray(crypto_header)
                pn_bytes = pn.to_bytes(6, "little")
                for index in range(min(len(header), 6)):
                    header[index] ^= pn_bytes[index]
                cases.append(Case(
                    f"frame.pv0.data.{subtype:02d}.crypto.{cipher}.pn_{pn_class}",
                    "frame", "send_after_continuity_fix",
                    "structurally_valid_crypto_fixture", "pv0_raw_encrypted",
                    "parser_accept_backend_candidate",
                    "preserve_or_precise_crypto_unsupported",
                    {"protocol_version": 0, "type": 2, "subtype": subtype,
                     "protected": True, "cipher": cipher, "pn_class": pn_class,
                     "iv_length": len(header), "trailer_length": len(trailer)},
                    rtap, data_frame(subtype, 0, False, seq,
                        crypto_fixture=(cipher, bytes(header), trailer))))
                seq += 1

    cases.extend([
        Case("frame.pv0.extension.00.dmg_beacon.host_minimum", "frame",
             "capability_only", "assigned_non_peach_phy", "dmg_extension",
             "parser_accept_backend_candidate", "hardware_unsupported",
             {"protocol_version": 0, "type": 3, "subtype": 0,
              "phy_family": "dmg"}, rtap, extension_frame(0)),
        Case("frame.pv0.extension.01.s1g_beacon.host_minimum", "frame",
             "capability_only", "assigned_non_peach_phy", "s1g_extension",
             "parser_accept_backend_candidate", "hardware_unsupported",
             {"protocol_version": 0, "type": 3, "subtype": 1,
              "phy_family": "s1g"}, rtap, extension_frame(1)),
    ])
    cases.append(Case(
        "frame.pv0.data.00.oversize_max_plus_one", "frame", "parse_only",
        "malformed", "pv0_data_boundary", "parse_reject_emsgsize",
        "reject_without_submit",
        {"protocol_version": 0, "type": 2, "subtype": 0,
         "boundary": "max_mpdu_plus_one", "mpdu_length": MAX_MPDU_LEN + 1},
        rtap, data_frame(0, 0, False, seq,
                         payload_override=b"X" * (MAX_MPDU_LEN + 1 - 24))))

    # PV1 is an S1G PHY format. Build its assigned layouts independently from
    # PV0, then classify each as an exact Peach hardware limitation. Reserved
    # type/subtype cells remain explicit classify-only cases.
    for pv1_type in range(8):
        for subtype in range(8):
            assigned = (pv1_type in {0, 3} or
                        (pv1_type == 1 and subtype in range(4)) or
                        (pv1_type == 2 and subtype in range(2)))
            if assigned:
                payload = pv1_frame(pv1_type, subtype)
                operation = "capability_only"
                legality = "assigned_non_peach_phy"
                requirement = "hardware_unsupported"
                family = "pv1_assigned"
            else:
                fc = 1 | pv1_type << 2 | subtype << 5
                payload = struct.pack("<H", fc) + b"PV1RESERVED"
                operation = "classify_only"
                legality = "reserved"
                requirement = "precise_reserved_reject"
                family = "pv1_reserved"
            cases.append(Case(
                f"frame.pv1.classifier.type{pv1_type}.subtype{subtype}",
                "frame", operation, legality, family,
                "parser_accepts_opaque_non_pv0", requirement,
                {"protocol_version": 1, "pv1_type": pv1_type,
                 "pv1_subtype": subtype, "assigned": assigned,
                 "phy_family": "s1g"}, rtap, payload))

    for pv1_type in (0, 3):
        for from_ds in (False, True):
            for a3 in (False, True):
                for a4 in (False, True):
                    for amsdu in (False, True):
                        cases.append(Case(
                            f"frame.pv1.data.type{pv1_type}.ds{int(from_ds)}."
                            f"a3{int(a3)}.a4{int(a4)}.amsdu{int(amsdu)}",
                            "frame", "capability_only",
                            "assigned_non_peach_phy", "pv1_assigned",
                            "parser_accepts_opaque_non_pv0",
                            "hardware_unsupported",
                            {"protocol_version": 1, "pv1_type": pv1_type,
                             "pv1_subtype": 0, "from_ds": from_ds,
                             "a3_present": a3, "a4_present": a4,
                             "amsdu_present": amsdu, "phy_family": "s1g"},
                            rtap, pv1_frame(pv1_type, 0, from_ds=from_ds,
                                a3=a3, a4=a4, amsdu=amsdu)))

    # S1G NDP CMAC is a PHY-sized 25/37-bit object rather than a normal PV0
    # MPDU.  Keep it in the matrix without pretending AF_PACKET can express it.
    for width, length in ((1, 4), (2, 5)):
        for ndp_type in range(8):
            payload = bytes([ndp_type]) + bytes(length - 1)
            cases.append(Case(
                f"frame.s1g_ndp.{width}mhz.type{ndp_type}", "frame",
                "capability_only", "assigned_non_peach_phy", "s1g_ndp",
                "not_representable_as_monitor_mpdu", "hardware_unsupported",
                {"phy_family": "s1g", "width_mhz": width,
                 "ndp_type": ndp_type, "bit_length": 25 if width == 1 else 37},
                b"", payload))

    return cases


def field_value(index: int, nonzero: bool) -> tuple[bytes, bytes, str]:
    size = RADIOTAP_FIXED[index][1]
    suffix = b""
    expectation = ("parser_accept_backend_candidate" if index in CURRENT_ACCEPTED_FIELDS
                   else "parse_reject_eopnotsupp")
    if not nonzero:
        value = bytes(size)
        if index == 2:
            expectation = "parse_reject_eopnotsupp"
        elif index == 3:
            expectation = "parse_reject_einval"
        elif index in (19, 21, 23):
            # An all-zero HT/VHT/HE field names no MCS: precisely rejected
            # instead of silently handing rate selection to the firmware.
            expectation = "parse_reject_eopnotsupp"
        return value, suffix, expectation
    value = bytes((0x31 + i * 7) & 0xFF for i in range(size))
    if index == 1:
        value = b"\x10"  # caller supplies FCS
        suffix = b"\x11\x22\x33\x44"
    elif index == 2:
        value = bytes([BASE_RATE])
    elif index == 3:
        value = struct.pack("<HH", 5785, 0x0140)
    elif index == 10:
        value = b"\x0a"  # +10 dBm (signed dBm byte)
    elif index == 11:
        value = b"\x03"  # chain index 3 of the 8-bit WMI chain_mask
    elif index == 15:
        value = struct.pack("<H", 0x0018)  # NOACK | NOSEQNO
    elif index == 17:
        value = b"\x7e"
    elif index == 19:
        # known = HAVE_MCS (0x02; kernel enum: BW=0x01, MCS=0x02), flags =
        # BW 20 MHz, index = MCS 4.
        value = b"\x02\x00\x04"
    elif index == 21:
        # known = 0 (nothing forced), flags = 0, BW 0 (20 MHz), one user:
        # NSS 1 MCS 3. Spec layout (v20): known(2) flags(1) bw(1)
        # mcs_nss(4) coding(1) group_id(1) partial_aid(2).
        value = struct.pack("<HBB4BBBH", 0, 0, 0, 0x13, 0, 0, 0, 0, 0, 0)
    elif index == 23:
        # data1 = DATA_MCS_KNOWN | BW_RU_ALLOC_KNOWN, format SU;
        # data3 = MCS 7; data5 = BW 80; data6 = NSTS 2.
        value = struct.pack("<6H", 0x4020, 0, 7 << 8, 0, 2, 2)
    return value, suffix, expectation


def radiotap_cases() -> list[Case]:
    cases: list[Case] = []
    mpdu = base_probe()
    for index, (_, _, direction, name) in RADIOTAP_FIXED.items():
        for mode in ("zero", "nonzero"):
            value, suffix, expectation = field_value(index, mode == "nonzero")
            cases.append(Case(
                f"radiotap.{index:02d}.{name}.present_{mode}", "radiotap",
                "parse_then_send_if_accepted_after_continuity_fix", "structurally_valid",
                "radiotap_fixed", expectation,
                "direction_semantics_and_backend_effect_or_precise_reject",
                {"radiotap_index": index, "field": name,
                 "direction": direction, "value_class": mode},
                radiotap_fixed({index: value}), mpdu, suffix))
        cases.append(Case(
            f"radiotap.{index:02d}.{name}.truncated", "radiotap",
            "parse_only", "malformed", "radiotap_fixed",
            "parse_reject_einval", "reject_without_submit",
            {"radiotap_index": index, "field": name,
             "direction": direction, "boundary": "size_minus_one"},
            radiotap_single_truncated(index), mpdu))

    usig = tlv_record(33, b"\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00")
    eht = tlv_record(34, bytes(range(40)))
    cases.extend([
        Case("radiotap.28.tlv.usig", "radiotap", "parse_only",
             "structurally_valid", "radiotap_tlv",
             "parse_reject_eopnotsupp",
             "tx_direction_semantics_or_precise_reject",
             {"radiotap_index": 28, "field": "tlv", "tlv_types": [33]},
             radiotap_tlv([usig]), mpdu),
        Case("radiotap.28.tlv.eht", "radiotap", "parse_only",
             "structurally_valid", "radiotap_tlv",
             "parse_reject_eopnotsupp",
             "tx_direction_semantics_or_precise_reject",
             {"radiotap_index": 28, "field": "tlv", "tlv_types": [34]},
             radiotap_tlv([eht]), mpdu),
        Case("radiotap.28.tlv.usig_eht_stream", "radiotap", "parse_only",
             "structurally_valid", "radiotap_tlv",
             "parse_reject_eopnotsupp",
             "tx_direction_semantics_or_precise_reject",
             {"radiotap_index": 28, "field": "tlv",
              "tlv_types": [33, 34]}, radiotap_tlv([usig, eht]), mpdu),
        Case("radiotap.28.tlv.truncated_header", "radiotap", "parse_only",
             "malformed", "radiotap_tlv", "parse_reject_einval",
             "reject_without_submit",
             {"radiotap_index": 28, "field": "tlv",
              "boundary": "header_minus_one"}, radiotap_tlv([b"\x21\x00\x01"]), mpdu),
        Case("radiotap.28.tlv.length_overrun", "radiotap", "parse_only",
             "malformed", "radiotap_tlv", "parse_reject_einval",
             "reject_without_submit",
             {"radiotap_index": 28, "field": "tlv",
              "boundary": "declared_payload_overrun"},
             radiotap_tlv([tlv_record(33, b"", declared=12)]), mpdu),
        Case("radiotap.28.tlv.padding_overrun", "radiotap", "parse_only",
             "malformed", "radiotap_tlv", "parse_reject_einval",
             "reject_without_submit",
             {"radiotap_index": 28, "field": "tlv",
              "boundary": "missing_alignment_padding"},
             radiotap_tlv([tlv_record(33, b"\x01", include_padding=False)]), mpdu),
        Case("radiotap.29.namespace.reset_only", "radiotap",
             "parse_then_send_if_accepted_after_continuity_fix",
             "structurally_valid", "radiotap_namespace",
             "parser_accept_backend_candidate", "namespace_reset_preserved",
             {"radiotap_index": 29, "field": "radiotap_namespace"},
             struct.pack("<BBHI", 0, 0, 8, 1 << 29), mpdu),
        Case("radiotap.29.namespace.reset_then_rate", "radiotap",
             "parse_then_send_if_accepted_after_continuity_fix",
             "structurally_valid", "radiotap_namespace",
             "parser_accept_backend_candidate", "namespace_reset_preserved",
             {"radiotap_index": 29, "field": "radiotap_namespace",
              "next_field": 2}, radiotap_namespace_reset_rate(), mpdu),
        Case("radiotap.30.vendor.atheros_selector0", "radiotap", "parse_only",
             "registered_rx_namespace", "radiotap_vendor",
             "parse_reject_eopnotsupp",
             "direction_semantics_and_registered_namespace_policy",
             {"radiotap_index": 30, "field": "vendor_namespace",
              "oui": "00037f", "selector": 0},
             radiotap_vendor(bytes.fromhex("00037f"), 0, bytes(16)), mpdu),
        Case("radiotap.30.vendor.unknown", "radiotap", "parse_only",
             "unknown_namespace", "radiotap_vendor",
             "parse_reject_eopnotsupp", "skip_or_reject_per_direction_contract",
             {"radiotap_index": 30, "field": "vendor_namespace",
              "oui": "123456", "selector": 7},
             radiotap_vendor(bytes.fromhex("123456"), 7, b"abc"), mpdu),
        Case("radiotap.30.vendor.length_overrun", "radiotap", "parse_only",
             "malformed", "radiotap_vendor",
             "parse_reject_eopnotsupp_before_vendor_decode",
             "reject_einval_without_submit_after_vendor_parser_exists",
             {"radiotap_index": 30, "field": "vendor_namespace",
              "boundary": "declared_skip_overrun"},
             radiotap_vendor(bytes.fromhex("00037f"), 0, b"x", declared_length=16), mpdu),
        Case("radiotap.31.ext.empty_word", "radiotap",
             "parse_then_send_if_accepted_after_continuity_fix",
             "structurally_valid", "radiotap_extended_presence",
             "parser_accept_backend_candidate", "extended_presence_preserved",
             {"radiotap_index": 31, "field": "ext"},
             struct.pack("<BBHII", 0, 0, 12, 1 << 31, 0), mpdu),
        Case("radiotap.31.ext.missing_word", "radiotap", "parse_only",
             "malformed", "radiotap_extended_presence",
             "parse_reject_einval", "reject_without_submit",
             {"radiotap_index": 31, "field": "ext",
              "boundary": "missing_presence_word"},
             struct.pack("<BBHI", 0, 0, 8, 1 << 31), mpdu),
    ])

    for index, name in ((32, "reserved_32"), (33, "bare_eht_usig"),
                        (34, "bare_eht")):
        cases.append(Case(
            f"radiotap.{index:02d}.{name}.extended_bitmap", "radiotap",
            "parse_only", "reserved_or_tlv_only",
            "radiotap_extended_presence", "parse_reject_eopnotsupp",
            "reject_bare_bitmap_and_use_registered_tlv_encoding",
            {"radiotap_index": index, "field": name,
             "encoding": "bare_extended_bitmap"},
            radiotap_extended_presence(index), mpdu))

    cases.extend([
        Case("radiotap.semantic.rate_plus_mcs_conflict", "radiotap",
             "parse_only", "conflicting_tx_controls", "radiotap_conflict",
             "parse_reject_einval", "precise_conflict_reject",
             {"radiotap_indices": [2, 19], "conflict": "legacy_rate_and_mcs"},
             radiotap_fixed({2: bytes([BASE_RATE]), 19: b"\x02\x00\x00"}), mpdu),
        Case("radiotap.semantic.aligned_multi_field", "radiotap",
             "parse_then_send_if_accepted_after_continuity_fix",
             "structurally_valid", "radiotap_alignment",
             "parser_accept_backend_candidate",
             "all_present_values_effective_or_precisely_limited",
             {"radiotap_indices": [2, 3, 15, 17],
              "alignment": "mixed"},
             radiotap_fixed({2: bytes([BASE_RATE]),
                              3: struct.pack("<HH", 5785, 0x0140),
                              15: struct.pack("<H", 0x0018), 17: b"\x02"}), mpdu),
        Case("radiotap.semantic.badfcs_intent", "radiotap", "parse_only",
             "structurally_valid_intent", "radiotap_flags",
             "parse_reject_ebadmsg",
             "intentional_badfcs_backend_or_precise_unsupported",
             {"radiotap_index": 1, "field": "flags",
              "intent": "bad_fcs"}, radiotap_fixed({1: b"\x40"}), mpdu),
        Case("radiotap.semantic.unsupported_flags_bit", "radiotap",
             "parse_only", "structurally_valid", "radiotap_flags",
             "parse_reject_eopnotsupp", "precise_direction_or_policy_reject",
             {"radiotap_index": 1, "field": "flags", "value": 2},
             radiotap_fixed({1: b"\x02"}), mpdu),
        Case("radiotap.semantic.data_retries_overflow", "radiotap",
             "parse_only", "out_of_range", "radiotap_data_retries",
             "parse_reject_erange", "reject_without_submit",
             {"radiotap_index": 17, "field": "data_retries",
              "value": 127}, radiotap_fixed({17: b"\x7f"}), mpdu),
    ])

    for rate in LEGACY_RATES:
        cases.append(Case(
            f"radiotap.phy.legacy.rate_{rate:03d}", "radiotap",
            "parse_then_send_if_accepted_after_continuity_fix",
            "structurally_valid", "radiotap_phy_legacy",
            "parser_accept_backend_candidate",
            "ota_phy_metadata_or_receiver_ab_effect_or_precise_limit",
            {"radiotap_index": 2, "field": "rate", "rate_500kbps": rate,
             "phy_family": "legacy"}, radiotap_fixed({2: bytes([rate])}), mpdu))
    for rate in (1, 3, 127, 255):
        cases.append(Case(
            f"radiotap.phy.legacy.unsupported_rate_{rate:03d}", "radiotap",
            "parse_only", "unsupported_value", "radiotap_phy_legacy",
            "parse_reject_eopnotsupp", "precise_unsupported",
            {"radiotap_index": 2, "field": "rate", "rate_500kbps": rate},
            radiotap_fixed({2: bytes([rate])}), mpdu))

    tx_flag_values = {
        "default": 0, "cts": 0x0002, "rts": 0x0004,
        "noack": 0x0008, "noseqno": 0x0010, "order": 0x0020,
        "noack_noseqno": 0x0018, "rts_noack": 0x000c,
    }
    for name, value in tx_flag_values.items():
        expectation = ("parser_accept_backend_candidate"
                       if value & ~0x0018 == 0 else "parse_reject_eopnotsupp")
        operation = ("parse_then_send_if_accepted_after_continuity_fix"
                     if expectation == "parser_accept_backend_candidate" else "parse_only")
        cases.append(Case(
            f"radiotap.policy.tx_flags.{name}", "radiotap", operation,
            "structurally_valid", "radiotap_tx_policy", expectation,
            "backend_effect_or_precise_unsupported",
            {"radiotap_index": 15, "field": "tx_flags", "value": value,
             "policy": name}, radiotap_fixed({15: struct.pack("<H", value)}), mpdu))

    for retries in (0, 1, 2, 7, 31, 126, 127, 255):
        expectation = ("parser_accept_backend_candidate" if retries <= 126
                       else "parse_reject_erange")
        operation = ("parse_then_send_if_accepted_after_continuity_fix"
                     if retries <= 126 else "parse_only")
        cases.append(Case(
            f"radiotap.policy.data_retries.{retries:03d}", "radiotap",
            operation, "structurally_valid", "radiotap_tx_policy",
            expectation, "backend_effect_or_precise_reject",
            {"radiotap_index": 17, "field": "data_retries",
             "value": retries}, radiotap_fixed({17: bytes([retries])}), mpdu))

    channel_cases = (
        (2412, 0x00a0, "2g"), (5180, 0x0140, "5g"),
        (5785, 0x0140, "5g_current"), (5955, 0x0140, "6g"),
    )
    for frequency, flags, label in channel_cases:
        cases.append(Case(
            f"radiotap.channel.{label}.{frequency}", "radiotap",
            "parse_then_send_if_accepted_after_continuity_fix",
            "structurally_valid_requires_runtime_regulatory_check",
            "radiotap_channel_policy", "parser_accept_backend_candidate",
            "off_channel_or_same_chandef_effect_fw_owned",
            {"radiotap_index": 3, "field": "channel",
             "frequency_mhz": frequency, "channel_flags": flags,
             "off_channel_passthrough": True},
            radiotap_fixed({3: struct.pack("<HH", frequency, flags)}), mpdu))

    fcs = struct.pack("<I", binascii.crc32(mpdu) & 0xffffffff)
    fcs_cases = (
        ("hardware_generate", radiotap_fixed({1: b"\x00"}), b"",
         "parser_accept_backend_candidate"),
        ("caller_valid", radiotap_fixed({1: b"\x10"}), fcs,
         "parser_accept_backend_candidate"),
        ("caller_invalid", radiotap_fixed({1: b"\x10"}), b"\xde\xad\xbe\xef",
         "parser_accept_backend_candidate"),
        ("intentional_badfcs", radiotap_fixed({1: b"\x40"}), b"",
         "parse_reject_ebadmsg"),
    )
    for name, fcs_rtap, suffix, expectation in fcs_cases:
        operation = ("parse_then_send_if_accepted_after_continuity_fix"
                     if expectation == "parser_accept_backend_candidate" else "parse_only")
        cases.append(Case(
            f"radiotap.fcs.{name}", "radiotap", operation,
            "structurally_valid_intent", "radiotap_fcs_policy", expectation,
            "ota_fcs_effect_or_precise_unsupported",
            {"radiotap_index": 1, "field": "flags", "fcs_mode": name},
            fcs_rtap, mpdu, suffix))

    phy_fields = {
        "ht": (19, b"\x07\x00\x00", "parser_accept_backend_candidate",
         "parse_then_send_if_accepted_after_continuity_fix"),
        "vht": (21, struct.pack("<HBB4BBBH", 0, 0, 0, 0x13, 0, 0, 0, 0, 0, 0),
         "parser_accept_backend_candidate",
         "parse_then_send_if_accepted_after_continuity_fix"),
        "he": (23, bytes.fromhex("fcff00000000000000000000"),
         "parser_accept_backend_candidate",
         "parse_then_send_if_accepted_after_continuity_fix"),
        "he_mu": (24, bytes.fromhex("ffff00000000000000000000"),
         "parse_reject_eopnotsupp", "parse_only"),
    }
    for family, (index, value, expectation, operation) in phy_fields.items():
        cases.append(Case(
            f"radiotap.phy.{family}.representative", "radiotap",
            operation, "structurally_valid", f"radiotap_phy_{family}",
            expectation, "backend_effect_or_precise_unsupported",
            {"radiotap_index": index, "field": RADIOTAP_FIXED[index][3],
             "phy_family": family, "axes": ["mcs", "nss", "bw", "gi",
             "ltf", "coding", "stbc"]}, radiotap_fixed({index: value}), mpdu))

    power_chain_cases = ((10, b"\x00", "tx_power_zero"),
                         (10, b"\x14", "tx_power_positive"),
                         (10, b"\xec", "tx_power_negative"),
                         (11, b"\x00", "antenna_zero"),
                         (11, b"\x03", "antenna_three"))
    for index, value, label in power_chain_cases:
        cases.append(Case(
            f"radiotap.phy.policy.{label}", "radiotap",
            "parse_then_send_if_accepted_after_continuity_fix",
            "structurally_valid", "radiotap_phy_policy",
            "parser_accept_backend_candidate", "backend_effect_or_precise_unsupported",
            {"radiotap_index": index, "field": RADIOTAP_FIXED[index][3],
             "value_hex": value.hex()}, radiotap_fixed({index: value}), mpdu))
    return cases


def all_cases() -> list[Case]:
    return frame_cases() + radiotap_cases()


def validate_case(case: Case) -> None:
    if not case.case_id or any(char.isspace() for char in case.case_id):
        raise ValueError(f"invalid case ID {case.case_id!r}")
    if case.operation not in {
        "send_after_continuity_fix",
        "parse_then_send_if_accepted_after_continuity_fix",
        "parse_only", "classify_only", "capability_only",
    }:
        raise ValueError(f"unknown operation for {case.case_id}")
    if case.radiotap:
        if len(case.radiotap) < 8 or case.radiotap[0] != 0:
            raise ValueError(f"invalid radiotap header for {case.case_id}")
        declared = struct.unpack_from("<H", case.radiotap, 2)[0]
        if declared != len(case.radiotap):
            raise ValueError(f"radiotap length mismatch for {case.case_id}")
    if len(case.mpdu) > MAX_MPDU_LEN and \
            case.current_expectation != "parse_reject_emsgsize":
        raise ValueError(f"MPDU exceeds current host ceiling for {case.case_id}")
    if case.operation.startswith("send") and case.legality in {
        "classification_required", "malformed", "unknown_namespace",
    }:
        raise ValueError(f"unsafe send classification for {case.case_id}")


def coverage(cases: list[Case]) -> dict[str, Any]:
    counts = Counter(case.suite for case in cases)
    operations = Counter(case.operation for case in cases)
    expectations = Counter(case.current_expectation for case in cases)
    gaps = [
        "local beacon continuity is recorded as a known todo 4.2 issue; it does not block Stage 1 parser/backend/completion execution",
    ]
    deferred_stage2 = [
        "independent OTA, response and rewrite observations require the later Stage 2 device/listener run",
    ]
    return {
        "schema": SCHEMA_VERSION,
        "status": "device_ready_4_2_continuity_observational",
        "total_cases": len(cases),
        "suite_counts": dict(sorted(counts.items())),
        "operation_counts": dict(sorted(operations.items())),
        "current_expectation_counts": dict(sorted(expectations.items())),
        "required_radiotap_indices": list(range(35)),
        "coverage_gaps": gaps,
        "deferred_stage2_work": deferred_stage2,
        "device_execution_enabled": True,
    }


def selftest(cases: list[Case]) -> dict[str, Any]:
    ids = [case.case_id for case in cases]
    if len(ids) != len(set(ids)):
        duplicates = [item for item, count in Counter(ids).items() if count > 1]
        raise AssertionError(f"duplicate case IDs: {duplicates}")
    for case in cases:
        validate_case(case)

    assigned_mgmt = {case.axes.get("subtype") for case in cases
                     if case.family == "pv0_management"}
    assigned_control = {case.axes.get("subtype") for case in cases
                        if case.family == "pv0_control"}
    data_cells = {(case.axes.get("subtype"), case.axes.get("to_ds"),
                   case.axes.get("from_ds")) for case in cases
                  if case.family == "pv0_data" and not case.axes.get("ht_control")}
    ordered_cells = {(case.axes.get("subtype"), case.axes.get("to_ds"),
                      case.axes.get("from_ds")) for case in cases
                     if case.family == "pv0_data" and case.axes.get("ht_control")}
    pv1_cells = {(case.axes.get("pv1_type"), case.axes.get("pv1_subtype"))
                 for case in cases if case.case_id.startswith("frame.pv1.classifier.")}
    ndp_cells = {(case.axes.get("width_mhz"), case.axes.get("ndp_type"))
                 for case in cases if case.family == "s1g_ndp"}
    rtap_indices = set()
    truncated = set()
    for case in cases:
        if "radiotap_index" in case.axes:
            rtap_indices.add(case.axes["radiotap_index"])
            if case.axes.get("boundary") == "size_minus_one":
                truncated.add(case.axes["radiotap_index"])

    checks = {
        "management_assigned_subtypes": assigned_mgmt == set(MGMT_NAMES),
        "control_assigned_subtypes": assigned_control == set(CONTROL_NAMES),
        "data_subtype_ds_cross_product": len(data_cells) == 16 * 4,
        "qos_ht_control_cross_product": len(ordered_cells) == 8 * 4,
        "pv1_classifier_cells": len(pv1_cells) == 8 * 8,
        "s1g_ndp_cells": len(ndp_cells) == 2 * 8,
        "radiotap_indices_0_34": rtap_indices == set(range(35)),
        "fixed_field_truncation_0_27": truncated == set(range(28)),
        "management_ie_equivalence_classes": {
            case.axes.get("ie_fixture") for case in cases
            if case.family == "pv0_management_ie"
        } == set(management_ie_fixtures()),
        "management_action_categories": {
            case.axes.get("action_category") for case in cases
            if case.family == "pv0_management_action"
        } == set(ACTION_CATEGORIES),
        "control_wrapper_carried_assigned": {
            case.axes.get("carried_subtype") for case in cases
            if case.family == "pv0_control_wrapper"
        } == set(CONTROL_NAMES) - {7},
        "block_ack_assigned_variants": {
            case.axes.get("block_ack_type") for case in cases
            if case.family == "pv0_block_ack"
        } == {"basic", "extended_compressed", "compressed", "multi_tid",
              "gcr", "glk_gcr", "multi_sta"},
        "trigger_types_and_users": {
            (case.axes.get("trigger_type"), case.axes.get("user_count"))
            for case in cases if case.family == "pv0_trigger"
        } == {(trigger_type, users) for trigger_type in range(9)
              for users in (0, 1, 2, 4)},
        "payload_boundaries": {
            case.axes.get("payload_boundary") for case in cases
            if case.family == "pv0_data_payload_boundary"
        } == set(PAYLOAD_BOUNDARIES),
        "crypto_cipher_pn_cross_product": {
            (case.axes.get("cipher"), case.axes.get("pn_class"))
            for case in cases if case.family == "pv0_raw_encrypted"
        } == {(cipher, pn) for cipher in
              ("wep40", "tkip", "ccmp128", "ccmp256", "gcmp128", "gcmp256")
              for pn in ("zero", "one", "max48")},
        "fcs_modes": {
            case.axes.get("fcs_mode") for case in cases
            if case.family == "radiotap_fcs_policy"
        } == {"hardware_generate", "caller_valid", "caller_invalid",
              "intentional_badfcs"},
        "device_execution_enabled": coverage(cases)["device_execution_enabled"] is True,
    }
    failed = [name for name, passed in checks.items() if not passed]
    if failed:
        raise AssertionError(f"coverage selftest failed: {failed}")

    serialized_once = serialize_jsonl(cases)
    serialized_twice = serialize_jsonl(all_cases())
    if serialized_once != serialized_twice:
        raise AssertionError("matrix generation is not deterministic")
    return {"checks": checks, "cases": len(cases),
            "sha256": hashlib.sha256(serialized_once).hexdigest()}


def serialize_jsonl(cases: list[Case]) -> bytes:
    return b"".join(
        (json.dumps(case.as_json(), sort_keys=True, separators=(",", ":")) + "\n").encode()
        for case in cases
    )


def summary_tsv(cases: list[Case]) -> bytes:
    header = ("case_id\tsuite\toperation\tlegality\tfamily\t"
              "current_expectation\tcurrent_parser_state\tcurrent_parser_errno\t"
              "stage1_requirement\tstage2_requirement\tpacket_sha256\n")
    rows = [header]
    for case in cases:
        record = case.as_json()
        rows.append("\t".join(str(record[key]) for key in (
            "case_id", "suite", "operation", "legality", "family",
            "current_expectation", "current_parser_state",
            "current_parser_errno", "stage1_requirement",
            "stage2_requirement", "packet_sha256"
        )) + "\n")
    return "".join(rows).encode()


def device_plan_tsv(cases: list[Case]) -> bytes:
    header = ("case_id\tcase_cookie\tpacket_sha256\toperation\t"
              "current_parser_state\tcurrent_parser_errno\tpacket_hex\n")
    rows = [header]
    eligible = {"send_after_continuity_fix",
                "parse_then_send_if_accepted_after_continuity_fix",
                "parse_only"}
    for case in cases:
        if case.operation not in eligible:
            continue
        record = case.as_json()
        errno = ("NA" if record["current_parser_errno"] is None
                 else str(record["current_parser_errno"]))
        rows.append("\t".join((record["case_id"], record["case_cookie"],
                               record["packet_sha256"], record["operation"],
                               record["current_parser_state"], errno,
                               record["packet_hex"])) + "\n")
    return "".join(rows).encode()


def evidence_template(cases: list[Case]) -> bytes:
    layer_names = ("parsed", "accepted", "submitted", "completion",
                   "ota", "response", "rewrite", "teardown",
                   "capability")
    records = []
    for case in cases:
        manifest = case.as_json()
        record: dict[str, Any] = {
            "schema": SCHEMA_VERSION,
            "case_id": case.case_id,
            "packet_sha256": manifest["packet_sha256"],
            "run_state": "not_run",
        }
        for layer in layer_names:
            record[layer] = {"state": "not_run"}
        records.append((json.dumps(record, sort_keys=True,
                                   separators=(",", ":")) + "\n").encode())
    return b"".join(records)


def generated_files(cases: list[Case]) -> dict[str, bytes]:
    report = coverage(cases)
    return {
        "stage1-cases.jsonl": serialize_jsonl(cases),
        "stage1-summary.tsv": summary_tsv(cases),
        "stage1-device-plan.tsv": device_plan_tsv(cases),
        "stage1-evidence-template.jsonl": evidence_template(cases),
        "coverage.json": (json.dumps(report, indent=2, sort_keys=True) + "\n").encode(),
    }


def write_outputs(directory: pathlib.Path, cases: list[Case]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    files = generated_files(cases)
    for name, data in files.items():
        (directory / name).write_bytes(data)
    sums = []
    for name in sorted(files):
        sums.append(f"{hashlib.sha256(files[name]).hexdigest()}  {name}\n")
    (directory / "SHA256SUMS.generated").write_text("".join(sums))


def check_outputs(directory: pathlib.Path, cases: list[Case]) -> None:
    with tempfile.TemporaryDirectory(prefix="stage1-matrix-check-") as temp:
        expected = pathlib.Path(temp)
        write_outputs(expected, cases)
        names = sorted(set(path.name for path in expected.iterdir()) |
                       set(path.name for path in directory.iterdir()
                           if path.name in {"stage1-cases.jsonl",
                                            "stage1-summary.tsv",
                                            "stage1-device-plan.tsv",
                                            "stage1-evidence-template.jsonl",
                                            "coverage.json",
                                            "SHA256SUMS.generated"}))
        for name in names:
            actual_path = directory / name
            expected_path = expected / name
            if not actual_path.exists() or actual_path.read_bytes() != expected_path.read_bytes():
                raise SystemExit(f"generated output mismatch: {name}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_mutually_exclusive_group(required=True)
    commands.add_argument("--selftest", action="store_true")
    commands.add_argument("--write", type=pathlib.Path)
    commands.add_argument("--check", type=pathlib.Path)
    commands.add_argument("--case")
    args = parser.parse_args(argv)

    cases = all_cases()
    result = selftest(cases)
    if args.selftest:
        report = coverage(cases)
        print(f"selftest=PASS schema={SCHEMA_VERSION} cases={len(cases)} "
              f"frame={report['suite_counts']['frame']} "
              f"radiotap={report['suite_counts']['radiotap']} "
              f"sha256={result['sha256']}")
        return 0
    if args.write:
        write_outputs(args.write, cases)
        print(f"generated={args.write} cases={len(cases)}")
        return 0
    if args.check:
        check_outputs(args.check, cases)
        print(f"generated_outputs=PASS directory={args.check} cases={len(cases)}")
        return 0
    for case in cases:
        if case.case_id == args.case:
            print(json.dumps(case.as_json(), sort_keys=True))
            return 0
    print(f"unknown case: {args.case}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
