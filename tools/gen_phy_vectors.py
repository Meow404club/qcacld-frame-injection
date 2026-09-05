#!/usr/bin/env python3
"""Regenerate the kit phy_ab vectors 1-10 with spec-correct encodings.

The v8/v9 hand-written vectors had three classes of defects (2026-09-04
scan): probe-request MPDUs without the sequence-control field (22B, driver
min-len 24 rejects before any PHY semantics), the TX-power vectors setting
DBM_ANTSIGNAL (bit 5) instead of DBM_TX_POWER (bit 10), VHT bandwidth
values from a non-spec table (radiotap VHT bandwidth is 0/1/4/11 =
20/40/80/160 MHz; 80+80 is not expressible), and a neg_mcs_stbc whose
known-bits did not assert HAVE_STBC. This generator builds each vector,
decodes it back, and asserts the semantics before printing the kit lines.
"""
import struct
import sys

import os
KERNEL = os.environ.get("RADIOTAP_HEADER")
if not KERNEL:
    sys.exit("set RADIOTAP_HEADER=<kernel>/include/net/ieee80211_radiotap.h (reference kernel)")
# kernel enum values (verified against the reference header)
MCS_HAVE_BW, MCS_HAVE_MCS, MCS_HAVE_STBC = 0x01, 0x02, 0x20
MCS_BW_20, MCS_BW_40 = 0, 1
VHT_KNOWN_BW, VHT_KNOWN_GI, VHT_FLAG_SGI = 0x0040, 0x0004, 0x0004
HE_DATA1_KNOWN = 0x4020  # DATA_MCS_KNOWN | BW_RU_ALLOC_KNOWN
RT_MCS, RT_VHT, RT_RATE, RT_TX_POWER, RT_FLAGS, RT_HE = 19, 21, 2, 10, 1, 23


def mpdu(sa_last, fcs=None):
    sa = bytes([0x02, 0xAB, 0xCD, 0x00, 0x00, sa_last])
    body = struct.pack("<HH", 0x0040, 0) + b"\xff" * 6 + sa + b"\xff" * 6
    body += struct.pack("<H", 0)  # sequence control
    return body + (fcs if fcs else b"")


def radiotap(present_bits, fields):
    """fields: list of bytes blobs appended in bit order."""
    present = 0
    for bit in present_bits:
        present |= 1 << bit
    blob = b"".join(fields)
    length = 8 + len(blob)
    header = struct.pack("<BBHI", 0, 0, length, present)
    return header + blob, length


def build(name):
    if name.startswith("ht_"):
        idx = int(name.split("mcs")[1].split("_")[0])
        bw40 = name.endswith("bw40")
        field = struct.pack("<BBB", MCS_HAVE_BW | MCS_HAVE_MCS,
                            MCS_BW_40 if bw40 else MCS_BW_20, idx)
        return radiotap([RT_MCS], [field])
    if name.startswith("vht"):
        bw = {"vht20": 0, "vht40": 1, "vht80": 4,
              "vht160": 11}[name.split("_")[0]]
        nss = int(name.split("nss")[1].split("_")[0])
        mcs = int(name.split("mcs")[1])
        # radiotap.org VHT layout (v20 spec conformance; mac80211 reads
        # flags at +2 and bandwidth at +3 as single bytes):
        # known u16, flags u8, bandwidth u8, mcs_nss[4], coding u8,
        # group_id u8, partial_aid u16 - 12 bytes total
        vht = struct.pack("<HBB", VHT_KNOWN_BW, 0, bw)
        vht += struct.pack("<BBBB", (nss << 4) | mcs, 0, 0, 0)
        vht += b"\x00\x00\x00\x00"
        return radiotap([RT_VHT], [vht])
    if name.startswith("he_"):
        mcs = int(name.split("mcs")[1].split("_")[0])
        bw = {"bw20": 0, "bw40": 1, "bw80": 2,
              "bw160": 3}[name.split("_")[2]]
        nsts = int(name.split("nsts")[1])
        # radiotap HE field is six LE u16 (kernel: {2, 12}); data3 MCS is
        # bits 8-11, data5 low nibble is the BW/RU alloc, data6 low nibble
        # is NSTS (driver mgmt.c reads exactly these)
        he = struct.pack("<6H", HE_DATA1_KNOWN, 0, mcs << 8, 0, bw, nsts)
        return radiotap([RT_HE], [he])
    if name.startswith("pwr"):
        power = int(name[3:5])
        rate = struct.pack("<BB", 0x0C, power)  # 6 Mbps, signed dBm
        return radiotap([RT_RATE, RT_TX_POWER], [rate])
    if name == "neg_mcs_stbc":
        field = struct.pack("<BBB", MCS_HAVE_BW | MCS_HAVE_MCS |
                            MCS_HAVE_STBC, 0x20, 0x00)  # stbc=1, bw=20
        return radiotap([RT_MCS], [field])
    if name == "neg_vht_sgi":
        vht = struct.pack("<HBB", VHT_KNOWN_GI | VHT_KNOWN_BW,
                          VHT_FLAG_SGI, 4)
        vht += struct.pack("<BBBB", 0x13, 0, 0, 0) + b"\x00\x00\x00\x00"
        return radiotap([RT_VHT], [vht])
    raise SystemExit(f"unknown vector {name}")


def decode_assert(name, packet):
    it_len = packet[2] | (packet[3] << 8)
    assert it_len == len(packet) - 24, (name, it_len)
    mpdu = packet[it_len:]
    fc = mpdu[0] | (mpdu[1] << 8)
    assert fc == 0x0040 and len(mpdu) == 24, (name, fc, len(mpdu))
    present = int.from_bytes(packet[4:8], "little")
    if name.startswith("ht_"):
        assert present == 1 << RT_MCS, (name, hex(present))
        known, flags, idx = packet[8:11]
        assert known & MCS_HAVE_MCS, name
        assert (flags & 3) in (MCS_BW_20, MCS_BW_40), name
    elif name.startswith("vht") or name == "neg_vht_sgi":
        assert present == 1 << RT_VHT, (name, hex(present))
        known = struct.unpack_from("<H", packet, 8)[0]
        flags, bw = packet[10], packet[11]
        assert bw in (0, 1, 4, 11), (name, bw)
        if name == "neg_vht_sgi":
            assert (known & VHT_KNOWN_GI) and (flags & VHT_FLAG_SGI), name
    elif name.startswith("pwr"):
        present_wanted = (1 << RT_RATE) | (1 << RT_TX_POWER)
        assert present == present_wanted, (name, hex(present))
        rate, power = packet[8], packet[9]
        assert rate == 0x0C and power in (10, 20), (name, rate, power)
    elif name.startswith("he_"):
        assert present == 1 << RT_HE, (name, hex(present))
        d1, d2, d3, d4, d5, d6 = struct.unpack_from("<6H", packet, 8)
        assert d1 == HE_DATA1_KNOWN, (name, hex(d1))
        assert 0 <= ((d3 & 0x0f00) >> 8) <= 11, (name, hex(d3))
        assert (d5 & 0x000f) <= 3, (name, hex(d5))
        assert 1 <= (d6 & 0x000f) <= 8, (name, hex(d6))
    elif name == "neg_mcs_stbc":
        known, flags, idx = packet[8:11]
        assert (known & MCS_HAVE_STBC) and \
            ((flags & 0x60) >> 5) >= 1, (name, hex(known), hex(flags))


order = ["ht_mcs0_bw20", "ht_mcs7_bw40", "ht_mcs9_nss2",
         "vht80_nss1_mcs3", "vht160_nss2_mcs8", "vht40_nss2_mcs9",
         "pwr10_legacy6m", "pwr20_legacy6m",
         "neg_mcs_stbc", "neg_vht_sgi"]
lines = []
for i, name in enumerate(order, 1):
    header, _ = build(name)
    packet = header + mpdu(i)
    decode_assert(name, packet)
    lines.append(f'"{name}|{packet.hex()}"')
print("\n".join(lines), file=sys.stdout)

if "--bisect" in sys.argv:
    # FW RAMDUMP boundary bisect vectors (run_v13a_bisect_host.sh): one
    # axis per vector. sa_last=0xf1 reproduces the exact packets already
    # sent on device (CONTROL crashed v13a 2026-09-05 with this SA).
    bisect = [
        ("VHT20", "vht20_nss1_mcs3"),    # pure VHT, bw BIT(2): SURVIVED v13a
        ("HT20", "ht_mcs0_bw20"),        # HT family @20 - predicted safe
        ("HE20", "he_mcs7_bw20_nsts1"),  # HE family @20 - predicted safe
        ("CONTROL", "vht80_nss1_mcs3"),  # bw BIT(4): crashed v13a @20 AND @80 ctx
        ("NSS", "vht40_nss2_mcs9"),      # bw BIT(3): predicted crash (midpoint)
        ("BWPURE", "vht160_nss1_mcs3"),  # bw BIT(5): predicted crash
        ("KILLER", "vht160_nss2_mcs8"),  # original v13 crash combination
        ("HE160", "he_mcs7_bw160_nsts1"),
    ]
    for key, name in bisect:
        header, _ = build(name)
        packet = header + mpdu(0xF1)
        decode_assert(name, packet)
        print(f"{key}|{name}|{packet.hex()}", file=sys.stdout)
