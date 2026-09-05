#!/usr/bin/env python3
"""Generate the A-1 watchdog-envelope vectors (todo 4.3 A-1).

The completion watchdog (3000 ms, frame_inject.c) can collide with the
driver's own legal worst case: data_retries=126 -> 127 attempts of a
maximum-length (2348 B) mgmt frame at 1 Mbps on 2.4 GHz is ~18.8 ms of
airtime per attempt, ~2.4 s pure airtime for the sequence plus DIFS and
growing contention windows - inside spitting distance of the watchdog.
Each vector isolates one axis so a boot can bisect length vs retries:

  control   26 B deauth (minimum: header + reason), 1 Mbps, no
            DATA_RETRIES (attempts=1) - harness baseline, milliseconds
  len       2348 B deauth, 1 Mbps, no retries  - max-frame axis only
  retries   26 B deauth, 1 Mbps, DATA_RETRIES=126 - retry axis only
  envelope  2348 B deauth, 1 Mbps, DATA_RETRIES=126 - the legal worst
            case the watchdog must survive (self-harm candidate)

radiotap fields: RATE=2 (1 Mbps is encoded in 500 kb/s units),
CHANNEL freq=2412 flags=CCK|2GHZ (0x00a0), DATA_RETRIES=17 (kernel enum,
NOT 15 which is TX_FLAGS - verified against the GKI reference header).
Like every suite vector these are generated and decode-asserted here;
the runner embeds the output verbatim and re-checks it at startup.
"""
import struct
import sys

RT_RATE, RT_CHANNEL, RT_DATA_RETRIES = 2, 3, 17
RATE_1MBPS = 2  # 500 kb/s units (HDD_FRAME_INJECT_RATE_1_MBPS)
CHAN_CCK, CHAN_2GHZ = 0x0020, 0x0080
MAX_MPDU = 2348  # IEEE80211_MAX_FRAME_LEN(2352) - FCS(4)

# (align, size) per field in present-bit walk order
FIELD_GEOM = {RT_RATE: (1, 1), RT_CHANNEL: (2, 4), RT_DATA_RETRIES: (1, 1)}


def mpdu(total_len):
    assert total_len in (26, MAX_MPDU)
    ra = bytes([0x02, 0x11, 0x22, 0x33, 0x44, 0x55])  # unicast, absent: no ACK
    ta = bytes([0x02, 0xAB, 0xCD, 0x00, 0x00, 0xF1])
    body = struct.pack("<HH", 0x00C0, 0) + ra + ta + ra  # fc, dur, a1/a2/a3
    body += struct.pack("<H", 0)  # sequence control
    body += struct.pack("<H", 1)  # reason: unspecified
    return body + b"\xAA" * (total_len - len(body))


def radiotap(retries):
    fields = [
        (RT_RATE, struct.pack("<B", RATE_1MBPS)),
        (RT_CHANNEL, struct.pack("<HH", 2412, CHAN_CCK | CHAN_2GHZ)),
    ]
    if retries is not None:
        fields.append((RT_DATA_RETRIES, struct.pack("<B", retries)))
    blob = b""
    offset = 8
    for index, data in sorted(fields):
        align, _size = FIELD_GEOM[index]
        pad = -offset % align
        blob += b"\x00" * pad
        offset += pad
        blob += data
        offset += len(data)
    present = 0
    for index, _ in fields:
        present |= 1 << index
    return struct.pack("<BBHI", 0, 0, 8 + len(blob), present) + blob


def build(name):
    table = {
        "control": (26, None),
        "len": (MAX_MPDU, None),
        "retries": (26, 126),
        "envelope": (MAX_MPDU, 126),
    }
    if name not in table:
        raise SystemExit(f"unknown vector {name}")
    frame_len, retries = table[name]
    packet = radiotap(retries) + mpdu(frame_len)
    decode_assert(name, packet)
    return packet


def decode_assert(name, packet):
    it_len = packet[2] | (packet[3] << 8)
    expected_frame = 26 if name in ("control", "retries") else MAX_MPDU
    assert it_len == len(packet) - expected_frame, (name, it_len)
    present = int.from_bytes(packet[4:8], "little")
    assert present == ((1 << RT_RATE) | (1 << RT_CHANNEL) |
                       ((1 << RT_DATA_RETRIES) if name in ("retries",
                                                           "envelope") else 0)
                       ), (name, hex(present))
    # rate@8 (align1), channel@10 (align2 after pad), retries@14 (align1)
    assert packet[8] == RATE_1MBPS, (name, packet[8])
    freq, flags = struct.unpack("<HH", packet[10:14])
    assert freq == 2412 and flags == (CHAN_CCK | CHAN_2GHZ), (name, freq, flags)
    if name in ("retries", "envelope"):
        assert packet[14] == 126, (name, packet[14])
    mpdu_bytes = packet[it_len:]
    fc = mpdu_bytes[0] | (mpdu_bytes[1] << 8)
    assert fc == 0x00C0, (name, hex(fc))
    assert len(mpdu_bytes) == expected_frame, (name, len(mpdu_bytes))
    reason = mpdu_bytes[24] | (mpdu_bytes[25] << 8)
    assert reason == 1, (name, reason)


def main():
    names = sys.argv[1:] or ["control", "len", "retries", "envelope"]
    for name in names:
        print(f"{name}={build(name).hex()}")


if __name__ == "__main__":
    main()
