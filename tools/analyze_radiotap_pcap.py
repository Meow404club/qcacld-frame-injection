#!/usr/bin/env python3
"""Offline radiotap audit for QCACLD3 monitor-RX pcaps (DLT 127).

v2 (2026-09-01): the presence-bit table is now taken verbatim from the
shipping kernel's include/net/ieee80211_radiotap.h (the same header the
TX-side bounded iterator is built against, kept at
tmp/suites/host-fuzz-frame-parser/linux_shim/net/ieee80211_radiotap.h).
The first draft of this script mislabelled the bitmap (bit15 decoded as
MCS, DBM_ANTSIGNAL/ANTNOISE swapped); those results are void.

Decodes the fields the stock qdf_nbuf_update_radiotap() builder emits,
walks the extension chain, validates that the walked layout consumes
exactly it_len bytes, and reports per-field population and value
quality.  Purely passive: it never claims on-air semantics, it only
characterizes what the local monitor delivered.
"""

import argparse
import collections
import struct
import sys

TYPE_MGMT, TYPE_CTRL, TYPE_DATA, TYPE_EXT = 0, 1, 2, 3
SUBTYPE_NAMES_MGMT = {
    0x8: "beacon", 0x5: "probe_resp", 0x4: "probe_req", 0xA: "disassoc",
    0xC: "deauth", 0xB: "auth", 0x0: "assoc_req", 0x1: "assoc_resp",
    0xD: "action", 0xE: "action_no_ack",
}
SUBTYPE_NAMES_CTRL = {
    0xD: "ACK", 0xB: "RTS", 0xC: "CTS", 0x8: "BAR", 0x9: "BA",
    0xA: "PS-Poll", 0xE: "CF-End", 0xF: "CF-End+ACK",
}

# Presence bits, verbatim from the shipping kernel header.
BIT_NAMES = {
    0: "TSFT", 1: "FLAGS", 2: "RATE", 3: "CHANNEL", 4: "FHSS",
    5: "DBM_ANTSIGNAL", 6: "DBM_ANTNOISE", 7: "LOCK_QUALITY",
    8: "TX_ATTENUATION", 9: "DB_TX_ATTENUATION", 10: "DBM_TX_POWER",
    11: "ANTENNA", 12: "DB_ANTSIGNAL", 13: "DB_ANTNOISE",
    14: "RX_FLAGS", 15: "TX_FLAGS", 16: "RTS_RETRIES",
    17: "DATA_RETRIES", 18: "XCHANNEL", 19: "MCS",
    20: "AMPDU_STATUS", 21: "VHT", 22: "TIMESTAMP", 23: "HE",
    24: "HE_MU", 25: "HE_MU_OTHER", 26: "ZERO_LEN_PSDU", 27: "LSIG",
    28: "TLV", 29: "RADIOTAP_NAMESPACE", 30: "VENDOR_NAMESPACE",
    31: "EXT",
}

# word geometry: bit -> (align_bytes, size_bytes); radiotap spec order.
# The QDF builder appends its conditional fields in bit order, so the
# spec walk and the builder layout coincide.  bit29 carries no payload;
# bit31 is the extension chain; bit30 payload size comes from its own
# skip_length field (QDF writes the Ath NS with 2-byte alignment).
GEOM = {
    0: (8, 8), 1: (1, 1), 2: (1, 1), 3: (2, 4), 4: (2, 2), 5: (1, 1),
    6: (1, 1), 7: (2, 2), 8: (2, 2), 9: (2, 2), 10: (1, 1), 11: (1, 1),
    12: (1, 1), 13: (1, 1), 14: (2, 2), 15: (2, 2), 16: (1, 1),
    17: (1, 1), 18: (4, 4), 19: (1, 3), 20: (4, 8), 21: (2, 12),
    22: (2, 8), 23: (2, 12), 24: (2, 8), 25: (2, 8), 26: (2, 4),
    27: (4, 4), 28: (4, 4),
}

CHAN_FLAG_NAMES = {
    0x0010: "turbo", 0x0020: "cck", 0x0040: "ofdm", 0x0080: "2ghz",
    0x0100: "5ghz", 0x0200: "passive", 0x0400: "dyn", 0x0800: "gfsk",
    0x1000: "gsm", 0x2000: "static", 0x4000: "half", 0x8000: "quarter",
}
FLAG_NAMES = {
    0x01: "ckip", 0x02: "shortpre", 0x04: "wep", 0x08: "frag",
    0x10: "fcs", 0x20: "pad", 0x40: "badfcs", 0x80: "shortgi",
}


def align(x, a):
    return (x + a - 1) & ~(a - 1)


def parse_pcap(path):
    with open(path, "rb") as f:
        d = f.read()
    if d[:4] == b"\xd4\xc3\xb2\xa1":
        end = "<"
    elif d[:4] == b"\xa1\xb2\xc3\xd4":
        end = ">"
    else:
        raise SystemExit(f"{path}: not a classic pcap")
    linktype = struct.unpack(end + "I", d[20:24])[0]
    if linktype != 127:
        raise SystemExit(f"{path}: linktype {linktype} != 127 (radiotap)")
    off = 24
    pkts = []
    while off + 16 <= len(d):
        ts, us, cap, orig = struct.unpack(end + "IIII", d[off:off + 16])
        off += 16
        pkts.append((ts + us / 1e6, d[off:off + cap]))
        off += cap
    return pkts


def decode_bit(bit, raw, fields):
    if bit == 0:
        fields["tsft"] = struct.unpack("<Q", raw)[0]
    elif bit == 1:
        fields["flags"] = raw[0]
    elif bit == 2:
        fields["rate"] = raw[0]
    elif bit == 3:
        fields["chan_freq"], fields["chan_flags"] = \
            struct.unpack("<HH", raw)
    elif bit == 5:
        fields["dbm_antsignal"] = struct.unpack("<b", raw)[0]
    elif bit == 6:
        fields["dbm_antnoise"] = struct.unpack("<b", raw)[0]
    elif bit == 11:
        fields["antenna"] = raw[0]
    elif bit == 14:
        fields["rx_flags"] = struct.unpack("<H", raw)[0]
    elif bit == 19:
        fields["mcs_known"], fields["mcs_flags"], fields["mcs_index"] = raw
    elif bit == 20:
        fields["ampdu_ref"] = struct.unpack("<I", raw[:4])[0]
        fields["ampdu_flags"] = struct.unpack("<H", raw[4:6])[0]
    elif bit == 21:
        fields["vht_known"] = struct.unpack("<H", raw[:2])[0]
        fields["vht_flags"] = raw[2]
        fields["vht_bw"] = raw[3]
        fields["vht_mcs_nss"] = list(raw[4:8])
        fields["vht_coding"] = raw[8]
        fields["vht_group_id"] = raw[9]
        fields["vht_partial_aid"] = struct.unpack("<H", raw[10:12])[0]
    elif bit == 30:
        oui = raw[:3]
        fields["vendor_oui"] = "%02x:%02x:%02x" % tuple(oui)
        fields["vendor_skip"] = struct.unpack("<H", raw[4:6])[0]


def parse_radiotap(pkt):
    """Walk one radiotap header the way the QDF builder lays it out.

    Returns (fields, body, words).  fields['walk_end_mismatch'] is set
    when the walked layout does not consume exactly it_len bytes.
    """
    fields = {}
    if len(pkt) < 8:
        return fields, b"", []
    ver, pad, rlen, present = struct.unpack("<BBHI", pkt[:8])
    fields["it_version"] = ver
    fields["it_len"] = rlen
    if rlen < 8 or rlen > len(pkt):
        fields["walk_end_mismatch"] = True
        return fields, b"", [present]
    body = pkt[rlen:]
    off = 8
    words = [present]
    # follow the extension chain (bit 31 of each word)
    while words[-1] & 0x80000000 and off + 4 <= rlen and len(words) < 5:
        words.append(struct.unpack("<I", pkt[off:off + 4])[0])
        off += 4
    fields["present_words"] = words

    # The radiotap spec forbids RADIOTAP_NAMESPACE and VENDOR_NAMESPACE in
    # the same presence word; wireshark flags the combination as malformed
    # and stops parsing the header (bit us on the first per-chain build).
    for word in words:
        if (word & (1 << 29)) and (word & (1 << 30)):
            fields["ns_vendor_conflict"] = True
            break

    for word_i, word in enumerate(words):
        for bit in range(31):
            if not (word & (1 << bit)):
                continue
            gbit = word_i * 32 + bit
            fields.setdefault("present_bits", set()).add(gbit)
            if bit == 30:
                off = align(off, 2)  # QDF writes the Ath NS at align 2
                if off + 6 > rlen:
                    fields["walk_end_mismatch"] = True
                    return fields, body, words
                skip = struct.unpack("<H", pkt[off + 4:off + 6])[0]
                size = 6 + skip
            elif bit in GEOM:
                a, size = GEOM[bit]
                off = align(off, a)
            else:
                continue  # bit29 namespace marker: no payload
            if off + size > rlen:
                fields["walk_end_mismatch"] = True
                return fields, body, words
            if word_i > 0 and bit in (5, 11):
                # repeated per-chain pair after a RADIOTAP_NAMESPACE
                # reset (mac80211 convention): word0 keeps the
                # aggregate signal/antenna, extension words carry one
                # (signal, antenna) pair each, in word order
                if bit == 5:
                    fields.setdefault("chain_signals", []).append(
                        struct.unpack("<b", pkt[off:off + 1])[0])
                else:
                    fields.setdefault("chain_idxs", []).append(pkt[off])
            else:
                decode_bit(bit, pkt[off:off + size], fields)
            off += size
    if off != rlen:
        fields["walk_end_mismatch"] = True
    return fields, body, words


def classify(body):
    if len(body) < 2:
        return "short"
    fc = struct.unpack("<H", body[:2])[0]
    t = (fc >> 2) & 0x3
    st = (fc >> 4) & 0xF
    if t == TYPE_MGMT:
        return "mgmt:" + SUBTYPE_NAMES_MGMT.get(st, hex(st))
    if t == TYPE_CTRL:
        return "ctrl:" + SUBTYPE_NAMES_CTRL.get(st, hex(st))
    if t == TYPE_DATA:
        return "data:" + ("qos" if fc & 0x80 else "plain")
    return "ext:" + hex(st)


def hist_line(name, counter, top=8):
    return f"{name}: {dict(counter.most_common(top))}"


def audit(paths):
    total = 0
    present_hist = collections.Counter()
    bit_pop = collections.Counter()
    type_hist = collections.Counter()
    rate_hist = collections.Counter()
    freq_hist = collections.Counter()
    chanflag_hist = collections.Counter()
    rssi_hist = collections.Counter()
    noise_hist = collections.Counter()
    antenna_hist = collections.Counter()
    flags_hist = collections.Counter()
    rtap_len_hist = collections.Counter()
    mcs_hist = collections.Counter()
    vht_hist = collections.Counter()
    vendor_oui_hist = collections.Counter()
    vendor_skip_hist = collections.Counter()
    tsft_present = 0
    tsft_zero = 0
    tsft_backwards = 0
    tsft_deltas = []
    fcs_in_frame = 0
    badfcs_flag = 0
    ext_word_frames = 0
    perchain_frames = 0
    perchain_pair_hist = collections.Counter()
    perchain_chain_rssi = collections.Counter()
    zero_len_psdus = 0
    walk_mismatch = 0
    ns_vendor_conflict = 0
    chain_idx_invalid = 0
    frame_dup_counter = collections.Counter()
    ack_ra = collections.Counter()
    per_file = []
    for path in paths:
        pkts = parse_pcap(path)
        last_tsft = None
        for ts, pkt in pkts:
            f, body, words = parse_radiotap(pkt)
            total += 1
            present_hist[f.get("present_words", ["none"])[0]
                         if f.get("present_words") else -1] += 1
            for b in f.get("present_bits", ()):
                bit_pop[b] += 1
            rtap_len_hist[f.get("it_len", 0)] += 1
            if f.get("walk_end_mismatch"):
                walk_mismatch += 1
            if f.get("ns_vendor_conflict"):
                ns_vendor_conflict += 1
            # chain pairs must carry real chain indexes (0..7); anything
            # else means the pairs are misaligned with the walk (this is
            # exactly how a stray pad byte in front of the pairs surfaced)
            if any(i > 7 for i in f.get("chain_idxs", [])):
                chain_idx_invalid += 1
            if len(words) > 1:
                ext_word_frames += 1
            sigs = f.get("chain_signals", [])
            idxs = f.get("chain_idxs", [])
            if sigs and len(sigs) == len(idxs):
                perchain_frames += 1
                perchain_pair_hist[len(sigs)] += 1
                for sig, idx in zip(sigs, idxs):
                    perchain_chain_rssi[(idx, sig)] += 1
            if f.get("tsft") is not None:
                tsft_present += 1
                if f["tsft"] == 0:
                    tsft_zero += 1
                if last_tsft is not None:
                    if f["tsft"] < last_tsft:
                        tsft_backwards += 1
                    tsft_deltas.append(
                        (f["tsft"] - last_tsft) / 1000.0)  # us -> ms
                last_tsft = f["tsft"]
            else:
                last_tsft = None
            if "rate" in f:
                rate_hist[f["rate"]] += 1
            if "chan_freq" in f:
                freq_hist[f["chan_freq"]] += 1
            if "chan_flags" in f:
                chanflag_hist[f["chan_flags"]] += 1
            if "dbm_antsignal" in f:
                rssi_hist[f["dbm_antsignal"]] += 1
            if "dbm_antnoise" in f:
                noise_hist[f["dbm_antnoise"]] += 1
            if "antenna" in f:
                antenna_hist[f["antenna"]] += 1
            flags_hist[f.get("flags", -1)] += 1
            if f.get("flags", 0) & 0x10:
                fcs_in_frame += 1
            if f.get("flags", 0) & 0x40:
                badfcs_flag += 1
            if "mcs_index" in f:
                mcs_hist[(f["mcs_known"], f["mcs_flags"] & 0x03,
                          f["mcs_index"])] += 1
            if "vht_known" in f:
                v0 = f["vht_mcs_nss"][0]
                vht_hist[(f["vht_known"], f["vht_bw"], v0 & 0xF,
                          ((v0 >> 4) & 0xF) + 1)] += 1
            if "vendor_oui" in f:
                vendor_oui_hist[f["vendor_oui"]] += 1
                vendor_skip_hist[f["vendor_skip"]] += 1
            if not body:
                zero_len_psdus += 1
            kind = classify(body)
            type_hist[kind] += 1
            if kind == "ctrl:ACK" and len(body) >= 10:
                ack_ra["%02x:%02x:%02x:%02x:%02x:%02x" % tuple(body[4:10])] += 1
            # Duplicate-delivery probe: identical MPDU bytes delivered more
            # than once would show as counter > 1 (ACK/BA legitimately repeat).
            if not kind.startswith("ctrl:"):
                frame_dup_counter[body[:64]] += 1
        per_file.append((path.split("/")[-1], len(pkts)))
    dup_multi = sum(1 for c in frame_dup_counter.values() if c > 1)

    rssi_bad_range = sum(c for v, c in rssi_hist.items()
                         if not -100 <= v <= 0)
    tsft_sorted = sorted(tsft_deltas)
    tsft_delta_summary = "n/a"
    if tsft_sorted:
        tsft_delta_summary = (
            f"min {tsft_sorted[0]:.3f} ms "
            f"median {tsft_sorted[len(tsft_sorted) // 2]:.3f} ms "
            f"max {tsft_sorted[-1]:.3f} ms")
    return dict(
        total=total, present_hist=present_hist, bit_pop=bit_pop,
        type_hist=type_hist, rate_hist=rate_hist, freq_hist=freq_hist,
        chanflag_hist=chanflag_hist, rssi_hist=rssi_hist,
        noise_hist=noise_hist, antenna_hist=antenna_hist,
        flags_hist=flags_hist, rtap_len_hist=rtap_len_hist,
        mcs_hist=mcs_hist, vht_hist=vht_hist,
        vendor_oui_hist=vendor_oui_hist, vendor_skip_hist=vendor_skip_hist,
        tsft_present=tsft_present, tsft_zero=tsft_zero,
        tsft_backwards=tsft_backwards, tsft_delta_summary=tsft_delta_summary,
        fcs_in_frame=fcs_in_frame, badfcs_flag=badfcs_flag,
        ext_word_frames=ext_word_frames,
        perchain_frames=perchain_frames,
        perchain_pair_hist=perchain_pair_hist,
        perchain_chain_rssi=perchain_chain_rssi,
        zero_len_psdus=zero_len_psdus,
        walk_mismatch=walk_mismatch, ns_vendor_conflict=ns_vendor_conflict,
        chain_idx_invalid=chain_idx_invalid,
        frame_dup_counter=frame_dup_counter,
        dup_multi=dup_multi, ack_ra=ack_ra, per_file=per_file,
        rssi_bad_range=rssi_bad_range,
    )


def chan_flags_str(v):
    return "|".join(n for b, n in CHAN_FLAG_NAMES.items() if v & b) or \
        f"0x{v:04x}"


def flags_str(v):
    return "|".join(n for b, n in FLAG_NAMES.items() if v & b) or \
        f"0x{v:02x}"


def print_report(r):
    total = r["total"]
    print(f"files={len(r['per_file'])} packets={total}")
    for name, n in r["per_file"]:
        print(f"  {name}: {n}")
    print("\npresence word0 top6:")
    for val, cnt in r["present_hist"].most_common(6):
        bits = [BIT_NAMES.get(i, str(i)) for i in range(31)
                if val & (1 << i)]
        ext = "EXT" if val & 0x80000000 else ""
        print(f"  0x{val:08x} x{cnt} ({cnt * 100 // max(total, 1)}%) "
              f"{ext} {','.join(bits)}")
    print("\nper-bit population (word0+ext, global bit index):")
    for b in sorted(r["bit_pop"]):
        name = BIT_NAMES.get(b % 32, "?")
        if b >= 32:
            name = f"ext+{name}"
        print(f"  bit{b:2d} {name:18s} {r['bit_pop'][b]:6d} "
              f"({r['bit_pop'][b] * 100 // max(total, 1)}%)")
    print("\nframe classes:")
    for k, cnt in r["type_hist"].most_common(16):
        print(f"  {k:24s} {cnt}")
    print(f"\nextension-word frames: {r['ext_word_frames']}")
    print(f"per-chain pair frames: {r['perchain_frames']} "
          f"(pairs/frame {dict(r['perchain_pair_hist'].most_common(6))})")
    if r['perchain_chain_rssi']:
        chains = sorted(set(k[0] for k in r['perchain_chain_rssi']))
        for c in chains:
            vals = sorted(((sig, n) for (idx, sig), n in
                           r['perchain_chain_rssi'].items() if idx == c),
                          key=lambda t: -t[1])
            sigs = [sig for sig, _ in vals]
            print(f"  chain{c}: min {min(sigs)} max {max(sigs)} "
                  f"distinct {len(sigs)} top {vals[:4]}")
    print(f"zero-body (control-only PSDU) records: {r['zero_len_psdus']}")
    print(f"layout walk mismatches (walk != it_len): {r['walk_mismatch']}")
    print(f"NAMESPACE+VENDOR same-word conflicts (malformed): "
          f"{r['ns_vendor_conflict']}")
    print(f"per-chain index values > 7 (misaligned pairs): "
          f"{r['chain_idx_invalid']}")
    print(f"TSFT present {r['tsft_present']}/{total} "
          f"(zero {r['tsft_zero']}) backwards {r['tsft_backwards']}")
    print(f"  tsft deltas: {r['tsft_delta_summary']}")
    print(f"FLAGS values: {dict(r['flags_hist'].most_common(8))}")
    for v, cnt in r["flags_hist"].most_common(4):
        if v >= 0:
            print(f"  0x{v:02x} = {flags_str(v)} x{cnt}")
    print(f"  frames with FCS-included flag: {r['fcs_in_frame']}")
    print(f"  frames with BAD-FCS flag: {r['badfcs_flag']}")
    print(f"radiotap lens: {dict(r['rtap_len_hist'].most_common(8))}")
    print(f"RATE(500kb/s) top: {dict(r['rate_hist'].most_common(12))}")
    print("chan freqs: "
          f"{dict((k, v) for k, v in r['freq_hist'].most_common(8))}")
    print("chan flags: ")
    for v, cnt in r["chanflag_hist"].most_common(6):
        print(f"  0x{v:04x} = {chan_flags_str(v)} x{cnt}")
    rssis = r["rssi_hist"]
    if rssis:
        lo, hi = min(rssis), max(rssis)
        print(f"dbm_antsignal(bit5): min {lo} max {hi} distinct {len(rssis)} "
              f"top {rssis.most_common(6)}")
        print(f"  values outside [-100,0]: {r['rssi_bad_range']}")
    else:
        print("dbm_antsignal(bit5): NEVER PRESENT")
    noises = r["noise_hist"]
    if noises:
        print(f"dbm_antnoise(bit6): min {min(noises)} max {max(noises)} "
              f"distinct {len(noises)} top {noises.most_common(6)}")
    else:
        print("dbm_antnoise(bit6): NEVER PRESENT")
    print(f"antenna(bit11): {dict(r['antenna_hist'].most_common(6))}")
    if r["mcs_hist"]:
        print("MCS(bit19) (known,bw,mcs) top: "
              f"{dict(r['mcs_hist'].most_common(8))}")
    else:
        print("MCS(bit19): never present")
    if r["vht_hist"]:
        print("VHT(bit21) (known,bw,mcs0,nss0) top: "
              f"{dict(r['vht_hist'].most_common(6))}")
    else:
        print("VHT(bit21): never present")
    print(f"vendor NS(bit30): OUI {dict(r['vendor_oui_hist'].most_common(4))}"
          f" skip_length {dict(r['vendor_skip_hist'].most_common(4))}")
    print(f"non-control identical-MPDU groups delivered >1x: "
          f"{r['dup_multi']}/{len(r['frame_dup_counter'])}")
    ack = r["ack_ra"]
    print(f"ACK frames: distinct RAs {len(ack)} top {ack.most_common(5)}")


# ------------------------------------------------------------------ selftest

def build_synthetic(present_bits, values):
    """Build a header the way qdf_nbuf_update_radiotap() lays it out."""
    if any(b >= 32 for b in present_bits):
        raise ValueError("synthetic builder only does word0")
    entries = []  # (offset, chunk)
    off = 8
    for bit in sorted(present_bits):
        if bit == 30:
            off = align(off, 2)
            skip = values.get("vendor_skip", 16)
            chunk = bytearray(6 + skip)
            chunk[0:3] = b"\x00\x03\x7f"          # Ath OUI
            chunk[4:6] = struct.pack("<H", skip)
            if skip >= 16:
                chunk[6:22] = bytes(range(16))     # dummy ath payload
        else:
            a, size = GEOM[bit]
            off = align(off, a)
            chunk = bytearray(size)
            if bit == 0:
                chunk[:] = struct.pack("<Q", values["tsft"])
            elif bit == 1:
                chunk[0] = values.get("flags", 0)
            elif bit == 2:
                chunk[0] = values["rate"]
            elif bit == 3:
                chunk[:] = struct.pack("<HH", values["chan_freq"],
                                       values["chan_flags"])
            elif bit == 5:
                chunk[0] = values["dbm_antsignal"] & 0xFF
            elif bit == 6:
                chunk[0] = values["dbm_antnoise"] & 0xFF
            elif bit == 11:
                chunk[0] = values["antenna"]
            elif bit == 14:
                chunk[:] = struct.pack("<H", values.get("rx_flags", 0))
            elif bit == 20:
                chunk[0:4] = struct.pack("<I", values.get("ampdu_ref", 0))
                chunk[4:6] = struct.pack("<H",
                                         values.get("ampdu_flags", 0))
            elif bit == 19:
                chunk[:] = bytes(values["mcs"])
            elif bit == 21:
                chunk[:] = bytes(values["vht"])
        entries.append((off, chunk))
        off += len(chunk)
    buf = bytearray(off)
    for o, chunk in entries:
        buf[o:o + len(chunk)] = chunk
    struct.pack_into("<BBHI", buf, 0, 0, 0, off,
                     sum(1 << b for b in present_bits))
    return bytes(buf)


SELFTEST_BODY = bytes.fromhex("b000") + b"\x00" * 28  # auth-ish frame


def selftest():
    """Decode three synthetic headers with known contents."""
    failures = []

    def check(name, got, want):
        if got != want:
            failures.append(f"{name}: got {got!r} want {want!r}")

    # 1) legacy frame: the fields the stock builder always emits
    vals = dict(tsft=0x1122334455667788, flags=0x10, rate=12,
                chan_freq=5745, chan_flags=0x0110,
                dbm_antsignal=-62, dbm_antnoise=-96, antenna=1,
                vendor_skip=16)
    hdr = build_synthetic({0, 1, 2, 3, 5, 6, 11, 30}, vals)
    pkt = hdr + SELFTEST_BODY
    f, body, words = parse_radiotap(pkt)
    check("legacy.len", f["it_len"], len(hdr))
    check("legacy.walk", f.get("walk_end_mismatch"), None)
    check("legacy.tsft", f["tsft"], vals["tsft"])
    check("legacy.flags", f["flags"], 0x10)
    check("legacy.rate", f["rate"], 12)
    check("legacy.freq", f["chan_freq"], 5745)
    check("legacy.rssi", f["dbm_antsignal"], -62)
    check("legacy.noise", f["dbm_antnoise"], -96)
    check("legacy.antenna", f["antenna"], 1)
    check("legacy.oui", f["vendor_oui"], "00:03:7f")
    check("legacy.skip", f["vendor_skip"], 16)
    check("legacy.body", body, SELFTEST_BODY)

    # 2) HT frame: MCS at bit19, no RATE
    vals = dict(tsft=1, flags=0, chan_freq=2437, chan_flags=0x0060,
                dbm_antsignal=-40, dbm_antnoise=-90, antenna=2,
                mcs=(0x07, 0x01, 9), vendor_skip=16)
    hdr = build_synthetic({0, 1, 3, 5, 6, 11, 19, 30}, vals)
    f, body, _ = parse_radiotap(hdr + SELFTEST_BODY)
    check("ht.walk", f.get("walk_end_mismatch"), None)
    check("ht.no_rate", "rate" in f, False)
    check("ht.mcs", (f["mcs_known"], f["mcs_flags"], f["mcs_index"]),
          (0x07, 0x01, 9))

    # 3) VHT frame with AMPDU (mcs_nss[0] packs one user: mcs | nss << 4)
    vals = dict(tsft=2, flags=0, chan_freq=5745, chan_flags=0x0140,
                dbm_antsignal=-50, dbm_antnoise=-95, antenna=1,
                ampdu_ref=7, ampdu_flags=1,
                vht=(0x55, 0x00, 0x00, 0x04, 0x93, 0, 0, 0, 0, 0, 0, 0),
                vendor_skip=16)
    hdr = build_synthetic({0, 1, 3, 5, 6, 11, 20, 21, 30}, vals)
    f, body, _ = parse_radiotap(hdr + SELFTEST_BODY)
    check("vht.walk", f.get("walk_end_mismatch"), None)
    check("vht.known", f["vht_known"], 0x55)
    check("vht.bw", f["vht_bw"], 4)
    check("vht.mcs_nss0", f["vht_mcs_nss"][0], 0x93)
    check("ampdu.ref", f["ampdu_ref"], 7)
    check("ampdu.flags", f["ampdu_flags"], 1)

    # 4) nsfix per-chain layout: pair words (all EXT-linked) in the
    #    header area after a NAMESPACE reset, trailing vendor word,
    #    no word0 ANTNOISE/ANTENNA (absent fields occupy no bytes)
    hdr = bytearray()
    presence0 = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 5) | \
                (1 << 29) | (1 << 31)
    hdr += struct.pack("<BBHI", 0, 0, 0, presence0)
    hdr += struct.pack("<I", (1 << 5) | (1 << 11) | (1 << 31))  # pair 1
    hdr += struct.pack("<I", (1 << 5) | (1 << 11) | (1 << 31))  # pair 2
    hdr += struct.pack("<I", (1 << 30))                          # vendor word
    hdr += b"\x00" * 4                                           # TSFT align pad
    hdr += struct.pack("<Q", 7)          # TSFT
    hdr += b"\x10"                       # FLAGS
    hdr += b"\x0c"                       # RATE 6 Mb/s
    hdr += struct.pack("<HH", 5745, 0x0140)  # CHANNEL
    hdr += struct.pack("<b", -66)        # DBM_ANTSIGNAL (aggregate)
    hdr += bytes([0xC2, 0, 0xC4, 1])     # pairs: (-62, ch0), (-60, ch1)
    hdr += struct.pack("<H", 16)         # vendor skip (align2 handled below)
    # rebuild properly: vendor needs align2; easier to assemble tail separately
    hdr = hdr[:len(hdr) - 2]
    if len(hdr) & 1:
        hdr += b"\x00"
    hdr += b"\x00\x03\x7f" + b"\x00" + struct.pack("<H", 16) + bytes(range(16))
    struct.pack_into("<H", hdr, 2, len(hdr))
    pkt = bytes(hdr) + SELFTEST_BODY
    f, body, words = parse_radiotap(pkt)
    check("nsfix.len", f["it_len"], len(hdr))
    check("nsfix.walk", f.get("walk_end_mismatch"), None)
    check("nsfix.no_conflict", f.get("ns_vendor_conflict"), None)
    check("nsfix.words", len(words), 4)
    check("nsfix.tsft", f["tsft"], 7)
    check("nsfix.rate", f["rate"], 12)
    check("nsfix.freq", f["chan_freq"], 5745)
    check("nsfix.agg_signal", f["dbm_antsignal"], -66)
    check("nsfix.signals", f.get("chain_signals"), [-62, -60])
    check("nsfix.idxs", f.get("chain_idxs"), [0, 1])
    check("nsfix.oui", f["vendor_oui"], "00:03:7f")
    check("nsfix.skip", f["vendor_skip"], 16)

    # 5) malformed detector: NAMESPACE and VENDOR_NAMESPACE in word0
    bad = struct.pack("<BBHI", 0, 0, 8,
                      (1 << 29) | (1 << 30) | (1 << 0))
    f, _, _ = parse_radiotap(bad + SELFTEST_BODY)
    check("malformed.conflict", f.get("ns_vendor_conflict"), True)

    if failures:
        print("SELFTEST FAIL")
        for x in failures:
            print("  " + x)
        return 1
    print("SELFTEST PASS (5 layouts, decode + walk verified)")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcaps", nargs="*")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        sys.exit(selftest())
    if not args.pcaps:
        ap.error("pcaps required (or --selftest)")
    print_report(audit(args.pcaps))


if __name__ == "__main__":
    main()
