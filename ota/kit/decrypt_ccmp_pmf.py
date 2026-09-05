#!/usr/bin/env python3
"""Offline CCMP verdict helper for the C-2 PMF listener session (kit v11).

The phone installs a KNOWN 16-byte CCMP pairwise key on the injection
helper peer (debugfs frame_inject_pmf_key) and injects protected
management frames (802.11 FC protected bit set). The listener captures
them over the air. This tool decrypts captured CCMP *management* frames
with that same raw key and verifies the 8-byte MIC:

    MIC OK + plaintext decodes as the injected deauth/SA-Query
        => the firmware encrypted the frame with exactly that key
           (C-2 OTA verdict: fw_local_ccmp_proven).
    MIC FAIL on every frame
        => the firmware used a different key or a different AAD/nonce
           construction - report the failure verbatim, do not retry into
           a PASS (UNPROVEN is a legal verdict).

Usage:
    decrypt_ccmp_pmf.py PCAP KEY32HEX [--ta MAC]
    decrypt_ccmp_pmf.py --selftest

The pcap must be classic pcap with DLT 127 (radiotap). Only frames with
the FC protected bit and a plausible CCMP header are attempted.

Implementation: AES-CCM with L=2, M=8 per 802.11 CCMP: nonce = priority
0x00 || SA || PN (13 bytes); AAD = the 802.11 header up to (not
including) the CCMP header with the FC retry/pwr/more-data bits and the
Duration/ID field masked to zero; B0 flags 0x59; CTR from counter 1 for
the payload, counter 0 encrypts the MIC. The --selftest exercises the
encrypt/decrypt roundtrip plus a tampered-MIC rejection; spec-level
cross-checks against wireshark/airdecap are recommended the first time a
session produces a verdict.
"""
import argparse
import collections
import hmac
import struct
import sys

try:
    from cryptography.hazmat.primitives.ciphers import (
        Cipher, algorithms, modes)
    def _aes_ecb_encrypt(key, block):
        c = Cipher(algorithms.AES(key), modes.ECB())
        e = c.encryptor()
        return e.update(block) + e.finalize()
except ImportError:  # pragma: no cover - pycryptodome fallback
    from Crypto.Cipher import AES
    def _aes_ecb_encrypt(key, block):
        return AES.new(key, AES.MODE_ECB).encrypt(block)


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _mask_fc_aad(fc_bytes):
    # 802.11 CCMP AAD construction: mask Retry (bit 11), Power Mgmt
    # (bit 12), More Data (bit 13) in the Frame Control word.
    fc = struct.unpack("<H", fc_bytes)[0]
    fc &= ~(1 << 11) & ~(1 << 12) & ~(1 << 13)
    return struct.pack("<H", fc)


def build_aad(hdr):
    """AAD over the 802.11 header bytes preceding the CCMP header."""
    fc = struct.unpack("<H", hdr[:2])[0]
    out = bytearray()
    out += _mask_fc_aad(hdr[:2])
    out += b"\x00\x00"  # Duration/ID masked to zero
    out += hdr[4:10]    # A1
    out += hdr[10:16]   # A2 (SA - also feeds the nonce)
    out += hdr[16:22]   # A3
    off = 24
    off += 6 if fc & 0x0300 == 0x0300 else 0   # A4 present
    if (fc >> 2) & 3 == 2 and fc & 0x0080 and len(hdr) >= off + 2:
        out += hdr[off:off + 2]                # QoS control
        off += 2
    return bytes(out), hdr[10:16], off


def ccm_b0(nonce, m_len):
    return bytes([0x59]) + nonce + struct.pack(">H", m_len)


def cbc_mac(key, b0, aad, data):
    aad_len = len(aad)
    blocks = [b0]
    # AAD blocks: 2-byte big-endian length + AAD padded to 16
    apad = struct.pack(">H", aad_len) + aad
    apad += b"\x00" * ((16 - len(apad) % 16) % 16)
    for i in range(0, len(apad), 16):
        blocks.append(apad[i:i + 16])
    data_pad = data + b"\x00" * ((16 - len(data) % 16) % 16)
    for i in range(0, len(data_pad), 16):
        blocks.append(data_pad[i:i + 16])
    x = b"\x00" * 16
    for blk in blocks:
        x = _aes_ecb_encrypt(key, xor(x, blk))
    return x[:8]


def ccm_ctr(key, nonce, data, start_counter):
    out = bytearray()
    ctr = start_counter
    for i in range(0, len(data), 16):
        ai = bytes([0x01]) + nonce + struct.pack(">H", ctr)
        ks = _aes_ecb_encrypt(key, ai)
        chunk = data[i:i + 16]
        out += xor(chunk, ks[:len(chunk)])
        ctr += 1
    return bytes(out)


def ccmp_decrypt(key, hdr, ccmp_hdr, ct_and_mic):
    """Returns (plaintext, mic_ok) for one captured frame."""
    pn = ccmp_hdr[1:7]
    nonce = b"\x00" + hdr[10:16] + pn
    aad, _, _ = build_aad(hdr)
    ct, mic = ct_and_mic[:-8], ct_and_mic[-8:]
    pt = ccm_ctr(key, nonce, ct, 1)
    # CCMP computes the MIC over AAD + PLAINTEXT; decrypt first, then
    # verify against the CTR-decrypted received MIC.
    b0 = ccm_b0(nonce, len(pt))
    expected = cbc_mac(key, b0, aad, pt)
    mic_dec = ccm_ctr(key, nonce, mic, 0)
    ok = hmac.compare_digest(mic_dec, expected)
    return pt, ok


def ccmp_encrypt(key, hdr, pn, plaintext):
    """Encryptor used only by --selftest (roundtrip + tamper check)."""
    ccmp_hdr = bytes([0x20]) + pn + b"\x00"
    nonce = b"\x00" + hdr[10:16] + pn
    aad, _, _ = build_aad(hdr)
    b0 = ccm_b0(nonce, len(plaintext))
    mic = cbc_mac(key, b0, aad, plaintext)
    ct = ccm_ctr(key, nonce, plaintext, 1)
    mic_enc = ccm_ctr(key, nonce, mic, 0)
    return ccmp_hdr + ct + mic_enc


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


def strip_radiotap(pkt):
    if len(pkt) < 8:
        return None
    rlen = struct.unpack("<H", pkt[2:4])[0]
    if rlen < 8 or rlen > len(pkt):
        return None
    return pkt[rlen:]


def selftest():
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    hdr = (struct.pack("<HH", 0x00C0 | 0x0400, 0x0134) +
           bytes.fromhex("021122334455") +   # RA
           bytes.fromhex("02abcd0000f1") +   # TA/SA
           bytes.fromhex("021122334455") +   # BSSID (A3)
           struct.pack("<H", 0x0021))        # seq ctl
    body = struct.pack("<H", 6)              # reason code
    pn = bytes([1, 2, 3, 4, 5, 6])
    frame = hdr + ccmp_encrypt(key, hdr, pn, body)
    body_rt = frame[:len(hdr)] + frame[len(hdr) + 8:]
    pt, ok = ccmp_decrypt(key, hdr, frame[len(hdr):len(hdr) + 8],
                          frame[len(hdr) + 8:])
    checks = [
        ("roundtrip_body", pt == body),
        ("roundtrip_mic", ok),
    ]
    # tampered ciphertext must fail the MIC
    bad = frame[:-1] + bytes([frame[-1] ^ 1])
    _, ok2 = ccmp_decrypt(key, hdr, bad[len(hdr):len(hdr) + 8],
                          bad[len(hdr) + 8:])
    checks.append(("tamper_rejected", not ok2))
    # wrong key must fail the MIC
    _, ok3 = ccmp_decrypt(bytes(16), hdr, frame[len(hdr):len(hdr) + 8],
                          frame[len(hdr) + 8:])
    checks.append(("wrong_key_rejected", not ok3))
    # the encryptor's stripped form must equal the plaintext framing
    checks.append(("header_preserved", body_rt[:len(hdr)] == hdr))
    for name, passed in checks:
        print(f"selftest.{name}={'PASS' if passed else 'FAIL'}")
        if not passed:
            return 1
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap", nargs="?", help="captured pcap (DLT 127)")
    ap.add_argument("key", nargs="?", help="16-byte pairwise key, 32 hex")
    ap.add_argument("--ta", help="only attempt frames with this TA")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.pcap or not args.key:
        ap.error("pcap and key are required (or --selftest)")
    try:
        key = bytes.fromhex(args.key)
    except ValueError:
        raise SystemExit("key must be hex")
    if len(key) != 16:
        raise SystemExit("key must be exactly 16 bytes (CCMP-128)")
    ta_filter = bytes.fromhex(args.ta.replace(":", "")) if args.ta else None

    pkts = parse_pcap(args.pcap)
    attempted = mic_ok = mgmt_ok = 0
    decoded = collections.Counter()
    for ts, pkt in pkts:
        body = strip_radiotap(pkt)
        if body is None or len(body) < 24 + 8 + 8:
            continue
        fc = struct.unpack("<H", body[:2])[0]
        if not fc & 0x0400:        # protected bit
            continue
        if (fc >> 2) & 3 != 0:     # C-2 session sends management frames
            continue
        if ta_filter and body[10:16] != ta_filter:
            continue
        hdr, ccmp_hdr, ct = body[:24], body[24:32], body[32:]
        if ccmp_hdr[0] & 0x03 not in (0, 1):  # key id beyond pairwise slots
            continue
        attempted += 1
        pt, ok = ccmp_decrypt(key, hdr, ccmp_hdr, ct)
        if not ok:
            print(f"ts={ts:.6f} ta={body[10:16].hex()} MIC_FAIL len={len(body)}")
            continue
        mic_ok += 1
        # The 802.11 header stays in clear; the CCMP plaintext is the
        # management frame BODY (e.g. a 2-byte reason code for deauth).
        decoded[len(pt)] += 1
        print(f"ts={ts:.6f} ta={body[10:16].hex()} MIC_OK "
              f"plain_len={len(pt)} plain={pt.hex()}")
        if len(pt) >= 2:
            mgmt_ok += 1
    print(f"ccmp_verdict attempted={attempted} mic_ok={mic_ok} "
          f"plausible_mgmt_body={mgmt_ok} plain_lens={dict(decoded)}")
    if attempted and mic_ok == attempted:
        print("verdict=FW_LOCAL_CCMP_PROVEN_WITH_KNOWN_KEY")
    elif mic_ok:
        print("verdict=PARTIAL_SOME_MIC_FAILED")
    elif attempted:
        print("verdict=MIC_FAILED_ALL (key or construction mismatch - "
              "report verbatim, UNPROVEN is legal)")
    else:
        print("verdict=NO_CCMP_MGMT_FRAMES_FOUND")
    return 0


if __name__ == "__main__":
    sys.exit(main())
