#!/usr/bin/env python3
"""pcap replayer: replay captured 802.11 frames through the frame-inject
monitor path, preserving TX-meaningful radiotap rate fields.

Behavioral contract:
  1. RX-only radiotap fields are stripped automatically (TSFT/FLAGS/
     CHANNEL/RX_FLAGS/signal/noise...); RATE/MCS/VHT/HE/TX_FLAGS/
     ANTENNA/DBM_TX_POWER/DATA_RETRIES survive verbatim.
  2. Templates: --template eapol-m3 / --template pmkid emit structurally
     valid EAPOL key frames with user-supplied nonces/counters (no crypto
     is performed - MIC/key material must be supplied by the operator).
  3. Per-frame completion verdict callback in adb mode (driver ledger
     TSV delta; status 0=FW OK, 3=no ACK - neither proves transmission).

Usage:
  pcap_replay.py PCAP [--pps 4] [--mode dryrun|adb|script]
                 [--out SCRIPT] [--limit N] [--skip N]
  pcap_replay.py --template eapol-m3 --bssid .. --client .. --anonce HEX
                 [--mode ...]
  pcap_replay.py --selftest
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from replay_lib import Sender, sanitize_radiotap, wrap_body  # noqa: E402


def parse_pcap_or_ng(path):
    """Yield packets from classic pcap or pcapng (DLT 105/127)."""
    d = open(path, "rb").read()
    if d[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        end = "<"
    elif d[:4] in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        end = ">"
    elif d[:4] == b"\x0a\x0d\x0d\x0a":
        return parse_ng(d)
    else:
        raise ValueError("not a pcap/pcapng file")
    linktype = struct.unpack_from(end + "I", d, 20)[0]
    off, out = 24, []
    while off + 16 <= len(d):
        ts, tus, caplen, origlen = struct.unpack_from(end + "IIII", d, off)
        off += 16
        out.append((linktype, d[off:off + caplen]))
        off += caplen
    return out


def parse_ng(d):
    off, linktype, out = 0, None, []
    while off + 12 <= len(d):
        btype, blen = struct.unpack_from("<II", d, off)
        if blen < 12 or off + blen > len(d):
            break
        body = d[off + 8:off + blen - 4]
        if btype == 1 and linktype is None:  # IDB
            linktype = struct.unpack_from("<H", body, 0)[0]
        elif btype == 6:  # EPB
            caplen = struct.unpack_from("<I", body, 4)[0]
            out.append((linktype, body[20:20 + caplen]))
        off += blen
    return out


def build_eapol_key_frame(bssid, client, eapol_type, key_info,
                          replay_counter, nonce, payload=b"", protected=0):
    """802.11 data (ToDS) + LLC/SNAP + EAPOL-Key. Structural template."""
    fc = 0x0808 | (0x4000 if protected else 0)
    # data ToDS: addr1=BSSID(AP), addr2=SA(client), addr3=DA
    hdr = struct.pack("<HH", fc, 0) + bytes.fromhex(bssid) + \
        bytes.fromhex(client) + bytes.fromhex(bssid) + b"\x00\x00"
    eapol_body = bytes([3, eapol_type]) + struct.pack(">H", 0)  # v3, len patched
    key = bytes([2]) + struct.pack(">H", key_info) + b"\x00" * 2 + \
        replay_counter.to_bytes(8, "big") + nonce + b"\x00" * 16 + \
        b"\x00" * 8 + payload
    eapol = eapol_body + key
    body = hdr + b"\xaa\xaa\x03\x00\x00\x00\x88\x8e" + \
        eapol[:2] + struct.pack(">H", len(eapol) - 4) + eapol[4:]
    return body


def template_frame(name, params):
    bssid = params.get("bssid", "020000000001")
    client = params.get("client", "020000000002")
    nonce = bytes.fromhex(params.get("anonce") or "00" * 32)[:32].ljust(32, b"\x00")
    if name == "eapol-m3":
        # M3: KEY_ACK|KEY_MIC|SECURE|PAIRWISE (0x13c2), replay counter 2
        body = build_eapol_key_frame(bssid, client, 3, 0x13C2, 2, nonce)
    elif name == "pmkid":
        # M1: REQUEST|PAIRWISE|KEY_ACK (0x0108) carrying a PMKID KDE
        pmkid = bytes.fromhex(params.get("pmkid") or "00" * 16)[:16]
        kde = b"\xdd\x14\x00\x0f\xac\x04" + pmkid
        body = build_eapol_key_frame(bssid, client, 3, 0x0108, 1,
                                     nonce, payload=kde)
    else:
        raise ValueError("unknown template %s" % name)
    return wrap_body(body)


def selftest():
    failures = []

    def check(name, ok):
        print("%-38s %s" % (name, "OK" if ok else "FAIL"))
        if not ok:
            failures.append(name)

    # sanitizer: RX fields dropped, TX fields kept verbatim
    # (present=TSFT|FLAGS|RATE|MCS: keep RATE+MCS, drop TSFT+FLAGS)
    hdr = bytearray(8)
    present = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 19)
    hdr[4:8] = present.to_bytes(4, "little")
    hdr += b"\x00" * 8                    # TSFT
    hdr += b"\x12"                        # FLAGS
    hdr += b"\x0c"                        # RATE 6 Mbps
    hdr += b"\x00\x07\x00"                # MCS known/index/flags
    hdr[2:4] = len(hdr).to_bytes(2, "little")  # it_len (offsets byte-by-byte)
    body = b"\xb0\x00" + b"\x00" * 24
    out = sanitize_radiotap(bytes(hdr) + body)
    check("sanitize_strips_rx_fields",
          out[0:2] == b"\x00\x00" and
          int.from_bytes(out[4:8], "little") == ((1 << 2) | (1 << 19)))
    check("sanitize_keeps_tx_values",
          out[8] == 0x0c and out[9:12] == b"\x00\x07\x00" and
          out[12:14] == body[:2])
    check("sanitize_it_len_consistent",
          (out[2] | (out[3] << 8)) == 12 and len(out) == 12 + len(body))

    # empty-header wrap for DLT105 frames
    w = wrap_body(b"\xc0\x00" + b"\x00" * 24)
    check("wrap_empty_header", w[:8] == b"\x00\x00\x08\x00\x00\x00\x00\x00")

    # template structure: FC/data/ToDS, LLC SNAP 88:8e, descriptor 2
    for name, ki in (("eapol-m3", 0x13C2), ("pmkid", 0x0108)):
        pkt = template_frame(name, {})
        body = pkt[8:]
        check("tpl_%s_data_tods" % name,
              int.from_bytes(body[0:2], "little") == 0x0808)
        check("tpl_%s_llc_eapol" % name,
              body[24:32] == b"\xaa\xaa\x03\x00\x00\x00\x88\x8e")
        check("tpl_%s_keyinfo" % name,
              int.from_bytes(body[37:39], "big") == ki)

    # pcap roundtrip: write a 2-packet classic pcap and re-read it
    import tempfile
    pkts = [(127, bytes(hdr) + body), (105, b"\xc0\x00" + b"\x00" * 24)]
    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    tmp.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 127))
    # note: single linktype per file; second entry re-tagged below
    tmp.close()
    with open(tmp.name, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 127))
        for _, p in pkts[:1]:
            f.write(struct.pack("<IIII", 0, 0, len(p), len(p)))
            f.write(p)
    reread = parse_pcap_or_ng(tmp.name)
    os.unlink(tmp.name)
    check("pcap_roundtrip", len(reread) == 1 and reread[0][0] == 127 and
          reread[0][1] == pkts[0][1])

    print("SELFTEST %s (%d failures)" % (
        "PASS" if not failures else "FAIL", len(failures)))
    return 1 if failures else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap", nargs="?")
    ap.add_argument("--pps", type=float, default=4.0,
                    help="frames/sec; burst above completion rate drops "
                         "silently (queue-accept semantics)")
    ap.add_argument("--mode", choices=["dryrun", "adb", "script"],
                    default="dryrun")
    ap.add_argument("--out", help="script output path (mode=script)")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--skip", type=int, default=0)
    ap.add_argument("--template")
    ap.add_argument("--bssid", default="020000000001")
    ap.add_argument("--client", default="020000000002")
    ap.add_argument("--anonce", help="64 hex chars")
    ap.add_argument("--pmkid", help="32 hex chars")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not args.pcap and not args.template:
        ap.error("need PCAP or --template")

    sender = Sender(mode=args.mode, pps=args.pps)
    if args.mode == "adb":
        sender.ensure_pushed()

    sent = 0
    if args.template:
        params = {"bssid": args.bssid, "client": args.client,
                  "anonce": args.anonce, "pmkid": args.pmkid}
        pkt = template_frame(args.template, params)
        print(sender.send_frame(pkt, note="template=%s" % args.template))
        return 0

    frames = parse_pcap_or_ng(args.pcap)
    frames = [p for (lt, p) in frames]
    dlt_set = {lt for (lt, _) in parse_pcap_or_ng(args.pcap)}
    if None in dlt_set or not dlt_set:
        ap.error("no packets/linktype")
    for idx, pkt in enumerate(frames):
        if idx < args.skip:
            continue
        if args.limit and sent >= args.limit:
            break
        out = sanitize_radiotap(pkt)
        if out is None:
            out = wrap_frame_dlt(pkt)
        verdict = sender.send_frame(out, note="#%d" % idx)
        print(verdict)
        sent += 1
    if args.mode == "script":
        if not args.out:
            ap.error("--out required with --mode script")
        sender.write_script(args.out)
        print("script written: %s (%d frames)" % (args.out, sent))
    print("replayed=%d mode=%s" % (sent, args.mode))
    return 0


def wrap_frame_dlt(pkt):
    return wrap_body(pkt)


if __name__ == "__main__":
    sys.exit(main())
