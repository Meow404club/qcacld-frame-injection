#!/usr/bin/env python3
"""Shared sender/pacing/verdict plumbing for the replay tools.

Zero-driver-footprint contract (see docs/boundaries.md):
  - sendto rc=0 is QUEUE-ACCEPT, not proof of transmission; per-frame
    verdicts come from the frame_inject_completions TSV delta.
  - tx inflight is 8 with a 64-entry queue on current builds, but an
    unthrottled burst still drops silently - pacing is mandatory and
    defaults conservatively.
  - AF_PACKET captures loop TX copies back; the verdict read here uses
    the driver ledger, never a local capture.
"""
import os
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_TOOLS = os.path.dirname(_HERE)
sys.path.insert(0, _TOOLS)

# (align, size) per radiotap present bit, verbatim from the delivered
# kernel shim header via analyze_radiotap_pcap.py (single authority).
from analyze_radiotap_pcap import GEOM  # noqa: E402

# radiotap fields the driver TX parser consumes; everything else is
# RX-oriented and gets stripped on replay (spec item 1).
TX_KEEP = {2, 10, 11, 15, 17, 19, 21, 23}


def _align(x, a):
    return (x + a - 1) & ~(a - 1)


def split_radiotap(pkt):
    """Return (radiotap_bytes, body) for a DLT127 frame."""
    if len(pkt) < 8 or pkt[0] != 0:
        return None, pkt
    it_len = pkt[2] | (pkt[3] << 8)
    if it_len < 8 or it_len > len(pkt):
        return None, pkt
    return pkt[:it_len], pkt[it_len:]


def radiotap_fields(header):
    """Yield (bit, offset) for every present field of a radiotap header."""
    present = 0
    for w in range(8):
        chunk = int.from_bytes(header[4 + 4 * w:8 + 4 * w], "little")
        present |= chunk << (32 * w)
        if not chunk & 0x80000000:
            break
    off = 4
    word = 0
    remaining = present
    while remaining:
        bits_in_word = remaining & 0xFFFFFFFF
        word_present = bits_in_word
        off = 4 + 4 * word
        for bit in range(32):
            if not (word_present >> bit) & 1:
                continue
            g = GEOM.get(32 * word + bit)
            if g is None:
                return  # unknown field: stop walking (fail-safe)
            a, s = g
            off = _align(off, a)
            yield 32 * word + bit, off
            off += s
        remaining >>= 32
        word += 1


def sanitize_radiotap(pkt):
    """Rebuild the radiotap header keeping only TX-meaningful fields.

    RX-only metadata (TSFT/FLAGS/CHANNEL/RX_FLAGS/signal/noise/...) is
    dropped so a captured frame replays as a rate request instead of
    carrying meaningless RX context (spec item 1).
    """
    header, body = split_radiotap(pkt)
    if header is None:
        return None
    keep = {}
    for bit, off in radiotap_fields(header):
        if bit in TX_KEEP and bit in GEOM:
            a, s = GEOM[bit]
            keep[bit] = header[off:off + s]
    present = 0
    for bit in keep:
        present |= 1 << bit
    out = bytearray(8)
    out[2:4] = len(out).to_bytes(2, "little")  # patched below
    out[4:8] = present.to_bytes(4, "little")
    for bit in sorted(keep):
        a, s = GEOM[bit]
        while len(out) % a:
            out.append(0)
        out += keep[bit]
    out[2:4] = len(out).to_bytes(2, "little")
    return bytes(out) + body


def wrap_body(body):
    """Wrap a bare 802.11 frame in an empty (present=0) radiotap header:
    FW-default-rate submission, the widest-safe replay shape."""
    return b"\x00\x00\x08\x00\x00\x00\x00\x00" + body


class Sender:
    """Device sender with per-frame verdict (adb mode) or batch emit."""

    def __init__(self, mode="dryrun", interface="wlan0", pps=4.0,
                 sender_bin=None, echo=print):
        self.mode = mode  # dryrun | adb | script
        self.interface = interface
        self.period = 1.0 / pps if pps > 0 else 0.0
        self.echo = echo
        self.script_lines = []
        self._remote_bin = None
        self._sender_bin = sender_bin or os.path.join(
            _TOOLS, "..", "ota", "kit", "send_stage1_packet")
        self._last_seq = None

    def _adb(self, *args, timeout=30):
        return subprocess.run(["adb", *args], capture_output=True,
                              text=True, timeout=timeout, stdin=subprocess.DEVNULL)

    def ensure_pushed(self):
        if self.mode != "adb" or self._remote_bin:
            return
        self._remote_bin = "/data/local/tmp/fi-replay-sender"
        r = self._adb("push", self._sender_bin, self._remote_bin)
        if r.returncode != 0:
            raise RuntimeError("push failed: %s" % r.stderr)
        self._adb("shell", "su", "-c",
                  "chmod 0755 %s" % self._remote_bin)

    def _completions_tail(self):
        r = self._adb("exec-out", "su", "-c",
                      "cat /sys/kernel/debug/wlan0/frame_inject_completions")
        lines = [l for l in r.stdout.splitlines() if l.strip()]
        return lines[-1] if lines else None

    def send_frame(self, pkt, note=""):
        """Send one sanitized packet; return verdict string (adb mode)."""
        hexstr = pkt.hex()
        if self.mode == "dryrun":
            r = subprocess.run([self._sender_bin, "--dry-run", hexstr],
                               capture_output=True, text=True, stdin=subprocess.DEVNULL)
            return "dryrun rc=%d" % r.returncode
        if self.mode == "script":
            self.script_lines.append(
                "%s --send %s %s" % (self._remote_bin or "$SENDER",
                                     self.interface, hexstr))
            return "script+1"
        # adb mode: per-frame verdict callback (spec item 3); the
        # ledger row can trail a cold helper rebuild by seconds
        before = self._completions_tail()
        r = self._adb("shell", "su", "-c",
                      "%s --send %s %s" % (self._remote_bin,
                                           self.interface, hexstr))
        verdict = "sent rc=%d" % r.returncode
        after = None
        for _ in range(12):
            time.sleep(0.5)
            after = self._completions_tail()
            if after and after != before and after[:1].isdigit():
                break
        if after and after != before:
            fields = after.split("\t")
            # TSV: seq ts status vdev desc ack_rssi pdev ppdu rate phymode ...
            verdict += " completion_seq=%s status=%s rate=%s" % (
                fields[0] if fields else "?",
                fields[2] if len(fields) > 2 else "?",
                fields[7] if len(fields) > 7 else "?")
        else:
            verdict += " completion=none(yet)"
        if note:
            verdict = "%s %s" % (verdict, note)
        if self.period:
            time.sleep(self.period)
        return verdict

    def write_script(self, path):
        with open(path, "w") as f:
            f.write("#!/system/bin/sh\n# replay batch (no per-frame verdict;"
                    " run on device as root)\n")
            f.write("# SENDER=/data/local/tmp/fi-replay-sender\n")
            for line in self.script_lines:
                f.write(line + "\n")
        os.chmod(path, 0o755)
