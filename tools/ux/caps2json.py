#!/usr/bin/env python3
"""caps2json - offline converter: frame_inject_capabilities key=value
lines to JSON (host-side; the kv node stays the machine-readable
authority on device).

usage: caps2json.py [FILE]      (stdin if no file)
       caps2json.py --selftest
"""
import json
import sys


def convert(text):
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()
        # numeric values stay numeric when they are pure integers
        if val.lstrip("-").isdigit():
            out[key] = int(val)
        else:
            out[key] = val
    return out


def selftest():
    sample = (
        "# header comment\n"
        "capabilities_version=14\n"
        "stats_format_version=13\n"
        "tx_power=param_default_on:s8_dbm_x2_half_dbm_units:ota_unproven\n"
        "selftests=407\n"
        "no_value_line_without_equals\n"
    )
    got = convert(sample)
    ok = (got["capabilities_version"] == 14 and
          got["stats_format_version"] == 12 and
          got["tx_power"] == "param_default_on:s8_dbm_x2_half_dbm_units:ota_unproven" and
          got["selftests"] == 407 and
          len(got) == 4)
    print("caps2json selftest: %s" % ("PASS" if ok else "FAIL"))
    print(json.dumps(got, indent=2, sort_keys=True))
    return 0 if ok else 1


def main():
    if "--selftest" in sys.argv:
        return selftest()
    text = open(sys.argv[1]).read() if len(sys.argv) > 1 else sys.stdin.read()
    print(json.dumps(convert(text), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
