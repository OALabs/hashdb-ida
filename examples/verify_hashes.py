"""Verify fixture constants locally; add --online to query HashDB as well."""

import argparse
import json
import urllib.request


def ror13_add(data):
    value = 0
    for byte in data:
        value = (((value >> 13) | (value << 19)) + byte) & 0xFFFFFFFF
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--online", action="store_true")
    args = parser.parse_args()
    for name, expected in (
        ("GetProcAddress", 0x7C0DFCAA),
        ("LoadLibraryA", 0xEC0E4E8E),
    ):
        actual = ror13_add(name.encode("ascii"))
        assert actual == expected, (name, actual, expected)
        print("%s: ror13_add = 0x%08X" % (name, actual))
        if args.online:
            url = "https://hashdb.openanalysis.net/hash/ror13_add/%d" % actual
            with urllib.request.urlopen(url, timeout=15) as response:
                results = json.load(response)
            assert any(
                hit.get("string", {}).get("api") == name
                and "kernel32" in hit["string"].get("modules", [])
                for hit in results.get("hashes", [])
            ), results
            print("  HashDB confirms kernel32!" + name)


if __name__ == "__main__":
    main()
