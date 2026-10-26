# Pseudocode hints (POC)

Install `requests` in IDA's Python environment, copy this branch's `hashdb.py` into your plugin directory, and restart IDA. No other plugin files are needed.

## Use it

1. Open a pseudocode function and select a numeric hash.
2. Right-click **HashDB Hunt Algorithm** and choose an algorithm.
3. Review the scan options, optionally enter a DLL preference, and click **Resolve**.
4. Leave **Apply inline hints** checked to show labels after matching constants. Uncheck it for results only.
5. Use **HashDB: Show/hide pseudocode hints** in the context menu or **Edit -> Plugins** to toggle them. The context menu also has clear and cancel actions.

Hunt fetches the algorithm list from the server. **Refresh Algorithms** in settings or scan options fetches it again. A scan requires a fetched list for its API URL; changing servers requires fetching that server's list first. Nothing is bundled or fetched at startup, and function-wide hash lookups start only when you click **Resolve**.

For `ror13_add`, `GetProcAddress` hashes to `0x7C0DFCAA` and `LoadLibraryA` to `0xEC0E4E8E`. With `kernel32` preferred, a label looks like:

```text
0x7C0DFCAA ror13_add: kernel32!GetProcAddress
```

Labels use the server's algorithm names. The [prototype screenshot](../assets/HashDB-Pseudocode-Hints.png) used a shortened name. Matches may be ambiguous; review them as suggestions.

## Try the example

Build [the small C fixture](../examples/pseudocode_hashes.c) with Windows LLVM:

```powershell
clang --target=x86_64-pc-windows-msvc -fuse-ld=lld -O0 -nostdlib examples/pseudocode_hashes.c '-Wl,/entry:demo_entry,/subsystem:console,/nodefaultlib' -o pseudocode_hashes.exe
```

Open it in IDA and decompile `demo_hash_hints`. Resolving with `ror13_add` makes two unique lookups and labels three occurrences. The fixture performs arithmetic, not API resolution.

```console
python examples/verify_hashes.py
python -m unittest discover -s tests -v
```

## Limits

Tested on IDA 9.4 with the Hex-Rays decompiler and Python 3.13 on Windows. Unsupported APIs disable the feature while keeping legacy HashDB actions available. Labels last for the session, are copied with pseudocode, and do not create enums or stored comments. All numeric expressions are candidates, including ordinary sizes and offsets. Scans default to 500 unique requests; cancellation waits for the current request (up to 15 seconds). Failed or canceled scans apply no partial hints.
