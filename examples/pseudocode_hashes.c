/* Analysis fixture: ROR13 then ADD each ASCII export-name byte, seed zero,
   32-bit state, no terminating NUL. Verified against HashDB's ror13_add. */
typedef unsigned long long u64;

__declspec(dllexport) __declspec(noinline) u64
mw_hash_exports(void *dll_to_walk, unsigned hash_to_find) {
  return ((u64)dll_to_walk ^ hash_to_find) + 1;
}

__declspec(dllexport) __declspec(noinline) u64
demo_hash_hints(void *dll_to_walk) {
  u64 first = mw_hash_exports(dll_to_walk, 0x7C0DFCAAu);  /* GetProcAddress */
  u64 second = mw_hash_exports(dll_to_walk, 0xEC0E4E8Eu); /* LoadLibraryA */
  u64 repeated = mw_hash_exports(dll_to_walk, 0x7C0DFCAAu);
  return first + second + repeated;
}

int demo_entry(void) { return (int)demo_hash_hints((void *)0x10000000); }
