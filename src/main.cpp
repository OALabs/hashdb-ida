#include <cstdio>

#include "hash-algorihtms/crc32.hpp"
#include "hash-algorihtms/fnv1a_64.hpp"
#include "hash-algorihtms/revil_010F.hpp"

namespace tests {
	#pragma region MACRO_DEFINITIONS
	#define ARRAY_VALUES(string_literal_suffix) \
		"ntdll.dll"##string_literal_suffix, \
		"RtlAllocateHeap"##string_literal_suffix, "RtlReAllocateHeap"##string_literal_suffix, "RtlFreeHeap"##string_literal_suffix, \
		"memcpy"##string_literal_suffix, "memset"##string_literal_suffix, "memmove"##string_literal_suffix
	#define ARRAY_VALUES_XOR(string_literal_suffix, xor_key) \
		"ntdll.dll"##string_literal_suffix ^ (xor_key), \
		"RtlAllocateHeap"##string_literal_suffix ^ (xor_key), "RtlReAllocateHeap"##string_literal_suffix ^ (xor_key), "RtlFreeHeap"##string_literal_suffix ^ (xor_key), \
		"memcpy"##string_literal_suffix ^ (xor_key), "memset"##string_literal_suffix ^ (xor_key), "memmove"##string_literal_suffix ^ xor_key
	#define ARRAY_VALUES_UNKNOWN_STRING(string_literal_suffix) \
		"ntdll.dll"##string_literal_suffix, \
		"RtlAllocateHeap"##string_literal_suffix, "UnKnOwN_StRiNg"##string_literal_suffix, "RtlFreeHeap"##string_literal_suffix, \
		"memcpy"##string_literal_suffix, "memset"##string_literal_suffix, "memmove"##string_literal_suffix
	#define IMPORT_ARRAYS(string_literal_suffix, xor_key) \
		constinit const std::array hashed_imports##string_literal_suffix {ARRAY_VALUES(string_literal_suffix)}; \
		constinit const std::array hashed_imports_xor##string_literal_suffix {ARRAY_VALUES_XOR(string_literal_suffix, xor_key)}; \
		constinit const std::array hashed_imports_unknown_string##string_literal_suffix {ARRAY_VALUES_UNKNOWN_STRING(string_literal_suffix)};
	#define MIXED_HASH_TYPES \
		std::uint32_t ntdll_crc32             {"ntdll.dll"_crc32}; \
        std::uint64_t ntdll_fnv1a_64          {"ntdll.dll"_fnv1a_64}; \
        std::uint32_t RtlAllocateHeap_crc32   {"RtlAllocateHeap"_crc32}; \
        std::uint32_t RtlReAllocateHeap_crc32 {"RtlReAllocateHeap"_crc32}; \
        std::uint64_t memset_fnv1a_64         {"memset"_fnv1a_64}; \
        std::uint32_t memmove_crc32           {"memmove"_crc32}; \
        std::uint64_t memcpy_fnv1a_64         {"memcpy"_fnv1a_64}; \
        std::uint64_t RtlFreeHeap_fnv1a_64    {"RtlFreeHeap"_fnv1a_64};
	#pragma endregion

	constexpr auto xor_key_32 {0x58f9f79b};
	constexpr auto xor_key_64 {0xf5a7ab4717bb3813};

	using namespace hash_algorithms::crc32;
	IMPORT_ARRAYS(_crc32, xor_key_32)

	using namespace hash_algorithms::fnv1a_64;
	IMPORT_ARRAYS(_fnv1a_64, xor_key_64)

	using namespace hash_algorithms::revil_010F;
	IMPORT_ARRAYS(_revil_010F, xor_key_64)

	struct [[gnu::packed]] MixedHashesPacked { MIXED_HASH_TYPES };
	constinit const MixedHashesPacked mixed_hashes_packed {};
	struct MixedHashesAligned { MIXED_HASH_TYPES };
	constinit const MixedHashesAligned mixed_hashes_aligned {};

	[[gnu::noinline]] static void print_crc32_hashes() noexcept {
		puts(__PRETTY_FUNCTION__);
		// expected behavior: Hash match found: Sleep
		std::printf(R"(crc32("Sleep"): %#x)""\n", "Sleep"_crc32);
		// expected behavior: Hash match found: ntdll.dll
		std::printf(R"(crc32("ntdll.dll"): %#x)""\n", "ntdll.dll"_crc32);
		// expected behavior: No hash found for 0xCACA8209
		std::printf(R"(crc32("UnKnOwN_StRiNg"): %#x)""\n", "UnKnOwN_StRiNg"_crc32);
		// expected behavior: Hash match found: -path, the user is asked to provide a correct enum name
		std::printf(R"(crc32("-path"): %#x)""\n", "-path"_crc32);

		// Note: make sure the hashes were inserted into the `hashdb_strings_crc32` struct
		puts("");
	}
	[[gnu::noinline]] static void print_fnv1a_64_hashes() {
		puts(__PRETTY_FUNCTION__);
		// expected behavior: Hash match found: Sleep
		std::printf(R"(fnv1a_64("Sleep"): %#llx)""\n", "Sleep"_fnv1a_64);
		// expected behavior: Hash match found: ntdll.dll
		std::printf(R"(fnv1a_64("ntdll.dll"): %#llx)""\n", "ntdll.dll"_fnv1a_64);
		// expected behavior: No hash found for 0xD2D7ACA1A764A7EB
		std::printf(R"(fnv1a_64("UnKnOwN_StRiNg"): %#llx)""\n", "UnKnOwN_StRiNg"_fnv1a_64);
		// expected behavior: Hash match found: -path, the user is asked to provide a correct enum name
		std::printf(R"(fnv1a_64("-path"): %#llx)""\n", "-path"_fnv1a_64);

		// Note: make sure the hashes were inserted into the `hashdb_strings_fnv1a_64` struct
		puts("");
	}
	[[gnu::noinline]] static void print_revil_010F_hashes() {
		puts(__PRETTY_FUNCTION__);
		// expected behavior: Hash collisions, the user chooses the correct hash
		std::printf(R"(revil_010F("Sleep"): %#x)""\n", "Sleep"_revil_010F);
		// expected behavior: Hash collisions, the user chooses the correct hash
		std::printf(R"(revil_010F("ntdll.dll"): %#x)""\n", "ntdll.dll"_revil_010F);
		// expected behavior: Hash collisions, the user chooses the correct hash
		std::printf(R"(revil_010F("UnKnOwN_StRiNg"): %#x)""\n", "UnKnOwN_StRiNg"_revil_010F);
		// expected behavior: Hash match found: -path, the user is asked to provide a correct enum name
		std::printf(R"(revil_010F("-path"): %#x)""\n", "-path"_revil_010F);

		// Note: make sure the hashes were inserted into the `hashdb_strings_revil_010F` struct
		puts("");
	}

	[[gnu::noinline]] static void import_table() {
		puts(__PRETTY_FUNCTION__);

		// Values for IAT scanning
		// Expected result: all values successfully recognized
		std::printf("hashed_imports_crc32: %p\n", static_cast<const void*>(hashed_imports_crc32.data()));
		// Expected result: one hash value missing
		std::printf("hashed_imports_unknown_string_crc32: %p\n", static_cast<const void*>(hashed_imports_unknown_string_crc32.data()));
		// Expected result: all values successfully recognized
		std::printf("hashed_imports_fnv1a_64: %p\n", static_cast<const void*>(hashed_imports_fnv1a_64.data()));
		// Expected result: one hash value missing
		std::printf("hashed_imports_unknown_string_fnv1a_64: %p\n", static_cast<const void*>(hashed_imports_unknown_string_fnv1a_64.data()));
		// Expected result: hash collisions, user chooses the correct hashes
		std::printf("hashed_imports_revil_010F: %p\n", static_cast<const void*>(hashed_imports_revil_010F.data()));
		// Expected result: hash collisions, user chooses the correct hashes
		std::printf("hashed_imports_unknown_string_revil_010F: %p\n", static_cast<const void*>(hashed_imports_unknown_string_revil_010F.data()));

		// IAT scanning + xor transformation
		std::printf("hashed_imports_xor_crc32: %p, xor_value_32: 0x%X\n",
					static_cast<const void*>(hashed_imports_xor_crc32.data()), xor_key_32);
		std::printf("hashed_imports_xor_fnv1a_64: %p, xor_value_64: 0x%llX\n",
					static_cast<const void*>(hashed_imports_xor_fnv1a_64.data()), xor_key_64);
		std::printf("hashed_imports_xor_revil_010F: %p, xor_value_32: 0x%X\n",
					static_cast<const void*>(hashed_imports_xor_revil_010F.data()), xor_key_32);

		// Mixed IAT hashes (packed)
		std::printf("mixed_hashes_packed: %p\n", static_cast<const void*>(&mixed_hashes_packed));
		// Mixed IAT hashes (aligned)
		std::printf("mixed_hashes_aligned: %p\n", static_cast<const void*>(&mixed_hashes_aligned));

		puts("");
	}
}

int main() {
	puts(__PRETTY_FUNCTION__);
	puts("");

	tests::print_crc32_hashes();
	tests::print_fnv1a_64_hashes();
	tests::print_revil_010F_hashes();
	tests::import_table();
}
