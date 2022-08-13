#pragma once

#include "../utilities/strings.hpp"

namespace hash_algorithms::fnv1a_64 {
    using UnderlyingType = std::uint64_t;
    using SeedType = std::uint64_t;

    constexpr UnderlyingType prime {0x100000001B3};
    constexpr UnderlyingType offset_basis {0xCBF29CE484222325};

    template<utilities::IsCharacter T, T... Characters>
    consteval auto calculate(const SeedType seed = {}) noexcept {
        auto hash = offset_basis + seed;
        (((hash ^= static_cast<UnderlyingType>(Characters)) *= prime + seed), ...);
        return hash;
    }

    template<utilities::IsCharacter T, T... Characters>
    consteval auto calculate(const std::integer_sequence<T, Characters...>, const SeedType seed = {}) noexcept {
        return calculate<T, Characters...>(seed);
    }

    template<utilities::IsCharacter T>
    [[gnu::always_inline]] constexpr auto calculate(const std::basic_string_view<T> input, const SeedType seed = {}) noexcept {
        auto hash = offset_basis + seed;
        for (auto &&character : input) {
            hash ^= character;
            hash *= prime + seed;
        }
        return hash;
    }

    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wgnu-string-literal-operator-template"
    template<utilities::IsCharacter T, T... Characters>
    consteval auto operator""_fnv1a_64() noexcept { return calculate<T, Characters...>(); }
    #pragma clang diagnostic pop

    // Compile-time tests
    constexpr auto expected_test_result = 0xDAF6DADFB5E5528D;
    static_assert("dummy_string"_fnv1a_64 == expected_test_result);
    static_assert(L"dummy_string"_fnv1a_64 == expected_test_result);
    static_assert(u8"dummy_string"_fnv1a_64 == expected_test_result);
    static_assert(u"dummy_string"_fnv1a_64 == expected_test_result);
    static_assert(U"dummy_string"_fnv1a_64 == expected_test_result);
}
