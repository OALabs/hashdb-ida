// ReSharper disable CppClangTidyClangDiagnosticGnuStringLiteralOperatorTemplate
#pragma once

#include <array>
#include <limits>

#include "../utilities/strings.hpp"

namespace hash_algorithms::crc32 {
    using UnderlyingType = std::uint32_t;
    using SignedUnderlyingType = std::make_signed_t<UnderlyingType>;

    constexpr std::size_t bytes {256};
    constexpr std::size_t iterations {8};
    constexpr UnderlyingType polynomial {0xEDB88320};

    consteval auto generate_table() noexcept {
        struct {
            std::array<UnderlyingType, bytes> table {};

            [[nodiscard]] constexpr std::size_t size() const noexcept { return this->table.size(); }
            constexpr UnderlyingType &operator[](const std::size_t index) noexcept { return this->table[index]; }
            constexpr UnderlyingType operator[](const std::size_t index) const noexcept { return this->table[index]; }
        } table {};

        for (std::size_t i {}; i < table.size(); ++i) {
            auto crc = static_cast<UnderlyingType>(i);
            for (std::size_t j {}; j < iterations; ++j)
				// ReSharper disable once CppRedundantParentheses
				crc = crc >> 1 ^ (polynomial & static_cast<UnderlyingType>(-static_cast<SignedUnderlyingType>(crc & 1)));
            table[i] = crc;
        }

        return table;
    }

    template<utilities::IsCharacter T, T... Characters>
    consteval auto calculate(const UnderlyingType base = {}) noexcept {
        constexpr auto table = generate_table();

        auto crc = base ^ std::numeric_limits<UnderlyingType>::max();
        ((crc = table[(crc ^ static_cast<UnderlyingType>(Characters)) & 0xFF] ^ crc >> 8), ...);
        return ~crc;
    }

    template<utilities::IsCharacter T>
    [[gnu::always_inline]] constexpr auto calculate(const std::basic_string_view<T> input, const UnderlyingType base = {}) noexcept {
        constexpr auto table = generate_table();

        auto crc = base ^ std::numeric_limits<UnderlyingType>::max();
        for (auto &&character : input)
            crc = table[(crc ^ static_cast<UnderlyingType>(character)) & 0xFF] ^ crc >> 8;
        return ~crc;
    }
    
    template<utilities::IsCharacter T, T... Characters>
    consteval auto operator""_crc32() noexcept { return calculate<T, Characters...>(); }

    // Compile-time tests
    constexpr auto expected_test_result = 0x1F3F8675;
    static_assert("dummy_string"_crc32 == expected_test_result);
    static_assert(L"dummy_string"_crc32 == expected_test_result);
    static_assert(u8"dummy_string"_crc32 == expected_test_result);
    static_assert(u"dummy_string"_crc32 == expected_test_result);
    static_assert(U"dummy_string"_crc32 == expected_test_result);
}
