// ReSharper disable CppClangTidyClangDiagnosticGnuStringLiteralOperatorTemplate
#pragma once

#include "../utilities/strings.hpp"

namespace hash_algorithms::revil_010F {
	using UnderlyingType = std::uint32_t;

    template<utilities::IsCharacter T, T... Characters>
    consteval auto calculate() noexcept {
        auto hash = static_cast<UnderlyingType>(0x2B);
        (((hash *= 0x010F) += static_cast<UnderlyingType>(Characters)), ...);
        return hash & 0x1FFFFF;
    }

    template<utilities::IsCharacter T, T... Characters>
    consteval auto operator""_revil_010F() noexcept { return calculate<T, Characters...>(); }

    // Compile-time tests
    constexpr auto expected_test_result = 0x1B06A3;
    static_assert("dummy_string"_revil_010F == expected_test_result);
    static_assert(L"dummy_string"_revil_010F == expected_test_result);
    static_assert(u8"dummy_string"_revil_010F == expected_test_result);
    static_assert(u"dummy_string"_revil_010F == expected_test_result);
    static_assert(U"dummy_string"_revil_010F == expected_test_result);
}
