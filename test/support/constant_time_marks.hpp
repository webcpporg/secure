// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The primitives of the constant-time checkers, for secure's tests and the constant-time lane's
// programs: under WEBCPP_SECURE_CT_VALGRIND memcheck's, under WEBCPP_SECURE_CT_MSAN
// MemorySanitizer's. A checker is a type with
//
// - `static void mark_secret(std::span<std::uint8_t>)`: the bytes are secret from now on;
// - `static void mark_public(std::span<std::uint8_t const>)`: the bytes are public;
// - `static std::optional<bool> traced(std::span<std::uint8_t const>)`: whether the secret mark
//   reached some byte of these; empty when the checker could not read its own shadow;
// - `static void verdict(bool const&)`: the verdict, whether a tag matched, must be public, the
//   checker reports it otherwise;
//
// and two facts about its shadow: `exact_subtraction`, whether the mark follows a subtraction's
// carry (memcheck's does, MemorySanitizer's approximation drops it), and `reads_destroyed`,
// whether a destroyed object's bytes can be read back (MemorySanitizer marks them by itself).
// Crypto keeps its own copies of the two structs.

#ifndef WEBCPP_TEST_SECURE_SUPPORT_CONSTANT_TIME_MARKS_HPP
#define WEBCPP_TEST_SECURE_SUPPORT_CONSTANT_TIME_MARKS_HPP

#if defined(WEBCPP_SECURE_CT_VALGRIND) && defined(WEBCPP_SECURE_CT_MSAN)
#error "define WEBCPP_SECURE_CT_VALGRIND or WEBCPP_SECURE_CT_MSAN, not both"
#endif

#ifdef WEBCPP_SECURE_CT_VALGRIND
#include <valgrind/memcheck.h>
#elif defined(WEBCPP_SECURE_CT_MSAN)
#include <sanitizer/msan_interface.h>
#endif

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace webcpp::secure::test {

#ifdef WEBCPP_SECURE_CT_VALGRIND

/** memcheck's primitives. */
struct memcheck {
    /** memcheck follows a subtraction's carry. */
    static constexpr bool exact_subtraction = true;
    /** A destroyed object's bytes keep their definedness. */
    static constexpr bool reads_destroyed = true;

    /** Marks bytes secret: memcheck's undefined. */
    static void mark_secret(std::span<std::uint8_t> bytes) {
        VALGRIND_MAKE_MEM_UNDEFINED(bytes.data(), bytes.size());
    }

    /** Marks bytes public: defined. */
    static void mark_public(std::span<std::uint8_t const> bytes) {
        VALGRIND_MAKE_MEM_DEFINED(bytes.data(), bytes.size());
    }

    /**
     * Whether memcheck holds some bit of the first 64 of `bytes` undefined, read from its own
     * shadow without an error; empty when memcheck cannot read it (not under Valgrind, or the
     * bytes are not addressable).
     */
    static std::optional<bool> traced(std::span<std::uint8_t const> bytes) {
        std::array<std::uint8_t, 64> bits{};
        std::size_t const size = (std::min)(bytes.size(), bits.size());
        if (VALGRIND_GET_VBITS(bytes.data(), bits.data(), size) != 1) {
            return std::nullopt;
        }
        return std::any_of(bits.begin(), bits.begin() + static_cast<std::ptrdiff_t>(size),
                           [](std::uint8_t bit) { return bit != 0; });
    }

    /** Reports the verdict when it is undefined. */
    static void verdict(bool const& value) {
        static_cast<void>(VALGRIND_CHECK_VALUE_IS_DEFINED(value));
    }
};

#elif defined(WEBCPP_SECURE_CT_MSAN)

/** MemorySanitizer's primitives. */
struct memory_sanitizer {
    /** A subtraction's shadow drops the carry. */
    static constexpr bool exact_subtraction = false;
    /**
     * A destroyed object is poisoned by MemorySanitizer itself (-fsanitize-memory-use-after-dtor,
     * on by default).
     */
    static constexpr bool reads_destroyed = false;

    /** Poisons bytes: they are secret. */
    static void mark_secret(std::span<std::uint8_t> bytes) {
        __msan_poison(bytes.data(), bytes.size());
    }

    /** Unpoisons bytes: they are public. */
    static void mark_public(std::span<std::uint8_t const> bytes) {
        __msan_unpoison(bytes.data(), bytes.size());
    }

    /** Whether some byte of `bytes` is poisoned; MemorySanitizer always reads its shadow. */
    static std::optional<bool> traced(std::span<std::uint8_t const> bytes) {
        return __msan_test_shadow(bytes.data(), bytes.size()) != -1;
    }

    /** Reports the verdict when it is poisoned. */
    static void verdict(bool const& value) {
        __msan_check_mem_is_initialized(&value, sizeof value);
    }
};

#endif

/**
 * Whether the checker read its shadow and the secret mark reached `bytes`.
 *
 * @tparam Checker `memcheck` or `memory_sanitizer`.
 * @param bytes The bytes to look at.
 * @return Whether the mark reached them.
 */
template <class Checker>
bool carries_mark(std::span<std::uint8_t const> bytes) {
    std::optional<bool> const traced = Checker::traced(bytes);
    return traced.has_value() && *traced;
}

}  // namespace webcpp::secure::test

#endif  // WEBCPP_TEST_SECURE_SUPPORT_CONSTANT_TIME_MARKS_HPP
