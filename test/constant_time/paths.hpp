// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The constant-time paths that memcheck (ctgrind_test.cpp) and MemorySanitizer (msan_test.cpp)
// both check, written once against a checker of support/constant_time_marks.hpp, so that the two
// checkers' coverage cannot diverge: every block of <webcpp/secure/constant_time.hpp> on
// std::uint8_t, std::uint32_t and std::uint64_t, the byte blocks, constant_time_equal and
// secret<32>'s moves, clone and destruction, each with its operands marked secret. A branch or an
// index on them is the checker's report, which fails the run. Each block's result is then checked
// to carry the mark, so that the path is traced, where the checker's shadow follows a subtraction's
// carry (exact_subtraction: memcheck); MemorySanitizer's drops it (msan_test.cpp says more), and
// the other checker checks it. Each result is then declassified and checked against its plain
// value, so that the path also computed what it should.
//
// The planted leaks, each a function of its own that a checker's report names in its first frame
// (the drivers' --in), are compiled only into the planted programs, which run them before every
// path: planted_select, a select written with a branch on its mask; planted_lookup, a lookup that
// indexes its table; planted_verdict, a branch on constant_time_equal's verdict that was never
// declassified (memcheck's alone: msan_test.cpp says why).

#ifndef WEBCPP_TEST_SECURE_CONSTANT_TIME_PATHS_HPP
#define WEBCPP_TEST_SECURE_CONSTANT_TIME_PATHS_HPP

#include "../support/constant_time_marks.hpp"

#include <webcpp/secure/constant_time.hpp>
#include <webcpp/secure/constant_time_equal.hpp>
#include <webcpp/secure/declassify.hpp>
#include <webcpp/secure/secret.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <new>
#include <optional>
#include <span>
#include <utility>

namespace webcpp::secure::test {

/** The bytes of an object, to read the checker's shadow of. */
template <class T>
std::span<std::uint8_t const> bytes_of(T const& object) {
    return {reinterpret_cast<std::uint8_t const*>(&object), sizeof object};
}

/** The bytes of an object, to mark. */
template <class T>
std::span<std::uint8_t> writable_bytes_of(T& object) {
    return {reinterpret_cast<std::uint8_t*>(&object), sizeof object};
}

/** Counts a failed check, with its name and the type it ran on. */
inline int check(bool passed, char const* what, char const* type_name = "") {
    if (!passed) {
        std::printf("FAILED: %s%s\n", what, type_name);
    }
    return passed ? 0 : 1;
}

/** Whether the checker read its shadow and the secret mark reached none of `bytes`. */
template <class Checker>
bool clear_of_mark(std::span<std::uint8_t const> bytes) {
    std::optional<bool> const traced = Checker::traced(bytes);
    return traced.has_value() && !*traced;
}

/**
 * Checks a block's result: it carries the mark where the checker's shadow follows a subtraction's
 * carry, then, declassified, it equals the plain value.
 */
template <class Checker, class T>
int traced_and_equal(T result, T expected, char const* what, char const* type_name) {
    int const untraced = Checker::exact_subtraction
                             ? check(carries_mark<Checker>(bytes_of(result)), what, type_name)
                             : 0;
    secure::declassify(result);
    return untraced + check(result == expected, what, type_name);
}

/** The name a check prints for a word type. */
template <class U>
constexpr char const* type_name() {
    if constexpr (sizeof(U) == 1) {
        return " on std::uint8_t";
    } else if constexpr (sizeof(U) == 4) {
        return " on std::uint32_t";
    } else {
        return " on std::uint64_t";
    }
}

/**
 * Every word block on `U`, its operands secret: value_barrier, mask_from_bit, is_zero_mask,
 * is_equal_mask, is_less_mask, is_in_range_mask and select.
 */
template <class Checker, class U>
int word_blocks() {
    namespace ct = secure::constant_time;
    constexpr U ones = std::numeric_limits<U>::max();
    // Not const: the mark changes each object in the checker's shadow, so it is read again.
    U high = static_cast<U>(0xA5A5A5A5A5A5A5A5ULL);    // NOLINT(misc-const-correctness)
    U middle = static_cast<U>(0x5A5A5A5A5A5A5A5AULL);  // NOLINT(misc-const-correctness)
    U bit = 1;                                         // NOLINT(misc-const-correctness)
    U zero = 0;                                        // NOLINT(misc-const-correctness)
    U mask = ones;                                     // NOLINT(misc-const-correctness)
    for (std::span<std::uint8_t> const bytes : {
             writable_bytes_of(high),
             writable_bytes_of(middle),
             writable_bytes_of(bit),
             writable_bytes_of(zero),
             writable_bytes_of(mask),
         }) {
        Checker::mark_secret(bytes);
    }
    char const* const type = type_name<U>();
    return traced_and_equal<Checker, U>(ct::value_barrier(high),
                                        static_cast<U>(0xA5A5A5A5A5A5A5A5ULL), "value_barrier",
                                        type) +
           traced_and_equal<Checker, U>(ct::mask_from_bit(bit), ones, "mask_from_bit", type) +
           traced_and_equal<Checker, U>(ct::is_zero_mask(zero), ones, "is_zero_mask", type) +
           traced_and_equal<Checker, U>(ct::is_zero_mask(high), U{0}, "is_zero_mask, nonzero",
                                        type) +
           traced_and_equal<Checker, U>(ct::is_equal_mask(high, middle), U{0}, "is_equal_mask",
                                        type) +
           traced_and_equal<Checker, U>(ct::is_less_mask(middle, high), ones, "is_less_mask",
                                        type) +
           traced_and_equal<Checker, U>(ct::is_in_range_mask(middle, zero, high), ones,
                                        "is_in_range_mask", type) +
           traced_and_equal<Checker, U>(ct::select(mask, high, middle),
                                        static_cast<U>(0xA5A5A5A5A5A5A5A5ULL), "select", type);
}

/** The entry of lookup_path's table at a position. */
template <class Element>
Element entry_at(std::size_t position) {
    std::size_t const value = (position * 3U) + 1U;
    return static_cast<Element>(value);
}

/** lookup over a 64-entry table of `Element`, its index secret. */
template <class Checker, class Element>
int lookup_path() {
    std::array<Element, 64> table{};
    for (std::size_t position = 0; position < table.size(); ++position) {
        table[position] = entry_at<Element>(position);
    }
    std::size_t index = 37;  // NOLINT(misc-const-correctness): the mark changes it
    Checker::mark_secret(writable_bytes_of(index));
    Element const found = secure::constant_time::lookup(std::span<Element const, 64>(table), index);
    return traced_and_equal<Checker, Element>(found, entry_at<Element>(37), "lookup",
                                              type_name<Element>());
}

/** select_bytes with its mask secret: the destination is written without a branch on it. */
template <class Checker>
int select_bytes_path() {
    std::array<std::uint8_t, 32> when_set{};
    std::array<std::uint8_t, 32> when_clear{};
    std::array<std::uint8_t, 32> destination{};
    when_set.fill(0x42);
    when_clear.fill(0x17);
    std::uint8_t mask = 0xFF;  // NOLINT(misc-const-correctness): the mark changes it
    Checker::mark_secret(writable_bytes_of(mask));
    secure::constant_time::select_bytes(mask, destination, when_set, when_clear);
    int const untraced =
        Checker::exact_subtraction ? check(carries_mark<Checker>(destination), "select_bytes") : 0;
    secure::declassify(destination);
    return untraced + check(destination == when_set, "select_bytes");
}

/** equal_mask, is_zero_mask and less_mask over bytes, every operand secret. */
template <class Checker>
int byte_blocks() {
    namespace ct = secure::constant_time;
    // Each operand its own object: the same object twice, x ^ x, would be folded to 0.
    std::array<std::uint8_t, 32> first{};
    std::array<std::uint8_t, 32> same{};
    std::array<std::uint8_t, 32> second{};
    std::array<std::uint8_t, 32> zero{};
    first.fill(0x42);
    same.fill(0x42);
    second.fill(0x42);
    second[31] = 0x43;
    Checker::mark_secret(first);
    Checker::mark_secret(same);
    Checker::mark_secret(second);
    Checker::mark_secret(zero);
    return traced_and_equal<Checker, std::uint8_t>(ct::equal_mask(first, second), 0, "equal_mask",
                                                   "") +
           traced_and_equal<Checker, std::uint8_t>(ct::equal_mask(first, same), 0xFF,
                                                   "equal_mask, equal", "") +
           traced_and_equal<Checker, std::uint8_t>(
               ct::is_zero_mask(std::span<std::uint8_t const>(zero)), 0xFF,
               "is_zero_mask over bytes", "") +
           traced_and_equal<Checker, std::uint8_t>(ct::less_mask(first, second), 0xFF, "less_mask",
                                                   "");
}

/**
 * constant_time_equal with both sides secret: its verdict carries the mark until it is
 * declassified, then the checker's `verdict` must hold it public, as a caller's branch on it
 * needs. Without the declassify, memcheck reports that check (planted_verdict shows the branch).
 */
template <class Checker>
int constant_time_equal_path() {
    std::array<std::uint8_t, 64> first{};
    std::array<std::uint8_t, 64> second{};
    first.fill(0x42);
    second.fill(0x42);
    Checker::mark_secret(first);
    Checker::mark_secret(second);
    // Not const: the mark changes the object in the checker's shadow, so it is read again.
    bool same = secure::constant_time_equal(first, second);  // NOLINT(misc-const-correctness)
    int const untraced = Checker::exact_subtraction ? check(carries_mark<Checker>(bytes_of(same)),
                                                            "constant_time_equal, traced")
                                                    : 0;
    secure::declassify(same);
    Checker::verdict(same);
    return untraced + check(same, "constant_time_equal");
}

/**
 * secret<32>'s move, move assignment, clone and destructor: the moves and the destructor overwrite
 * the bytes they leave behind with constants, without a branch on them, so that the checker holds
 * them public after; the clone and the moved-to secret carry the mark.
 */
template <class Checker>
int secret_path() {
    using secret_bytes = secure::secret<32>;
    alignas(secret_bytes) std::array<std::byte, sizeof(secret_bytes)> storage{};
    auto* const first = new (storage.data()) secret_bytes;
    std::ranges::fill(first->writable(), std::uint8_t{0x42});
    Checker::mark_secret(first->writable());
    secret_bytes const copy = first->clone();
    bool const cloned = carries_mark<Checker>(copy.bytes());
    secret_bytes moved(std::move(*first));
    bool const moved_from_wiped = clear_of_mark<Checker>(first->bytes());
    secret_bytes assigned;
    assigned = std::move(moved);
    bool const assigned_from_wiped =
        clear_of_mark<Checker>(moved.bytes());  // NOLINT(bugprone-use-after-move)
    bool const kept = carries_mark<Checker>(assigned.bytes());
    *first = std::move(assigned);
    first->~secret_bytes();
    // MemorySanitizer poisons a destroyed object by itself: only a checker that reads it back
    // checks the destructor's wipe.
    bool const destroyed_wiped =
        !Checker::reads_destroyed ||
        clear_of_mark<Checker>(
            {reinterpret_cast<std::uint8_t const*>(storage.data()), storage.size()});
    return check(cloned, "secret's clone") +
           check(moved_from_wiped && assigned_from_wiped && kept, "secret's moves") +
           check(destroyed_wiped, "secret's destructor");
}

/** Every path above, on the checker: the number of failed checks. */
template <class Checker>
int common_paths() {
    return word_blocks<Checker, std::uint8_t>() + word_blocks<Checker, std::uint32_t>() +
           word_blocks<Checker, std::uint64_t>() + lookup_path<Checker, std::uint8_t>() +
           lookup_path<Checker, std::uint32_t>() + lookup_path<Checker, std::uint64_t>() +
           select_bytes_path<Checker>() + byte_blocks<Checker>() +
           constant_time_equal_path<Checker>() + secret_path<Checker>();
}

#if defined(WEBCPP_TEST_SECURE_PLANTED_SELECT) || defined(WEBCPP_TEST_SECURE_PLANTED_VERDICT)
/** Where a planted leak's branch leads: a call no compiler turns into a select. */
[[gnu::noinline]] inline void planted_sink(std::uint8_t value) {
    std::uint8_t const volatile sunk = value;
    static_cast<void>(sunk);
}
#endif

#ifdef WEBCPP_TEST_SECURE_PLANTED_SELECT
/** The planted leak: a select written with a branch on its mask, which the checker must report. */
[[gnu::noinline]] inline void planted_select(std::uint8_t mask, std::uint8_t when_set) {
    if (mask != 0) {  // the planted leak: a branch on the secret mask
        planted_sink(when_set);
    }
}
#endif

#ifdef WEBCPP_TEST_SECURE_PLANTED_LOOKUP
/** The planted leak: a lookup that indexes its table by the secret index. */
[[gnu::noinline]] inline std::uint8_t planted_lookup(std::span<std::uint8_t const, 64> table,
                                                     std::size_t index) {
    return table[index];  // the planted leak: an address that depends on the secret index
}
#endif

#ifdef WEBCPP_TEST_SECURE_PLANTED_VERDICT
/**
 * The planted leak: a branch on constant_time_equal's verdict, never declassified, which the
 * checker must report (the declassified branch is constant_time_equal_path's).
 */
[[gnu::noinline]] inline void planted_verdict(std::span<std::uint8_t const, 64> first,
                                              std::span<std::uint8_t const, 64> second) {
    bool const same = secure::constant_time_equal(first, second);
    if (same) {  // the planted leak: a branch on a verdict that was not declassified
        planted_sink(1);
    }
}
#endif

/** The planted leak this program is built with, if any, run on a secret operand. */
template <class Checker>
void run_planted() {
#ifdef WEBCPP_TEST_SECURE_PLANTED_SELECT
    std::uint8_t mask = 0xFF;  // NOLINT(misc-const-correctness): the mark changes it
    Checker::mark_secret(writable_bytes_of(mask));
    planted_select(mask, 0x42);
#endif
#ifdef WEBCPP_TEST_SECURE_PLANTED_LOOKUP
    std::array<std::uint8_t, 64> table{};
    std::size_t index = 5;  // NOLINT(misc-const-correctness): the mark changes it
    Checker::mark_secret(writable_bytes_of(index));
    std::uint8_t found = planted_lookup(table, index);  // NOLINT(misc-const-correctness)
    secure::declassify(found);
    static_cast<void>(check(found == 0, "the planted lookup"));
#endif
#ifdef WEBCPP_TEST_SECURE_PLANTED_VERDICT
    std::array<std::uint8_t, 64> first{};
    std::array<std::uint8_t, 64> second{};
    Checker::mark_secret(first);
    Checker::mark_secret(second);
    planted_verdict(first, second);
#endif
}

}  // namespace webcpp::secure::test

#endif  // WEBCPP_TEST_SECURE_CONSTANT_TIME_PATHS_HPP
