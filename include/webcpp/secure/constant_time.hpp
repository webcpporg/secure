// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The constant-time building blocks: masks, selection, table lookup and byte comparisons that
 neither branch on nor index memory by the values they receive, BoringSSL's `constant_time_*`.

 A mask is all zeros or all ones of its type, never a `bool`, so that callers combine masks with
 `&`, `|` and `~` without making a value the compiler may branch on. Every mask a block makes
 passes through `value_barrier`, which hides it from the optimiser. This is what the source can
 do; a compiler may still, in principle, rewrite arithmetic into a branch, which is why the
 constant-time lanes check the machine code under Valgrind's memcheck and MemorySanitizer and
 measure it with dudect.
*/
#ifndef WEBCPP_SECURE_CONSTANT_TIME_HPP
#define WEBCPP_SECURE_CONSTANT_TIME_HPP

#include <webcpp/secure/config.hpp>

#include <boost/assert.hpp>

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <type_traits>

namespace webcpp::secure {

namespace detail {

/**
 A type a mask is made of: any unsigned integral type but `bool`, which `std::unsigned_integral`
 accepts.
*/
template <class U>
concept mask_word = std::unsigned_integral<U> && !std::same_as<U, bool>;

/**
 The most significant bit of a word, moved to the least significant place.

 @param value The word.
 @return 1 when its top bit is set, else 0.
*/
template <mask_word U>
[[nodiscard]] constexpr U top_bit(U value) noexcept {
    constexpr auto shift = static_cast<unsigned>(std::numeric_limits<U>::digits - 1);
    return static_cast<U>(value >> shift);
}

/**
 Whether the program is built with clang's MemorySanitizer, which takes an `asm` statement's
 register input for a use and reports it when it is uninitialised: `value_barrier` then makes its
 round trip through a `volatile` local instead, which carries the value's shadow to its result, so
 that MemorySanitizer reports a branch or an index on a secret mask, not the barrier.
*/
#ifdef __has_feature
#if __has_feature(memory_sanitizer)
inline constexpr bool memory_sanitizer = true;
#else
inline constexpr bool memory_sanitizer = false;
#endif
#else
inline constexpr bool memory_sanitizer = false;
#endif

/**
 A value's round trip through a `volatile` local, which the compiler must store and load again.

 @param value The value.
 @return The same value.
*/
template <mask_word U>
[[nodiscard]] U volatile_round_trip(U value) noexcept {
    U volatile held = value;
    return held;
}

}  // namespace detail

namespace constant_time {

/**
 * Returns its argument, hidden from the optimiser, so that it cannot reason about which values
 * a mask may take and turn the arithmetic that uses it back into a branch.
 *
 * On GCC and clang it is an empty `asm volatile` statement with the value in a register
 * (BoringSSL's `value_barrier_w`); the `volatile` keeps the compiler from merging, hoisting or
 * dropping the statement, which has an output and would otherwise be an ordinary expression; on
 * MSVC and on WebAssembly, which have no such statement, and under MemorySanitizer, which would
 * report the statement's input when it is a secret marked uninitialised, a round trip through a
 * `volatile` local.
 * In a constant expression it is the identity. The barrier holds the value in this one place: it
 * does not stop the compiler from transforming the code around it.
 *
 * @tparam U Any unsigned integral type but `bool`.
 * @param value The value.
 * @return The same value.
 */
template <detail::mask_word U>
[[nodiscard]] constexpr U value_barrier(U value) noexcept {
    if (std::is_constant_evaluated()) {
        return value;
    }
#if (defined(__GNUC__) || defined(__clang__)) && !defined(__wasm__)
    if constexpr (detail::memory_sanitizer) {
        return detail::volatile_round_trip(value);
    } else {
        __asm__ volatile("" : "+r"(value));
        return value;
    }
#else
    return detail::volatile_round_trip(value);
#endif
}

/**
 * Spreads a bit across a whole word: 0 to the zero mask, 1 to the all-ones mask.
 *
 * @tparam U Any unsigned integral type but `bool`.
 * @param bit 0 or 1; any other value gives a word that is not a mask.
 * @return The mask, through `value_barrier`.
 */
template <detail::mask_word U>
[[nodiscard]] constexpr U mask_from_bit(U bit) noexcept {
    return value_barrier(static_cast<U>(U{0} - bit));
}

/**
 * The all-ones mask when a word is zero, else the zero mask.
 *
 * @tparam U Any unsigned integral type but `bool`.
 * @param value The word.
 * @return The mask.
 */
template <detail::mask_word U>
[[nodiscard]] constexpr U is_zero_mask(U value) noexcept {
    // ~value & (value - 1) has its top bit set exactly when value is zero.
    return mask_from_bit(
        detail::top_bit(static_cast<U>(static_cast<U>(~value) & static_cast<U>(value - U{1}))));
}

/**
 * The all-ones mask when two words are equal, else the zero mask.
 *
 * @tparam U Any unsigned integral type but `bool`.
 * @param first The first word.
 * @param second The second.
 * @return The mask.
 */
template <detail::mask_word U>
[[nodiscard]] constexpr U is_equal_mask(U first, U second) noexcept {
    return is_zero_mask(static_cast<U>(first ^ second));
}

/**
 * The all-ones mask when one word is less than another, as unsigned numbers, else the zero mask.
 *
 * @tparam U Any unsigned integral type but `bool`.
 * @param first The first word.
 * @param second The second.
 * @return The mask of `first < second`.
 */
template <detail::mask_word U>
[[nodiscard]] constexpr U is_less_mask(U first, U second) noexcept {
    // BoringSSL's constant_time_lt_w: the top bit of first ^ ((first ^ second) | ((first - second)
    // ^ first)) is the borrow of first - second.
    auto const difference = static_cast<U>(first ^ second);
    auto const wrapped = static_cast<U>(static_cast<U>(first - second) ^ first);
    return mask_from_bit(
        detail::top_bit(static_cast<U>(first ^ static_cast<U>(difference | wrapped))));
}

/**
 * The all-ones mask when a word lies in a closed range, `low <= value <= high`, else the zero
 * mask: an alphabet's character class, a digit's range.
 *
 * @tparam U Any unsigned integral type but `bool`.
 * @param value The word.
 * @param low The range's first value.
 * @param high Its last value; a range with `high < low` holds no value.
 * @return The mask, through `value_barrier`.
 */
template <detail::mask_word U>
[[nodiscard]] constexpr U is_in_range_mask(U value, U low, U high) noexcept {
    return value_barrier(static_cast<U>(static_cast<U>(~is_less_mask(value, low)) &
                                        static_cast<U>(~is_less_mask(high, value))));
}

/**
 * Chooses between two words by a mask, with no branch: `mask ? when_set : when_clear`.
 *
 * @tparam U Any unsigned integral type but `bool`.
 * @param mask The zero or the all-ones mask; any other word mixes the two words' bits.
 * @param when_set The word chosen by the all-ones mask.
 * @param when_clear The word chosen by the zero mask.
 * @return The chosen word.
 */
template <detail::mask_word U>
[[nodiscard]] constexpr U select(U mask, U when_set, U when_clear) noexcept {
    return static_cast<U>(static_cast<U>(value_barrier(mask) & when_set) |
                          static_cast<U>(static_cast<U>(~value_barrier(mask)) & when_clear));
}

/**
 * The entry of a table at an index, reading every entry in order so that neither the time nor
 * the addresses read depend on the index: an alphabet, a generator's constants.
 *
 * Its cost is the table's size. An index past the table selects no entry. The index is compared
 * in the wider of `std::size_t` and `Element`, so that the mask covers every bit of an entry
 * wider than `std::size_t` (a 64-bit entry on WebAssembly's 32-bit `std::size_t`) and narrows
 * to all ones for a narrower one.
 *
 * @tparam Element The entries' type: any unsigned integral type but `bool`.
 * @tparam N The table's extent, or `std::dynamic_extent`.
 * @param table The table, whose size is public.
 * @param index The index, which may be secret.
 * @return `table[index]`, or a value-initialised `Element` when `index` is past the table.
 */
template <detail::mask_word Element, std::size_t N>
[[nodiscard]] constexpr Element lookup(std::span<Element const, N> table,
                                       std::size_t index) noexcept {
    using index_word =
        std::conditional_t<(sizeof(Element) > sizeof(std::size_t)), Element, std::size_t>;
    Element result{};
    for (std::size_t position = 0; position < table.size(); ++position) {
        auto const keep = static_cast<Element>(is_equal_mask<index_word>(
            static_cast<index_word>(position), static_cast<index_word>(index)));
        result = static_cast<Element>(result | static_cast<Element>(table[position] & keep));
    }
    return result;
}

/**
 * Writes one of two byte sequences into a third by a mask, byte by byte, with no branch.
 *
 * The three sizes are public and must be equal: `BOOST_ASSERT` checks it, and with assertions
 * off unequal sizes write nothing.
 *
 * @param mask The zero or the all-ones mask.
 * @param destination Where the chosen bytes are written; it may be either source.
 * @param when_set The bytes chosen by the all-ones mask.
 * @param when_clear The bytes chosen by the zero mask.
 */
constexpr void select_bytes(std::uint8_t mask, std::span<std::uint8_t> destination,
                            std::span<std::uint8_t const> when_set,
                            std::span<std::uint8_t const> when_clear) noexcept {
    BOOST_ASSERT(destination.size() == when_set.size() && destination.size() == when_clear.size());
    if (destination.size() != when_set.size() || destination.size() != when_clear.size()) {
        return;
    }
    for (std::size_t position = 0; position < destination.size(); ++position) {
        destination[position] =
            select<std::uint8_t>(mask, when_set[position], when_clear[position]);
    }
}

/**
 * The all-ones byte mask when two byte sequences are equal, else the zero mask; every byte of
 * both is read.
 *
 * The sizes are public and must be equal: `BOOST_ASSERT` checks it, and with assertions off
 * unequal sizes give the zero mask without reading a byte.
 *
 * @param first The first sequence.
 * @param second The second.
 * @return The mask.
 */
[[nodiscard]] constexpr std::uint8_t equal_mask(std::span<std::uint8_t const> first,
                                                std::span<std::uint8_t const> second) noexcept {
    BOOST_ASSERT(first.size() == second.size());
    if (first.size() != second.size()) {
        return 0;
    }
    std::uint8_t difference = 0;
    for (std::size_t position = 0; position < first.size(); ++position) {
        difference = static_cast<std::uint8_t>(
            difference | static_cast<std::uint8_t>(first[position] ^ second[position]));
    }
    return is_zero_mask<std::uint8_t>(difference);
}

/**
 * The all-ones byte mask when every byte of a sequence is zero, else the zero mask; every byte
 * is read. An empty sequence is all zeros.
 *
 * @param bytes The sequence.
 * @return The mask.
 */
[[nodiscard]] constexpr std::uint8_t is_zero_mask(std::span<std::uint8_t const> bytes) noexcept {
    std::uint8_t accumulated = 0;
    for (std::uint8_t const byte : bytes) {
        accumulated = static_cast<std::uint8_t>(accumulated | byte);
    }
    return is_zero_mask<std::uint8_t>(accumulated);
}

/**
 * The all-ones byte mask when one byte sequence is less than another as big-endian unsigned
 * numbers, else the zero mask: a scalar against a group order, a value against a bound.
 *
 * Every byte of both is read, from the last to the first, carrying the borrow of the subtraction
 * through each. The sizes are public and must be equal: `BOOST_ASSERT` checks it, and with
 * assertions off unequal sizes give the zero mask without reading a byte.
 *
 * @param first The first number, most significant byte first.
 * @param second The second.
 * @return The mask of `first < second`.
 */
[[nodiscard]] constexpr std::uint8_t less_mask(std::span<std::uint8_t const> first,
                                               std::span<std::uint8_t const> second) noexcept {
    BOOST_ASSERT(first.size() == second.size());
    if (first.size() != second.size()) {
        return 0;
    }
    std::uint8_t borrow = 0;
    for (std::size_t position = first.size(); position != 0; --position) {
        auto const difference =
            static_cast<std::uint16_t>(first[position - 1] - second[position - 1] - borrow);
        borrow = static_cast<std::uint8_t>((static_cast<unsigned>(difference) >> 8U) & 1U);
    }
    return mask_from_bit<std::uint8_t>(borrow);
}

}  // namespace constant_time

}  // namespace webcpp::secure

#endif  // WEBCPP_SECURE_CONSTANT_TIME_HPP
