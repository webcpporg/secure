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

 On 64-bit ARM, branch-free and index-free code is not enough: Arm promises a time independent of
 the operands only for the instructions it lists, and only with DIT set. A caller that runs the
 blocks on a secret holds a `webcpp::secure::timing_guard` around them, as every function of
 webcpp that computes on a secret does: with DIT clear, MSVC 14.5's `lookup` was measured to take a
 time that depends on its index on Windows on ARM64.
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

 @param word_value The word.
 @return 1 when its top bit is set, else 0.
*/
template <mask_word U>
[[nodiscard]] constexpr U top_bit(U word_value) noexcept {
    constexpr auto shift_count = static_cast<unsigned>(std::numeric_limits<U>::digits - 1);
    return static_cast<U>(word_value >> shift_count);
}

#ifdef __has_feature
#if __has_feature(memory_sanitizer)
/**
 Whether the program is built with clang's MemorySanitizer, which takes an `asm` statement's
 register input for a use and reports it when it is uninitialised: `value_barrier` then makes its
 round trip through a `volatile` local instead, which carries the value's shadow to its result, so
 that MemorySanitizer reports a branch or an index on a secret mask, not the barrier.
*/
inline constexpr bool memory_sanitizer = true;
#else
/**
 Whether the program is built with clang's MemorySanitizer, which takes an `asm` statement's
 register input for a use and reports it when it is uninitialised: `value_barrier` then makes its
 round trip through a `volatile` local instead, which carries the value's shadow to its result, so
 that MemorySanitizer reports a branch or an index on a secret mask, not the barrier.
*/
inline constexpr bool memory_sanitizer = false;
#endif
#else
/**
 Whether the program is built with clang's MemorySanitizer: not, on a compiler without
 `__has_feature`.
*/
inline constexpr bool memory_sanitizer = false;
#endif

/**
 A value's round trip through a `volatile` local, which the compiler must store and load again.

 @param word_value The value.
 @return The same value.
*/
template <mask_word U>
[[nodiscard]] U volatile_round_trip(U word_value) noexcept {
    U volatile held_value = word_value;
    return held_value;
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
 * @param word_value The value.
 * @return The same value.
 */
template <detail::mask_word U>
[[nodiscard]] constexpr U value_barrier(U word_value) noexcept {
    if (std::is_constant_evaluated()) {
        return word_value;
    }
#if (defined(__GNUC__) || defined(__clang__)) && !defined(__wasm__)
    if constexpr (detail::memory_sanitizer) {
        return detail::volatile_round_trip(word_value);
    } else {
        __asm__ volatile("" : "+r"(word_value));
        return word_value;
    }
#else
    return detail::volatile_round_trip(word_value);
#endif
}

/**
 * Spreads a bit across a whole word: 0 to the zero mask, 1 to the all-ones mask.
 *
 * @tparam U Any unsigned integral type but `bool`.
 * @param low_bit 0 or 1; any other value gives a word that is not a mask.
 * @return The mask, through `value_barrier`.
 */
template <detail::mask_word U>
[[nodiscard]] constexpr U mask_from_bit(U low_bit) noexcept {
    return value_barrier(static_cast<U>(U{0} - low_bit));
}

/**
 * The all-ones mask when a word is zero, else the zero mask.
 *
 * @tparam U Any unsigned integral type but `bool`.
 * @param word_value The word.
 * @return The mask.
 */
template <detail::mask_word U>
[[nodiscard]] constexpr U is_zero_mask(U word_value) noexcept {
    // ~word_value & (word_value - 1) has its top bit set exactly when word_value is zero.
    return mask_from_bit(detail::top_bit(
        static_cast<U>(static_cast<U>(~word_value) & static_cast<U>(word_value - U{1}))));
}

/**
 * The all-ones mask when two words are equal, else the zero mask.
 *
 * @tparam U Any unsigned integral type but `bool`.
 * @param first_word The first word.
 * @param second_word The second.
 * @return The mask.
 */
template <detail::mask_word U>
[[nodiscard]] constexpr U is_equal_mask(U first_word, U second_word) noexcept {
    return is_zero_mask(static_cast<U>(first_word ^ second_word));
}

/**
 * The all-ones mask when one word is less than another, as unsigned numbers, else the zero mask.
 *
 * @tparam U Any unsigned integral type but `bool`.
 * @param first_word The first word.
 * @param second_word The second.
 * @return The mask of `first_word < second_word`.
 */
template <detail::mask_word U>
[[nodiscard]] constexpr U is_less_mask(U first_word, U second_word) noexcept {
    // BoringSSL's constant_time_lt_w: the top bit of first_word ^ ((first_word ^ second_word) |
    // ((first_word - second_word) ^ first_word)) is the borrow of first_word - second_word.
    auto const word_difference = static_cast<U>(first_word ^ second_word);
    auto const wrapped_difference =
        static_cast<U>(static_cast<U>(first_word - second_word) ^ first_word);
    return mask_from_bit(detail::top_bit(
        static_cast<U>(first_word ^ static_cast<U>(word_difference | wrapped_difference))));
}

/**
 * The all-ones mask when a word lies in a closed range, `low_bound <= word_value <= high_bound`,
 * else the zero mask: an alphabet's character class, a digit's range.
 *
 * @tparam U Any unsigned integral type but `bool`.
 * @param word_value The word.
 * @param low_bound The range's first value.
 * @param high_bound Its last value; a range with `high_bound < low_bound` holds no value.
 * @return The mask, through `value_barrier`.
 */
template <detail::mask_word U>
[[nodiscard]] constexpr U is_in_range_mask(U word_value, U low_bound, U high_bound) noexcept {
    return value_barrier(static_cast<U>(static_cast<U>(~is_less_mask(word_value, low_bound)) &
                                        static_cast<U>(~is_less_mask(high_bound, word_value))));
}

/**
 * Chooses between two words by a mask, with no branch: `choice_mask ? when_set : when_clear`.
 *
 * @tparam U Any unsigned integral type but `bool`.
 * @param choice_mask The zero or the all-ones mask; any other word mixes the two words' bits.
 * @param when_set The word chosen by the all-ones mask.
 * @param when_clear The word chosen by the zero mask.
 * @return The chosen word.
 */
template <detail::mask_word U>
[[nodiscard]] constexpr U select(U choice_mask, U when_set, U when_clear) noexcept {
    return static_cast<U>(static_cast<U>(value_barrier(choice_mask) & when_set) |
                          static_cast<U>(static_cast<U>(~value_barrier(choice_mask)) & when_clear));
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
 * @param table_entries The table, whose size is public.
 * @param entry_index The index, which may be secret.
 * @return `table_entries[entry_index]`, or a value-initialised `Element` when `entry_index` is past
 * the table.
 */
template <detail::mask_word Element, std::size_t N>
[[nodiscard]] constexpr Element lookup(std::span<Element const, N> table_entries,
                                       std::size_t entry_index) noexcept {
    using index_word =
        std::conditional_t<(sizeof(Element) > sizeof(std::size_t)), Element, std::size_t>;
    Element selected_entry{};
    for (std::size_t entry_position = 0; entry_position < table_entries.size(); ++entry_position) {
        auto const keep_mask = static_cast<Element>(is_equal_mask<index_word>(
            static_cast<index_word>(entry_position), static_cast<index_word>(entry_index)));
        selected_entry = static_cast<Element>(
            selected_entry | static_cast<Element>(table_entries[entry_position] & keep_mask));
    }
    return selected_entry;
}

/**
 * Writes one of two byte sequences into a third by a mask, byte by byte, with no branch.
 *
 * The three sizes are public and must be equal: `BOOST_ASSERT` checks it, and with assertions
 * off unequal sizes write nothing.
 *
 * @param choice_mask The zero or the all-ones mask.
 * @param destination_bytes Where the chosen bytes are written; it may be either source.
 * @param when_set The bytes chosen by the all-ones mask.
 * @param when_clear The bytes chosen by the zero mask.
 */
constexpr void select_bytes(std::uint8_t choice_mask, std::span<std::uint8_t> destination_bytes,
                            std::span<std::uint8_t const> when_set,
                            std::span<std::uint8_t const> when_clear) noexcept {
    BOOST_ASSERT(destination_bytes.size() == when_set.size() &&
                 destination_bytes.size() == when_clear.size());
    if (destination_bytes.size() != when_set.size() ||
        destination_bytes.size() != when_clear.size()) {
        return;
    }
    for (std::size_t byte_index = 0; byte_index < destination_bytes.size(); ++byte_index) {
        destination_bytes[byte_index] =
            select<std::uint8_t>(choice_mask, when_set[byte_index], when_clear[byte_index]);
    }
}

/**
 * The all-ones byte mask when two byte sequences are equal, else the zero mask; every byte of
 * both is read.
 *
 * The sizes are public and must be equal: `BOOST_ASSERT` checks it, and with assertions off
 * unequal sizes give the zero mask without reading a byte.
 *
 * @param first_bytes The first sequence.
 * @param second_bytes The second.
 * @return The mask.
 */
[[nodiscard]] constexpr std::uint8_t equal_mask(
    std::span<std::uint8_t const> first_bytes,
    std::span<std::uint8_t const> second_bytes) noexcept {
    BOOST_ASSERT(first_bytes.size() == second_bytes.size());
    if (first_bytes.size() != second_bytes.size()) {
        return 0;
    }
    std::uint8_t byte_difference = 0;
    for (std::size_t byte_index = 0; byte_index < first_bytes.size(); ++byte_index) {
        byte_difference = static_cast<std::uint8_t>(
            byte_difference |
            static_cast<std::uint8_t>(first_bytes[byte_index] ^ second_bytes[byte_index]));
    }
    return is_zero_mask<std::uint8_t>(byte_difference);
}

/**
 * The all-ones byte mask when every byte of a sequence is zero, else the zero mask; every byte
 * is read.
 *
 * An empty sequence is all zeros.
 *
 * @param tested_bytes The sequence.
 * @return The mask.
 */
[[nodiscard]] constexpr std::uint8_t is_zero_mask(
    std::span<std::uint8_t const> tested_bytes) noexcept {
    std::uint8_t accumulated_bits = 0;
    for (std::uint8_t const tested_byte : tested_bytes) {
        accumulated_bits = static_cast<std::uint8_t>(accumulated_bits | tested_byte);
    }
    return is_zero_mask<std::uint8_t>(accumulated_bits);
}

/**
 * The all-ones byte mask when one byte sequence is less than another as big-endian unsigned
 * numbers, else the zero mask: a scalar against a group order, a value against a bound.
 *
 * Every byte of both is read, from the last to the first, carrying the borrow of the subtraction
 * through each. The sizes are public and must be equal: `BOOST_ASSERT` checks it, and with
 * assertions off unequal sizes give the zero mask without reading a byte.
 *
 * @param first_bytes The first number, most significant byte first.
 * @param second_bytes The second.
 * @return The mask of `first_bytes < second_bytes`.
 */
[[nodiscard]] constexpr std::uint8_t less_mask(
    std::span<std::uint8_t const> first_bytes,
    std::span<std::uint8_t const> second_bytes) noexcept {
    BOOST_ASSERT(first_bytes.size() == second_bytes.size());
    if (first_bytes.size() != second_bytes.size()) {
        return 0;
    }
    std::uint8_t borrow_bit = 0;
    for (std::size_t byte_index = first_bytes.size(); byte_index != 0; --byte_index) {
        auto const byte_difference = static_cast<std::uint16_t>(
            first_bytes[byte_index - 1] - second_bytes[byte_index - 1] - borrow_bit);
        borrow_bit = static_cast<std::uint8_t>((static_cast<unsigned>(byte_difference) >> 8U) & 1U);
    }
    return mask_from_bit<std::uint8_t>(borrow_bit);
}

}  // namespace constant_time

}  // namespace webcpp::secure

#endif  // WEBCPP_SECURE_CONSTANT_TIME_HPP
