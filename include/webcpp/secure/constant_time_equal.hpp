// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `constant_time_equal`, the constant-time comparison of two byte sequences: tags, MACs, digests.

 It includes no header of a hash library: a hash library's digest, a `std::array`, a `std::span`, a
 `std::string_view`, a `secret<N>` are byte sequences by their shape.
*/
#ifndef WEBCPP_SECURE_CONSTANT_TIME_EQUAL_HPP
#define WEBCPP_SECURE_CONSTANT_TIME_EQUAL_HPP

#include <webcpp/secure/config.hpp>

#include <webcpp/secure/timing_guard.hpp>

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <ranges>
#include <span>
#include <type_traits>

namespace webcpp::secure {

namespace detail {

/** An element type that is one byte: `std::uint8_t`, `unsigned char`, `char`, `std::byte`. */
template <class T>
concept byte_element =
    std::same_as<std::remove_cv_t<T>, std::uint8_t> ||
    std::same_as<std::remove_cv_t<T>, unsigned char> || std::same_as<std::remove_cv_t<T>, char> ||
    std::same_as<std::remove_cv_t<T>, std::byte>;

/**
 A contiguous sized range of bytes, or a type whose `bytes()` gives a span of them, as `secret<N>`
 does.
*/
template <class T>
concept byte_sequence =
    (std::ranges::contiguous_range<T const&> && std::ranges::sized_range<T const&> &&
     byte_element<std::ranges::range_value_t<T const&>>) ||
    requires(T const& value) {
        { value.bytes() } -> std::convertible_to<std::span<std::uint8_t const>>;
    };

/**
 The bytes of a sequence, as an address and a size.

 @tparam Element The element type, without cv.
*/
template <class Element>
struct byte_view {
    /** The first element; null when the sequence has none. */
    Element const* first;
    /** The number of elements. */
    std::size_t count;
};

/**
 Holds a sequence's `bytes()` result, or the sequence itself when it has no `bytes()`.

 The caller binds the result with `auto&&`, which extends the life of a result returned by value.

 @param sequence The sequence.
 @return Its `bytes()` result, else a reference to it.
*/
template <byte_sequence Sequence>
[[nodiscard]] constexpr decltype(auto) held_bytes(Sequence const& sequence) noexcept {
    if constexpr (requires {
                      { sequence.bytes() } -> std::convertible_to<std::span<std::uint8_t const>>;
                  }) {
        return sequence.bytes();
    } else {
        return (sequence);
    }
}

/**
 Views what `held_bytes` returned: the address and size of its bytes.

 @param held The held result, which must outlive the view.
 @return Its bytes' address and size; nothing is read.
*/
template <class Held>
[[nodiscard]] constexpr auto view_bytes(Held const& held) noexcept {
    if constexpr (std::convertible_to<Held const&, std::span<std::uint8_t const>>) {
        std::span<std::uint8_t const> const bytes = held;
        return byte_view<std::uint8_t>{.first = bytes.data(), .count = bytes.size()};
    } else {
        using element = std::remove_cv_t<std::ranges::range_value_t<Held const&>>;
        return byte_view<element>{
            .first = std::ranges::data(held),
            .count = std::ranges::size(held),
        };
    }
}

}  // namespace detail

/**
 * Whether two byte sequences are equal, in a time that does not depend on their contents.
 *
 * Every byte is read, and no branch or index depends on one: the XOR of each pair is
 * accumulated with OR in a volatile local, read once after the loop, and reduced to one bit
 * without a branch, as BearSSL's tag check does. Sizes are public: sequences of different sizes
 * compare unequal without reading their contents. On 64-bit ARM the comparison runs with DIT
 * set where the CPU has it, and leaves the thread's DIT as it found it.
 *
 * @tparam First The first operand's type.
 * @tparam Second The second operand's type.
 * @param first_operand The first sequence, a tag or a MAC: a contiguous sized range of bytes
 *   (`std::span`, `std::array`, `std::vector`, `std::string_view`, a hash library's digest), or a
 *   type whose `bytes()` gives the bytes, as `secret<N>`.
 * @param second_operand The second.
 * @return Whether they have the same size and the same bytes.
 */
template <class First, class Second>
    requires detail::byte_sequence<First> && detail::byte_sequence<Second>
[[nodiscard]] bool constant_time_equal(First const& first_operand,
                                       Second const& second_operand) noexcept {
    timing_guard const timing_scope;
    auto&& first_held = detail::held_bytes(first_operand);
    auto&& second_held = detail::held_bytes(second_operand);
    auto const first = detail::view_bytes(first_held);
    auto const second = detail::view_bytes(second_held);
    if (first.count != second.count) {
        return false;
    }
    unsigned volatile accumulated_difference = 0;
    for (std::size_t byte_index = 0; byte_index < first.count; ++byte_index) {
        auto const first_byte = static_cast<std::uint8_t>(first.first[byte_index]);
        auto const second_byte = static_cast<std::uint8_t>(second.first[byte_index]);
        accumulated_difference =
            accumulated_difference | static_cast<unsigned>(first_byte ^ second_byte);
    }
    unsigned const total_difference = accumulated_difference;
    // total_difference is at most 255: minus 1 wraps to the type's maximum only when it is 0.
    return (((total_difference - 1U) >> 8U) & 1U) != 0;
}

}  // namespace webcpp::secure

#endif  // WEBCPP_SECURE_CONSTANT_TIME_EQUAL_HPP
