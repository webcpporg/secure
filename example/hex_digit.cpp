// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A 4-bit value to its hex character and back without a branch or a table index that depends on the
// value, by is_in_range_mask and select: libsodium's method for sodium_bin2hex and sodium_hex2bin,
// the shape of every codec that turns a secret into text.

// tag::example[]
#include <webcpp/secure/constant_time.hpp>

#include <cstdint>
#include <iostream>
#include <string>

namespace ct = webcpp::secure::constant_time;

namespace {

// 0 to 15 to '0'..'9', 'a'..'f'.
constexpr std::uint8_t hex_character(std::uint8_t nibble) {
    auto const is_digit = ct::is_in_range_mask<std::uint8_t>(nibble, 0, 9);
    auto const digit = static_cast<std::uint8_t>('0' + nibble);
    auto const letter = static_cast<std::uint8_t>('a' - 10 + nibble);
    return ct::select(is_digit, digit, letter);
}

// The value of a hex character, and in valid whether it was one: 0xff for a hex digit, else 0.
struct decoded {
    std::uint8_t value;
    std::uint8_t valid;
};

constexpr decoded hex_value(std::uint8_t character) {
    auto const is_digit = ct::is_in_range_mask<std::uint8_t>(character, '0', '9');
    auto const is_lower = ct::is_in_range_mask<std::uint8_t>(character, 'a', 'f');
    auto const is_upper = ct::is_in_range_mask<std::uint8_t>(character, 'A', 'F');
    auto const from_digit = static_cast<std::uint8_t>(character - '0');
    auto const from_lower = static_cast<std::uint8_t>(character - 'a' + 10);
    auto const from_upper = static_cast<std::uint8_t>(character - 'A' + 10);
    auto value = ct::select<std::uint8_t>(is_upper, from_upper, 0);
    value = ct::select(is_lower, from_lower, value);
    value = ct::select(is_digit, from_digit, value);
    auto valid = ct::select<std::uint8_t>(is_upper, 0xff, 0);
    valid = ct::select(is_lower, std::uint8_t{0xff}, valid);
    valid = ct::select(is_digit, std::uint8_t{0xff}, valid);
    return {.value = value, .valid = valid};
}

}  // namespace

int main() {
    std::string text;
    for (std::uint8_t nibble = 0; nibble < 16; ++nibble) {
        text += static_cast<char>(hex_character(nibble));
    }
    std::cout << "encoded: " << text << '\n';

    bool round_trip = true;
    for (std::uint8_t nibble = 0; nibble < 16; ++nibble) {
        decoded const back = hex_value(hex_character(nibble));
        round_trip = round_trip && back.value == nibble && back.valid == 0xff;
    }
    std::cout << "round trip of all 16: " << (round_trip ? "yes" : "NO") << '\n';

    decoded const upper = hex_value('C');
    std::cout << "'C': value " << static_cast<unsigned>(upper.value) << ", valid "
              << (upper.valid == 0xff ? "yes" : "no") << '\n';
    decoded const bad = hex_value('g');
    std::cout << "'g': valid " << (bad.valid == 0xff ? "yes" : "no") << '\n';
    return round_trip && upper.value == 12 && bad.valid == 0 ? 0 : 1;
}

// end::example[]
