// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// constant_time_equal: whether two byte sequences are equal, in a time that does not depend on
// their contents. A MAC is checked the way a server checks a webhook's: the tag it computes against
// the tag it was sent, any sequence of bytes on either side.

// tag::example[]
#include <webcpp/secure/constant_time_equal.hpp>
#include <webcpp/secure/declassify.hpp>
#include <webcpp/secure/secret.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <numeric>
#include <span>
#include <string_view>
#include <vector>

namespace secure = webcpp::secure;

// tag::verdict[]
namespace {

// Whether a received tag is the one computed: the verdict is public, and the caller branches on it.
bool accept(std::span<std::uint8_t const> computed, std::span<std::uint8_t const> received) {
    bool verdict = secure::constant_time_equal(computed, received);
    // The one branch on a value derived from secrets that is the design: public for the checkers,
    // and nothing in a program's build.
    secure::declassify(verdict);
    return verdict;
}

}  // namespace

// end::verdict[]

int main() {
    std::array<std::uint8_t, 16> computed{};
    std::iota(computed.begin(), computed.end(), std::uint8_t{0x10});
    std::vector<std::uint8_t> received(computed.begin(), computed.end());

    // Different containers of bytes compare: an array, a vector, a span, a string_view, a
    // secret<N>.
    std::cout << "same tag: " << (accept(computed, received) ? "equal" : "different") << '\n';

    // The last byte differs: every byte is still read, and the answer is the same kind of time.
    received.back() ^= 1U;
    std::cout << "last byte flipped: "
              << (secure::constant_time_equal(computed, received) ? "equal" : "different") << '\n';

    // Sizes are public: different sizes are different, and no byte is read.
    std::cout << "a truncated tag: "
              << (secure::constant_time_equal(computed, std::span(received).first(15))
                      ? "equal"
                      : "different")
              << '\n';

    // Characters count as bytes, whatever their sign.
    std::string_view const text = "\xff\x80";
    std::array<std::uint8_t, 2> const bytes{0xff, 0x80};
    std::cout << "text and bytes: "
              << (secure::constant_time_equal(text, bytes) ? "equal" : "different") << '\n';

    // A secret is compared through its bytes.
    secure::secret<16> mac;
    std::ranges::copy(computed, mac.writable().begin());
    std::cout << "secret and array: "
              << (secure::constant_time_equal(mac, computed) ? "equal" : "different") << '\n';
}

// end::example[]
