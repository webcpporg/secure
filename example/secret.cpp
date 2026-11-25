// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// secret<N>: bytes that wipe themselves. It cannot be copied by accident, a move leaves the source
// zero, a clone is asked for by name, and its bytes are viewed, never taken.

// tag::example[]
#include <webcpp/secure/constant_time_equal.hpp>
#include <webcpp/secure/secret.hpp>

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <span>
#include <utility>

namespace secure = webcpp::secure;

bool all_zero(std::span<std::uint8_t const> bytes) {
    return std::ranges::all_of(bytes, [](std::uint8_t byte) { return byte == 0; });
}

int main() {
    // A new secret holds zeros; the library that fills it writes through writable().
    secure::secret<32> key;
    std::ranges::fill(key.writable(), std::uint8_t{0x42});
    std::cout << "size: " << key.size() << " bytes\n";

    // A copy is asked for by name; two secrets of the same bytes compare in constant time.
    secure::secret<32> const copy = key.clone();
    std::cout << "clone equals the original: "
              << (secure::constant_time_equal(copy, key) ? "yes" : "no") << '\n';

    // A move takes the bytes and wipes the source.
    secure::secret<32> moved = std::move(key);
    std::cout << "moved-from secret is zero: " << (all_zero(key.bytes()) ? "yes" : "no") << '\n';
    std::cout << "the destination has the bytes: "
              << (secure::constant_time_equal(moved, copy) ? "yes" : "no") << '\n';

    // A secret is passed where a function takes the span of its bytes.
    std::span<std::uint8_t const, 32> const view = moved;
    std::cout << "first byte through the view: " << static_cast<unsigned>(view[0]) << '\n';
    // A view of a temporary would dangle, so secure::secret<32>{}.bytes() does not compile.
}

// end::example[]
