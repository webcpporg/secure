// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// erase_secret zeroes a buffer the program owns, whatever the buffer: a password in a std::string,
// a key in a std::vector, a C library's context as a range of one. Built with the wipe's test seam,
// so that the program can count what was wiped.

// tag::example[]
#include <webcpp/secure/erase_secret.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <string>
#include <vector>

namespace secure = webcpp::secure;

namespace {

// A C library's plain state, as BearSSL's contexts are.
struct context {
    std::array<std::uint8_t, 16> state;
    std::uint32_t counter;
};

}  // namespace

int main() {
    std::string password = "correct horse battery staple";
    std::size_t const password_size = password.size();
    secure::erase_secret(password);  // size() bytes, not capacity()
    std::cout << "password: " << password_size << " bytes zeroed, size kept "
              << (password.size() == password_size ? "yes" : "NO") << '\n';

    std::vector<std::uint8_t> key(32, 0xA5);
    secure::erase_secret(key);
    std::cout << "key all zero: "
              << (std::ranges::all_of(key, [](auto b) { return b == 0; }) ? "yes" : "NO") << '\n';

    // An object is erased as a span of one: there is no second function for it.
    context ctx{.state = {1, 2, 3}, .counter = 7};
    secure::erase_secret(std::span(&ctx, 1));
    std::cout << "context counter: " << ctx.counter << '\n';
}

// end::example[]

// tag::seam[]
// The test seam: WEBCPP_SECURE_TEST_WIPE_RECORD (the Jamfile defines it for every translation unit
// of the program) makes every wipe call this function once its bytes are zero. This program counts
// them, and reports and checks the count as it exits.
#include <webcpp/secure/detail/wipe.hpp>

#include <cstddef>
#include <cstdlib>
#include <iostream>

namespace {

struct wipe_counts {
    std::size_t wipes = 0;
    std::size_t bytes = 0;

    ~wipe_counts() {
        std::cout << "wipes seen: " << wipes << ", bytes: " << bytes << '\n';
        if (wipes != 3) {
            std::cout.flush();
            std::_Exit(1);
        }
    }
};

wipe_counts& counts() {
    static wipe_counts instance;
    return instance;
}

}  // namespace

void webcpp::secure::test::wipe_record(void const* /*wiped_data*/,
                                       std::size_t byte_count) noexcept {
    ++counts().wipes;
    counts().bytes += byte_count;
}

// end::seam[]
