// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// erase_secret zeroes a buffer the program owns, whatever the buffer: a password in a std::string,
// a key in a std::vector, a C library's context as a range of one. Built with the wipe's test seam,
// so that the program counts what was wiped and main checks it. The check is main's, not a static
// object's destructor: Emscripten (EXIT_RUNTIME=0, its default) destroys no static object when main
// returns, and the check's result must be the program's status.

// tag::seam[]
// The test seam: WEBCPP_SECURE_TEST_WIPE_RECORD (the Jamfile defines it for every translation unit
// of the program) makes every wipe call this function once its bytes are zero. This program counts
// them.
#include <webcpp/secure/detail/wipe.hpp>

#include <cstddef>

namespace {

struct wipe_counts {
    std::size_t wipes = 0;
    std::size_t bytes = 0;
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

// The page's listing of the example leaves the check out (tags=example;!check): it stands alone,
// its <cstddef> too, and its main ends where the check begins.
// NOLINTBEGIN(readability-duplicate-include)
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
    // tag::check[]
    std::cout << "wipes seen: " << counts().wipes << ", bytes: " << counts().bytes << '\n';
    if (counts().wipes != 3 || counts().bytes != password_size + key.size() + sizeof(ctx)) {
        return 1;
    }
    // end::check[]
}

// end::example[]
// NOLINTEND(readability-duplicate-include)
