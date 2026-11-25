// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// <webcpp/secure.hpp>, included alone, brings every public header of the library: this program
// names one function or type of each of them and nothing else is included.

#include <webcpp/secure.hpp>

#include <array>
#include <cstddef>
#include <cstdint>

#ifndef WEBCPP_VERSION
#error "<webcpp/secure.hpp> must bring config.hpp, which defines WEBCPP_VERSION"
#endif

// config.hpp: WEBCPP_SECURE_NO_EXCEPTIONS is defined exactly where webcpp has no exceptions.
#if defined(WEBCPP_HAS_EXCEPTIONS) == defined(WEBCPP_SECURE_NO_EXCEPTIONS)
#error "config.hpp must define WEBCPP_SECURE_NO_EXCEPTIONS exactly when webcpp has no exceptions"
#endif

int main() {
    namespace secure = webcpp::secure;
    int failures = 0;

    // timing_guard.hpp
    {
        secure::timing_guard const guard;
        static_cast<void>(secure::cpu_has_dit());
        static_cast<void>(secure::dit_is_set());
    }

    // erase_secret.hpp, with detail/wipe.hpp
    std::array<std::uint8_t, 4> buffer{1, 2, 3, 4};
    secure::erase_secret(buffer);
    failures += buffer[0] != 0 ? 1 : 0;

    // constant_time_equal.hpp
    std::array<std::uint8_t, 4> const zeros{};
    failures += secure::constant_time_equal(buffer, zeros) ? 0 : 1;

    // secret.hpp
    secure::secret<4> const held;
    failures += secure::secret<4>::size() == 4 ? 0 : 1;

    // constant_time.hpp
    failures += secure::constant_time::is_zero_mask<std::uint8_t>(0) == 0xff ? 0 : 1;

    // declassify.hpp
    std::uint8_t verdict = 1;
    secure::declassify(verdict);
    failures += verdict == 1 ? 0 : 1;

    static_cast<void>(held);
    return failures;
}
