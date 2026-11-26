// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A test's control of the thread's DIT: force_dit sets or clears it, as a program can, so that a
// check starts from a known state. A test that defines the seam of webcpp::secure::timing_guard
// ("support/timing_seam.hpp") includes it before this header, which includes the guard's.

#ifndef WEBCPP_TEST_SECURE_SUPPORT_TIMING_DIT_HPP
#define WEBCPP_TEST_SECURE_SUPPORT_TIMING_DIT_HPP

#include <webcpp/secure/timing_guard.hpp>

namespace webcpp::secure::test {

/**
 * Sets or clears DIT for this thread, as a program can; only where the CPU has DIT, since the
 * instruction traps on a CPU without it, and nothing where the guard does not act.
 *
 * @param set Whether to set DIT.
 */
inline void force_dit([[maybe_unused]] bool set) noexcept {
#ifdef WEBCPP_SECURE_TIMING_COVERED
    if (cpu_has_dit()) {
        detail::write_dit(set ? detail::dit_bit : 0);
    }
#endif
}

}  // namespace webcpp::secure::test

#endif  // WEBCPP_TEST_SECURE_SUPPORT_TIMING_DIT_HPP
