// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// MemorySanitizer's poisoning: the operands of every block, of constant_time_equal and of
// secret<32>'s moves are poisoned (paths.hpp, shared with ctgrind_test.cpp), and a branch or an
// index that depends on them ends the run with a report. A planted program
// (msan_planted_test.cpp) runs its planted leak first, which MemorySanitizer must report.
//
// MemorySanitizer approximates a subtraction's shadow by its operands' without the carry, so the
// constant-time reduction to one bit of a value whose low bits are poisoned comes out initialised
// (crypto's msan_test.cpp, measured with clang 18): the blocks' results and constant_time_equal's
// verdict are not checked poisoned here, and ctgrind_test.cpp checks them traced. For the same
// reason MemorySanitizer reports no branch on constant_time_equal's verdict, declassified or not
// (measured with clang 18 on Linux arm64, 2026-11-25: a planted branch on the undeclassified
// verdict, run first, went unreported); memcheck's ctgrind_planted_verdict shows that branch
// reported. MemorySanitizer takes an asm statement's register input for a use, so under it
// value_barrier is a round trip through a volatile local (constant_time.hpp), which carries a
// mask's shadow to its result.

#include "paths.hpp"

#include <cstdio>

int main() {
    using checker = webcpp::secure::test::memory_sanitizer;
    webcpp::secure::test::run_planted<checker>();
    int const failures = webcpp::secure::test::common_paths<checker>();
    std::printf("constant time under MemorySanitizer: %s\n", failures == 0 ? "ok" : "FAILED");
    return failures == 0 ? 0 : 1;
}
