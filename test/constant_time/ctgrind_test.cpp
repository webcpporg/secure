// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Under Valgrind's memcheck, the operands of every block, of constant_time_equal and of
// secret<32>'s moves are marked undefined (paths.hpp, shared with msan_test.cpp): a branch or a
// memory index that depends on them is an error, and the run fails (valgrind.mjs's
// --error-exitcode). memcheck follows a subtraction's carry, so each result is also checked to be
// undefined until it is declassified: the mark reaches it, so the path is traced. A planted
// program (ctgrind_planted_test.cpp) runs its planted leak first, which memcheck must report.

#include "paths.hpp"

#include <cstdio>

int main() {
    using checker = webcpp::secure::test::memcheck;
    webcpp::secure::test::run_planted<checker>();
    int const failures = webcpp::secure::test::common_paths<checker>();
    std::printf("constant time under memcheck: %s\n", failures == 0 ? "ok" : "FAILED");
    return failures == 0 ? 0 : 1;
}
