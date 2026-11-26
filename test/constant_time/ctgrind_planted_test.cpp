// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// ctgrind_test.cpp with a planted leak, a source of its own so that b2 compiles it with its own
// defines: the builds the lane expects memcheck to fail, each in its planted function (paths.hpp),
// run before every path. With WEBCPP_TEST_SECURE_PLANTED_SELECT, a select that branches on its
// secret mask; with WEBCPP_TEST_SECURE_PLANTED_LOOKUP, a lookup that indexes its table by the
// secret index; with WEBCPP_TEST_SECURE_PLANTED_VERDICT, a branch on constant_time_equal's verdict
// that was never declassified.
#include "ctgrind_test.cpp"  // NOLINT(bugprone-suspicious-include)
