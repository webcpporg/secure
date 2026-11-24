// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A stand-in for Valgrind's <valgrind/memcheck.h>, for declassify_compile_test.cpp alone: the
// client requests that secure's declassify and the constant-time marks header
// (support/constant_time_marks.hpp) name under WEBCPP_SECURE_CT_VALGRIND, each reading its
// arguments, so that every lane compiles the marks the constant-time lane alone runs.

#ifndef WEBCPP_TEST_SECURE_SUPPORT_VALGRIND_STUB_MEMCHECK_H
#define WEBCPP_TEST_SECURE_SUPPORT_VALGRIND_STUB_MEMCHECK_H

/** Reads the address and the size, as Valgrind's request does, and marks nothing. */
#define VALGRIND_MAKE_MEM_DEFINED(address, size) \
    (static_cast<void>(address), static_cast<void>(size), 0)

/** Reads the address and the size, as Valgrind's request does, and marks nothing. */
#define VALGRIND_MAKE_MEM_UNDEFINED(address, size) \
    (static_cast<void>(address), static_cast<void>(size), 0)

/** Reads its arguments and, as outside Valgrind, returns 0: the shadow is not readable. */
#define VALGRIND_GET_VBITS(address, vbits, size) \
    (static_cast<void>(address), static_cast<void>(vbits), static_cast<void>(size), 0)

/** Reads its argument and, as outside Valgrind, reports nothing. */
#define VALGRIND_CHECK_VALUE_IS_DEFINED(lvalue) (static_cast<void>(lvalue), 0)

#endif  // WEBCPP_TEST_SECURE_SUPPORT_VALGRIND_STUB_MEMCHECK_H
