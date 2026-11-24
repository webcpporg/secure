// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// <webcpp/secure/timing_guard.hpp> compiles first and alone, brings <webcpp/secure/config.hpp> with
// it, and defines WEBCPP_SECURE_TIMING_COVERED exactly on the targets the guard covers:
// arm64 under an Apple system or Linux (Android included), and Windows on ARM64 with MSVC or
// clang-cl (not ARM64EC).

#include <webcpp/secure/timing_guard.hpp>

#ifndef WEBCPP_SECURE_TIMING_GUARD_HPP
#error "the timing guard's header does not define WEBCPP_SECURE_TIMING_GUARD_HPP"
#endif

#ifndef WEBCPP_VERSION
#error "<webcpp/secure/timing_guard.hpp> does not include <webcpp/secure/config.hpp>"
#endif

#if defined(__aarch64__) && (defined(__APPLE__) || defined(__linux__))
#ifndef WEBCPP_SECURE_TIMING_COVERED
#error "the guard does not act on arm64 under an Apple system or Linux"
#endif
#elif defined(_MSC_VER) && defined(_M_ARM64) && !defined(_M_ARM64EC)
#ifndef WEBCPP_SECURE_TIMING_COVERED
#error "the guard does not act on Windows on ARM64"
#endif
#elif defined(WEBCPP_SECURE_TIMING_COVERED)
#error "the guard acts on a target it does not cover"
#endif
