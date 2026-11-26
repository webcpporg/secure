// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// <webcpp/secure/config.hpp> defines WEBCPP_SECURE_NO_EXCEPTIONS exactly when
// webcpp has no exceptions, and keeps the developer's own definition in a build
// that has them. test/Jamfile builds this file as the build asks; without
// exceptions; with WEBCPP_NO_EXCEPTIONS defined as a developer defines it for
// every webcpp library, which WEBCPP_TEST_SECURE_ALL_OFF tells this file; and
// with the macro itself defined on the command line, which
// WEBCPP_TEST_SECURE_DEVELOPER_DEFINED tells this file.

#include <webcpp/secure/config.hpp>

// webcpp's configuration, which config.hpp includes, has said whether webcpp
// has exceptions and which target the program is for.
#ifndef WEBCPP_CONFIG_HPP
#error "config.hpp does not include <webcpp/config.hpp>"
#endif

#ifndef WEBCPP_VERSION
#error "webcpp's configuration does not define WEBCPP_VERSION"
#endif

#ifdef WEBCPP_TEST_SECURE_ALL_OFF
#ifndef WEBCPP_SECURE_NO_EXCEPTIONS
#error "WEBCPP_NO_EXCEPTIONS does not define WEBCPP_SECURE_NO_EXCEPTIONS"
#endif
#elif defined(WEBCPP_TEST_SECURE_DEVELOPER_DEFINED)
#ifndef WEBCPP_SECURE_NO_EXCEPTIONS
#error "config.hpp drops WEBCPP_SECURE_NO_EXCEPTIONS, which the developer defined"
#endif
#elif defined(WEBCPP_HAS_EXCEPTIONS) == defined(WEBCPP_SECURE_NO_EXCEPTIONS)
#error "WEBCPP_SECURE_NO_EXCEPTIONS is not defined exactly when webcpp has no exceptions"
#endif

int main() {
    return 0;
}
