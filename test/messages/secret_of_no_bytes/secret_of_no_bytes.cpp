// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program that names a secret of no bytes stops where it names it.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/secure/secret.hpp:* {{webcpp::secure: a secret of no bytes holds nothing.}}
// clang-format on

#include <webcpp/secure/secret.hpp>

int main() {
    return static_cast<int>(webcpp::secure::secret<0>::size_bytes);
}
