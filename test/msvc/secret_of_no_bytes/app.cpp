// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program that names a secret of no bytes stops where it names it. On MSVC the compile fails;
// the text is checked on clang, in test/messages/secret_of_no_bytes.
#include <webcpp/secure/secret.hpp>

int main() {
    return static_cast<int>(webcpp::secure::secret<0>::size_bytes);
}
