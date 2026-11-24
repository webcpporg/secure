// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// declassify and the checkers' marks (support/constant_time_marks.hpp) compile with the marks
// on: Valgrind's (WEBCPP_SECURE_CT_VALGRIND, the Jamfile's, against a stand-in header that reads
// its arguments, on every lane) or MemorySanitizer's (WEBCPP_SECURE_CT_MSAN, compiled under clang
// natively). The test defines neither macro itself. Outside those builds declassify expands to
// nothing, so a mark that names a local no longer there compiles everywhere else; here it stops
// the build.

#include <webcpp/secure.hpp>
#include <webcpp/secure/config.hpp>
#include <webcpp/secure/constant_time_equal.hpp>
#include <webcpp/secure/declassify.hpp>
#include <webcpp/secure/detail/wipe.hpp>
#include <webcpp/secure/erase_secret.hpp>
#include <webcpp/secure/secret.hpp>
#include <webcpp/secure/timing_guard.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/constant_time_marks.hpp"

#include <array>
#include <cstdint>
#include <string>

#if !defined(WEBCPP_SECURE_CT_VALGRIND) && !defined(WEBCPP_SECURE_CT_MSAN)
#error \
    "the test compiles the marks of a checker's build: define WEBCPP_SECURE_CT_VALGRIND or WEBCPP_SECURE_CT_MSAN"
#endif

namespace {

namespace secure = webcpp::secure;
namespace marks = webcpp::secure::test;

#ifdef WEBCPP_SECURE_CT_VALGRIND
using checker = marks::memcheck;
#else
using checker = marks::memory_sanitizer;
#endif

template <class T>
concept declassifiable = requires(T& value) { secure::declassify(value); };

static_assert(declassifiable<bool>);
static_assert(declassifiable<std::uint32_t>);
static_assert(declassifiable<std::array<std::uint8_t, 4>>);
static_assert(!declassifiable<bool const>);
static_assert(!declassifiable<std::string>);

/** Marks bytes with the checker's primitives and reads its shadow, so that all are compiled. */
bool uses_marks() {
    std::array<std::uint8_t, 4> bytes{};
    checker::mark_secret(bytes);
    checker::mark_public(bytes);
    bool const verdict = true;
    checker::verdict(verdict);
    return marks::carries_mark<checker>(bytes) && verdict;
}

}  // namespace

int main() {
    bool verdict =
        secure::constant_time_equal(std::array<std::uint8_t, 4>{}, std::array<std::uint8_t, 4>{});
    secure::declassify(verdict);
    std::uint32_t word = 7;
    secure::declassify(word);
    std::array<std::uint8_t, 4> bytes{1, 2, 3, 4};
    secure::declassify(bytes);
    int failed = 0;
    if (!verdict) {
        ++failed;
    }
    if (word != 7) {
        ++failed;
    }
    if (bytes[3] != 4) {
        ++failed;
    }
#ifdef WEBCPP_SECURE_CT_VALGRIND
    // The stand-in's shadow is not readable: no byte carries the mark.
    if (uses_marks()) {
        ++failed;
    }
#else
    // MemorySanitizer's marks need an instrumented program: compiled, not run.
    static_cast<void>(&uses_marks);
#endif
    return webcpp::test::exit_status(failed);
}
