// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The test support's recorder, "support/timing_seam.hpp": a guard declared in this test is counted
// by timing_all_entries and not by timing_entries (this file is not under include/webcpp/secure/),
// timing_first_entry keeps the first guard's function and timing_last_entry the last's, and
// path_in_library tells secure's headers from every other path, in the spellings of clang, GCC and
// MSVC and on near misses.

#include "support/timing_seam.hpp"

#include <webcpp/secure/timing_guard.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <cstddef>
#include <string_view>

namespace {

using webcpp::secure::timing_guard;
using webcpp::secure::test::path_in_library;
using webcpp::secure::test::timing_all_entries;
using webcpp::secure::test::timing_entries;
using webcpp::secure::test::timing_first_entry;
using webcpp::secure::test::timing_last_entry;

/** Holds a guard, as a guarded function of secure does. */
void first_guarded_function() {
    timing_guard const guard;
}

/** Holds another guard. */
void second_guarded_function() {
    timing_guard const guard;
}

/** Holds a disengaged guard, which the recorder never sees. */
void disengaged_function() {
    timing_guard const guard{false};
}

void library_is_secure() {
    BOOST_TEST(webcpp::secure::test::timing_library == "secure");
}

// A guard declared here raises timing_all_entries by one and timing_entries by none.
void counts_every_guard_and_secures_own() {
    std::size_t const all_before = timing_all_entries;
    std::size_t const own_before = timing_entries;
    first_guarded_function();
    BOOST_TEST_EQ(timing_all_entries, all_before + 1);
    BOOST_TEST_EQ(timing_entries, own_before);
    disengaged_function();
    BOOST_TEST_EQ(timing_all_entries, all_before + 1);
}

// The first entry since a reset is kept, the last is the latest.
void names_first_and_last_function() {
    timing_first_entry = nullptr;
    timing_last_entry = nullptr;
    first_guarded_function();
    second_guarded_function();
    BOOST_TEST(timing_first_entry != nullptr);
    BOOST_TEST(timing_last_entry != nullptr);
    if (timing_first_entry != nullptr && timing_last_entry != nullptr) {
        BOOST_TEST(std::string_view{timing_first_entry}.find("first_guarded_function") !=
                   std::string_view::npos);
        BOOST_TEST(std::string_view{timing_last_entry}.find("second_guarded_function") !=
                   std::string_view::npos);
    }
}

// The paths of secure's headers, in each compiler's spelling, and the near misses.
void path_in_library_spellings() {
    constexpr std::string_view library = "secure";
    BOOST_TEST(path_in_library("/w/libs/secure/include/webcpp/secure/timing_guard.hpp", library));
    BOOST_TEST(path_in_library("../include/webcpp/secure/x.hpp", library));
    BOOST_TEST(path_in_library("include/webcpp/secure/x.hpp", library));
    BOOST_TEST(path_in_library(R"(C:\t\a\libs\secure\include\webcpp\secure\x.hpp)", library));
    BOOST_TEST(path_in_library(R"(C:\t\a\include\webcpp/secure\detail\wipe.hpp)", library));
    BOOST_TEST(!path_in_library("/w/libs/secure/test/x_test.cpp", library));
    BOOST_TEST(!path_in_library("/w/include/webcpp/securex/x.hpp", library));
    BOOST_TEST(!path_in_library("/w/myinclude/webcpp/secure/x.hpp", library));
    BOOST_TEST(!path_in_library("/w/include/webcpp/crypto/x.hpp", library));
    BOOST_TEST(!path_in_library("/w/include/webcpp/secure", library));
}

}  // namespace

int main() {
    library_is_secure();
    counts_every_guard_and_secures_own();
    names_first_and_last_function();
    path_in_library_spellings();
    return webcpp::test::exit_status(boost::report_errors());
}
