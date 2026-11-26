// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// No local name in a secure header hides a program's global. MSVC warns, C4459, at a parameter or a
// local that has the name of a global of the program ("declaration of 'first' hides global
// declaration"), and, in a function template that is instantiated, at its locals (measured on 14.3
// and 14.5, which say nothing of a template's parameters): an error at /W4 /WX. Clang and GCC never
// warn across namespaces, so the test is MSVC's, and on the other native compilers it only
// compiles. A local takes two words, the role then the kind (`first_bytes`, `byte_index`), which no
// program names a global.
//
// Every header of another library that a secure header includes comes first, so that their own
// names are parsed before the globals exist; then a global of every one-word name a secure header
// gave a local or a parameter until each took two words; then every public header. Every function
// is called, which instantiates every template.
//
// How the list was made: the AST of <webcpp/secure.hpp> (clang -Xclang -ast-dump=json), each
// ParmVarDecl and VarDecl inside a function of include/ whose name matches ^[a-z][a-z0-9]*$; again
// with the two test seams; and timing_guard.hpp's code of Windows on ARM64, read. A name that the
// platform's C library already declares as a global (`index`, <strings.h>'s) cannot be a program's
// global there anyway: it is declared on MSVC alone.

#include <webcpp/config.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/assert.hpp>
#include <boost/core/lightweight_test.hpp>

#include <array>
#include <atomic>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <ranges>
#include <source_location>
#include <span>
#include <type_traits>
#include <utility>

#ifdef _MSC_VER
#include <excpt.h>
#include <intrin.h>
#elif defined(__APPLE__)
#include <sys/sysctl.h>
#elif defined(__linux__)
#include <sys/auxv.h>
#endif

// NOLINTBEGIN(readability-redundant-declaration)
extern int const accumulated, bit, borrow, byte, bytes, destination, difference, engaged, first,
    held, high, keep, low, mask, position, result, second, sequence, shift, state, table, value,
    where, wrapped;
#ifdef _MSC_VER
extern int const index;
#endif
// NOLINTEND(readability-redundant-declaration)

#ifdef WEBCPP_TEST_SECURE_USER_GLOBALS_SEAM
// timing_guard's test seam, whose parameter only this compiles.
#define WEBCPP_SECURE_TIMING_ENTERED(entered_location) static_cast<void>(entered_location)
#endif

#include <webcpp/secure.hpp>

int main() {
    namespace secure = webcpp::secure;
    namespace ct = webcpp::secure::constant_time;
    secure::timing_guard const guard_scope;
    BOOST_TEST(!secure::dit_is_set() || secure::cpu_has_dit());

    std::array<std::uint8_t, 4> const some_bytes{1, 2, 3, 4};
    std::array<std::uint8_t, 4> const other_bytes{1, 2, 3, 5};
    std::array<std::uint8_t, 4> selected_bytes{};
    std::span<std::uint8_t const> const some_span = some_bytes;
    ct::select_bytes(0xff, selected_bytes, some_bytes, other_bytes);
    BOOST_TEST(selected_bytes == some_bytes);
    BOOST_TEST_EQ(ct::equal_mask(some_bytes, other_bytes), 0U);
    BOOST_TEST_EQ(ct::less_mask(some_bytes, other_bytes), 0xffU);
    BOOST_TEST_EQ(ct::is_zero_mask(some_span), 0U);
    BOOST_TEST_EQ(ct::is_zero_mask<std::uint32_t>(0), 0xffffffffU);
    BOOST_TEST_EQ(ct::is_equal_mask<std::uint32_t>(1, 2), 0U);
    BOOST_TEST_EQ(ct::is_less_mask<std::uint32_t>(1, 2), 0xffffffffU);
    BOOST_TEST_EQ(ct::is_in_range_mask<std::uint32_t>(2, 1, 3), 0xffffffffU);
    BOOST_TEST_EQ(ct::select<std::uint32_t>(0, 1, 2), 2U);
    BOOST_TEST_EQ(ct::lookup(some_span, 2), 3U);

    secure::secret<4> held_secret;
    BOOST_TEST(!secure::constant_time_equal(some_bytes, other_bytes));
    BOOST_TEST(!secure::constant_time_equal(held_secret, some_bytes));
    secure::secret<4> moved_secret(std::move(held_secret));
    held_secret = std::move(moved_secret);
    BOOST_TEST(secure::constant_time_equal(held_secret.clone(), held_secret));
    secure::erase_secret(selected_bytes);
    bool same_bytes = selected_bytes == some_bytes;
    secure::declassify(same_bytes);
    BOOST_TEST(!same_bytes);
    return webcpp::test::exit_status(boost::report_errors());
}
