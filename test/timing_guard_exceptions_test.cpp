// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A guard leaves the thread's DIT as it found it also when something inside its scope changed DIT
// and when an exception ends its scope. Windows on ARM64 clears DIT whenever it resumes a thread
// after a catch or in an __except block (the guard's page, "Exceptions"), so that code that catches
// an exception inside a guard's scope goes on with DIT clear: a guard that found DIT set sets it
// again at its end.
// - Without exceptions too: inside guards nested three deep, engaged in every order, from DIT clear
//   and from set, the innermost scope clears DIT, as a catch there does on Windows; each engaged
//   guard's end leaves DIT as that guard found it, and a disengaged one's changes nothing.
// - With exceptions: an exception thrown and caught inside an engaged guard's scope, from clear and
//   from set; DIT after the guard is as before it. An exception thrown through guards nested three
//   deep, in every order of engaged and disengaged, from clear and from set: a recorder outside
//   each guard, destroyed during the unwinding just after it, sees DIT as that guard found it; at
//   the throw DIT is set where any guard is engaged (on a CPU with DIT). After the catch, outside
//   every guard, DIT is what the same throw and catch leave with no guard at all: as before it,
//   except on Windows on ARM64, where it is clear, which the test also checks, as the page says.

#include <webcpp/secure/timing_guard.hpp>
#include <webcpp/test/exit_status.hpp>
#include "support/timing_dit.hpp"

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstddef>

namespace {

using webcpp::secure::cpu_has_dit;
using webcpp::secure::dit_is_set;
using webcpp::secure::timing_guard;
using webcpp::secure::test::force_dit;

/** The depth of the nested guards. */
constexpr std::size_t depth = 3;

/** Whether the guard at `level` (0 the outermost) is engaged, by `pattern`'s bit `level`. */
bool engaged_at(unsigned pattern, std::size_t level) {
    return ((pattern >> level) & 1U) != 0;
}

/**
 * DIT as it must be inside the guards down to `level` (all of them when `level` is `depth`), from
 * `before`: set when it was set before or when one of them is engaged, on a CPU with DIT.
 */
bool expected_inside(unsigned pattern, std::size_t level, bool before) {
    bool any_engaged = false;
    for (std::size_t outer = 0; outer < level; ++outer) {
        any_engaged = any_engaged || engaged_at(pattern, outer);
    }
    return before || (cpu_has_dit() && any_engaged);
}

/** Guards from `Level` down, engaged as `pattern` says; the innermost scope clears DIT. */
template <std::size_t Level>
void nest_and_clear(unsigned pattern, bool before) {
    if constexpr (Level == depth) {
        static_cast<void>(pattern);
        static_cast<void>(before);
        force_dit(false);
    } else {
        bool const engaged = engaged_at(pattern, Level);
        bool at_end = false;
        {
            timing_guard const guard{engaged};
            BOOST_TEST_EQ(dit_is_set(), expected_inside(pattern, Level + 1, before));
            nest_and_clear<Level + 1>(pattern, before);
            at_end = dit_is_set();
        }
        // An engaged guard's end leaves DIT as the guard found it, as inside the guards above it;
        // a disengaged one's changes nothing.
        bool const after_guard = engaged ? expected_inside(pattern, Level, before) : at_end;
        BOOST_TEST_EQ(dit_is_set(), after_guard);
    }
}

// Without exceptions: DIT cleared inside nested guards, every order, from clear and from set.
void cleared_inside_nested_guards() {
    for (unsigned pattern = 0; pattern < (1U << depth); ++pattern) {
        for (bool const initially_set : {false, true}) {
            force_dit(initially_set);
            bool const before = dit_is_set();
            nest_and_clear<0>(pattern, before);
            // One engaged guard restores what the innermost scope cleared; disengaged ones do not.
            BOOST_TEST_EQ(dit_is_set(), pattern != 0 && before);
        }
    }
    force_dit(false);
}

#ifndef WEBCPP_SECURE_NO_EXCEPTIONS
/** The exception the tests throw. */
struct thrown {};

/** Throws `thrown`. */
void throw_now() {
    throw thrown{};
}

/** Records the thread's DIT when it is destroyed: during the unwinding, after the guards inside. */
class recorder {
public:
    explicit recorder(bool& seen) noexcept : seen_(&seen) {}

    recorder(recorder const&) = delete;
    recorder& operator=(recorder const&) = delete;
    recorder(recorder&&) = delete;
    recorder& operator=(recorder&&) = delete;

    ~recorder() { *seen_ = dit_is_set(); }

private:
    bool* seen_;
};

/**
 * What the thread's DIT is after a throw and a catch that cross no guard, from `initially_set`:
 * as before them, except on Windows on ARM64, which clears it on resuming after the catch.
 */
bool after_unguarded_catch(bool initially_set) {
    force_dit(initially_set);
    bool caught = false;
    try {
        throw_now();
    } catch (thrown const&) {
        caught = true;
    }
    BOOST_TEST(caught);
    return dit_is_set();
}

// The system's own effect, which the guard does not change: as before, except on Windows on ARM64.
void the_system_without_a_guard() {
    for (bool const initially_set : {false, true}) {
        bool const before = initially_set && cpu_has_dit();
#if defined(_MSC_VER) && defined(_M_ARM64) && !defined(_M_ARM64EC)
        static_cast<void>(before);
        BOOST_TEST(!after_unguarded_catch(initially_set));
#else
        BOOST_TEST_EQ(after_unguarded_catch(initially_set), before);
#endif
    }
    force_dit(false);
}

// An exception thrown and caught inside an engaged guard's scope: DIT as before after the guard.
void caught_inside_a_guard() {
    for (bool const initially_set : {false, true}) {
        force_dit(initially_set);
        bool const before = dit_is_set();
        bool caught = false;
        {
            timing_guard const guard;
            BOOST_TEST_EQ(dit_is_set(), cpu_has_dit());
            try {
                throw_now();
            } catch (thrown const&) {
                caught = true;
            }
        }
        BOOST_TEST(caught);
        BOOST_TEST_EQ(dit_is_set(), before);
    }
    force_dit(false);
}

/**
 * Guards from `Level` down, engaged as `pattern` says, each with a recorder outside it into
 * `seen[Level]`; at the bottom, records DIT into `at_throw` and throws.
 */
template <std::size_t Level>
void nest_and_throw(unsigned pattern, std::array<bool, depth>& seen, bool& at_throw) {
    if constexpr (Level == depth) {
        static_cast<void>(pattern);
        static_cast<void>(seen);
        at_throw = dit_is_set();
        throw_now();
    } else {
        recorder const after_this_guard{seen[Level]};
        timing_guard const guard{engaged_at(pattern, Level)};
        nest_and_throw<Level + 1>(pattern, seen, at_throw);
    }
}

// An exception through guards nested three deep, every order, from clear and from set.
void thrown_through_nested_guards() {
    for (unsigned pattern = 0; pattern < (1U << depth); ++pattern) {
        for (bool const initially_set : {false, true}) {
            bool const unguarded = after_unguarded_catch(initially_set);
            force_dit(initially_set);
            bool const before = dit_is_set();
            std::array<bool, depth> seen{};
            bool at_throw = false;
            bool caught = false;
            try {
                nest_and_throw<0>(pattern, seen, at_throw);
            } catch (thrown const&) {
                caught = true;
            }
            BOOST_TEST(caught);
            BOOST_TEST_EQ(at_throw, expected_inside(pattern, depth, before));
            for (std::size_t level = 0; level < depth; ++level) {
                // The recorder outside guard `level` sees DIT as that guard found it.
                BOOST_TEST_EQ(seen[level], expected_inside(pattern, level, before));
            }
            BOOST_TEST_EQ(dit_is_set(), unguarded);
        }
    }
    force_dit(false);
}
#endif

}  // namespace

int main() {
    force_dit(false);
    cleared_inside_nested_guards();
#ifndef WEBCPP_SECURE_NO_EXCEPTIONS
    the_system_without_a_guard();
    caught_inside_a_guard();
    thrown_through_nested_guards();
#endif
    BOOST_TEST(!dit_is_set());
    return webcpp::test::exit_status(boost::report_errors());
}
