// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// timing_guard around a computation on a secret: where the CPU has DIT the guard sets it for the
// scope and clears it after; guards nest, and a disengaged guard does nothing. The output is the
// same on every target: on one the guard does not cover, every line holds because nothing is set.

// tag::example[]
#include <webcpp/secure/timing_guard.hpp>

#include <iostream>

namespace secure = webcpp::secure;

int main() {
    bool const before = secure::dit_is_set();
    bool inside = false;
    bool nested_inside = false;
    bool nested_after_inner = false;
    bool disengaged_inside = false;
    {
        // The first statement of a function that computes on a secret.
        secure::timing_guard const guard;
        inside = secure::dit_is_set();
        {
            // A guard that finds DIT set leaves it set, and at its end sets it again if
            // something inside its scope cleared it.
            secure::timing_guard const inner;
            nested_inside = secure::dit_is_set();
        }
        nested_after_inner = secure::dit_is_set();
    }
    bool const after = secure::dit_is_set();
    {
        // A call keyed only by its arguments, made without a key, computes on public data.
        secure::timing_guard const unkeyed{false};
        disengaged_inside = secure::dit_is_set();
    }

    // Where the CPU has DIT the guard set it; where it does not, nothing was set.
    std::cout << "set inside the guard: "
              << (inside == secure::cpu_has_dit() ? "as the CPU allows" : "WRONG") << '\n';
    std::cout << "set inside a nested guard: " << (nested_inside == inside ? "same" : "WRONG")
              << '\n';
    std::cout << "still set after the inner guard: "
              << (nested_after_inner == inside ? "yes" : "WRONG") << '\n';
    std::cout << "restored after the outer guard: " << (after == before ? "yes" : "WRONG") << '\n';
    std::cout << "disengaged guard sets nothing: " << (!disengaged_inside ? "yes" : "WRONG")
              << '\n';
    if (inside != secure::cpu_has_dit() || nested_inside != inside ||
        nested_after_inner != inside || after != before || disengaged_inside) {
        return 1;
    }
}

// end::example[]
