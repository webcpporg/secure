// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The planted leak under dudect: a comparison of 4096 bytes that exits at the first byte that
// differs, class 0 differing at byte 0, class 1 equal, so that class 1 reads every byte. The
// program passes only when dudect finds the leak, judged everywhere, on hosted runners too: it
// shows that the measurement, on the machine it ran on, finds a leak the lane's cases must not
// have.

#include "dudect.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>

namespace {

namespace test = webcpp::secure::test;

constexpr std::size_t count = 200'000;

/**
 * The planted leak: whether two byte arrays are equal, returning at the first byte that differs.
 * Each byte is read through a volatile, so that the compiler keeps one read per byte compared.
 */
template <std::size_t Size>
bool early_exit_equal(std::array<std::uint8_t, Size> const& first,
                      std::array<std::uint8_t, Size> const& second) {
    for (std::size_t index = 0; index < Size; ++index) {
        if (static_cast<std::uint8_t const volatile&>(first[index]) !=
            static_cast<std::uint8_t const volatile&>(second[index])) {
            return false;
        }
    }
    return true;
}

}  // namespace

// NOLINTNEXTLINE(misc-const-correctness): main's arguments have the type the standard gives them
int main(int argc, char** argv) {
    auto const selection = test::select_case(argc, argv, {"early_exit_equal"});
    if (!selection) {
        return 2;
    }
    if (!test::report_data_independent_timing()) {
        return 1;
    }
    test::report_machine();
    std::array<std::uint8_t, 4096> const reference{};
    std::array<std::uint8_t, 4096> differing{};
    differing[0] = 1;
    std::array<std::uint8_t, 4096> compared{};
    bool volatile sink = false;  // keeps the comparison from being optimised away
    // Class 0 compares an input that differs at byte 0; class 1 the reference itself.
    auto const planted = test::measure(
        20261011, count,
        [&](int which, auto&) {
            std::uint8_t volatile const chosen = which == 0 ? 0xFFU : 0x00U;
            unsigned const keep = chosen;
            unsigned const drop = keep ^ 0xFFU;
            for (std::size_t index = 0; index < compared.size(); ++index) {
                compared[index] = static_cast<std::uint8_t>((unsigned{differing[index]} & keep) |
                                                            (unsigned{reference[index]} & drop));
            }
        },
        [&] { sink = early_exit_equal(reference, compared); });
    static_cast<void>(sink);
    test::report_case("early_exit_equal", planted, true,
                      {{"reference", reference.data()}, {"compared", compared.data()}});
    std::printf("|t| early-exit comparison %.2f (threshold 10)\n", test::printed(planted.t));
    bool const found = test::printed(planted.t) >= 10;
    std::printf("planted leak %s\n", found ? "found" : "not found");
    return found ? 0 : 1;
}
