// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// dudect's statistics, natively: constant_time_equal's time against its second argument (class 0
// equal 64-byte inputs, class 1 a random second), lookup's against its index (0, against random
// indexes, over 64 entries), select_bytes's against its mask (0x00, against 0xFF) and less_mask's
// against its second argument (equal 32-byte inputs, against a random second). Each case is
// measured once more as its A/A control (<case>_aa), both classes the class 0 input, prepared by
// the same instructions. `--case <name>` measures one case alone.

#include "dudect.hpp"

#include <webcpp/secure/constant_time.hpp>
#include <webcpp/secure/constant_time_equal.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <span>
#include <string>

namespace {

namespace test = webcpp::secure::test;
namespace ct = webcpp::secure::constant_time;

constexpr std::size_t count = 2'000'000;

/**
 * Writes into `input` either `first`, for class 0, or `second`, for class 1, both classes reading
 * both sources and writing `input` with the same instructions, through a mask read from a volatile,
 * as `test::choose` blends; with `Control`, both classes write `first`, the A/A control. For a
 * case whose class 1 is a fixed value, not drawn bytes: select_bytes's mask.
 * @tparam Control Whether both classes write `first`.
 * @param which The class, 0 or 1.
 * @param first The class 0 input.
 * @param second The class 1 input.
 * @param input Where the input of the class is written.
 */
template <bool Control, std::size_t Size>
void pick(int which, std::array<std::uint8_t, Size> const& first,
          std::array<std::uint8_t, Size> const& second, std::array<std::uint8_t, Size>& input) {
    std::array<std::uint8_t, Size> other{};
    for (std::size_t index = 0; index < Size; ++index) {
        // Read through a volatile, so that the compiler cannot fold the control's blend of two
        // equal sources into a copy: the control blends as the case does.
        other[index] = Control ? static_cast<std::uint8_t const volatile&>(first[index])
                               : static_cast<std::uint8_t const volatile&>(second[index]);
    }
    std::uint8_t volatile const chosen = which == 0 ? 0xFFU : 0x00U;
    unsigned const keep = chosen;
    unsigned const drop = keep ^ 0xFFU;
    for (std::size_t index = 0; index < Size; ++index) {
        input[index] = static_cast<std::uint8_t>((unsigned{first[index]} & keep) |
                                                 (unsigned{other[index]} & drop));
    }
}

/**
 * Measures a case and its A/A control, each when selected, with `prepare.template
 * operator()<Control>(which, generator)` setting up the class's input.
 * @param results Where each case measured is recorded.
 * @param selection The cases to measure.
 * @param name The case's name; its control's is `<name>_aa`.
 * @param prepare Sets up the class's input, unmeasured, for the case or its control.
 * @param run The operation measured.
 * @param buffers The buffers it measures.
 */
template <class Prepare, class Run>
void measure_with_control(test::case_results& results, test::case_selection const& selection,
                          char const* name, Prepare&& prepare, Run&& run,
                          std::initializer_list<test::address> buffers) {
    std::string const control = std::string(name) + "_aa";
    std::string const control_label = std::string(name) + " A/A";
    if (selection.runs(name)) {
        auto const measured = test::twice(
            count,
            [&](int which, auto& generator) {
                prepare.template operator()<false>(which, generator);
            },
            run);
        results.record(name, name, measured, true, buffers);
    }
    if (selection.runs(control.c_str())) {
        auto const measured = test::twice(
            count,
            [&](int which, auto& generator) {
                prepare.template operator()<true>(which, generator);
            },
            run);
        results.record(control.c_str(), control_label.c_str(), measured, true, buffers);
    }
}

}  // namespace

// NOLINTNEXTLINE(misc-const-correctness): main's arguments have the type the standard gives them
int main(int argc, char** argv) {
    auto const selection = test::select_case(argc, argv,
                                             {
                                                 "constant_time_equal",
                                                 "constant_time_equal_aa",
                                                 "lookup",
                                                 "lookup_aa",
                                                 "select_bytes",
                                                 "select_bytes_aa",
                                                 "less_mask",
                                                 "less_mask_aa",
                                             });
    if (!selection) {
        return 2;
    }
    if (!test::report_data_independent_timing()) {
        return 1;
    }
    test::report_machine();
    test::case_results results;
    bool volatile sink = false;  // keeps a comparison from being optimised away
    std::uint8_t volatile byte_sink = 0;

    // constant_time_equal: equal 64-byte inputs, against a random second.
    std::array<std::uint8_t, 64> const equal_first{};
    std::array<std::uint8_t, 64> equal_second{};
    measure_with_control(
        results, *selection, "constant_time_equal",
        [&]<bool Control>(int which, auto& generator) {
            test::choose<Control>(which, generator, equal_first, equal_second);
        },
        [&] { sink = webcpp::secure::constant_time_equal(equal_first, equal_second); },
        {{"first", equal_first.data()}, {"second", equal_second.data()}});

    // lookup: index 0, against random indexes, over 64 entries.
    std::array<std::uint32_t, 64> table{};
    for (std::size_t position = 0; position < table.size(); ++position) {
        table[position] = static_cast<std::uint32_t>(position * 0x9E3779B9U);
    }
    std::array<std::uint8_t, 1> const index_zero{};
    std::array<std::uint8_t, 1> index_byte{};
    std::size_t index = 0;
    std::uint32_t volatile entry_sink = 0;
    measure_with_control(
        results, *selection, "lookup",
        [&]<bool Control>(int which, auto& generator) {
            test::choose<Control>(which, generator, index_zero, index_byte);
            index = index_byte[0] & 63U;
        },
        [&] { entry_sink = ct::lookup(std::span<std::uint32_t const, 64>(table), index); },
        {{"table", table.data()}, {"index", &index}});

    // select_bytes: the mask 0x00, against 0xFF.
    std::array<std::uint8_t, 1> const mask_clear{0x00};
    std::array<std::uint8_t, 1> const mask_set{0xFF};
    std::array<std::uint8_t, 1> mask{};
    std::array<std::uint8_t, 64> when_set{};
    std::array<std::uint8_t, 64> when_clear{};
    std::array<std::uint8_t, 64> destination{};
    when_set.fill(0x42);
    when_clear.fill(0x17);
    measure_with_control(
        results, *selection, "select_bytes",
        [&]<bool Control>(int which, auto&) { pick<Control>(which, mask_clear, mask_set, mask); },
        [&] {
            ct::select_bytes(mask[0], destination, when_set, when_clear);
            byte_sink = destination[0];
        },
        {{"mask", mask.data()}, {"destination", destination.data()}});

    // less_mask: equal 32-byte inputs, against a random second.
    std::array<std::uint8_t, 32> less_first{};
    less_first.fill(0x42);
    std::array<std::uint8_t, 32> less_second{};
    measure_with_control(
        results, *selection, "less_mask",
        [&]<bool Control>(int which, auto& generator) {
            test::choose<Control>(which, generator, less_first, less_second);
        },
        [&] { byte_sink = ct::less_mask(less_first, less_second); },
        {{"first", less_first.data()}, {"second", less_second.data()}});

    static_cast<void>(sink);
    static_cast<void>(byte_sink);
    static_cast<void>(entry_sink);
    results.print();
    return test::verdict(results.passes());
}
