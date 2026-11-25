// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// dudect.hpp's statistics, its class-blind preparation, its argument parser and its lines, on
// synthetic data and without timing anything: the largest |t| with its cropping and the classes'
// counts and means there, the A/A control's preparation, `--case`, and the exact text of a case
// line, its evidence and its addresses, which the CI's judge reads.

#include "dudect.hpp"

#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <random>
#include <string>
#include <vector>

namespace test = webcpp::secure::test;

namespace {

/** The number of timings at or below the limit of a cropping. */
std::size_t kept(std::vector<double> const& timings, double limit) {
    std::size_t count = 0;
    for (double const timing : timings) {
        count += timing <= limit ? 1U : 0U;
    }
    return count;
}

/** Equal classes but for one outlier of class 1 at the largest timing. */
void largest_t_whole_set() {
    std::vector<double> timings(1000, 100.0);
    std::vector<int> classes(1000);
    for (std::size_t i = 0; i < classes.size(); ++i) {
        classes[i] = static_cast<int>(i % 2);
    }
    timings[999] = 10000.0;
    auto const result = test::largest_t(timings, classes);
    BOOST_TEST(result.crop >= -1 && result.crop <= 99);
    if (result.crop == -1) {
        BOOST_TEST_EQ(result.limit_ns, 10000.0);
    } else {
        BOOST_TEST_LT(result.limit_ns, 10000.0);
    }
    BOOST_TEST_EQ(result.classes[0].count + result.classes[1].count,
                  kept(timings, result.limit_ns));
    BOOST_TEST_LT(result.t, 10.0);

    // Class 1 one nanosecond slower, each class's variance about 1: |t| about 22.
    std::vector<double> shifted(2000);
    std::vector<int> shifted_classes(2000);
    for (std::size_t i = 0; i < shifted.size(); ++i) {
        int const which = static_cast<int>(i % 2);
        double const noise = (i / 2) % 2 == 0 ? -1.0 : 1.0;
        shifted[i] = 100.0 + which + noise;
        shifted_classes[i] = which;
    }
    auto const high = test::largest_t(shifted, shifted_classes);
    BOOST_TEST_GT(high.t, 10.0);
    BOOST_TEST(high.crop >= -1 && high.crop <= 99);
    BOOST_TEST_EQ(high.classes[0].count + high.classes[1].count, kept(shifted, high.limit_ns));
    BOOST_TEST_LT(std::fabs(high.classes[1].mean_ns - high.classes[0].mean_ns - 1.0), 0.1);
}

/** The A/A control writes the fixed value for both classes, after the same draws. */
void choose_control() {
    std::array<std::uint8_t, 24> fixed{};
    for (std::size_t i = 0; i < fixed.size(); ++i) {
        fixed[i] = static_cast<std::uint8_t>(0xA0U + i);
    }
    for (int which = 0; which < 2; ++which) {
        // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp): reproducible
        std::mt19937_64 control(7);
        // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp): reproducible
        std::mt19937_64 plain(7);
        std::array<std::uint8_t, 24> input{};
        test::choose<true>(which, control, fixed, input);
        BOOST_TEST(input == fixed);
        std::array<std::uint8_t, 24> ignored{};
        test::choose(which, plain, fixed, ignored);
        BOOST_TEST_EQ(control(), plain());
    }
    // Without the control, class 1 writes the drawn bytes.
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp): reproducible
    std::mt19937_64 plain(7);
    std::array<std::uint8_t, 24> input{};
    test::choose(1, plain, fixed, input);
    BOOST_TEST(input != fixed);
}

/** `--case` selects one case; no argument selects every one; an unknown name none. */
void select_case() {
    std::string program = "dudect_x";
    std::string flag = "--case";
    std::string compared = "constant_time_equal";
    std::string unknown = "unknown";
    std::array<char*, 1> alone{program.data()};
    auto const every = test::select_case(1, alone.data(), {"seal", "constant_time_equal"});
    BOOST_TEST(every.has_value());
    BOOST_TEST(every && every->runs("seal"));
    BOOST_TEST(every && every->runs("constant_time_equal"));

    std::array<char*, 3> one{program.data(), flag.data(), compared.data()};
    auto const only = test::select_case(3, one.data(), {"seal", "constant_time_equal"});
    BOOST_TEST(only.has_value());
    BOOST_TEST(only && only->runs("constant_time_equal"));
    BOOST_TEST(only && !only->runs("seal"));

    std::array<char*, 3> wrong{program.data(), flag.data(), unknown.data()};
    BOOST_TEST(!test::select_case(3, wrong.data(), {"seal", "constant_time_equal"}).has_value());
    std::array<char*, 2> missing{program.data(), flag.data()};
    BOOST_TEST(!test::select_case(2, missing.data(), {"seal", "constant_time_equal"}).has_value());
}

/** Every decision reads |t| as printed: 9.996 prints 10.00, with its evidence, and fails. */
void printed_boundary() {
    test::class_summary const small_class{.count = 3, .mean_ns = 40.0};
    test::class_summary const larger_class{.count = 4, .mean_ns = 41.0};
    BOOST_TEST_EQ(test::printed(9.996), 10.0);
    BOOST_TEST_EQ(test::printed(9.994), 9.99);
    test::t_statistic const just_above{
        .t = 9.996,
        .crop = 2,
        .limit_ns = 50.0,
        .classes = {small_class, larger_class},
    };
    test::t_statistic const just_below{
        .t = 9.994,
        .crop = 2,
        .limit_ns = 50.0,
        .classes = {small_class, larger_class},
    };
    BOOST_TEST_EQ(test::case_lines("x", just_above, true, {}),
                  "dudect case=x t=10.00 threshold=10 judged=yes\n"
                  "dudect evidence case=x crop=2 limit_ns=50.00 class0_n=3 class0_mean_ns=40.00 "
                  "class1_n=4 class1_mean_ns=41.00\n"
                  "dudect addresses case=x\n");
    BOOST_TEST_EQ(test::case_lines("x", just_below, true, {}),
                  "dudect case=x t=9.99 threshold=10 judged=yes\n");
    test::case_results failing;
    failing.record("x", "x", just_above, true, {});
    BOOST_TEST(!failing.passes());
    test::case_results passing;
    passing.record("x", "x", just_below, true, {});
    passing.record("y", "y", just_above, false, {});
    BOOST_TEST(passing.passes());
}

/** /proc/cpuinfo's text: x86's model name and microcode, arm64's identification fields. */
void cpuinfo() {
    auto const x86 = test::parse_cpuinfo(
        "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) \"6975P-C\"\n"
        "microcode\t: 0x10003a2 \n\nprocessor\t: 1\nmodel name\t: second\nmicrocode\t: 0x0\n");
    BOOST_TEST_EQ(x86.cpu, "Intel(R) Xeon(R) '6975P-C'");
    BOOST_TEST_EQ(x86.microcode, "0x10003a2");
    auto const arm64 = test::parse_cpuinfo(
        "processor\t: 0\nBogoMIPS\t: 2000.00\nFeatures\t: fp asimd\nCPU implementer\t: 0x41\n"
        "CPU architecture: 8\nCPU variant\t: 0x1\nCPU part\t: 0xd4f\nCPU revision\t: 1\n\n"
        "processor\t: 1\nCPU implementer\t: 0x61\nCPU part\t: 0x000\n");
    BOOST_TEST_EQ(arm64.cpu, "arm64 implementer=0x41 part=0xd4f variant=0x1 revision=1");
    BOOST_TEST_EQ(arm64.microcode, "unavailable");
    auto const none = test::parse_cpuinfo("");
    BOOST_TEST_EQ(none.cpu, "unavailable");
    BOOST_TEST_EQ(none.microcode, "unavailable");
}

/** The lines' exact text, which the CI's judge parses. */
void report_case_format([[maybe_unused]] char const* program) {
    test::class_summary const first{.count = 10, .mean_ns = 100.0};
    test::class_summary const second{.count = 12, .mean_ns = 101.0};
    test::t_statistic const high{
        .t = 12.3456,
        .crop = 4,
        .limit_ns = 101.5,
        .classes = {first, second},
    };
    test::t_statistic const low{
        .t = 3.0,
        .crop = -1,
        .limit_ns = 200.0,
        .classes = {first, second},
    };
    std::string const high_lines =
        "dudect case=equal t=12.35 threshold=10 judged=yes\n"
        "dudect evidence case=equal crop=4 limit_ns=101.50 class0_n=10 class0_mean_ns=100.00 "
        "class1_n=12 class1_mean_ns=101.00\n"
        "dudect addresses case=equal a=0x234\n";
    std::string const low_lines = "dudect case=equal t=3.00 threshold=10 judged=no\n";
    auto const* const where = reinterpret_cast<void const*>(0x1234);
    BOOST_TEST_EQ(test::case_lines("equal", high, true, {{"a", where}}), high_lines);
    BOOST_TEST_EQ(test::case_lines("equal", low, false, {{"a", where}}), low_lines);
    // The low 12 bits of each address, three hexadecimal digits.
    BOOST_TEST_EQ(test::case_lines("x", high, true,
                                   {{"a", reinterpret_cast<void const*>(0x2005)},
                                    {"b", reinterpret_cast<void const*>(0xfff)}}),
                  "dudect case=x t=12.35 threshold=10 judged=yes\n"
                  "dudect evidence case=x crop=4 limit_ns=101.50 class0_n=10 "
                  "class0_mean_ns=100.00 class1_n=12 class1_mean_ns=101.00\n"
                  "dudect addresses case=x a=0x005 b=0xfff\n");

#ifndef __wasi__
    // report_case writes the same lines to stdout. Under wasmtime the lane preopens no
    // directory, so there no file can stand in for stdout: case_lines above is the text. The
    // file is named after the program, in its build directory, so that no other run shares it.
    std::string const path = std::string(program) + ".stdout";
    static_cast<void>(std::fflush(stdout));
    if (BOOST_TEST(std::freopen(path.c_str(), "w", stdout) != nullptr)) {
        test::report_case("equal", high, true, {{"a", where}});
        test::report_case("equal", low, true, {{"a", where}});
        static_cast<void>(std::fflush(stdout));
        std::string written;
        if (std::FILE* const file = std::fopen(path.c_str(), "r")) {
            std::array<char, 512> buffer{};
            std::size_t read = 0;
            while ((read = std::fread(buffer.data(), 1, buffer.size(), file)) > 0) {
                written.append(buffer.data(), read);
            }
            static_cast<void>(std::fclose(file));
        }
        // Nothing is printed to stdout after this: the test's report goes to stderr.
#ifdef _WIN32
        static_cast<void>(std::freopen("NUL", "w", stdout));
#else
        static_cast<void>(std::freopen("/dev/null", "w", stdout));
#endif
        static_cast<void>(std::remove(path.c_str()));
        BOOST_TEST_EQ(written, high_lines + "dudect case=equal t=3.00 threshold=10 judged=yes\n");
    }
#endif
}

}  // namespace

// NOLINTNEXTLINE(misc-const-correctness): main's arguments have the type the standard gives them
int main(int argc, char** argv) {
    largest_t_whole_set();
    choose_control();
    select_case();
    printed_boundary();
    cpuinfo();
    // Last: it leaves stdout on the null device.
    report_case_format(argc > 0 ? argv[0] : "dudect_harness");
    return webcpp::test::exit_status(boost::report_errors());
}
