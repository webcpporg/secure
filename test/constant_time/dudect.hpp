// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Welch's t-test over two classes of timings, with dudect's cropping. Copied from crypto's
// test/constant_time/dudect.hpp, which keeps its own (secure's tests keep their own support): the
// measurements its comments cite were made on crypto's lane, whose cases the reasons were found on.

#ifndef WEBCPP_TEST_SECURE_DUDECT_HPP
#define WEBCPP_TEST_SECURE_DUDECT_HPP

#include <webcpp/secure/timing_guard.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifdef _MSC_VER
#include <intrin.h>
#endif

#ifdef __APPLE__
#include <sys/sysctl.h>
#endif

namespace webcpp::secure::test {

/**
 * Waits until every instruction before it has completed, so that a clock read after it does
 * not start while the preparation's last instructions still run: `isb` on 64-bit ARM, `lfence`
 * on x86. Without it the clock is read out of order, and what the preparation does by class
 * (it copies the fixed input or just-drawn bytes) leaks into the measured time (measured
 * natively on an Apple M5, 2026-11-18: |t| 25 to 35 on a ChaCha20-Poly1305 decryption that
 * never reads the classes' input, below 2 with the barriers; an early-exit comparison's |t|
 * rose from 18 to 42). WebAssembly has no such instruction: there the clock is a host call.
 */
inline void serialise() noexcept {
#ifdef __aarch64__
    __asm__ volatile("isb" ::: "memory");
#elif defined(__x86_64__) || defined(__i386__)
    __asm__ volatile("lfence" ::: "memory");
#elif defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
    _mm_lfence();
#elif defined(_MSC_VER) && defined(_M_ARM64)
    __isb(_ARM64_BARRIER_SY);
#endif
}

/**
 * Prints, in one line, what the program finds of 64-bit ARM's DIT (Data Independent Timing) bit,
 * PSTATE.DIT, and whether the measurements may go on. The harness never sets DIT for the
 * measurements: `constant_time_equal` sets it in each call through secure's guard
 * (`secure::timing_guard`), and the lane measures that, what a program gets; the blocks hold no
 * guard, and a caller that wants DIT over them holds its own. Where the CPU has DIT, the line
 * also shows the guard at work, once, before any measurement: DIT set inside a guard's scope and
 * clear again after it. It must be clear on this thread outside the calls, or the timings would
 * be those of a DIT the program set itself, not the guard's.
 * @return false where the CPU has DIT and it is set on this thread outside a guard, or not set
 * inside one, so that the program fails rather than measure it; true otherwise: where the CPU has
 * DIT and the guard sets and clears it, where the CPU has none, and where the guard does not
 * apply (not macOS or Linux on arm64: x86, WebAssembly, where the engine decides, and Windows on
 * ARM64).
 */
inline bool report_data_independent_timing() noexcept {
#ifdef WEBCPP_SECURE_TIMING_COVERED
    if (!secure::cpu_has_dit()) {
        std::printf("DIT (data-independent timing): not on this CPU\n");
        return true;
    }
    bool const set_before = secure::dit_is_set();
    bool set_inside = false;
    {
        secure::timing_guard const timing_scope;
        set_inside = secure::dit_is_set();
    }
    bool const set_after = secure::dit_is_set();
    bool const outside_set = set_before || set_after;
    std::printf(
        "DIT (data-independent timing): the CPU has it; secure's guard sets it in each call of "
        "constant_time_equal, the harness does not (%s inside a guard; %s)\n",
        set_inside ? "set" : "NOT set",
        outside_set ? "set on this thread outside the calls: not measured"
                    : "clear on this thread outside the calls");
    return set_inside && !outside_set;
#else
    std::printf(
        "DIT (data-independent timing): not applicable here (not macOS or Linux on arm64)\n");
    return true;
#endif
}

/** Online mean and variance of one class, Welford's. */
struct moments {
    /** The number of values pushed. */
    double n = 0;
    /** Their mean. */
    double mean = 0;
    /** The sum of squared differences from the mean. */
    double m2 = 0;

    /**
     * Adds a value.
     * @param x The value.
     */
    void push(double x) {
        n += 1;
        double const delta = x - mean;
        mean += delta / n;
        m2 += delta * (x - mean);
    }

    /**
     * The sample variance.
     * @return The variance, 0 below two values.
     */
    [[nodiscard]] double variance() const { return n > 1 ? m2 / (n - 1) : 0; }
};

/**
 * Welch's t of two classes.
 * @param a The first class.
 * @param b The second class.
 * @return t, 0 when both variances are 0.
 */
inline double welch(moments const& a, moments const& b) {
    double const denominator = std::sqrt((a.variance() / a.n) + (b.variance() / b.n));
    return denominator == 0 ? 0 : (a.mean - b.mean) / denominator;
}

/** One class's count and mean at a cropping. */
struct class_summary {
    /** The number of its timings kept. */
    std::size_t count;
    /** Their mean, in nanoseconds. */
    double mean_ns;
};

/** The largest |t| of a set of timings, with what gave it. */
struct t_statistic {
    /** The largest |t| over the whole set and dudect's 100 croppings. */
    double t;
    /** The cropping that gave it: -1 for the whole set, else 0 to 99. */
    int crop;
    /** The largest timing that cropping kept, in nanoseconds. */
    double limit_ns;
    /** Each class's count and mean at that cropping. */
    std::array<class_summary, 2> classes;
};

/**
 * A |t| as the lines print it, rounded to two decimals: every decision reads this value (the
 * evidence's condition, a case's pass, `twice`'s second run, the planted leak's verdict), so that
 * a |t| of 9.996 prints 10.00, with its evidence, and fails as 10.00 does, and the CI's judge,
 * which reads the printed value, agrees with the program.
 * @param t The |t|.
 * @return It rounded to two decimals.
 */
inline double printed(double t) {
    return std::round(t * 100) / 100;
}

/**
 * The largest |t| over the whole set and dudect's 100 croppings, each of which keeps the timings
 * at or below a percentile, with the cropping that gave it and each class's count and mean there.
 * A cropping that leaves a class empty has no t and is skipped; of equal values the first, the
 * whole set before the croppings, is kept.
 * @param timings The measurements, at least one.
 * @param classes The class, 0 or 1, of each.
 * @return The largest |t| and what gave it.
 */
inline t_statistic largest_t(std::vector<double> const& timings, std::vector<int> const& classes) {
    std::vector<double> sorted = timings;
    std::ranges::sort(sorted);
    t_statistic largest{.t = 0, .crop = -1, .limit_ns = sorted.back(), .classes = {}};
    for (int k = -1; k < 100; ++k) {
        double const keep = k < 0 ? 1.0 : 1.0 - std::pow(0.5, 10.0 * (k + 1) / 100.0);
        double const limit =
            sorted[static_cast<std::size_t>(keep * static_cast<double>(sorted.size() - 1))];
        std::array<moments, 2> m{};
        for (std::size_t i = 0; i < timings.size(); ++i) {
            if (timings[i] <= limit) {
                m[static_cast<std::size_t>(classes[i])].push(timings[i]);
            }
        }
        double const t = std::fabs(welch(m[0], m[1]));
        if (!std::isfinite(t) || (k >= 0 && !(t > largest.t))) {
            continue;
        }
        largest = {
            .t = t,
            .crop = k,
            .limit_ns = limit,
            .classes =
                {
                    class_summary{.count = static_cast<std::size_t>(m[0].n), .mean_ns = m[0].mean},
                    class_summary{.count = static_cast<std::size_t>(m[1].n), .mean_ns = m[1].mean},
                },
        };
    }
    return largest;
}

/**
 * Draws `Size` bytes, then writes into `input` either `fixed`, for class 0, or the drawn bytes,
 * for class 1, so that the two classes differ in the bytes written and in nothing else. Both
 * classes draw the same bytes, read both `fixed` and the drawn bytes, and write `input` with the
 * same instructions: each byte is blended through a mask read from a volatile, which the
 * compiler cannot see through, so that it can neither split the work by class nor read one
 * source alone. Whatever a class does differently before the measured call leaks the class into
 * it. A copy from a volatile pointer to the chosen source (until 2026-11-20) read the fixed
 * input for class 0 and the bytes just drawn, still in the store buffer, for class 1: on the
 * CI's x86-64 runners the measured call then differed by class whatever it computed (measured
 * on GitHub's ubuntu-24.04 runners, 2026-11-20: equal at |t| 31 to 56 on an Intel Xeon 6975P-C
 * and ChaCha20-Poly1305's seal at 28 to 85 on AMD EPYC 9V45 and 9V74; through this blend, on
 * the Xeon, the EPYC 9V74 and an AMD EPYC 7763, idle and with every processor busy, every case
 * of 23 runs of 24 stayed below 4.4, the 24th is in `judged`). Before it,
 * a choice the optimiser made of `which == 0 ? 0 : drawn` split the copy into a store of
 * constants and a store of drawn bytes (measured natively on an Apple M5, 2026-11-18: |t| 16 to
 * 18 on equal and 9 to 26 on open with the split, below 3 for both without it).
 * With `Control`, the A/A control: the bytes are drawn, then overwritten with `fixed`, and blended
 * through the same volatile mask, so that both classes write the fixed value with the same
 * instructions as a case's and the generator advances as it does; its |t| shows what the
 * measurement on that machine finds where nothing differs.
 * @tparam Control Whether both classes write `fixed`.
 * @param which The class, 0 or 1.
 * @param generator The seeded generator.
 * @param fixed The class 0 input.
 * @param input Where the input of the class is written.
 */
template <bool Control = false, std::size_t Size, class Generator>
void choose(int which, Generator& generator, std::array<std::uint8_t, Size> const& fixed,
            std::array<std::uint8_t, Size>& input) {
    std::array<std::uint8_t, Size> drawn{};
    for (auto& byte : drawn) {
        byte = static_cast<std::uint8_t>(generator());
    }
    if constexpr (Control) {
        // Read through a volatile, so that the compiler cannot know the two sources of the blend
        // below equal and fold it into a copy: the control blends as every case does.
        for (std::size_t index = 0; index < Size; ++index) {
            drawn[index] = static_cast<std::uint8_t const volatile&>(fixed[index]);
        }
    }
    std::uint8_t volatile const chosen = which == 0 ? 0xFFU : 0x00U;
    unsigned const keep = chosen;
    unsigned const drop = keep ^ 0xFFU;
    for (std::size_t index = 0; index < Size; ++index) {
        input[index] = static_cast<std::uint8_t>((unsigned{fixed[index]} & keep) |
                                                 (unsigned{drawn[index]} & drop));
    }
}

/**
 * The largest |t| of `count` measurements of `run`, each after `prepare(class, generator)`
 * with a class drawn at random from the seeded generator, prepare unmeasured; each clock read
 * is fenced by `serialise`.
 * @param seed The generator's seed.
 * @param count The number of measurements.
 * @param prepare Sets up the class's input, unmeasured.
 * @param run The operation measured.
 * @return The largest |t|, with what gave it.
 */
template <class Prepare, class Run>
t_statistic measure(std::uint64_t seed, std::size_t count, Prepare&& prepare, Run&& run) {
    std::mt19937_64 generator(seed);
    std::vector<double> timings;
    std::vector<int> classes;
    timings.reserve(count);
    classes.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        int const which = static_cast<int>(generator() & 1U);
        prepare(which, generator);
        serialise();
        auto const start = std::chrono::steady_clock::now();
        serialise();
        run();
        serialise();
        auto const end = std::chrono::steady_clock::now();
        timings.push_back(std::chrono::duration<double, std::nano>(end - start).count());
        classes.push_back(which);
    }
    return largest_t(timings, classes);
}

/**
 * The largest |t| of a first run, and of a second with another seed when the first, as printed,
 * is at least 10.
 * @param count The number of measurements of each run.
 * @param prepare Sets up the class's input, unmeasured.
 * @param run The operation measured.
 * @return The first run's statistic when its |t|, as printed, is below 10, else that of the run
 * with the smaller |t|.
 */
template <class Prepare, class Run>
t_statistic twice(std::size_t count, Prepare&& prepare, Run&& run) {
    t_statistic const first = measure(20261011, count, prepare, run);
    if (printed(first.t) < 10) {
        return first;
    }
    t_statistic const second = measure(20261012, count, prepare, run);
    return second.t < first.t ? second : first;
}

/** A buffer a case measures, named in its addresses line. */
struct address {
    /**
     * Names a buffer, as `{"data", data.data()}` does in a case's list.
     * @param name Its name in the line, as `data` or `object`.
     * @param buffer Where it is.
     */
    constexpr address(char const* name, void const* buffer) noexcept : label(name), where(buffer) {}

    /** Its name in the line, as `data` or `object`. */
    char const* label;
    /** Where it is. */
    void const* where;
};

/**
 * The lines of a case, which the CI's judge reads (design D6 of the change api-gaps): `dudect
 * case=<name> t=<|t|> threshold=10 judged=<yes|no>`, and, when |t| is at least 10, `dudect
 * evidence case=<name> crop=<k> limit_ns=<x> class0_n=<n> class0_mean_ns=<x> class1_n=<n>
 * class1_mean_ns=<x>`, the cropping that gave |t| and each class there, and `dudect addresses
 * case=<name> <label>=0x<low 12 bits> ...`, where the measured buffers lie within their page,
 * three hexadecimal digits each. Every value has two decimals.
 * @param name The case's name, as `--case` takes it.
 * @param result Its statistic.
 * @param judged_case Whether its |t| counts in the program's verdict.
 * @param buffers The buffers it measures: its input, its output and its object.
 * @return The lines, each ending with a newline.
 */
inline std::string case_lines(char const* name, t_statistic const& result, bool judged_case,
                              std::initializer_list<address> buffers) {
    std::array<char, 512> line{};
    double const t = printed(result.t);
    static_cast<void>(std::snprintf(line.data(), line.size(),
                                    "dudect case=%s t=%.2f threshold=10 judged=%s\n", name, t,
                                    judged_case ? "yes" : "no"));
    std::string text = line.data();
    if (!(t >= 10)) {
        return text;
    }
    static_cast<void>(std::snprintf(
        line.data(), line.size(),
        "dudect evidence case=%s crop=%d limit_ns=%.2f class0_n=%zu class0_mean_ns=%.2f "
        "class1_n=%zu class1_mean_ns=%.2f\n",
        name, result.crop, result.limit_ns, result.classes[0].count, result.classes[0].mean_ns,
        result.classes[1].count, result.classes[1].mean_ns));
    text += line.data();
    text += "dudect addresses case=";
    text += name;
    for (address const& buffer : buffers) {
        static_cast<void>(std::snprintf(
            line.data(), line.size(), " %s=0x%03x", buffer.label,
            static_cast<unsigned>(reinterpret_cast<std::uintptr_t>(buffer.where) & 0xFFFU)));
        text += line.data();
    }
    text += '\n';
    return text;
}

/**
 * Prints a case's lines (`case_lines`) to stdout, and flushes them.
 * @param name The case's name, as `--case` takes it.
 * @param result Its statistic.
 * @param judged_case Whether its |t| counts in the program's verdict.
 * @param buffers The buffers it measures: its input, its output and its object.
 */
inline void report_case(char const* name, t_statistic const& result, bool judged_case,
                        std::initializer_list<address> buffers) {
    static_cast<void>(std::fputs(case_lines(name, result, judged_case, buffers).c_str(), stdout));
    static_cast<void>(std::fflush(stdout));
}

/**
 * The smallest nonzero difference of 10,000 pairs of `steady_clock::now()` read back to back,
 * each read fenced by `serialise`.
 * @return The clock's resolution in nanoseconds, 0 when every pair read the same time.
 */
inline double clock_resolution_ns() {
    double smallest = 0;
    for (int pair = 0; pair < 10'000; ++pair) {
        serialise();
        auto const first = std::chrono::steady_clock::now();
        serialise();
        auto const second = std::chrono::steady_clock::now();
        serialise();
        double const difference = std::chrono::duration<double, std::nano>(second - first).count();
        if (difference > 0 && (smallest == 0 || difference < smallest)) {
            smallest = difference;
        }
    }
    return smallest;
}

/** What the machine line says of the CPU. */
struct cpu_identity {
    /** The model, with no double quote in it. */
    std::string cpu = "unavailable";
    /** The microcode's version, with no space or double quote in it. */
    std::string microcode = "unavailable";
};

/**
 * Makes a CPU's identity fit the machine line: a double quote in the model becomes a single one,
 * so that the quoted value does not end early, and a space or double quote in the microcode an
 * underscore.
 * @param identity The identity as the system gave it.
 * @return The identity to print.
 */
inline cpu_identity printable(cpu_identity identity) {
    std::ranges::replace(identity.cpu, '"', '\'');
    for (char& character : identity.microcode) {
        if (character == ' ' || character == '"') {
            character = '_';
        }
    }
    return identity;
}

/**
 * Reads the CPU's identity from the text of Linux's /proc/cpuinfo: the first `model name` and
 * `microcode` (x86); where there is no `model name` (arm64), the first `CPU implementer`, `CPU
 * part`, `CPU variant` and `CPU revision`, as `arm64 implementer=<x> part=<x> variant=<x>
 * revision=<x>` with the fields found. What the text does not hold stays `unavailable`.
 * @param text The file's text.
 * @return The identity, `printable`.
 */
inline cpu_identity parse_cpuinfo(std::string_view text) {
    using field = std::pair<char const*, std::string>;
    std::array<field, 6> fields{
        field{"model name", {}}, field{"microcode", {}},   field{"CPU implementer", {}},
        field{"CPU part", {}},   field{"CPU variant", {}}, field{"CPU revision", {}},
    };
    constexpr std::string_view blank = " \t\r";
    while (!text.empty()) {
        auto const end = text.find('\n');
        std::string_view const line = text.substr(0, end);
        text = end == std::string_view::npos ? std::string_view{} : text.substr(end + 1);
        auto const colon = line.find(':');
        if (colon == std::string_view::npos) {
            continue;
        }
        std::string_view key = line.substr(0, colon);
        std::string_view value = line.substr(colon + 1);
        auto const key_end = key.find_last_not_of(blank);
        key = key_end == std::string_view::npos ? std::string_view{} : key.substr(0, key_end + 1);
        auto const value_start = value.find_first_not_of(blank);
        value =
            value_start == std::string_view::npos ? std::string_view{} : value.substr(value_start);
        value = value.substr(0, value.find_last_not_of(blank) + 1);
        for (auto& [name, found] : fields) {
            if (key == name && found.empty()) {
                found = value;
            }
        }
    }
    cpu_identity identity;
    if (!fields[0].second.empty()) {
        identity.cpu = fields[0].second;
    } else if (!fields[2].second.empty()) {
        identity.cpu = "arm64";
        constexpr std::array<char const*, 4> labels{"implementer", "part", "variant", "revision"};
        for (std::size_t index = 0; index < labels.size(); ++index) {
            if (!fields[index + 2].second.empty()) {
                identity.cpu += ' ';
                identity.cpu += labels[index];
                identity.cpu += '=';
                identity.cpu += fields[index + 2].second;
            }
        }
    }
    if (!fields[1].second.empty()) {
        identity.microcode = fields[1].second;
    }
    return printable(identity);
}

/**
 * The CPU a measurement runs on: /proc/cpuinfo's model and microcode (`parse_cpuinfo`) on Linux,
 * `machdep.cpu.brand_string` on macOS with the microcode `unavailable`, and `unavailable`
 * elsewhere, WebAssembly included, as where the system does not tell them.
 * @return The identity, `printable`.
 */
inline cpu_identity machine_identity() {
    cpu_identity identity;
#ifdef __linux__
    if (std::FILE* const file = std::fopen("/proc/cpuinfo", "r")) {
        std::string text;
        std::array<char, 4096> buffer{};
        std::size_t read = 0;
        while ((read = std::fread(buffer.data(), 1, buffer.size(), file)) > 0) {
            text.append(buffer.data(), read);
        }
        static_cast<void>(std::fclose(file));
        identity = parse_cpuinfo(text);
    }
#elif defined(__APPLE__)
    std::array<char, 256> brand{};
    std::size_t size = brand.size();
    if (sysctlbyname("machdep.cpu.brand_string", brand.data(), &size, nullptr, 0) == 0 &&
        brand[0] != '\0') {
        brand.back() = '\0';
        identity.cpu = brand.data();
    }
    identity = printable(identity);
#endif
    return identity;
}

/**
 * Prints, once per program, the machine a measurement ran on: `dudect machine cpu="<model>"
 * microcode=<value> clock_resolution_ns=<x>`, the CPU's `machine_identity`; the resolution is
 * `clock_resolution_ns`'s, with two decimals, or `below_resolution` when it measured none.
 */
inline void report_machine() {
    static bool printed_once = false;
    if (printed_once) {
        return;
    }
    printed_once = true;
    cpu_identity const identity = machine_identity();
    double const resolution = clock_resolution_ns();
    std::array<char, 32> written{};
    if (resolution > 0) {
        static_cast<void>(std::snprintf(written.data(), written.size(), "%.2f", resolution));
    } else {
        static_cast<void>(std::snprintf(written.data(), written.size(), "below_resolution"));
    }
    std::printf("dudect machine cpu=\"%s\" microcode=%s clock_resolution_ns=%s\n",
                identity.cpu.c_str(), identity.microcode.c_str(), written.data());
    static_cast<void>(std::fflush(stdout));
}

/** The case a program measures: every one, or the one `--case` names. */
struct case_selection {
    /** The one case to measure, or none for every case. */
    char const* only = nullptr;

    /**
     * Whether a case is measured.
     * @param name The case's name.
     * @return true when no case was named or this one was.
     */
    [[nodiscard]] bool runs(char const* name) const {
        return only == nullptr || std::strcmp(only, name) == 0;
    }
};

/**
 * Reads a dudect program's arguments: none, to measure every case, or `--case <name>`, to measure
 * that case alone, so that the CI measures a case again in a fresh process.
 * @param argc main's argc.
 * @param argv main's argv.
 * @param names The program's cases.
 * @return The selection; empty, after a line on stderr that lists the cases (`unknown case <x>;
 * the cases: <names>` for a name not among them), when the arguments are neither.
 */
inline std::optional<case_selection> select_case(int argc, char const* const* argv,
                                                 std::initializer_list<char const*> names) {
    std::string list;
    for (char const* const name : names) {
        list += list.empty() ? "" : ", ";
        list += name;
    }
    if (argc <= 1) {
        return case_selection{};
    }
    if (argc == 3 && std::strcmp(argv[1], "--case") == 0) {
        for (char const* const name : names) {
            if (std::strcmp(argv[2], name) == 0) {
                return case_selection{name};
            }
        }
        static_cast<void>(
            std::fprintf(stderr, "unknown case %s; the cases: %s\n", argv[2], list.c_str()));
        return std::nullopt;
    }
    static_cast<void>(std::fprintf(stderr, "usage: %s [--case <name>]; the cases: %s\n",
                                   argc > 0 ? argv[0] : "dudect", list.c_str()));
    return std::nullopt;
}

/**
 * The cases a program measured: each one's lines printed as it is recorded, the human line that
 * lists them, and whether every judged one passes.
 */
class case_results {
public:
    /**
     * Prints a case's lines (`report_case`) and adds it to the human line and to the verdict.
     * @param name The case's name, as `--case` takes it.
     * @param label Its name in the human line.
     * @param result Its statistic.
     * @param judged_case Whether its |t| counts in the verdict.
     * @param buffers The buffers it measures: its input, its output and its object.
     * @param note Printed after its value in the human line.
     */
    void record(char const* name, char const* label, t_statistic const& result, bool judged_case,
                std::initializer_list<address> buffers, char const* note = "") {
        report_case(name, result, judged_case, buffers);
        std::array<char, 128> value{};
        static_cast<void>(std::snprintf(value.data(), value.size(), "%s%s %.2f%s",
                                        human_.empty() ? "" : ", ", label, printed(result.t),
                                        note));
        human_ += value.data();
        passes_ = passes_ && (!judged_case || printed(result.t) < 10);
    }

    /** Prints the human line: `|t| <label> <value>, ... (threshold 10)`. */
    void print() const { std::printf("|t| %s (threshold 10)\n", human_.c_str()); }

    /**
     * Whether every judged case's |t| is below the threshold.
     * @return true when they all are.
     */
    [[nodiscard]] bool passes() const { return passes_; }

private:
    std::string human_;
    bool passes_ = true;
};

/**
 * The statistic of a case: `twice`'s for a judged case; for a case printed and not judged, one
 * run's. The second run of `twice` only decides whether a high first value fails the program, and
 * an unjudged case fails nothing, so its second run would cost the time of a whole case (under
 * wasmtime, X25519's agreement reads above 10 on every run, an open finding, and its second run
 * is minutes) and change no verdict.
 * @param judged_case Whether the case's |t| counts in the verdict.
 * @param count The number of measurements of each run.
 * @param prepare Sets up the class's input, unmeasured.
 * @param run The operation measured.
 * @return The statistic.
 */
template <class Prepare, class Run>
t_statistic measure_case(bool judged_case, std::size_t count, Prepare&& prepare, Run&& run) {
    return judged_case ? twice(count, prepare, run) : measure(20261011, count, prepare, run);
}

/**
 * Whether this build's verdict is judged: false where the lane's Jamfile defines
 * WEBCPP_TEST_DUDECT_UNJUDGED, on a runner GitHub hosts (RUNNER_ENVIRONMENT=github-hosted), true
 * elsewhere. A hosted runner is a virtual machine shared with other tenants, whose processor
 * changes from one run to the next (an Intel Xeon 6975P-C, an AMD EPYC 7763, 9V45 or 9V74 on
 * 2026-11-20), and there |t| moved with what the measurement could not control: through the
 * class-blind preparation of `choose`, one run of 24 read |t| 69.8 on ChaCha20-Poly1305's open,
 * on both seeds, where the 23 others read below 4.4 (an AMD EPYC 7763, idle); through the
 * earlier copy, a measured call that does nothing read up to 117 with every processor busy. A
 * verdict there would pass or fail with the machine drawn, so the program prints its |t| and
 * passes, and the CI's judge (dudect_judge.py) decides: it measures a case over 10 again in two
 * fresh processes and fails when two of the three values are 10 or more. Valgrind's memcheck and
 * MemorySanitizer, which do not measure time, are judged there. dudect is judged by the program
 * wherever else the lane runs, natively and on wasip2, on a machine of one's own;
 * dudect_planted is judged everywhere, as it shows that the measurement still finds a leak of a
 * few nanoseconds on the machine it ran on.
 */
#ifdef WEBCPP_TEST_DUDECT_UNJUDGED
inline constexpr bool judged = false;
#else
inline constexpr bool judged = true;
#endif

/**
 * The exit status of a dudect program: 0 when every case passes, else 1, where `judged`; 0
 * elsewhere, after a line that says so.
 * @param passes Whether every case's |t| is below the threshold.
 * @return The exit status.
 */
inline int verdict(bool passes) noexcept {
    if (!judged) {
        std::printf(
            "printed here; the CI's judge (dudect_judge.py) measures a case over 10 again on a "
            "hosted runner\n");
        return 0;
    }
    return passes ? 0 : 1;
}

}  // namespace webcpp::secure::test

#endif
