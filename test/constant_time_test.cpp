// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The constant-time building blocks of <webcpp/secure/constant_time.hpp> equal a plain reference
// on every input: every pair (and triple) of bytes, the edges and random values of 16, 32 and 64
// bits; lookup at every index and past the table, narrow and wide, of static and dynamic extent;
// the byte comparisons against the standard algorithms; in constant expressions too; and no
// block accepts `bool` or a signed type.

#include <webcpp/secure/constant_time.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <random>
#include <span>
#include <vector>

namespace {

namespace constant_time = webcpp::secure::constant_time;

template <class U>
concept maskable = requires(U value) { constant_time::is_equal_mask(value, value); };

static_assert(maskable<std::uint8_t> && maskable<std::uint16_t> && maskable<std::uint32_t> &&
              maskable<std::uint64_t> && maskable<std::size_t>);
static_assert(!maskable<bool> && !maskable<int> && !maskable<char> && !maskable<std::int64_t>);

template <class Element>
concept lookup_entry =
    requires(std::span<Element const, 2> table) { constant_time::lookup(table, std::size_t{0}); };

static_assert(lookup_entry<std::uint8_t> && lookup_entry<std::uint64_t>);
static_assert(!lookup_entry<bool> && !lookup_entry<int>);

/** The plain reference: a mask from a bool, with a branch. */
template <class U>
constexpr U reference_mask(bool on) {
    return on ? static_cast<U>(~U{0}) : U{0};
}

// Constant expressions.
static_assert(constant_time::select<std::uint8_t>(0xFF, 0x12, 0x34) == 0x12);
static_assert(constant_time::select<std::uint8_t>(0x00, 0x12, 0x34) == 0x34);
static_assert(constant_time::select<std::uint64_t>(~std::uint64_t{0}, 7, 9) == 7);
static_assert(constant_time::is_in_range_mask<std::uint8_t>('m', 'a', 'z') == 0xFF);
static_assert(constant_time::is_in_range_mask<std::uint8_t>('A', 'a', 'z') == 0x00);
static_assert(constant_time::is_in_range_mask<std::uint32_t>(10, 10, 10) == 0xFFFFFFFFU);
static_assert(constant_time::is_less_mask<std::uint16_t>(1, 2) == 0xFFFF);
static_assert(constant_time::mask_from_bit<std::uint8_t>(1) == 0xFF);
static_assert(constant_time::value_barrier<std::uint32_t>(42) == 42);

constexpr std::array<std::uint8_t, 4> small_table{10, 20, 30, 40};
static_assert(constant_time::lookup(std::span<std::uint8_t const, 4>(small_table), 2) == 30);
static_assert(constant_time::lookup(std::span<std::uint8_t const, 4>(small_table), 4) == 0);
static_assert(constant_time::lookup(std::span<std::uint8_t const>(small_table), 0) == 10);

constexpr std::array<std::uint8_t, 3> three_a{1, 2, 3};
constexpr std::array<std::uint8_t, 3> three_b{1, 2, 4};
static_assert(constant_time::equal_mask(three_a, three_a) == 0xFF);
static_assert(constant_time::equal_mask(three_a, three_b) == 0x00);
static_assert(constant_time::less_mask(three_a, three_b) == 0xFF);
static_assert(constant_time::less_mask(three_b, three_a) == 0x00);
static_assert(constant_time::is_zero_mask(std::span<std::uint8_t const>(three_a)) == 0x00);
static_assert(constant_time::is_zero_mask(std::span<std::uint8_t const>{}) == 0xFF);

/** Every single-operand and two-operand block against the reference, at one pair. */
template <class U>
void check_pair(U first, U second) {
    BOOST_TEST_EQ(constant_time::value_barrier(first), first);
    BOOST_TEST_EQ(constant_time::mask_from_bit(static_cast<U>(first & U{1})),
                  reference_mask<U>((first & U{1}) != 0));
    BOOST_TEST_EQ(constant_time::is_zero_mask(first), reference_mask<U>(first == 0));
    BOOST_TEST_EQ(constant_time::is_equal_mask(first, second), reference_mask<U>(first == second));
    BOOST_TEST_EQ(constant_time::is_less_mask(first, second), reference_mask<U>(first < second));
    bool const chooses_set = (second & U{1}) != 0;
    auto const complement = static_cast<U>(~first);
    BOOST_TEST_EQ(constant_time::select(reference_mask<U>(chooses_set), first, complement),
                  chooses_set ? first : complement);
}

/** is_in_range_mask against the reference, at one triple. */
template <class U>
void check_triple(U value, U low, U high) {
    BOOST_TEST_EQ(constant_time::is_in_range_mask(value, low, high),
                  reference_mask<U>(low <= value && value <= high));
}

void exhaustive_bytes() {
    for (unsigned first = 0; first <= 0xFFU; ++first) {
        for (unsigned second = 0; second <= 0xFFU; ++second) {
            check_pair(static_cast<std::uint8_t>(first), static_cast<std::uint8_t>(second));
        }
    }
    // Counted outside BOOST_TEST, so that 2^24 checks do not each pass through the reporter.
    std::size_t mismatches = 0;
    for (unsigned value = 0; value <= 0xFFU; ++value) {
        for (unsigned low = 0; low <= 0xFFU; ++low) {
            for (unsigned high = 0; high <= 0xFFU; ++high) {
                auto const mask = constant_time::is_in_range_mask(static_cast<std::uint8_t>(value),
                                                                  static_cast<std::uint8_t>(low),
                                                                  static_cast<std::uint8_t>(high));
                if (mask != reference_mask<std::uint8_t>(low <= value && value <= high)) {
                    ++mismatches;
                }
            }
        }
    }
    BOOST_TEST_EQ(mismatches, 0U);
}

template <class U>
void edges_and_random() {
    constexpr U max = std::numeric_limits<U>::max();
    constexpr std::array<U, 7> edges{
        0,   1, 2, static_cast<U>(max / 2), static_cast<U>((max / 2) + 1), static_cast<U>(max - 1),
        max,
    };
    for (U const first : edges) {
        for (U const second : edges) {
            check_pair(first, second);
            for (U const third : edges) {
                check_triple(first, second, third);
            }
        }
    }
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp): reproducible
    std::mt19937_64 generator{20261124};
    auto const draw = [&generator] { return static_cast<U>(generator()); };
    for (std::size_t round = 0; round < (std::size_t{1} << 16U); ++round) {
        U const first = draw();
        U const second = draw();
        U const third = draw();
        check_pair(first, second);
        check_pair(first, first);
        check_pair(first, static_cast<U>(first + 1));
        check_triple(first, second, third);
        check_triple(first, std::min(first, second), std::max(first, third));
        check_triple(first, first, first);
    }
}

template <class Element, std::size_t N>
void check_lookup(std::array<Element, N> const& table) {
    std::span<Element const, N> const fixed(table);
    std::span<Element const> const dynamic(table);
    for (std::size_t index = 0; index < N; ++index) {
        BOOST_TEST_EQ(constant_time::lookup(fixed, index), table[index]);
        BOOST_TEST_EQ(constant_time::lookup(dynamic, index), table[index]);
    }
    for (std::size_t const past :
         {N, N + 1, std::size_t{64}, std::size_t{65}, std::numeric_limits<std::size_t>::max()}) {
        BOOST_TEST_EQ(constant_time::lookup(fixed, past), Element{});
        BOOST_TEST_EQ(constant_time::lookup(dynamic, past), Element{});
    }
}

void lookups() {
    std::array<std::uint8_t, 64> bytes{};
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<std::uint8_t>((i * 7) + 3);
    }
    check_lookup(bytes);
    std::array<std::uint32_t, 32> words{};
    for (std::size_t i = 0; i < words.size(); ++i) {
        words[i] = static_cast<std::uint32_t>(0x9E3779B9U * (i + 1));
    }
    check_lookup(words);
    check_lookup(std::array<std::uint8_t, 1>{0xFF});
    check_lookup(std::array<std::uint64_t, 1>{0xFEDCBA9876543210U});
    // The entry at the top of a narrow element: the size_t mask narrowed keeps every bit.
    check_lookup(std::array<std::uint16_t, 2>{0xFFFF, 0x8001});
}

/** The byte blocks against the standard algorithms, at one pair of equal sizes. */
void check_bytes(std::vector<std::uint8_t> const& left, std::vector<std::uint8_t> const& right) {
    std::span<std::uint8_t const> const left_view(left);
    std::span<std::uint8_t const> const right_view(right);
    BOOST_TEST_EQ(constant_time::equal_mask(left_view, right_view),
                  reference_mask<std::uint8_t>(std::ranges::equal(left, right)));
    BOOST_TEST_EQ(constant_time::less_mask(left_view, right_view),
                  reference_mask<std::uint8_t>(std::ranges::lexicographical_compare(left, right)));
    BOOST_TEST_EQ(constant_time::is_zero_mask(left_view),
                  reference_mask<std::uint8_t>(
                      std::ranges::all_of(left, [](auto byte) { return byte == 0; })));
    std::vector<std::uint8_t> destination(left.size(), 0x5A);
    constant_time::select_bytes(0xFF, destination, left_view, right_view);
    BOOST_TEST_ALL_EQ(destination.begin(), destination.end(), left.begin(), left.end());
    constant_time::select_bytes(0x00, destination, left_view, right_view);
    BOOST_TEST_ALL_EQ(destination.begin(), destination.end(), right.begin(), right.end());
}

void byte_comparisons() {
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp): reproducible
    std::mt19937_64 generator{20261124};
    for (std::size_t const size : {0U, 1U, 31U, 32U}) {
        std::vector<std::uint8_t> const zeros(size, 0x00);
        std::vector<std::uint8_t> const ones(size, 0xFF);
        check_bytes(zeros, zeros);
        check_bytes(zeros, ones);
        check_bytes(ones, zeros);
        check_bytes(ones, ones);
        for (std::size_t round = 0; round < 256; ++round) {
            std::vector<std::uint8_t> first(size);
            std::vector<std::uint8_t> second(size);
            for (std::size_t i = 0; i < size; ++i) {
                first[i] = static_cast<std::uint8_t>(generator());
                second[i] = static_cast<std::uint8_t>(generator());
            }
            check_bytes(first, second);
            check_bytes(first, first);
            if (size == 0) {
                continue;
            }
            for (std::size_t const position : {std::size_t{0}, size - 1}) {
                auto differs = first;
                differs[position] = static_cast<std::uint8_t>(differs[position] + 1);
                check_bytes(first, differs);
                check_bytes(differs, first);
                auto one_set = zeros;
                one_set[position] = static_cast<std::uint8_t>(first[position] | 1U);
                check_bytes(one_set, zeros);
                check_bytes(zeros, one_set);
            }
        }
    }
}

}  // namespace

int main() {
    exhaustive_bytes();
    edges_and_random<std::uint16_t>();
    edges_and_random<std::uint32_t>();
    edges_and_random<std::uint64_t>();
    lookups();
    byte_comparisons();
    return webcpp::test::exit_status(boost::report_errors());
}
