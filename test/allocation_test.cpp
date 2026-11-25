// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// webcpp::secure allocates nothing: every function of the library is called under the counter of
// support/counting.hpp, which replaces every form of the global operator new (plain, array,
// sized-delete, nothrow and aligned) and, where the target lets a program count it, the C
// library's allocator, and the count does not move. A control first calls each form of operator
// new once and checks that each is counted, so a zero is not a replacement that never ran.

#include "support/counting.hpp"

#include <webcpp/secure.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <new>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace {

namespace secure = webcpp::secure;
namespace ct = webcpp::secure::constant_time;
namespace counting = webcpp::secure::test;

constexpr std::size_t big = 64;
constexpr std::align_val_t aligned{big};

/** Runs `body` and checks that it moved neither counter. */
template <class Body>
void expect_no_allocation(char const* what, Body body) {
    std::size_t const new_before = counting::counted_new.load();
    std::size_t const c_before = counting::counted_c.load();
    body();
    std::size_t const new_after = counting::counted_new.load();
    std::size_t const c_after = counting::counted_c.load();
    if (new_after != new_before || c_after != c_before) {
        std::printf("allocated: %s\n", what);
    }
    BOOST_TEST_EQ(new_after - new_before, 0U);
    BOOST_TEST_EQ(c_after - c_before, 0U);
}

/** Runs `body`, one allocation of operator new's form, and checks that the counter saw it. */
template <class Body>
void expect_counted(char const* form, Body body) {
    std::size_t const before = counting::counted_new.load();
    body();
    std::size_t const counted = counting::counted_new.load() - before;
    if (counted != 1) {
        std::printf("not counted once: %s\n", form);
    }
    BOOST_TEST_EQ(counted, 1U);
}

/** Every form of operator new moves the counter: the control of the zeros below. */
void control_counts_every_form() {
    expect_counted("new", [] {
        void* volatile block = ::operator new(24);
        ::operator delete(block);
    });
    expect_counted("new[]", [] {
        void* volatile block = ::operator new[](24);
        ::operator delete[](block);
    });
    expect_counted("sized delete", [] {
        void* volatile block = ::operator new(24);
        ::operator delete(block, std::size_t{24});
    });
    expect_counted("sized delete[]", [] {
        void* volatile block = ::operator new[](24);
        ::operator delete[](block, std::size_t{24});
    });
    expect_counted("nothrow new", [] {
        void* volatile block = ::operator new(24, std::nothrow);
        BOOST_TEST(block != nullptr);
        ::operator delete(block, std::nothrow);
    });
    expect_counted("nothrow new[]", [] {
        void* volatile block = ::operator new[](24, std::nothrow);
        BOOST_TEST(block != nullptr);
        ::operator delete[](block, std::nothrow);
    });
    expect_counted("aligned new", [] {
        void* volatile block = ::operator new(24, aligned);
        ::operator delete(block, aligned);
    });
    expect_counted("aligned new[]", [] {
        void* volatile block = ::operator new[](24, aligned);
        ::operator delete[](block, aligned);
    });
    expect_counted("aligned nothrow new", [] {
        void* volatile block = ::operator new(24, aligned, std::nothrow);
        BOOST_TEST(block != nullptr);
        ::operator delete(block, aligned, std::nothrow);
    });
    expect_counted("aligned nothrow new[]", [] {
        void* volatile block = ::operator new[](24, aligned, std::nothrow);
        BOOST_TEST(block != nullptr);
        ::operator delete[](block, aligned, std::nothrow);
    });
    // The standard allocator's storage, which every container takes: not a container's own, since
    // MSVC's debug library (_ITERATOR_DEBUG_LEVEL 1 or 2) also allocates a proxy per container.
    expect_counted("std::allocator's storage", [] {
        std::allocator<std::uint8_t> allocator;
        std::uint8_t* volatile block = allocator.allocate(16);
        BOOST_TEST(block != nullptr);
        allocator.deallocate(block, 16);
    });
    expect_counted("new int[]", [] {
        int const* volatile block = new int[4];
        delete[] block;
    });
}

/** The blocks of one mask word, each called with values the optimiser cannot fold. */
template <class U>
void check_word_blocks() {
    U volatile first_source = 0x5a;
    U volatile second_source = 0xa5;
    U const first = first_source;
    U const second = second_source;
    U volatile sink = 0;
    expect_no_allocation("top_bit", [&] { sink = secure::detail::top_bit<U>(first); });
    expect_no_allocation("value_barrier", [&] { sink = ct::value_barrier<U>(first); });
    expect_no_allocation("mask_from_bit", [&] { sink = ct::mask_from_bit<U>(U{1}); });
    expect_no_allocation("is_zero_mask", [&] { sink = ct::is_zero_mask<U>(first); });
    expect_no_allocation("is_equal_mask", [&] { sink = ct::is_equal_mask<U>(first, second); });
    expect_no_allocation("is_less_mask", [&] { sink = ct::is_less_mask<U>(first, second); });
    expect_no_allocation("is_in_range_mask",
                         [&] { sink = ct::is_in_range_mask<U>(first, first, second); });
    expect_no_allocation("select", [&] { sink = ct::select<U>(first, first, second); });
    std::array<U, 4> const table{U{1}, U{2}, U{3}, U{4}};
    std::size_t volatile index = 2;
    expect_no_allocation("lookup", [&] {
        sink = ct::lookup(std::span<U const, 4>(table), index);
        sink = ct::lookup(std::span<U const>(table), index + 9);
    });
    BOOST_TEST_EQ(sink, U{0});
}

void check_constant_time_blocks() {
    check_word_blocks<std::uint8_t>();
    check_word_blocks<std::uint64_t>();
    std::array<std::uint8_t, 32> first{};
    std::array<std::uint8_t, 32> second{};
    std::array<std::uint8_t, 32> destination{};
    first.fill(0x11);
    second.fill(0x22);
    std::uint8_t volatile sink = 0;
    expect_no_allocation("select_bytes", [&] {
        ct::select_bytes(0xff, destination, first, second);
        ct::select_bytes(0x00, destination, first, second);
    });
    expect_no_allocation("equal_mask", [&] { sink = ct::equal_mask(first, second); });
    expect_no_allocation("is_zero_mask of bytes", [&] { sink = ct::is_zero_mask(first); });
    expect_no_allocation("less_mask", [&] { sink = ct::less_mask(first, second); });
    BOOST_TEST_EQ(destination[0], 0x22U);
    BOOST_TEST_EQ(sink, 0xffU);
}

void check_constant_time_equal() {
    std::array<std::uint8_t, 32> const first{};
    std::array<std::uint8_t, 32> second{};
    std::array<std::byte, 32> const raw{};
    std::vector<std::uint8_t> const heap_first(32);  // built before the window
    std::vector<std::uint8_t> const heap_short(31);
    std::string_view const view = "constant-time";
    secure::secret<32> const held;
    bool equal_result = false;
    expect_no_allocation("constant_time_equal on arrays",
                         [&] { equal_result = secure::constant_time_equal(first, second); });
    BOOST_TEST(equal_result);
    expect_no_allocation("constant_time_equal on spans", [&] {
        equal_result = secure::constant_time_equal(std::span<std::uint8_t const>(first),
                                                   std::span<std::uint8_t const>(second));
    });
    BOOST_TEST(equal_result);
    expect_no_allocation("constant_time_equal on a std::byte array",
                         [&] { equal_result = secure::constant_time_equal(raw, raw); });
    BOOST_TEST(equal_result);
    expect_no_allocation("constant_time_equal on vectors",
                         [&] { equal_result = secure::constant_time_equal(heap_first, first); });
    BOOST_TEST(equal_result);
    expect_no_allocation("constant_time_equal on unequal sizes", [&] {
        equal_result = secure::constant_time_equal(heap_first, heap_short);
    });
    BOOST_TEST(!equal_result);
    expect_no_allocation("constant_time_equal on string views",
                         [&] { equal_result = secure::constant_time_equal(view, view); });
    BOOST_TEST(equal_result);
    expect_no_allocation("constant_time_equal on a secret",
                         [&] { equal_result = secure::constant_time_equal(held, first); });
    BOOST_TEST(equal_result);
    expect_no_allocation("constant_time_equal on a temporary secret", [&] {
        equal_result = secure::constant_time_equal(secure::secret<32>{}, held);
    });
    BOOST_TEST(equal_result);
    second[7] = 1;
    expect_no_allocation("constant_time_equal on different bytes",
                         [&] { equal_result = secure::constant_time_equal(first, second); });
    BOOST_TEST(!equal_result);
}

void check_erase_secret() {
    std::array<std::uint8_t, 32> buffer{};
    std::vector<std::uint8_t> heap_buffer(32, 0x7f);  // built before the window
    std::array<std::uint64_t, 4> words{1, 2, 3, 4};
    buffer.fill(0x7f);
    expect_no_allocation("erase_secret", [&] {
        secure::erase_secret(buffer);
        secure::erase_secret(heap_buffer);
        secure::erase_secret(words);
    });
    BOOST_TEST_EQ(buffer[0], 0U);
    BOOST_TEST_EQ(heap_buffer[31], 0U);
    BOOST_TEST_EQ(words[3], 0U);
}

void check_secret() {
    expect_no_allocation("secret", [] {
        secure::secret<32> original;
        original.writable()[0] = 0x42;
        secure::secret<32> moved(std::move(original));
        BOOST_TEST_EQ(moved.bytes()[0], 0x42U);
        // NOLINTNEXTLINE(bugprone-use-after-move): the move wipes its source, which this reads.
        BOOST_TEST_EQ(original.bytes()[0], 0U);
        secure::secret<32> assigned;
        assigned = std::move(moved);
        secure::secret<32> const copy = assigned.clone();
        BOOST_TEST_EQ(copy.bytes()[0], 0x42U);
        std::span<std::uint8_t const, 32> const viewed = copy;
        BOOST_TEST_EQ(viewed.size(), 32U);
        BOOST_TEST_EQ(secure::secret<32>::size(), 32U);
    });
}

void check_timing_guard() {
    bool volatile sink = false;
    expect_no_allocation("timing_guard", [&] {
        sink = secure::cpu_has_dit();
        {
            secure::timing_guard const engaged;
            sink = secure::dit_is_set();
            secure::timing_guard const nested(true);
            sink = secure::dit_is_set();
        }
        {
            secure::timing_guard const disengaged(false);
            sink = secure::dit_is_set();
        }
    });
    static_cast<void>(sink);
}

void check_declassify() {
    std::uint64_t verdict = 0x1234;
    bool flag = true;
    expect_no_allocation("declassify", [&] {
        secure::declassify(verdict);
        secure::declassify(flag);
    });
    BOOST_TEST_EQ(verdict, 0x1234U);
    BOOST_TEST(flag);
}

}  // namespace

int main() {
    std::printf("c_allocations_counted=%d\n", counting::c_allocations_counted ? 1 : 0);
    control_counts_every_form();
    check_constant_time_blocks();
    check_constant_time_equal();
    check_erase_secret();
    check_secret();
    check_timing_guard();
    check_declassify();
    return webcpp::test::exit_status(boost::report_errors());
}
