// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Built with BOOST_DISABLE_ASSERTS (the Jamfile): with the size assertion off, the byte blocks
// that take two or three sequences of unequal sizes read and write nothing. equal_mask and
// less_mask give the zero mask; select_bytes leaves the destination as it was. In a constant
// expression a read past the sequences' storage would stop the build; at run time their data()
// is null, so a read would crash.

#include <webcpp/secure/constant_time.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#ifndef BOOST_DISABLE_ASSERTS
#error "constant_time_sizes_test is built with BOOST_DISABLE_ASSERTS"
#endif

namespace {

namespace constant_time = webcpp::secure::constant_time;

constexpr std::array<std::uint8_t, 1> one_byte{0};

/** A sequence of `size` bytes from one_byte's storage: reading past its first byte stops the build.
 */
constexpr std::span<std::uint8_t const> claimed(std::size_t size) {
    return {one_byte.data(), size};
}

static_assert(constant_time::equal_mask(claimed(31), claimed(32)) == 0);
static_assert(constant_time::equal_mask(claimed(1), claimed(0)) == 0);
static_assert(constant_time::less_mask(claimed(31), claimed(32)) == 0);
static_assert(constant_time::less_mask(claimed(0), claimed(1)) == 0);

constexpr bool select_bytes_writes_nothing() {
    std::array<std::uint8_t, 2> destination{7, 9};
    constant_time::select_bytes(0xFF, std::span(destination).first(1), claimed(31), claimed(1));
    constant_time::select_bytes(0x00, std::span(destination).first(1), claimed(1), claimed(32));
    constant_time::select_bytes(0xFF, destination, claimed(2), claimed(3));
    return destination[0] == 7 && destination[1] == 9;
}

static_assert(select_bytes_writes_nothing());

/** A span of `size` bytes whose data() is null: reading one would crash natively. */
std::span<std::uint8_t const> null_bytes(std::size_t size) {
    std::uint8_t const* const nowhere = nullptr;
    return {nowhere, size};
}

void at_run_time() {
    BOOST_TEST_EQ(constant_time::equal_mask(null_bytes(31), null_bytes(32)), 0);
    BOOST_TEST_EQ(constant_time::equal_mask(null_bytes(32), null_bytes(31)), 0);
    BOOST_TEST_EQ(constant_time::less_mask(null_bytes(31), null_bytes(32)), 0);
    BOOST_TEST_EQ(constant_time::less_mask(null_bytes(32), null_bytes(31)), 0);

    std::array<std::uint8_t, 32> destination{};
    destination.fill(0x5A);
    std::array<std::uint8_t, 31> const shorter{};
    std::array<std::uint8_t, 32> const longer{};
    constant_time::select_bytes(0xFF, destination, shorter, longer);
    constant_time::select_bytes(0x00, destination, longer, shorter);
    constant_time::select_bytes(0xFF, destination, null_bytes(31), null_bytes(31));
    for (std::uint8_t const byte : destination) {
        BOOST_TEST_EQ(byte, 0x5A);
    }
    std::uint8_t* const nowhere = nullptr;
    constant_time::select_bytes(0xFF, std::span<std::uint8_t>(nowhere, 31), longer, longer);
}

}  // namespace

int main() {
    at_run_time();
    return webcpp::test::exit_status(boost::report_errors());
}
