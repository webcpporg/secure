// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// constant_time_equal compares any two byte sequences (spans, arrays of bytes, secrets, string
// views, Boost.Hash2 digests), tells them apart by any bit, calls sequences of different sizes
// unequal without reading them, and enters the guard of <webcpp/secure/timing_guard.hpp> once
// per call, from its own header.

#include "support/timing_seam.hpp"

#include <webcpp/secure/constant_time_equal.hpp>
#include <webcpp/secure/secret.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/digest.hpp>
#include <boost/hash2/hmac.hpp>
#include <boost/hash2/sha2.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <list>
#include <span>
#include <string_view>
#include <vector>

namespace {

namespace secure = webcpp::secure;
namespace seam = webcpp::secure::test;

static_assert(!secure::detail::byte_sequence<std::list<char>>);
static_assert(!secure::detail::byte_sequence<std::vector<std::uint16_t>>);
static_assert(!secure::detail::byte_sequence<int>);
static_assert(secure::detail::byte_sequence<secure::secret<32>>);
static_assert(secure::detail::byte_sequence<std::string_view>);
static_assert(secure::detail::byte_sequence<boost::hash2::digest<32>>);
static_assert(secure::detail::byte_sequence<std::array<std::byte, 32>>);
static_assert(secure::detail::byte_sequence<std::span<std::uint8_t const>>);

/** A sequence with no storage that claims `size()` elements: reading one would crash. */
struct null_sequence {
    std::size_t claimed;

    [[nodiscard]] static unsigned char const* begin() noexcept { return nullptr; }

    [[nodiscard]] static unsigned char const* end() noexcept { return nullptr; }

    [[nodiscard]] static unsigned char const* data() noexcept { return nullptr; }

    [[nodiscard]] std::size_t size() const noexcept { return claimed; }
};

static_assert(secure::detail::byte_sequence<null_sequence>);

/** A type whose `bytes()` returns its bytes by value, as crypto's ed25519 public key does. */
struct by_value_bytes {
    std::array<std::uint8_t, 32> stored;

    [[nodiscard]] std::array<std::uint8_t, 32> bytes() const { return stored; }
};

static_assert(secure::detail::byte_sequence<by_value_bytes>);

secure::secret<32> make_secret(std::uint8_t first) {
    secure::secret<32> made;
    auto const bytes = made.writable();
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<std::uint8_t>(first + i);
    }
    return made;
}

std::array<std::uint8_t, 32> base_bytes() {
    std::array<std::uint8_t, 32> bytes{};
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<std::uint8_t>(0x80U + i);
    }
    return bytes;
}

/** Checks a representation of the base sequence against each of its one-bit flips. */
template <class Make>
void check_flips(Make make) {
    auto const base = base_bytes();
    auto const same = make(base);
    BOOST_TEST(secure::constant_time_equal(same, make(base)));
    for (std::size_t byte = 0; byte < base.size(); ++byte) {
        for (unsigned bit = 0; bit < 8; ++bit) {
            auto flipped = base;
            flipped[byte] ^= static_cast<std::uint8_t>(1U << bit);
            BOOST_TEST(!secure::constant_time_equal(same, make(flipped)));
            BOOST_TEST(!secure::constant_time_equal(make(flipped), same));
        }
    }
}

void shapes() {
    check_flips([](std::array<std::uint8_t, 32> const& bytes) {
        return std::span<std::uint8_t const>(bytes);
    });
    check_flips([](std::array<std::uint8_t, 32> const& bytes) { return bytes; });
    check_flips([](std::array<std::uint8_t, 32> const& bytes) {
        std::array<std::byte, 32> made{};
        for (std::size_t i = 0; i < made.size(); ++i) {
            made[i] = static_cast<std::byte>(bytes[i]);
        }
        return made;
    });
    check_flips([](std::array<std::uint8_t, 32> const& bytes) {
        secure::secret<32> made;
        std::ranges::copy(bytes, made.writable().begin());
        return made;
    });
    check_flips([](std::array<std::uint8_t, 32> const& bytes) {
        boost::hash2::digest<32> made{};
        std::ranges::copy(bytes, made.data());
        return made;
    });
    check_flips([](std::array<std::uint8_t, 32> const& bytes) {
        return std::vector<unsigned char>(bytes.begin(), bytes.end());
    });
    // A std::string_view of bytes 0x80 to 0x9F: char is signed on most targets.
    static constexpr std::string_view high =
        "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
        "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f";
    static_assert(high.size() == 32);
    BOOST_TEST(secure::constant_time_equal(high, high));
    BOOST_TEST(secure::constant_time_equal(high, base_bytes()));
    for (std::size_t byte = 0; byte < high.size(); ++byte) {
        for (unsigned bit = 0; bit < 8; ++bit) {
            auto flipped = base_bytes();
            flipped[byte] ^= static_cast<std::uint8_t>(1U << bit);
            BOOST_TEST(!secure::constant_time_equal(high, flipped));
            BOOST_TEST(!secure::constant_time_equal(flipped, high));
        }
    }
}

void mixed_pairs() {
    auto const base = base_bytes();
    boost::hash2::digest<32> digest{};
    std::ranges::copy(base, digest.data());
    BOOST_TEST(secure::constant_time_equal(digest, base));
    BOOST_TEST(secure::constant_time_equal(base, digest));
    secure::secret<32> const secret_bytes = make_secret(0x80);
    BOOST_TEST(secure::constant_time_equal(secret_bytes, std::span<std::uint8_t const>(base)));
    BOOST_TEST(secure::constant_time_equal(std::span<std::uint8_t const>(base), secret_bytes));
    // A temporary secret, bound to the const& for the call.
    BOOST_TEST(secure::constant_time_equal(make_secret(0x80), base));
    BOOST_TEST(!secure::constant_time_equal(make_secret(0x81), base));
    BOOST_TEST(secure::constant_time_equal(make_secret(1), make_secret(1)));
    BOOST_TEST(!secure::constant_time_equal(make_secret(1), make_secret(2)));
    BOOST_TEST(secure::constant_time_equal(secret_bytes, digest));
}

void bytes_by_value() {
    auto const base = base_bytes();
    by_value_bytes const same{base};
    BOOST_TEST(secure::constant_time_equal(same, by_value_bytes{base}));
    BOOST_TEST(secure::constant_time_equal(same, same));
    BOOST_TEST(secure::constant_time_equal(same, std::span<std::uint8_t const>(base)));
    BOOST_TEST(secure::constant_time_equal(std::span<std::uint8_t const>(base), same));
    for (std::size_t byte = 0; byte < base.size(); ++byte) {
        for (unsigned bit = 0; bit < 8; ++bit) {
            auto flipped = base;
            flipped[byte] ^= static_cast<std::uint8_t>(1U << bit);
            BOOST_TEST(!secure::constant_time_equal(same, by_value_bytes{flipped}));
            BOOST_TEST(!secure::constant_time_equal(same, std::span<std::uint8_t const>(flipped)));
            BOOST_TEST(!secure::constant_time_equal(std::span<std::uint8_t const>(flipped), same));
        }
    }
}

void sizes() {
    std::array<std::uint8_t, 32> const thirty_two = base_bytes();
    std::span<std::uint8_t const> const thirty_one(thirty_two.data(), 31);
    BOOST_TEST(!secure::constant_time_equal(thirty_one, thirty_two));
    BOOST_TEST(!secure::constant_time_equal(thirty_two, thirty_one));
    // Sizes are compared first: no byte of a sequence with no storage is read.
    BOOST_TEST(!secure::constant_time_equal(null_sequence{31}, thirty_two));
    BOOST_TEST(!secure::constant_time_equal(thirty_two, null_sequence{31}));
    BOOST_TEST(secure::constant_time_equal(null_sequence{0}, std::span<std::uint8_t const>()));
    BOOST_TEST(secure::constant_time_equal(std::span<std::uint8_t const>(),
                                           std::span<std::uint8_t const>()));
    boost::hash2::digest<16> const sixteen{};
    std::array<std::uint8_t, 15> const fifteen{};
    BOOST_TEST(!secure::constant_time_equal(sixteen, fifteen));
}

void guard_through_the_seam() {
    std::array<std::uint8_t, 32> const bytes = base_bytes();
    seam::timing_entries = 0;
    seam::timing_first_entry = nullptr;
    BOOST_TEST(secure::constant_time_equal(bytes, bytes));
    BOOST_TEST_EQ(seam::timing_entries, 1U);
    BOOST_TEST(seam::timing_first_entry != nullptr);
    if (seam::timing_first_entry != nullptr) {
        BOOST_TEST(std::string_view(seam::timing_first_entry).find("constant_time_equal") !=
                   std::string_view::npos);
    }
    // Each call is one guard, equal or not, and with unequal sizes too.
    seam::timing_entries = 0;
    BOOST_TEST(
        !secure::constant_time_equal(bytes, std::span<std::uint8_t const>(bytes.data(), 31)));
    BOOST_TEST_EQ(seam::timing_entries, 1U);
    BOOST_TEST(secure::constant_time_equal(make_secret(3), make_secret(3)));
    BOOST_TEST_EQ(seam::timing_entries, 2U);
}

}  // namespace

int main() {
    // The prior's cases: digests, arrays, spans, Hash2's MAC.
    boost::hash2::digest<16> const a{};
    boost::hash2::digest<16> b{};
    BOOST_TEST(secure::constant_time_equal(a, b));
    for (std::size_t i = 0; i < a.size(); ++i) {
        for (unsigned bit = 0; bit < 8; ++bit) {
            b = a;
            b.data()[i] ^= static_cast<unsigned char>(1U << bit);
            BOOST_TEST(!secure::constant_time_equal(a, b));
        }
    }
    std::array<std::uint8_t, 16> const array{};
    BOOST_TEST(secure::constant_time_equal(a, array));
    std::array<std::uint8_t, 8> const eight{1, 2, 3, 4, 5, 6, 7, 8};
    auto different_first = eight;
    different_first.front() ^= 0x80U;
    auto different_last = eight;
    different_last.back() ^= 0x01U;
    BOOST_TEST(secure::constant_time_equal(std::span<std::uint8_t const>(eight), std::span(eight)));
    BOOST_TEST(!secure::constant_time_equal(std::span<std::uint8_t const>(eight),
                                            std::span(different_first)));
    BOOST_TEST(!secure::constant_time_equal(std::span<std::uint8_t const>(eight),
                                            std::span(different_last)));
    boost::hash2::digest<32> const first_digest{};
    boost::hash2::digest<32> second_digest{};
    BOOST_TEST(secure::constant_time_equal(first_digest, second_digest));
    second_digest.data()[31] = 1;
    BOOST_TEST(!secure::constant_time_equal(first_digest, second_digest));
    boost::hash2::hmac_sha2_256 first(reinterpret_cast<unsigned char const*>("key"), 3);
    boost::hash2::hmac_sha2_256 second(reinterpret_cast<unsigned char const*>("key"), 3);
    first.update("message", 7);
    second.update("message", 7);
    BOOST_TEST(secure::constant_time_equal(first.result(), second.result()));

    shapes();
    mixed_pairs();
    bytes_by_value();
    sizes();
    guard_through_the_seam();
    return webcpp::test::exit_status(boost::report_errors());
}
