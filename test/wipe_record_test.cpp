// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The wipe's test seam: built with WEBCPP_SECURE_TEST_WIPE_RECORD, every wipe is reported to this
// test once, after its bytes are zero, with the address and the size it wiped. The test checks
// what erase_secret and secret<N> report: one record for an erased range, one for a destroyed
// secret, two for a move assignment (the target before it takes the bytes, the source after),
// one for a move construction, and one of size 0 for an empty range.

#include <webcpp/secure/detail/wipe.hpp>
#include <webcpp/secure/erase_secret.hpp>
#include <webcpp/secure/secret.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <span>
#include <utility>

#ifndef WEBCPP_SECURE_TEST_WIPE_RECORD
#error "wipe_record_test is built with WEBCPP_SECURE_TEST_WIPE_RECORD (test/Jamfile)"
#endif

namespace {

namespace secure = webcpp::secure;

// One wipe: where, how many bytes, and whether they read zero when it was reported.
struct wipe_entry {
    void const* at = nullptr;
    std::size_t size = 0;
    bool zero = false;
};

// The wipes reported since the last clear.
struct record {
    std::array<wipe_entry, 16> entries{};
    std::size_t count = 0;
};

// The seam's record, which detail::wipe reaches through a function of this test.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the seam's record
record wipes;

void clear() {
    wipes = record{};
}

}  // namespace

void webcpp::secure::test::wipe_record(void const* wiped_data, std::size_t byte_count) noexcept {
    bool zero = true;
    auto const* const bytes = static_cast<unsigned char const*>(wiped_data);
    for (std::size_t i = 0; i < byte_count; ++i) {
        if (bytes[i] != 0) {
            zero = false;
            break;
        }
    }
    if (wipes.count < wipes.entries.size()) {
        wipes.entries[wipes.count] = wipe_entry{.at = wiped_data, .size = byte_count, .zero = zero};
    }
    ++wipes.count;
}

namespace {

struct context {
    std::uint64_t key[4];  // NOLINT(modernize-avoid-c-arrays): a C library's plain state
};

void test_erase_array() {
    std::array<std::uint8_t, 32> bytes{};
    bytes.fill(0xa5);
    clear();
    secure::erase_secret(bytes);
    BOOST_TEST_EQ(wipes.count, 1U);
    BOOST_TEST(wipes.entries[0].at == bytes.data());
    BOOST_TEST_EQ(wipes.entries[0].size, 32U);
    BOOST_TEST(wipes.entries[0].zero);
}

void test_erase_span_of_object() {
    context object{{1, 2, 3, 4}};
    clear();
    secure::erase_secret(std::span(&object, 1));
    BOOST_TEST_EQ(wipes.count, 1U);
    BOOST_TEST(wipes.entries[0].at == &object);
    BOOST_TEST_EQ(wipes.entries[0].size, sizeof(context));
    BOOST_TEST(wipes.entries[0].zero);
    BOOST_TEST_EQ(object.key[0] | object.key[1] | object.key[2] | object.key[3], 0U);
}

void test_erase_subspan() {
    std::array<std::uint8_t, 34> framed{};
    framed.fill(0xa5);
    clear();
    secure::erase_secret(std::span<std::uint8_t>(framed).subspan(1, 32));
    BOOST_TEST_EQ(wipes.count, 1U);
    BOOST_TEST(wipes.entries[0].at == framed.data() + 1);
    BOOST_TEST_EQ(wipes.entries[0].size, 32U);
    BOOST_TEST(wipes.entries[0].zero);
    BOOST_TEST_EQ(framed.front(), 0xa5);
    BOOST_TEST_EQ(framed.back(), 0xa5);
}

// An empty range is one report of size 0: the wipe is called, and has no byte to write.
void test_erase_empty() {
    clear();
    secure::erase_secret(std::span<std::uint8_t>());
    BOOST_TEST_EQ(wipes.count, 1U);
    BOOST_TEST(wipes.entries[0].at == nullptr);
    BOOST_TEST_EQ(wipes.entries[0].size, 0U);
    BOOST_TEST(wipes.entries[0].zero);

    clear();
    secure::detail::wipe(nullptr, 0);
    BOOST_TEST_EQ(wipes.count, 1U);
    BOOST_TEST_EQ(wipes.entries[0].size, 0U);
}

void test_destroy_secret() {
    alignas(secure::secret<16>) std::array<std::byte, sizeof(secure::secret<16>)> storage{};
    auto* const placed = new (storage.data()) secure::secret<16>;
    for (auto& byte : placed->writable()) {
        byte = 0x5a;
    }
    clear();
    std::destroy_at(placed);
    BOOST_TEST_EQ(wipes.count, 1U);
    BOOST_TEST(wipes.entries[0].at == storage.data());
    BOOST_TEST_EQ(wipes.entries[0].size, 16U);
    BOOST_TEST(wipes.entries[0].zero);
}

void test_move_secret() {
    secure::secret<16> source;
    secure::secret<16> target;
    for (auto& byte : source.writable()) {
        byte = 0x5a;
    }
    for (auto& byte : target.writable()) {
        byte = 0xc3;
    }
    void const* const source_at = &source;
    void const* const target_at = &target;
    clear();
    target = std::move(source);
    // The target's old bytes first, then the source after the move.
    BOOST_TEST_EQ(wipes.count, 2U);
    BOOST_TEST(wipes.entries[0].at == target_at);
    BOOST_TEST(wipes.entries[1].at == source_at);
    for (std::size_t i = 0; i < 2; ++i) {
        BOOST_TEST_EQ(wipes.entries[i].size, 16U);
        BOOST_TEST(wipes.entries[i].zero);
    }
    BOOST_TEST_EQ(target.bytes()[0], 0x5a);

    clear();
    secure::secret<16> const taker(std::move(target));
    BOOST_TEST_EQ(wipes.count, 1U);
    BOOST_TEST(wipes.entries[0].at == target_at);
    BOOST_TEST_EQ(wipes.entries[0].size, 16U);
    BOOST_TEST(wipes.entries[0].zero);
    BOOST_TEST_EQ(taker.bytes()[0], 0x5a);
}

}  // namespace

int main() {
    test_erase_array();
    test_erase_span_of_object();
    test_erase_subspan();
    test_erase_empty();
    test_destroy_secret();
    test_move_secret();
    return webcpp::test::exit_status(boost::report_errors());
}
