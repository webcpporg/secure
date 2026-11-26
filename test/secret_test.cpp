// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// secret<N> is not copyable, clone copies by name, a move leaves the source zero, it converts to
// a span of fixed size, and its storage is zero after its destructor, read at -O2 (the Jamfile's
// <optimization>speed), where a store the optimiser may drop is the case.

#include <webcpp/secure/secret.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <span>
#include <type_traits>
#include <utility>

namespace {

namespace secure = webcpp::secure;

using key = secure::secret<32>;

static_assert(!std::is_copy_constructible_v<key>);
static_assert(!std::is_copy_assignable_v<key>);
static_assert(std::is_nothrow_move_constructible_v<key>);
static_assert(std::is_nothrow_move_assignable_v<key>);
static_assert(std::is_convertible_v<key const&, std::span<std::uint8_t const, 32>>);
static_assert(key::size() == 32 && key::size_bytes == 32);
static_assert(sizeof(key) == 32);

// A view of a secret that is about to die does not compile: it would dangle.
template <class T>
concept views_lvalue = requires(T& k) { k.bytes(); } && requires(T& k) { k.writable(); };
template <class T>
concept views_const_lvalue = requires(T const& k) { k.bytes(); };
template <class T>
concept writes_const_lvalue = requires(T const& k) { k.writable(); };
template <class T>
concept views_rvalue_bytes = requires { T{}.bytes(); };
template <class T>
concept views_rvalue_writable = requires { T{}.writable(); };
template <class T>
concept spans_rvalue = std::is_convertible_v<T, std::span<std::uint8_t const, 32>>;

static_assert(views_lvalue<key>);
static_assert(views_const_lvalue<key>);
static_assert(!writes_const_lvalue<key>);
static_assert(!views_rvalue_bytes<key>);
static_assert(!views_rvalue_writable<key>);
static_assert(!spans_rvalue<key>);

void fill(key& target, std::uint8_t first) {
    auto const bytes = target.writable();
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<std::uint8_t>(first + i);
    }
}

// A function the optimiser cannot see into, so that what it is handed is read from memory.
#if defined(_MSC_VER) && !defined(__clang__)
#define WEBCPP_TEST_NOINLINE __declspec(noinline)
#else
#define WEBCPP_TEST_NOINLINE __attribute__((noinline))
#endif

// Whether every byte at `where` is zero, read through a volatile pointer in a function that is
// never inlined: a store that was dropped before the call is found here. It may be handed the
// address of an object that is gone (the point of the destructor's check), so it is exempt from
// the sanitizers that would stop that read.
#if defined(__clang__) || defined(__GNUC__)
__attribute__((no_sanitize("address")))
#endif
WEBCPP_TEST_NOINLINE bool memory_is_zero(std::uint8_t const* where, std::size_t count) {
    auto const volatile* const bytes = where;
    for (std::size_t i = 0; i < count; ++i) {
        if (bytes[i] != 0) {
            return false;
        }
    }
    return true;
}

// The same, for a secret that is alive.
bool is_zero(key const& source) {
    return memory_is_zero(source.bytes().data(), source.bytes().size());
}

// A secret in a scope of its own, which a call the optimiser cannot see into is handed, is
// destroyed; its storage, in this frame, is read after the scope. A wipe that is a dead store
// (a plain write to an object about to die) is dropped by the optimiser and the bytes remain.
WEBCPP_TEST_NOINLINE bool destruction_leaves_zero() {
    std::uint8_t const* where = nullptr;
    {
        key local;
        fill(local, 1);
        where = local.bytes().data();
        if (memory_is_zero(where, key::size())) {
            return false;
        }
    }
    return memory_is_zero(where, key::size());
}

// Whether any byte of the storage is not zero, read through a volatile pointer.
bool any_set(std::array<std::byte, sizeof(key)> const& storage) {
    auto const* const bytes = reinterpret_cast<unsigned char const volatile*>(storage.data());
    for (std::size_t i = 0; i < storage.size(); ++i) {
        if (bytes[i] != 0) {
            return true;
        }
    }
    return false;
}

}  // namespace

int main() {
    // A new secret is zero.
    key const zero;
    BOOST_TEST(is_zero(zero));

    // A secret that is destroyed in an ordinary scope leaves zero behind, at -O2.
    BOOST_TEST(destruction_leaves_zero());

    // clone copies, and the two are then independent.
    key original;
    fill(original, 1);
    key copy = original.clone();
    BOOST_TEST(!is_zero(original));
    BOOST_TEST(std::equal(copy.bytes().begin(), copy.bytes().end(), original.bytes().begin()));
    copy.writable()[0] = 0xee;
    BOOST_TEST_EQ(original.bytes()[0], 1);

    // A move construction leaves the source zero and the destination with the bytes.
    key from;
    fill(from, 7);
    key const expected = from.clone();
    key const to(std::move(from));
    // NOLINTNEXTLINE(bugprone-use-after-move): a moved-from secret's bytes are what is tested
    BOOST_TEST(is_zero(from));
    BOOST_TEST(std::equal(to.bytes().begin(), to.bytes().end(), expected.bytes().begin()));

    // A move assignment does too, over the destination's own bytes.
    key assigned;
    fill(assigned, 100);
    key source;
    fill(source, 7);
    assigned = std::move(source);
    // NOLINTNEXTLINE(bugprone-use-after-move): a moved-from secret's bytes are what is tested
    BOOST_TEST(is_zero(source));
    BOOST_TEST(
        std::equal(assigned.bytes().begin(), assigned.bytes().end(), expected.bytes().begin()));

    // A move assignment to itself keeps the bytes; clone of a moved-from secret is zero.
    {
        key self;
        fill(self, 9);
        key& alias = self;
        self = std::move(alias);
        BOOST_TEST(!is_zero(self));
        BOOST_TEST_EQ(self.bytes()[0], 9);

        key gone;
        fill(gone, 5);
        key const taker(std::move(gone));
        // NOLINTNEXTLINE(bugprone-use-after-move): a moved-from secret's clone is what is tested
        key const empty = gone.clone();
        BOOST_TEST(is_zero(empty));
        BOOST_TEST(!is_zero(taker));
    }

    // The conversion to a span of fixed size views the same bytes.
    std::span<std::uint8_t const, 32> const view = expected;
    BOOST_TEST(view.data() == expected.bytes().data());
    BOOST_TEST_EQ(view.size(), 32u);

    // After the destructor, the storage is zero.
    alignas(key) std::array<std::byte, sizeof(key)> storage{};
    auto* const placed = new (storage.data()) key;
    fill(*placed, 1);
    BOOST_TEST(any_set(storage));
    std::destroy_at(placed);
    BOOST_TEST(!any_set(storage));

    return webcpp::test::exit_status(boost::report_errors());
}
