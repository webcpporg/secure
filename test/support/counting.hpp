// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Counts every allocation of the program that includes this header once (spec section 8.5):
// every form of the global operator new (plain, array, aligned, nothrow, aligned nothrow), and
// the C library's malloc, calloc, realloc, aligned_alloc and posix_memalign, where a program
// can see them: glibc's replaced and forwarded to its __libc_* functions, Emscripten's replaced
// and forwarded to its emscripten_builtin_* (its dlmalloc defines them weak), macOS's through
// malloc_logger, the hook libsystem_malloc calls on every allocation. The glibc functions
// memalign, valloc, pvalloc and reallocarray are not replaced and so not counted. WASI's
// wasi-libc defines malloc and its __libc_malloc in one object (dlmalloc.c.obj, measured with
// nm), so a program cannot replace one and keep the other, and MSVC's C runtime has no hook:
// there the C library's allocations are not counted, and c_allocations_counted says so, which
// the tests print.
// A block of operator new is counted twice where the C library is counted (once by new, once
// by the malloc it calls): every test compares a count before and after a window, so this
// changes no verdict. The replaced throwing operator new does not run the new_handler loop: a
// failed allocation throws std::bad_alloc (or aborts without exceptions) at once.
// Nothing here reads a thread_local: on macOS the first read of one on a thread allocates
// through dyld (_tlv_get_addr), inside malloc_logger, which recursed until the stack ended
// (N1: measured with a malloc_logger that read a thread_local, which crashed before main).
// On macOS the hook is installed at static initialisation, relies on the private malloc_logger
// symbol of libsystem_malloc, and overwrites any hook already there (MallocStackLogging's, a
// sanitizer's).

#ifndef WEBCPP_TEST_SECURE_SUPPORT_COUNTING_HPP
#define WEBCPP_TEST_SECURE_SUPPORT_COUNTING_HPP

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>

#include <boost/config.hpp>

#ifdef __APPLE__
#include <malloc/malloc.h>
#elif defined(__EMSCRIPTEN__)
#include <emscripten/heap.h>
#endif

namespace webcpp::secure::test {

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the replaced new's count
inline std::atomic<std::size_t> counted_new{0};
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the C library's count
inline std::atomic<std::size_t> counted_c{0};
static_assert(std::atomic<std::size_t>::is_always_lock_free,
              "the counters are called from inside the allocator and must not allocate or lock");

/** Every allocation counted so far: operator new's and the C library's. */
inline std::size_t allocations() {
    return counted_new.load() + counted_c.load();
}

/** Whether this target counts the C library's allocations too. */
inline constexpr bool c_allocations_counted =
#if defined(__GLIBC__) || defined(__EMSCRIPTEN__) || defined(__APPLE__)
    true;
#else
    false;
#endif

inline void count_c() noexcept {
    ++counted_c;
}

/**
 * Allocates for an operator new form: plain forms use malloc, aligned forms the aligned
 * allocator of the platform (on Windows always _aligned_malloc, so that _aligned_free matches).
 */
inline void* new_block(std::size_t size, std::size_t alignment, bool aligned) {
    ++counted_new;
    std::size_t const bytes = size == 0 ? 1 : size;
    if (!aligned) {
        return std::malloc(bytes);
    }
#ifdef _WIN32
    return _aligned_malloc(bytes, alignment);
#else
    alignment = std::max(alignment, sizeof(void*));  // posix_memalign's and macOS's minimum
    std::size_t const padded = bytes + alignment - 1;
    if (padded < bytes) {
        return nullptr;  // the rounding overflows: a failure, never a small block
    }
    return std::aligned_alloc(alignment, padded / alignment * alignment);
#endif
}

}  // namespace webcpp::secure::test

[[noreturn]] inline void webcpp_test_out_of_memory() {
#ifdef __cpp_exceptions
    throw std::bad_alloc();  // the replaced operator's contract
#else
    std::abort();
#endif
}

// The replaceable global allocation functions cannot be inline: they are defined here, in the
// one translation unit of a program that includes this header, under the standard's names. None is
// ever inlined: GCC 15 at -O3, seeing the malloc or the free inside one, pairs it with the other's
// call (a std::allocator's operator new, an exception's) and warns of a mismatch
// (-Wmismatched-new-delete), though both replaced forms use the C library.
// NOLINTBEGIN(misc-definitions-in-headers,readability-inconsistent-declaration-parameter-name)
BOOST_NOINLINE void* operator new(std::size_t size) {
    if (void* const p = webcpp::secure::test::new_block(size, alignof(std::max_align_t), false)) {
        return p;
    }
    webcpp_test_out_of_memory();
}

BOOST_NOINLINE void* operator new[](std::size_t size) {
    return operator new(size);
}

BOOST_NOINLINE void* operator new(std::size_t size, std::align_val_t alignment) {
    if (void* const p =
            webcpp::secure::test::new_block(size, static_cast<std::size_t>(alignment), true)) {
        return p;
    }
    webcpp_test_out_of_memory();
}

BOOST_NOINLINE void* operator new[](std::size_t size, std::align_val_t alignment) {
    return operator new(size, alignment);
}

BOOST_NOINLINE void* operator new(std::size_t size, std::nothrow_t const& /*unused*/) noexcept {
    return webcpp::secure::test::new_block(size, alignof(std::max_align_t), false);
}

BOOST_NOINLINE void* operator new[](std::size_t size, std::nothrow_t const& /*unused*/) noexcept {
    return webcpp::secure::test::new_block(size, alignof(std::max_align_t), false);
}

BOOST_NOINLINE void* operator new(std::size_t size, std::align_val_t alignment,
                                  std::nothrow_t const& /*unused*/) noexcept {
    return webcpp::secure::test::new_block(size, static_cast<std::size_t>(alignment), true);
}

BOOST_NOINLINE void* operator new[](std::size_t size, std::align_val_t alignment,
                                    std::nothrow_t const& /*unused*/) noexcept {
    return webcpp::secure::test::new_block(size, static_cast<std::size_t>(alignment), true);
}

BOOST_NOINLINE void operator delete(void* p) noexcept {
    std::free(p);
}

BOOST_NOINLINE void operator delete[](void* p) noexcept {
    std::free(p);
}

BOOST_NOINLINE void operator delete(void* p, std::size_t /*unused*/) noexcept {
    std::free(p);
}

BOOST_NOINLINE void operator delete[](void* p, std::size_t /*unused*/) noexcept {
    std::free(p);
}

BOOST_NOINLINE void operator delete(void* p, std::nothrow_t const& /*unused*/) noexcept {
    std::free(p);
}

BOOST_NOINLINE void operator delete[](void* p, std::nothrow_t const& /*unused*/) noexcept {
    std::free(p);
}
#ifdef _WIN32
BOOST_NOINLINE void operator delete(void* p, std::align_val_t /*unused*/) noexcept {
    _aligned_free(p);
}

BOOST_NOINLINE void operator delete[](void* p, std::align_val_t /*unused*/) noexcept {
    _aligned_free(p);
}

BOOST_NOINLINE void operator delete(void* p, std::size_t /*unused*/,
                                    std::align_val_t /*unused*/) noexcept {
    _aligned_free(p);
}

BOOST_NOINLINE void operator delete[](void* p, std::size_t /*unused*/,
                                      std::align_val_t /*unused*/) noexcept {
    _aligned_free(p);
}

BOOST_NOINLINE void operator delete(void* p, std::align_val_t /*unused*/,
                                    std::nothrow_t const& /*unused*/) noexcept {
    _aligned_free(p);
}

BOOST_NOINLINE void operator delete[](void* p, std::align_val_t /*unused*/,
                                      std::nothrow_t const& /*unused*/) noexcept {
    _aligned_free(p);
}
#else
BOOST_NOINLINE void operator delete(void* p, std::align_val_t /*unused*/) noexcept {
    std::free(p);
}

BOOST_NOINLINE void operator delete[](void* p, std::align_val_t /*unused*/) noexcept {
    std::free(p);
}

BOOST_NOINLINE void operator delete(void* p, std::size_t /*unused*/,
                                    std::align_val_t /*unused*/) noexcept {
    std::free(p);
}

BOOST_NOINLINE void operator delete[](void* p, std::size_t /*unused*/,
                                      std::align_val_t /*unused*/) noexcept {
    std::free(p);
}

BOOST_NOINLINE void operator delete(void* p, std::align_val_t /*unused*/,
                                    std::nothrow_t const& /*unused*/) noexcept {
    std::free(p);
}

BOOST_NOINLINE void operator delete[](void* p, std::align_val_t /*unused*/,
                                      std::nothrow_t const& /*unused*/) noexcept {
    std::free(p);
}
#endif
// NOLINTEND(misc-definitions-in-headers,readability-inconsistent-declaration-parameter-name)

#if defined(__GLIBC__) || defined(__EMSCRIPTEN__)
#ifdef __GLIBC__
extern "C" {
void* __libc_malloc(std::size_t);
void* __libc_calloc(std::size_t, std::size_t);
void* __libc_realloc(void*, std::size_t);
void* __libc_memalign(std::size_t, std::size_t);
void __libc_free(void*);
}
#define WEBCPP_TEST_C(name) __libc_##name
// glibc declares these with __THROW, noexcept in C++11 and later: a replacement must match.
#define WEBCPP_TEST_C_NOEXCEPT noexcept
#else
#define WEBCPP_TEST_C(name) emscripten_builtin_##name
// Emscripten's musl declares them without an exception specification.
#define WEBCPP_TEST_C_NOEXCEPT
#endif
// The C library's allocation functions, replaced for this program alone; cert-dcl58-cpp takes
// a replacement of what <cstdlib> declares for a change to namespace std.
// misc-definitions-in-headers: a replacement is a definition, and each test program includes
// this header in one translation unit.
// NOLINTBEGIN(misc-definitions-in-headers)
// NOLINTBEGIN(readability-inconsistent-declaration-parameter-name,cert-dcl58-cpp)
extern "C" {
void* malloc(std::size_t size) WEBCPP_TEST_C_NOEXCEPT {
    webcpp::secure::test::count_c();
    return WEBCPP_TEST_C(malloc)(size);
}

void* calloc(std::size_t count, std::size_t size) WEBCPP_TEST_C_NOEXCEPT {
    webcpp::secure::test::count_c();
    return WEBCPP_TEST_C(calloc)(count, size);
}

void* realloc(void* p, std::size_t size) WEBCPP_TEST_C_NOEXCEPT {
    webcpp::secure::test::count_c();
    return WEBCPP_TEST_C(realloc)(p, size);
}

void* aligned_alloc(std::size_t alignment, std::size_t size) WEBCPP_TEST_C_NOEXCEPT {
    webcpp::secure::test::count_c();
    return WEBCPP_TEST_C(memalign)(alignment, size);
}

int posix_memalign(void** p, std::size_t alignment, std::size_t size) WEBCPP_TEST_C_NOEXCEPT {
    webcpp::secure::test::count_c();
    *p = WEBCPP_TEST_C(memalign)(alignment, size);
    return *p == nullptr ? 12 /* ENOMEM */ : 0;
}

void free(void* p) WEBCPP_TEST_C_NOEXCEPT {
    WEBCPP_TEST_C(free)(p);
}
}
// NOLINTEND(readability-inconsistent-declaration-parameter-name,cert-dcl58-cpp)
// NOLINTEND(misc-definitions-in-headers)
#elif defined(__APPLE__)
// libsystem_malloc's hook, called on every allocation and release of the process.
using webcpp_test_malloc_logger = void(std::uint32_t, std::uintptr_t, std::uintptr_t,
                                       std::uintptr_t, std::uintptr_t, std::uint32_t);
extern "C" webcpp_test_malloc_logger* malloc_logger;

inline void webcpp_test_count_c_allocation(std::uint32_t type, std::uintptr_t /*unused*/,
                                           std::uintptr_t /*unused*/, std::uintptr_t /*unused*/,
                                           std::uintptr_t /*unused*/, std::uint32_t /*unused*/) {
    constexpr std::uint32_t allocate = 2;  // MALLOC_LOG_TYPE_ALLOCATE
    if ((type & allocate) != 0) {
        webcpp::secure::test::count_c();
    }
}

namespace webcpp::secure::test {
/** Installs the hook at static initialisation, before main, as this inline variable is defined. */
inline bool const logger_installed = (malloc_logger = &webcpp_test_count_c_allocation, true);
}  // namespace webcpp::secure::test
#endif

#endif
