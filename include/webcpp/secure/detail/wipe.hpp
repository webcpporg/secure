// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

#ifndef WEBCPP_SECURE_DETAIL_WIPE_HPP
#define WEBCPP_SECURE_DETAIL_WIPE_HPP

#include <webcpp/secure/config.hpp>

#include <atomic>
#include <cstddef>

#ifdef WEBCPP_SECURE_TEST_WIPE_RECORD
namespace webcpp::secure::test {

/**
 The test seam through which @ref webcpp::secure::detail::wipe reports each wipe. A program built
 with `WEBCPP_SECURE_TEST_WIPE_RECORD` defines this function, which each wipe calls once its
 bytes are zero, with what it wiped. A program built without the macro neither declares nor
 calls it.

 @param wiped_data The first byte wiped, or null when `byte_count` is 0.
 @param byte_count How many bytes.
*/
void wipe_record(void const* wiped_data, std::size_t byte_count) noexcept;

}  // namespace webcpp::secure::test
#endif

namespace webcpp::secure::detail {

/**
 Zeroes `byte_count` bytes at `wiped_data` with stores the optimiser cannot drop.

 Tip: a `memset` before an object dies is a dead store a compiler may remove; stores through a
 volatile pointer, then a signal fence, are kept.

 @param wiped_data The first byte, or null when `byte_count` is 0.
 @param byte_count How many bytes.
*/
inline void wipe(void* wiped_data, std::size_t byte_count) noexcept {
    auto* const wiped_bytes = static_cast<unsigned char volatile*>(wiped_data);
    for (std::size_t byte_index = 0; byte_index < byte_count; ++byte_index) {
        wiped_bytes[byte_index] = 0;
    }
    std::atomic_signal_fence(std::memory_order_seq_cst);
#ifdef WEBCPP_SECURE_TEST_WIPE_RECORD
    test::wipe_record(wiped_data, byte_count);
#endif
}

}  // namespace webcpp::secure::detail

#endif  // WEBCPP_SECURE_DETAIL_WIPE_HPP
