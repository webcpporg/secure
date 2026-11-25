// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `declassify`, which marks a value derived from secrets as public, where webcpp's code branches on
 it by design: the verdict of a tag's check.

 It does nothing in a program's build and includes nothing. A constant-time test defines
 `WEBCPP_SECURE_CT_VALGRIND` or `WEBCPP_SECURE_CT_MSAN`, and the mark is then Valgrind's or
 MemorySanitizer's, so that the checker reports every other branch on a secret and not this one.
*/
#ifndef WEBCPP_SECURE_DECLASSIFY_HPP
#define WEBCPP_SECURE_DECLASSIFY_HPP

#include <webcpp/secure/config.hpp>

#if defined(WEBCPP_SECURE_CT_VALGRIND) && defined(WEBCPP_SECURE_CT_MSAN)
#error "define WEBCPP_SECURE_CT_VALGRIND or WEBCPP_SECURE_CT_MSAN, not both"
#endif

#ifdef WEBCPP_SECURE_CT_VALGRIND
#include <valgrind/memcheck.h>
#elif defined(WEBCPP_SECURE_CT_MSAN)
#include <sanitizer/msan_interface.h>
#endif

#include <type_traits>

namespace webcpp::secure {

/**
 * Marks a value as public for the constant-time checkers; nothing in a program's build.
 *
 * The object is never const, so the branch that follows reads it again after the mark instead of
 * a register the compiler kept from before it (BoringSSL's practice).
 *
 * @tparam T The value's type, trivially copyable.
 * @param derived_value The value, derived from secrets, that the code branches on.
 */
template <class T>
    requires std::is_trivially_copyable_v<T> && (!std::is_const_v<T>)
void declassify(T& derived_value) noexcept {
#ifdef WEBCPP_SECURE_CT_VALGRIND
    static_cast<void>(VALGRIND_MAKE_MEM_DEFINED(&derived_value, sizeof derived_value));
#elif defined(WEBCPP_SECURE_CT_MSAN)
    __msan_unpoison(&derived_value, sizeof derived_value);
#else
    static_cast<void>(derived_value);
#endif
}

}  // namespace webcpp::secure

#endif  // WEBCPP_SECURE_DECLASSIFY_HPP
