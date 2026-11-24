// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The configuration of secure, which each of its headers includes first: whether
 secure is built without exceptions.

 @see "Exceptions", in the guide.
*/
#ifndef WEBCPP_SECURE_CONFIG_HPP
#define WEBCPP_SECURE_CONFIG_HPP

#include <webcpp/config.hpp>

// MrDocs parses secure as a build with exceptions does, where the macro is not
// defined: this definition, undone at once, is the one the reference lists.
#ifdef __MRDOCS__
/**
 Defined when secure is built without exceptions: when webcpp has none (the
 compiler has none, or the developer defined `WEBCPP_NO_EXCEPTIONS` for every
 webcpp library), or when the developer defines it alone, to disable secure's
 in a build that has them.

 secure raises no exception: every function is `noexcept`, so the macro changes
 nothing in it. It is provided so that a program can set it for every webcpp
 library alike.

 @see "Exceptions", in the guide.
*/
#define WEBCPP_SECURE_NO_EXCEPTIONS
#undef WEBCPP_SECURE_NO_EXCEPTIONS
#endif

#if !defined(WEBCPP_HAS_EXCEPTIONS) && !defined(WEBCPP_SECURE_NO_EXCEPTIONS)
#define WEBCPP_SECURE_NO_EXCEPTIONS
#endif

/**
 The side-channel and secret-in-memory primitives that webcpp's libraries
 share.
*/
namespace webcpp::secure {
}  // namespace webcpp::secure

#endif  // WEBCPP_SECURE_CONFIG_HPP
