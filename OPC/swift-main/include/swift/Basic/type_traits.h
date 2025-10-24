//===--- type_traits.h - Type traits ----------------------------*- C++ -*-===//
//
// This source file is part of the Swift.org open source project
//
// Copyright (c) 2014 - 2017 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See https://swift.org/LICENSE.txt for license information
// See https://swift.org/CONTRIBUTORS.txt for the list of Swift project authors
//
//===----------------------------------------------------------------------===//

#ifndef SWIFT_BASIC_TYPETRAITS_H
#define SWIFT_BASIC_TYPETRAITS_H

#include <type_traits>
#include "swift/Basic/Compiler.h"

#ifndef __has_keyword
#define __has_keyword(__x) !(__is_identifier(__x))
#endif

#ifndef __has_feature
#define SWIFT_DEFINED_HAS_FEATURE
#define __has_feature(x) 0
#endif

namespace swift {

/// Same as \c std::is_trivially_copyable, which we cannot use directly
/// because it is not implemented yet in all C++11 standard libraries.
///
/// Unlike \c llvm::isPodLike, this trait should produce a precise result and
/// is not intended to be specialized.
template<typename T>
struct IsTriviallyCopyable {
#if defined(_LIBCPP_VERSION) || SWIFT_COMPILER_IS_MSVC
  // libc++ and MSVC implement is_trivially_copyable.
  static const bool value = std::is_trivially_copyable<T>::value;
#elif __has_feature(is_trivially_copyable) || __GNUC__ >= 5
  static const bool value = __is_trivially_copyable(T);
#else
#  error "Not implemented"
#endif
};

template<typename T>
struct IsTriviallyConstructible {
#if defined(_LIBCPP_VERSION) || SWIFT_COMPILER_IS_MSVC
  // libc++ and MSVC implement is_trivially_constructible.
  static const bool value = std::is_trivially_constructible<T>::value;
#elif __has_feature(is_trivially_constructible) || __has_keyword(__is_trivially_constructible)
  static const bool value = __is_trivially_constructible(T);
#elif __has_feature(has_trivial_constructor) || __GNUC__ >= 5
  static const bool value = __has_trivial_constructor(T);
#else
#  error "Not implemented"
#endif
};

template<typename T>
struct IsTriviallyDestructible {
#if defined(_LIBCPP_VERSION) || SWIFT_COMPILER_IS_MSVC
  // libc++ and MSVC implement is_trivially_destructible.
  static const bool value = std::is_trivially_destructible<T>::value;
#elif __has_feature(is_trivially_destructible) || __has_keyword(__is_trivially_destructible)
  static const bool value = __is_trivially_destructible(T);
#elif __has_feature(has_trivial_destructor) || __GNUC__ >= 5
  static const bool value = __has_trivial_destructor(T);
#else
#  error "Not implemented"
#endif
};

} // end namespace swift

#ifdef SWIFT_DEFINED_HAS_FEATURE
#undef __has_feature
#endif

#endif // SWIFT_BASIC_TYPETRAITS_H
