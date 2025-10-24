//===--- Once.h - Runtime support for lazy initialization -------*- C++ -*-===//
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
//
// Swift runtime functions in support of lazy initialization.
//
//===----------------------------------------------------------------------===//

#ifndef SWIFT_RUNTIME_ONCE_BACKDEPLOY56_H
#define SWIFT_RUNTIME_ONCE_BACKDEPLOY56_H

#include "swift/Runtime/HeapObject.h"
#include <mutex>

namespace swift {

#ifdef SWIFT_STDLIB_SINGLE_THREADED_RUNTIME

typedef bool swift_once_t;

#elif defined(__APPLE__)

// On OS X and iOS, swift_once_t matches dispatch_once_t.
typedef long swift_once_t;

#elif defined(__CYGWIN__)

// On Cygwin, std::once_flag can not be used because it is larger than the
// platform word.
typedef uintptr_t swift_once_t;
#else

// On other platforms swift_once_t is std::once_flag
typedef std::once_flag swift_once_t;

#endif

/// Runs the given function with the given context argument exactly once.
/// The predicate argument must point to a global or static variable of static
/// extent of type swift_once_t.
void swift_once(swift_once_t *predicate, void (*fn)(void *), void *context);

}

#endif // SWIFT_RUNTIME_ONCE_BACKDEPLOY56_H
