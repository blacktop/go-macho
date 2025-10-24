//===--- SwiftValue.h - Boxed Swift value class -----------------*- C++ -*-===//
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
// This implements the Objective-C class that is used to carry Swift values
// that have been bridged to Objective-C objects without special handling.
// The class is opaque to user code, but is `NSObject`- and `NSCopying`-
// conforming and is understood by the Swift runtime for dynamic casting
// back to the contained type.
//
//===----------------------------------------------------------------------===//

#ifndef SWIFT_RUNTIME_SWIFTVALUE_H
#define SWIFT_RUNTIME_SWIFTVALUE_H

#if SWIFT_OBJC_INTEROP
#include <objc/runtime.h>
#include "swift/Runtime/Metadata.h"

// __SwiftValue is an Objective-C class, but we shouldn't interface with it
// directly as such. Keep the type opaque.
#if __OBJC__
@class __SwiftValue;
#else
typedef struct __SwiftValue __SwiftValue;
#endif

namespace swift {

/// Bridge a Swift value to an Objective-C object by boxing it as a __SwiftValue.
__SwiftValue *bridgeAnythingToSwiftValueObject(OpaqueValue *src,
                                              const Metadata *srcType,
                                              bool consume);

/// Get the type metadata for a value in a Swift box.
const Metadata *getSwiftValueTypeMetadata(__SwiftValue *v);

/// Get the value out of a Swift box along with its type metadata. The value
/// inside the box is immutable and must not be modified or taken from the box.
std::pair<const Metadata *, const OpaqueValue *>
getValueFromSwiftValue(__SwiftValue *v);

/// Return the object reference as a __SwiftValue* if it is a __SwiftValue instance,
/// or nil if it is not.
__SwiftValue *getAsSwiftValue(id object);

/// Find conformances for SwiftValue to the given existential type.
///
/// Returns true if SwiftValue does conform to all the protocols.
bool findSwiftValueConformances(const ExistentialTypeMetadata *existentialType,
                                const WitnessTable **tablesBuffer);

} // namespace swift
#endif

#endif
