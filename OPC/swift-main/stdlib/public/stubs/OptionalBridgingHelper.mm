//===----------------------------------------------------------------------===//
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

#include "swift/Runtime/Config.h"

#if SWIFT_OBJC_INTEROP
#include "swift/Basic/Lazy.h"
#include "swift/Runtime/Metadata.h"
#include "swift/Runtime/ObjCBridge.h"
#include "swift/Runtime/Portability.h"
#include "swift/Threading/Mutex.h"
#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#include <vector>

using namespace swift;

/// Class of sentinel objects used to represent the `nil` value of nested
/// optionals.
///
/// NOTE: older runtimes called this _SwiftNull. The two must
/// coexist, so it was renamed. The old name must not be used in the new
/// runtime.
@interface __SwiftNull : NSObject {
@public
  unsigned depth;
}
@end



@implementation __SwiftNull : NSObject

- (id)description {
  char *str = NULL;
  const char *clsName = class_getName([self class]);
  int fmtResult = swift_asprintf(&str, "<%s %p depth = %u>", clsName,
                                                       (void*)self,
                                                       self->depth);
  (void)fmtResult;
  assert(fmtResult != -1 && "unable to format description of null");
  id result = swift_stdlib_NSStringFromUTF8(str, strlen(str));
  free(str);
  return result;
}

@end

namespace {

struct SwiftNullSentinelCache {
  std::vector<id> Cache;
  Mutex Lock;
};

static Lazy<SwiftNullSentinelCache> Sentinels;

static id getSentinelForDepth(unsigned depth) {
  // For unnested optionals, use NSNull.
  if (depth == 1)
    return SWIFT_LAZY_CONSTANT(id_const_cast([objc_getClass("NSNull") null]));
  // Otherwise, make up our own sentinel.
  // See if we created one for this depth.
  auto &theSentinels = Sentinels.get();
  unsigned depthIndex = depth - 2;
  {
    Mutex::ScopedLock lock(theSentinels.Lock);
    const auto &cache = theSentinels.Cache;
    if (depthIndex < cache.size()) {
      id cached = cache[depthIndex];
      if (cached)
        return cached;
    }
  }
  // Make one if we need to.
  {
    Mutex::ScopedLock lock(theSentinels.Lock);
    if (depthIndex >= theSentinels.Cache.size())
      theSentinels.Cache.resize(depthIndex + 1);
    auto &cached = theSentinels.Cache[depthIndex];
    // Make sure another writer didn't sneak in.
    if (!cached) {
      auto sentinel = [[__SwiftNull alloc] init];
      sentinel->depth = depth;
      cached = sentinel;
    }
    return cached;
  }
}

}

/// Return the sentinel object to use to represent `nil` for a given Optional
/// type.
SWIFT_RUNTIME_STDLIB_API SWIFT_CC(swift)
id _swift_Foundation_getOptionalNilSentinelObject(const Metadata *Wrapped) {
  // Figure out the depth of optionality we're working with.
  unsigned depth = 1;
  while (Wrapped->getKind() == MetadataKind::Optional) {
    ++depth;
    Wrapped = cast<EnumMetadata>(Wrapped)->getGenericArgs()[0];
  }

  return objc_retain(getSentinelForDepth(depth));
}
#endif

