//===--- ObjectiveCNoBridgingStubs.swift ----------------------------------===//
//
// This source file is part of the Swift.org open source project
//
// Copyright (c) 2014 - 2021 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See https://swift.org/LICENSE.txt for license information
// See https://swift.org/CONTRIBUTORS.txt for the list of Swift project authors
//
//===----------------------------------------------------------------------===//
//
// This file is compiled with -Xfrontend -disable-swift-bridge-attr. No bridging
// of swift types happens.
//
//===----------------------------------------------------------------------===//

import TestsUtils
import Foundation
#if _runtime(_ObjC)
import ObjectiveCTests
#endif

let t: [BenchmarkCategory] = [.validation, .bridging, .cpubench]

public let benchmarks = [
  BenchmarkInfo(name: "ObjectiveCBridgeStubToNSStringRef",
    runFunction: run_ObjectiveCBridgeStubToNSStringRef, tags: t),
  BenchmarkInfo(name: "ObjectiveCBridgeStubToNSDateRef",
    runFunction: run_ObjectiveCBridgeStubToNSDateRef, tags: t,
    legacyFactor: 20),
  BenchmarkInfo(name: "ObjectiveCBridgeStubNSDateRefAccess",
    runFunction: run_ObjectiveCBridgeStubNSDateRefAccess, tags: t),
  BenchmarkInfo(name: "ObjectiveCBridgeStubNSDateMutationRef",
    runFunction: run_ObjectiveCBridgeStubNSDateMutationRef, tags: t,
    legacyFactor: 4),
  BenchmarkInfo(name: "ObjectiveCBridgeStubNSDataAppend",
    runFunction: run_ObjectiveCBridgeStubNSDataAppend, tags: t,
    legacyFactor: 10),
  BenchmarkInfo(name: "ObjectiveCBridgeStubFromNSStringRef",
    runFunction: run_ObjectiveCBridgeStubFromNSStringRef, tags: t),
  BenchmarkInfo(name: "ObjectiveCBridgeStubFromNSDateRef",
    runFunction: run_ObjectiveCBridgeStubFromNSDateRef, tags: t,
    legacyFactor: 10),
  BenchmarkInfo(name: "ObjectiveCBridgeStubURLAppendPathRef2",
    runFunction: run_ObjectiveCBridgeStubURLAppendPathRef, tags: t,
    legacyFactor: 10),
]

#if _runtime(_ObjC)
@inline(never)
func testObjectiveCBridgeStubFromNSStringRef() {
  let b = BridgeTester()
  var nsString : NSString = NSString()
  for _ in 0 ..< 10_000 {
    nsString = b.testToString()
  }
  check(nsString.isEqual(to: "Default string value no tagged pointer" as NSString))
}
#endif

@inline(never)
public func run_ObjectiveCBridgeStubFromNSStringRef(n: Int) {
#if _runtime(_ObjC)
  for _ in 0 ..< n {
    autoreleasepool {
      testObjectiveCBridgeStubFromNSStringRef()
    }
  }
#endif
}

#if _runtime(_ObjC)
@inline(never)
func testObjectiveCBridgeStubToNSStringRef() {
   let b = BridgeTester()
   let str = NSString(cString: "hello world", encoding: String.Encoding.utf8.rawValue)!
   for _ in 0 ..< 10_000 {
     b.test(from: str)
   }
}
#endif

@inline(never)
public func run_ObjectiveCBridgeStubToNSStringRef(n: Int) {
#if _runtime(_ObjC)
  for _ in 0 ..< n {
    autoreleasepool {
      testObjectiveCBridgeStubToNSStringRef()
    }
  }
#endif
}
#if _runtime(_ObjC)
@inline(never)
func testObjectiveCBridgeStubFromNSDateRef() {
  let b = BridgeTester()
  for _ in 0 ..< 10_000 {
    let bridgedBegin = b.beginDate()
    let bridgedEnd = b.endDate()
    let _ = bridgedEnd.timeIntervalSince(bridgedBegin)
  }
}
#endif

@inline(never)
public func run_ObjectiveCBridgeStubFromNSDateRef(n: Int) {
#if _runtime(_ObjC)
  autoreleasepool {
    for _ in 0 ..< n {
      testObjectiveCBridgeStubFromNSDateRef()
    }
  }
#endif
}

#if _runtime(_ObjC)
@inline(never)
public func testObjectiveCBridgeStubToNSDateRef() {
  let b = BridgeTester()
  let d = NSDate()
  for _ in 0 ..< 1_000 {
    b.use(d)
  }
}
#endif

@inline(never)
public func run_ObjectiveCBridgeStubToNSDateRef(n: Int) {
#if _runtime(_ObjC)
  for _ in 0 ..< 5 * n {
    autoreleasepool {
      testObjectiveCBridgeStubToNSDateRef()
    }
  }
#endif
}


#if _runtime(_ObjC)
@inline(never)
func testObjectiveCBridgeStubNSDateRefAccess() {
  var remainders = 0.0
  let d = NSDate()
  for _ in 0 ..< 100_000 {
    remainders += d.timeIntervalSinceReferenceDate.truncatingRemainder(dividingBy: 10)
  }
}
#endif

@inline(never)
public func run_ObjectiveCBridgeStubNSDateRefAccess(n: Int) {
#if _runtime(_ObjC)
  for _ in 0 ..< n {
    autoreleasepool {
      testObjectiveCBridgeStubNSDateRefAccess()
    }
  }
#endif
}

#if _runtime(_ObjC)
@inline(never)
func testObjectiveCBridgeStubNSDateMutationRef() {
  var d = NSDate()
  for _ in 0 ..< 25 {
      d = d.addingTimeInterval(1)
  }
}
#endif

@inline(never)
public func run_ObjectiveCBridgeStubNSDateMutationRef(n: Int) {
#if _runtime(_ObjC)
  for _ in 0 ..< 100 * n {
    autoreleasepool {
      testObjectiveCBridgeStubNSDateMutationRef()
    }
  }
#endif
}

#if _runtime(_ObjC)
@inline(never)
func testObjectiveCBridgeStubURLAppendPathRef() {
  let startUrl = URL(string: "/")!
  for _ in 0 ..< 10 {
    var url = startUrl
    for _ in 0 ..< 10 {
      url = url.appendingPathComponent("foo")
    }
  }
}
#endif

@inline(never)
public func run_ObjectiveCBridgeStubURLAppendPathRef(n: Int) {
#if _runtime(_ObjC)
  for _ in 0 ..< n {
   autoreleasepool {
     testObjectiveCBridgeStubURLAppendPathRef()
   }
  }
#endif
}

#if _runtime(_ObjC)
@inline(never)
func testObjectiveCBridgeStubNSDataAppend() {
  let proto = NSMutableData()
  var value: UInt8 = 1
  for _ in 0 ..< 100 {
    let d = proto.mutableCopy() as! NSMutableData
    for _ in 0 ..< 100 {
       d.append(&value, length: 1)
    }
  }
}
#endif

@inline(never)
public func run_ObjectiveCBridgeStubNSDataAppend(n: Int) {
#if _runtime(_ObjC)
  for _ in 0 ..< n {
    autoreleasepool {
      testObjectiveCBridgeStubNSDataAppend()
    }
  }
#endif
}
