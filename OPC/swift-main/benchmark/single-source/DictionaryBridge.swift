//===--- DictionaryBridge.swift -------------------------------------------===//
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

// benchmark to test the performance of bridging an NSDictionary to a
// Swift.Dictionary.

import Foundation
import TestsUtils

public let benchmarks =
  BenchmarkInfo(
    name: "DictionaryBridge",
    runFunction: run_DictionaryBridge,
    tags: [.validation, .api, .Dictionary, .bridging])

#if _runtime(_ObjC)
class Thing : NSObject {

  required override init() {
    let c = type(of: self).col()
    check(c!.count == 10)
  }

  private class func col() -> [String : AnyObject]? {
    let dict = NSMutableDictionary()
    dict.setValue(1, forKey: "one")
    dict.setValue(2, forKey: "two")
    dict.setValue(3, forKey: "three")
    dict.setValue(4, forKey: "four")
    dict.setValue(5, forKey: "five")
    dict.setValue(6, forKey: "six")
    dict.setValue(7, forKey: "seven")
    dict.setValue(8, forKey: "eight")
    dict.setValue(9, forKey: "nine")
    dict.setValue(10, forKey: "ten")

    return NSDictionary(dictionary: dict) as? [String: AnyObject]
  }

  class func mk() -> Thing {
    return self.init()
  }
}

class Stuff {
  var c: Thing = Thing.mk()
  init() {

  }
}
#endif

@inline(never)
public func run_DictionaryBridge(_ n: Int) {
#if _runtime(_ObjC)
    for _ in 1...100*n {
      autoreleasepool {
        _ = Stuff()
      }
    }
#endif
}
