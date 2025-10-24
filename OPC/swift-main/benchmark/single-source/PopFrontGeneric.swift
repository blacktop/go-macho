//===--- PopFrontGeneric.swift --------------------------------------------===//
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

import TestsUtils

public let benchmarks =
  BenchmarkInfo(
    name: "PopFrontArrayGeneric",
    runFunction: run_PopFrontArrayGeneric,
    tags: [.validation, .api, .Array],
    legacyFactor: 20)

let arrayCount = 1024

// This test case exposes rdar://17440222 which caused rdar://17974483 (popFront
// being really slow).
protocol MyArrayBufferProtocol : MutableCollection, RandomAccessCollection {
  mutating func myReplace<C>(
    _ subRange: Range<Int>,
    with newValues: C
  ) where C : Collection, C.Element == Element
}

extension Array : MyArrayBufferProtocol {
  mutating func myReplace<C>(
    _ subRange: Range<Int>,
    with newValues: C
  ) where C : Collection, C.Element == Element {
    replaceSubrange(subRange, with: newValues)
  }
}

func myArrayReplace<
  B: MyArrayBufferProtocol,
  C: Collection
>(_ target: inout B, _ subRange: Range<Int>, _ newValues: C)
  where C.Element == B.Element, B.Index == Int {
  target.myReplace(subRange, with: newValues)
}

@inline(never)
public func run_PopFrontArrayGeneric(_ n: Int) {
  let orig = Array(repeating: 1, count: arrayCount)
  var a = [Int]()
  for _ in 1...n {
      var result = 0
      a.append(contentsOf: orig)
      while a.count != 0 {
        result += a[0]
        myArrayReplace(&a, 0..<1, EmptyCollection())
      }
      check(result == arrayCount)
  }
}
