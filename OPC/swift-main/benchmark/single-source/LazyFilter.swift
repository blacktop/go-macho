//===--- LazyFilter.swift -------------------------------------------------===//
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

// This test checks performance of creating an array from lazily filtered
// collections.
import TestsUtils

public let benchmarks = [
  BenchmarkInfo(name: "LazilyFilteredArrays2",
    runFunction: run_LazilyFilteredArrays,
    tags: [.validation, .api, .Array],
    setUpFunction: { blackHole(filteredRange) },
    legacyFactor: 100),
  BenchmarkInfo(name: "LazilyFilteredRange",
    runFunction: run_LazilyFilteredRange,
    tags: [.validation, .api, .Array],
    legacyFactor: 10),
  BenchmarkInfo(
    name: "LazilyFilteredArrayContains",
    runFunction: run_LazilyFilteredArrayContains,
    tags: [.validation, .api, .Array],
    setUpFunction: {
      multiplesOfThree = Array(1..<500).lazy.filter { $0 % 3 == 0 } },
    tearDownFunction: { multiplesOfThree = nil },
    legacyFactor: 100),
]

@inline(never)
public func run_LazilyFilteredRange(_ n: Int) {
  var res = 123
  let c = (1..<100_000).lazy.filter { $0 % 7 == 0 }
  for _ in 1...n {
    res += Array(c).count
    res -= Array(c).count
  }
  check(res == 123)
}

let filteredRange = (1..<1_000).map({[$0]}).lazy.filter { $0.first! % 7 == 0 }

@inline(never)
public func run_LazilyFilteredArrays(_ n: Int) {
  var res = 123
  let c = filteredRange
  for _ in 1...n {
    res += Array(c).count
    res -= Array(c).count
  }
  check(res == 123)
}

fileprivate var multiplesOfThree: LazyFilterCollection<Array<Int>>?

@inline(never)
fileprivate func run_LazilyFilteredArrayContains(_ n: Int) {
  let xs = multiplesOfThree!
  for _ in 1...n {
    var filteredCount = 0
    for candidate in 1..<500 {
      filteredCount += xs.contains(candidate) ? 1 : 0
    }
    check(filteredCount == 166)
  }
}
