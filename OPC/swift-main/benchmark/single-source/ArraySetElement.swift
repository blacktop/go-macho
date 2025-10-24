//===--- ArraySetElement.swift ---------------------------------------------===//
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

// 33% isUniquelyReferenced
//   15% swift_rt_swift_isUniquelyReferencedOrPinned_nonNull_native
//   18% swift_isUniquelyReferencedOrPinned_nonNull_native
public let benchmarks =
  BenchmarkInfo(
    name: "ArraySetElement",
    runFunction: run_ArraySetElement,
    tags: [.runtime, .cpubench]
  )

// This is an effort to defeat isUniquelyReferenced optimization. Ideally
// microbenchmarks list this should be written in C.
@inline(never)
func storeArrayElement(_ array: inout [Int], _ i: Int) {
  array[i] = i
}

public func run_ArraySetElement(_ n: Int) {
  var array = [Int](repeating: 0, count: 10000)
  for _ in 0..<10*n {
    for i in 0..<array.count {
      storeArrayElement(&array, i)
    }
  }
}
