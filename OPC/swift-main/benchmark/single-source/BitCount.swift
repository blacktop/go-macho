//===--- BitCount.swift ---------------------------------------------------===//
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

// This test checks performance of Swift bit count.
// and mask operator.
// rdar://problem/22151678
import TestsUtils

public let benchmarks =
  BenchmarkInfo(
    name: "BitCount",
    runFunction: run_BitCount,
    tags: [.validation, .algorithm])

func countBitSet(_ num: Int) -> Int {
  let bits = MemoryLayout<Int>.size * 8
  var cnt: Int = 0
  var mask: Int = 1
  for _ in 0...bits {
    if num & mask != 0 {
      cnt += 1
    }
    mask <<= 1
  }
  return cnt
}

@inline(never)
public func run_BitCount(_ n: Int) {
  var sum = 0
  for _ in 1...1000*n {
    // Check some results.
    sum = sum &+ countBitSet(getInt(1))
              &+ countBitSet(getInt(2))
              &+ countBitSet(getInt(2457))
  }
  check(sum == 8 * 1000 * n)
}
