//===--- Prefix.swift -----------------------------------------*- swift -*-===//
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

////////////////////////////////////////////////////////////////////////////////
// WARNING: This file is manually generated from .gyb template and should not
// be directly modified. Instead, make changes to Prefix.swift.gyb and run
// scripts/generate_harness/generate_harness.py to regenerate this file.
////////////////////////////////////////////////////////////////////////////////

import TestsUtils

let sequenceCount = 4096
let prefixCount = sequenceCount - 1024
let sumCount = prefixCount * (prefixCount - 1) / 2
let array: [Int] = Array(0..<sequenceCount)

public let benchmarks = [
  BenchmarkInfo(
    name: "PrefixCountableRange",
    runFunction: run_PrefixCountableRange,
    tags: [.validation, .api]),
  BenchmarkInfo(
    name: "PrefixSequence",
    runFunction: run_PrefixSequence,
    tags: [.validation, .api]),
  BenchmarkInfo(
    name: "PrefixAnySequence",
    runFunction: run_PrefixAnySequence,
    tags: [.validation, .api]),
  BenchmarkInfo(
    name: "PrefixAnySeqCntRange",
    runFunction: run_PrefixAnySeqCntRange,
    tags: [.validation, .api]),
  BenchmarkInfo(
    name: "PrefixAnySeqCRangeIter",
    runFunction: run_PrefixAnySeqCRangeIter,
    tags: [.validation, .api]),
  BenchmarkInfo(
    name: "PrefixAnyCollection",
    runFunction: run_PrefixAnyCollection,
    tags: [.validation, .api]),
  BenchmarkInfo(
    name: "PrefixArray",
    runFunction: run_PrefixArray,
    tags: [.validation, .api, .Array],
    setUpFunction: { blackHole(array) }),
  BenchmarkInfo(
    name: "PrefixCountableRangeLazy",
    runFunction: run_PrefixCountableRangeLazy,
    tags: [.validation, .api]),
  BenchmarkInfo(
    name: "PrefixSequenceLazy",
    runFunction: run_PrefixSequenceLazy,
    tags: [.validation, .api]),
  BenchmarkInfo(
    name: "PrefixAnySequenceLazy",
    runFunction: run_PrefixAnySequenceLazy,
    tags: [.validation, .api]),
  BenchmarkInfo(
    name: "PrefixAnySeqCntRangeLazy",
    runFunction: run_PrefixAnySeqCntRangeLazy,
    tags: [.validation, .api]),
  BenchmarkInfo(
    name: "PrefixAnySeqCRangeIterLazy",
    runFunction: run_PrefixAnySeqCRangeIterLazy,
    tags: [.validation, .api]),
  BenchmarkInfo(
    name: "PrefixAnyCollectionLazy",
    runFunction: run_PrefixAnyCollectionLazy,
    tags: [.validation, .api]),
  BenchmarkInfo(
    name: "PrefixArrayLazy",
    runFunction: run_PrefixArrayLazy,
    tags: [.validation, .api, .Array],
    setUpFunction: { blackHole(array) }),
]

@inline(never)
public func run_PrefixCountableRange(_ n: Int) {
  let s = 0..<sequenceCount
  for _ in 1...20*n {
    var result = 0
    for element in s.prefix(prefixCount) {
      result += element
    }
    check(result == sumCount)
  }
}
@inline(never)
public func run_PrefixSequence(_ n: Int) {
  let s = sequence(first: 0) { $0 < sequenceCount - 1 ? $0 &+ 1 : nil }
  for _ in 1...20*n {
    var result = 0
    for element in s.prefix(prefixCount) {
      result += element
    }
    check(result == sumCount)
  }
}
@inline(never)
public func run_PrefixAnySequence(_ n: Int) {
  let s = AnySequence(sequence(first: 0) { $0 < sequenceCount - 1 ? $0 &+ 1 : nil })
  for _ in 1...20*n {
    var result = 0
    for element in s.prefix(prefixCount) {
      result += element
    }
    check(result == sumCount)
  }
}
@inline(never)
public func run_PrefixAnySeqCntRange(_ n: Int) {
  let s = AnySequence(0..<sequenceCount)
  for _ in 1...20*n {
    var result = 0
    for element in s.prefix(prefixCount) {
      result += element
    }
    check(result == sumCount)
  }
}
@inline(never)
public func run_PrefixAnySeqCRangeIter(_ n: Int) {
  let s = AnySequence((0..<sequenceCount).makeIterator())
  for _ in 1...20*n {
    var result = 0
    for element in s.prefix(prefixCount) {
      result += element
    }
    check(result == sumCount)
  }
}
@inline(never)
public func run_PrefixAnyCollection(_ n: Int) {
  let s = AnyCollection(0..<sequenceCount)
  for _ in 1...20*n {
    var result = 0
    for element in s.prefix(prefixCount) {
      result += element
    }
    check(result == sumCount)
  }
}
@inline(never)
public func run_PrefixArray(_ n: Int) {
  let s = array
  for _ in 1...20*n {
    var result = 0
    for element in s.prefix(prefixCount) {
      result += element
    }
    check(result == sumCount)
  }
}
@inline(never)
public func run_PrefixCountableRangeLazy(_ n: Int) {
  let s = (0..<sequenceCount).lazy
  for _ in 1...20*n {
    var result = 0
    for element in s.prefix(prefixCount) {
      result += element
    }
    check(result == sumCount)
  }
}
@inline(never)
public func run_PrefixSequenceLazy(_ n: Int) {
  let s = (sequence(first: 0) { $0 < sequenceCount - 1 ? $0 &+ 1 : nil }).lazy
  for _ in 1...20*n {
    var result = 0
    for element in s.prefix(prefixCount) {
      result += element
    }
    check(result == sumCount)
  }
}
@inline(never)
public func run_PrefixAnySequenceLazy(_ n: Int) {
  let s = (AnySequence(sequence(first: 0) { $0 < sequenceCount - 1 ? $0 &+ 1 : nil })).lazy
  for _ in 1...20*n {
    var result = 0
    for element in s.prefix(prefixCount) {
      result += element
    }
    check(result == sumCount)
  }
}
@inline(never)
public func run_PrefixAnySeqCntRangeLazy(_ n: Int) {
  let s = (AnySequence(0..<sequenceCount)).lazy
  for _ in 1...20*n {
    var result = 0
    for element in s.prefix(prefixCount) {
      result += element
    }
    check(result == sumCount)
  }
}
@inline(never)
public func run_PrefixAnySeqCRangeIterLazy(_ n: Int) {
  let s = (AnySequence((0..<sequenceCount).makeIterator())).lazy
  for _ in 1...20*n {
    var result = 0
    for element in s.prefix(prefixCount) {
      result += element
    }
    check(result == sumCount)
  }
}
@inline(never)
public func run_PrefixAnyCollectionLazy(_ n: Int) {
  let s = (AnyCollection(0..<sequenceCount)).lazy
  for _ in 1...20*n {
    var result = 0
    for element in s.prefix(prefixCount) {
      result += element
    }
    check(result == sumCount)
  }
}
@inline(never)
public func run_PrefixArrayLazy(_ n: Int) {
  let s = (array).lazy
  for _ in 1...20*n {
    var result = 0
    for element in s.prefix(prefixCount) {
      result += element
    }
    check(result == sumCount)
  }
}

// Local Variables:
// eval: (read-only-mode 1)
// End:
