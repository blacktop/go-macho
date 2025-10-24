//===--- DropWhile.swift --------------------------------------*- swift -*-===//
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
// be directly modified. Instead, make changes to DropWhile.swift.gyb and run
// scripts/generate_harness/generate_harness.py to regenerate this file.
////////////////////////////////////////////////////////////////////////////////

import TestsUtils

let sequenceCount = 4096
let dropCount = 1024
let suffixCount = sequenceCount - dropCount
let sumCount = suffixCount * (2 * sequenceCount - suffixCount - 1) / 2
let array: [Int] = Array(0..<sequenceCount)

public let benchmarks = [
  BenchmarkInfo(
    name: "DropWhileCountableRange",
    runFunction: run_DropWhileCountableRange,
    tags: [.validation, .api]),
  BenchmarkInfo(
    name: "DropWhileSequence",
    runFunction: run_DropWhileSequence,
    tags: [.validation, .api]),
  BenchmarkInfo(
    name: "DropWhileAnySequence",
    runFunction: run_DropWhileAnySequence,
    tags: [.validation, .api]),
  BenchmarkInfo(
    name: "DropWhileAnySeqCntRange",
    runFunction: run_DropWhileAnySeqCntRange,
    tags: [.validation, .api]),
  BenchmarkInfo(
    name: "DropWhileAnySeqCRangeIter",
    runFunction: run_DropWhileAnySeqCRangeIter,
    tags: [.validation, .api]),
  BenchmarkInfo(
    name: "DropWhileAnyCollection",
    runFunction: run_DropWhileAnyCollection,
    tags: [.validation, .api]),
  BenchmarkInfo(
    name: "DropWhileArray",
    runFunction: run_DropWhileArray,
    tags: [.validation, .api, .Array],
    setUpFunction: { blackHole(array) }),
  BenchmarkInfo(
    name: "DropWhileCountableRangeLazy",
    runFunction: run_DropWhileCountableRangeLazy,
    tags: [.validation, .api]),
  BenchmarkInfo(
    name: "DropWhileSequenceLazy",
    runFunction: run_DropWhileSequenceLazy,
    tags: [.validation, .api]),
  BenchmarkInfo(
    name: "DropWhileAnySequenceLazy",
    runFunction: run_DropWhileAnySequenceLazy,
    tags: [.validation, .api]),
  BenchmarkInfo(
    name: "DropWhileAnySeqCntRangeLazy",
    runFunction: run_DropWhileAnySeqCntRangeLazy,
    tags: [.validation, .api]),
  BenchmarkInfo(
    name: "DropWhileAnySeqCRangeIterLazy",
    runFunction: run_DropWhileAnySeqCRangeIterLazy,
    tags: [.validation, .api]),
  BenchmarkInfo(
    name: "DropWhileAnyCollectionLazy",
    runFunction: run_DropWhileAnyCollectionLazy,
    tags: [.validation, .api]),
  BenchmarkInfo(
    name: "DropWhileArrayLazy",
    runFunction: run_DropWhileArrayLazy,
    tags: [.validation, .api, .Array],
    setUpFunction: { blackHole(array) }),
]

@inline(never)
public func run_DropWhileCountableRange(_ n: Int) {
  let s = 0..<sequenceCount
  for _ in 1...20*n {
    var result = 0
    for element in s.drop(while: {$0 < dropCount} ) {
      result += element
    }
    check(result == sumCount)
  }
}
@inline(never)
public func run_DropWhileSequence(_ n: Int) {
  let s = sequence(first: 0) { $0 < sequenceCount - 1 ? $0 &+ 1 : nil }
  for _ in 1...20*n {
    var result = 0
    for element in s.drop(while: {$0 < dropCount} ) {
      result += element
    }
    check(result == sumCount)
  }
}
@inline(never)
public func run_DropWhileAnySequence(_ n: Int) {
  let s = AnySequence(sequence(first: 0) { $0 < sequenceCount - 1 ? $0 &+ 1 : nil })
  for _ in 1...20*n {
    var result = 0
    for element in s.drop(while: {$0 < dropCount} ) {
      result += element
    }
    check(result == sumCount)
  }
}
@inline(never)
public func run_DropWhileAnySeqCntRange(_ n: Int) {
  let s = AnySequence(0..<sequenceCount)
  for _ in 1...20*n {
    var result = 0
    for element in s.drop(while: {$0 < dropCount} ) {
      result += element
    }
    check(result == sumCount)
  }
}
@inline(never)
public func run_DropWhileAnySeqCRangeIter(_ n: Int) {
  let s = AnySequence((0..<sequenceCount).makeIterator())
  for _ in 1...20*n {
    var result = 0
    for element in s.drop(while: {$0 < dropCount} ) {
      result += element
    }
    check(result == sumCount)
  }
}
@inline(never)
public func run_DropWhileAnyCollection(_ n: Int) {
  let s = AnyCollection(0..<sequenceCount)
  for _ in 1...20*n {
    var result = 0
    for element in s.drop(while: {$0 < dropCount} ) {
      result += element
    }
    check(result == sumCount)
  }
}
@inline(never)
public func run_DropWhileArray(_ n: Int) {
  let s = array
  for _ in 1...20*n {
    var result = 0
    for element in s.drop(while: {$0 < dropCount} ) {
      result += element
    }
    check(result == sumCount)
  }
}
@inline(never)
public func run_DropWhileCountableRangeLazy(_ n: Int) {
  let s = (0..<sequenceCount).lazy
  for _ in 1...20*n {
    var result = 0
    for element in s.drop(while: {$0 < dropCount} ) {
      result += element
    }
    check(result == sumCount)
  }
}
@inline(never)
public func run_DropWhileSequenceLazy(_ n: Int) {
  let s = (sequence(first: 0) { $0 < sequenceCount - 1 ? $0 &+ 1 : nil }).lazy
  for _ in 1...20*n {
    var result = 0
    for element in s.drop(while: {$0 < dropCount} ) {
      result += element
    }
    check(result == sumCount)
  }
}
@inline(never)
public func run_DropWhileAnySequenceLazy(_ n: Int) {
  let s = (AnySequence(sequence(first: 0) { $0 < sequenceCount - 1 ? $0 &+ 1 : nil })).lazy
  for _ in 1...20*n {
    var result = 0
    for element in s.drop(while: {$0 < dropCount} ) {
      result += element
    }
    check(result == sumCount)
  }
}
@inline(never)
public func run_DropWhileAnySeqCntRangeLazy(_ n: Int) {
  let s = (AnySequence(0..<sequenceCount)).lazy
  for _ in 1...20*n {
    var result = 0
    for element in s.drop(while: {$0 < dropCount} ) {
      result += element
    }
    check(result == sumCount)
  }
}
@inline(never)
public func run_DropWhileAnySeqCRangeIterLazy(_ n: Int) {
  let s = (AnySequence((0..<sequenceCount).makeIterator())).lazy
  for _ in 1...20*n {
    var result = 0
    for element in s.drop(while: {$0 < dropCount} ) {
      result += element
    }
    check(result == sumCount)
  }
}
@inline(never)
public func run_DropWhileAnyCollectionLazy(_ n: Int) {
  let s = (AnyCollection(0..<sequenceCount)).lazy
  for _ in 1...20*n {
    var result = 0
    for element in s.drop(while: {$0 < dropCount} ) {
      result += element
    }
    check(result == sumCount)
  }
}
@inline(never)
public func run_DropWhileArrayLazy(_ n: Int) {
  let s = (array).lazy
  for _ in 1...20*n {
    var result = 0
    for element in s.drop(while: {$0 < dropCount} ) {
      result += element
    }
    check(result == sumCount)
  }
}

// Local Variables:
// eval: (read-only-mode 1)
// End:
