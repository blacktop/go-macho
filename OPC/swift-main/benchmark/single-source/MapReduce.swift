//===--- MapReduce.swift --------------------------------------------------===//
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
import Foundation

let t: [BenchmarkCategory] = [.validation, .algorithm]
let ts: [BenchmarkCategory] = [.validation, .algorithm, .String]

public let benchmarks = [
  BenchmarkInfo(name: "MapReduce", runFunction: run_MapReduce, tags: t),
  BenchmarkInfo(name: "MapReduceAnyCollection",
    runFunction: run_MapReduceAnyCollection, tags: t),
  BenchmarkInfo(name: "MapReduceAnyCollectionShort",
    runFunction: run_MapReduceAnyCollectionShort, tags: t, legacyFactor: 10),
  BenchmarkInfo(name: "MapReduceClass2",
    runFunction: run_MapReduceClass, tags: t,
    setUpFunction: { boxedNumbers(1000) }, tearDownFunction: releaseDecimals),
  BenchmarkInfo(name: "MapReduceClassShort2",
    runFunction: run_MapReduceClassShort, tags: t,
    setUpFunction: { boxedNumbers(10) }, tearDownFunction: releaseDecimals),
  BenchmarkInfo(name: "MapReduceNSDecimalNumber",
    runFunction: run_MapReduceNSDecimalNumber, tags: t,
    setUpFunction: { decimals(1000) }, tearDownFunction: releaseDecimals),
  BenchmarkInfo(name: "MapReduceNSDecimalNumberShort",
    runFunction: run_MapReduceNSDecimalNumberShort, tags: t,
    setUpFunction: { decimals(10) }, tearDownFunction: releaseDecimals),
  BenchmarkInfo(name: "MapReduceLazyCollection",
    runFunction: run_MapReduceLazyCollection, tags: t),
  BenchmarkInfo(name: "MapReduceLazyCollectionShort",
    runFunction: run_MapReduceLazyCollectionShort, tags: t),
  BenchmarkInfo(name: "MapReduceLazySequence",
    runFunction: run_MapReduceLazySequence, tags: t),
  BenchmarkInfo(name: "MapReduceSequence",
    runFunction: run_MapReduceSequence, tags: t),
  BenchmarkInfo(name: "MapReduceShort",
    runFunction: run_MapReduceShort, tags: t, legacyFactor: 10),
  BenchmarkInfo(name: "MapReduceShortString",
    runFunction: run_MapReduceShortString, tags: ts),
  BenchmarkInfo(name: "MapReduceString",
    runFunction: run_MapReduceString, tags: ts),
]

#if _runtime(_ObjC)
var decimals : [NSDecimalNumber]!
func decimals(_ n: Int) {
  decimals = (0..<n).map { NSDecimalNumber(value: $0) }
}
func releaseDecimals() { decimals = nil }
#else
func decimals(_ n: Int) {}
func releaseDecimals() {}
#endif

class Box {
  var v: Int
  init(_ v: Int) { self.v = v }
}

var boxedNumbers : [Box]!
func boxedNumbers(_ n: Int) { boxedNumbers = (0..<n).map { Box($0) } }
func releaseboxedNumbers() { boxedNumbers = nil }

@inline(never)
public func run_MapReduce(_ n: Int) {
  var numbers = [Int](0..<1000)

  var c = 0
  for _ in 1...n*100 {
    numbers = numbers.map { $0 &+ 5 }
    c = c &+ numbers.reduce(0, &+)
  }
  check(c != 0)
}

@inline(never)
public func run_MapReduceAnyCollection(_ n: Int) {
  let numbers = AnyCollection([Int](0..<1000))

  var c = 0
  for _ in 1...n*100 {
    let mapped = numbers.map { $0 &+ 5 }
    c = c &+ mapped.reduce(0, &+)
  }
  check(c != 0)
}

@inline(never)
public func run_MapReduceAnyCollectionShort(_ n: Int) {
  let numbers = AnyCollection([Int](0..<10))

  var c = 0
  for _ in 1...n*1_000 {
    let mapped = numbers.map { $0 &+ 5 }
    c = c &+ mapped.reduce(0, &+)
  }
  check(c != 0)
}

@inline(never)
public func run_MapReduceShort(_ n: Int) {
  var numbers = [Int](0..<10)

  var c = 0
  for _ in 1...n*1_000 {
    numbers = numbers.map { $0 &+ 5 }
    c = c &+ numbers.reduce(0, &+)
  }
  check(c != 0)
}

@inline(never)
public func run_MapReduceSequence(_ n: Int) {
  let numbers = sequence(first: 0) { $0 < 1000 ? $0 &+ 1 : nil }

  var c = 0
  for _ in 1...n*100 {
    let mapped = numbers.map { $0 &+ 5 }
    c = c &+ mapped.reduce(0, &+)
  }
  check(c != 0)
}

@inline(never)
public func run_MapReduceLazySequence(_ n: Int) {
  let numbers = sequence(first: 0) { $0 < 1000 ? $0 &+ 1 : nil }

  var c = 0
  for _ in 1...n*100 {
    let mapped = numbers.lazy.map { $0 &+ 5 }
    c = c &+ mapped.reduce(0, &+)
  }
  check(c != 0)
}

@inline(never)
public func run_MapReduceLazyCollection(_ n: Int) {
  let numbers = [Int](0..<1000)

  var c = 0
  for _ in 1...n*100 {
    let mapped = numbers.lazy.map { $0 &+ 5 }
    c = c &+ mapped.reduce(0, &+)
  }
  check(c != 0)
}

@inline(never)
public func run_MapReduceLazyCollectionShort(_ n: Int) {
  let numbers = [Int](0..<10)

  var c = 0
  for _ in 1...n*10000 {
    let mapped = numbers.lazy.map { $0 &+ 5 }
    c = c &+ mapped.reduce(0, &+)
  }
  check(c != 0)
}

@inline(never)
public func run_MapReduceString(_ n: Int) {
  let s = "thequickbrownfoxjumpsoverthelazydogusingasmanycharacteraspossible123456789"

  var c: UInt64 = 0
  for _ in 1...n*100 {
    c = c &+ s.utf8.map { UInt64($0 &+ 5) }.reduce(0, &+)
  }
  check(c != 0)
}

@inline(never)
public func run_MapReduceShortString(_ n: Int) {
  let s = "12345"

  var c: UInt64 = 0
  for _ in 1...n*100 {
    c = c &+ s.utf8.map { UInt64($0 &+ 5) }.reduce(0, &+)
  }
  check(c != 0)
}

@inline(never)
public func run_MapReduceNSDecimalNumber(_ n: Int) {
#if _runtime(_ObjC)
  let numbers: [NSDecimalNumber] = decimals

  var c = 0
  for _ in 1...n*10 {
    let mapped = numbers.map { $0.intValue &+ 5 }
    c = c &+ mapped.reduce(0, &+)
  }
  check(c != 0)
#endif
}

@inline(never)
public func run_MapReduceNSDecimalNumberShort(_ n: Int) {
#if _runtime(_ObjC)
  let numbers: [NSDecimalNumber] = decimals

  var c = 0
  for _ in 1...n*1_000 {
    let mapped = numbers.map { $0.intValue &+ 5 }
    c = c &+ mapped.reduce(0, &+)
  }
  check(c != 0)
#endif
}


@inline(never)
public func run_MapReduceClass(_ n: Int) {
  let numbers: [Box] = boxedNumbers

  var c = 0
  for _ in 1...n*10 {
    let mapped = numbers.map { $0.v &+ 5 }
    c = c &+ mapped.reduce(0, &+)
  }
  check(c != 0)
}

@inline(never)
public func run_MapReduceClassShort(_ n: Int) {
  let numbers: [Box] = boxedNumbers

  var c = 0
  for _ in 1...n*1_000 {
    let mapped = numbers.map { $0.v &+ 5 }
    c = c &+ mapped.reduce(0, &+)
  }
  check(c != 0)
}
