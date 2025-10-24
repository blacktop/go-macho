//===--- DictionarySubscriptDefault.swift ---------------------------------===//
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

public let benchmarks = [
  BenchmarkInfo(name: "DictionarySubscriptDefaultMutation",
                runFunction: run_DictionarySubscriptDefaultMutation,
                tags: [.validation, .api, .Dictionary]),
  BenchmarkInfo(name: "DictionarySubscriptDefaultMutationArray",
                runFunction: run_DictionarySubscriptDefaultMutationArray,
                tags: [.validation, .api, .Dictionary]),
  BenchmarkInfo(name: "DictionarySubscriptDefaultMutationOfObjects",
                runFunction: run_DictionarySubscriptDefaultMutationOfObjects,
                tags: [.validation, .api, .Dictionary], legacyFactor: 20),
  BenchmarkInfo(name: "DictionarySubscriptDefaultMutationArrayOfObjects",
                runFunction:
                  run_DictionarySubscriptDefaultMutationArrayOfObjects,
                tags: [.validation, .api, .Dictionary], legacyFactor: 20),
]

@inline(never)
public func run_DictionarySubscriptDefaultMutation(_ n: Int) {
  for _ in 1...n {

    var dict = [Int: Int]()

    for i in 0..<10_000 {
      dict[i % 100, default: 0] += 1
    }

    check(dict.count == 100)
    check(dict[0]! == 100)
  }
}

@inline(never)
public func run_DictionarySubscriptDefaultMutationArray(_ n: Int) {
  for _ in 1...n {

    var dict = [Int: [Int]]()

    for i in 0..<10_000 {
      dict[i % 100, default: []].append(i)
    }

    check(dict.count == 100)
    check(dict[0]!.count == 100)
  }
}

// Hack to workaround the fact that if we attempt to increment the Box's value
// from the subscript, the compiler will just call the subscript's getter (and
// therefore not insert the instance) as it's dealing with a reference type.
// By using a mutating method in a protocol extension, the compiler is forced to
// treat this an actual mutation, so cannot call the getter.
protocol P {
  associatedtype T
  var value: T { get set }
}

extension P {
  mutating func mutateValue(_ mutations: (inout T) -> Void) {
    mutations(&value)
  }
}

class Box<T : Hashable> : Hashable, P {
  var value: T

  init(_ v: T) {
    value = v
  }

  func hash(into hasher: inout Hasher) {
    hasher.combine(value)
  }

  static func ==(lhs: Box, rhs: Box) -> Bool {
    return lhs.value == rhs.value
  }
}

@inline(never)
public func run_DictionarySubscriptDefaultMutationOfObjects(_ n: Int) {
  for _ in 1...n {

    var dict = [Box<Int>: Box<Int>]()

    for i in 0..<500 {
      dict[Box(i % 5), default: Box(0)].mutateValue { $0 += 1 }
    }

    check(dict.count == 5)
    check(dict[Box(0)]!.value == 100)
  }
}

@inline(never)
public func run_DictionarySubscriptDefaultMutationArrayOfObjects(_ n: Int) {
    for _ in 1...n {

    var dict = [Box<Int>: [Box<Int>]]()

    for i in 0..<500 {
      dict[Box(i % 5), default: []].append(Box(i))
    }

    check(dict.count == 5)
    check(dict[Box(0)]!.count == 100)
  }
}
