//===--- DictTest3.swift --------------------------------------------------===//
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
  BenchmarkInfo(name: "Dictionary3", runFunction: run_Dictionary3, tags: [.validation, .api, .Dictionary]),
  BenchmarkInfo(name: "Dictionary3OfObjects", runFunction: run_Dictionary3OfObjects, tags: [.validation, .api, .Dictionary]),
]

@inline(never)
public func run_Dictionary3(_ n: Int) {
  let size1 = 100
  let reps = 20
  let ref_result = "1 99 20 1980"
  var hash1 = [String: Int]()
  var hash2 = [String: Int]()
  var res = ""

  for _ in 1...n {
    hash1 = [:]
    for i in 0..<size1 {
      hash1["foo_" + String(i)] = i
    }

    hash2 = hash1

    for _ in 1..<reps {
      for (k, v) in hash1 {
        hash2[k] = hash2[k]! + v
      }
    }

    res = (String(hash1["foo_1"]!) + " " + String(hash1["foo_99"]!) + " " +
           String(hash2["foo_1"]!) + " " + String(hash2["foo_99"]!))
    if res != ref_result {
      break
    }
  }
  check(res == ref_result)
}

class Box<T : Hashable> : Hashable {
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
public func run_Dictionary3OfObjects(_ n: Int) {
  let size1 = 100
  let reps = 20
  let ref_result = "1 99 20 1980"
  var hash1 : [ Box<String> : Box<Int> ] = [:]
  var hash2 : [ Box<String> : Box<Int> ] = [:]
  var res = ""

  for _ in 1...n {
    hash1 = [:]
    for i in 0..<size1 {
      hash1[Box("foo_" + String(i))] = Box(i)
    }

    hash2 = hash1

    for _ in 1..<reps {
      for (k, v) in hash1 {
        hash2[k] = Box(hash2[k]!.value + v.value)
      }
    }

    res = (String(hash1[Box("foo_1")]!.value) + " " + String(hash1[Box("foo_99")]!.value) + " " +
           String(hash2[Box("foo_1")]!.value) + " " + String(hash2[Box("foo_99")]!.value))
    if res != ref_result {
      break
    }
  }
  check(res == ref_result)
}
