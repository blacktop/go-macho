//===--- DictTest2.swift --------------------------------------------------===//
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
  BenchmarkInfo(name: "Dictionary2",
    runFunction: run_Dictionary2,
    tags: [.validation, .api, .Dictionary],
    legacyFactor: 5),
  BenchmarkInfo(name: "Dictionary2OfObjects",
    runFunction: run_Dictionary2OfObjects,
    tags: [.validation, .api, .Dictionary],
    legacyFactor: 5),
]

@inline(never)
public func run_Dictionary2(_ n: Int) {
  let size = 500
  let ref_result = 199
  var res = 0
  for _ in 1...n {
    var x: [String: Int] = [:]
    for i in 1...size {
      x[String(i, radix:16)] = i
    }

    res = 0
    for i in 0..<size {
      let i2 = size-i
      if x[String(i2)] != nil {
        res += 1
      }
    }
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
public func run_Dictionary2OfObjects(_ n: Int) {

  let size = 500
  let ref_result = 199
  var res = 0
  for _ in 1...n {
    var x: [Box<String>:Box<Int>] = [:]
    for i in 1...size {
      x[Box(String(i, radix:16))] = Box(i)
    }

    res = 0
    for i in 0..<size {
      let i2 = size-i
      if x[Box(String(i2))] != nil {
        res += 1
      }
    }
    if res != ref_result {
      break
    }
  }
  check(res == ref_result)
}
