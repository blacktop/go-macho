//===--- StringInterpolation.swift ----------------------------------------===//
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
  BenchmarkInfo(
    name: "StringInterpolation",
    runFunction: run_StringInterpolation,
    tags: [.validation, .api, .String],
    legacyFactor: 100),
  BenchmarkInfo(
    name: "StringInterpolationSmall",
    runFunction: run_StringInterpolationSmall,
    tags: [.validation, .api, .String],
    legacyFactor: 10),
  BenchmarkInfo(
    name: "StringInterpolationManySmallSegments",
    runFunction: run_StringInterpolationManySmallSegments,
    tags: [.validation, .api, .String],
    legacyFactor: 100),
]

class RefTypePrintable : CustomStringConvertible {
  var description: String {
    return "01234567890123456789012345678901234567890123456789"
  }
}

@inline(never)
public func run_StringInterpolation(_ n: Int) {
  let reps = 100
  let refResult = reps
  let anInt: Int64 = 0x1234567812345678
  let aRefCountedObject = RefTypePrintable()

  for _ in 1...n {
    var result = 0
    for _ in 1...reps {
      let s: String = getString(
        "\(anInt) abcdefdhijklmn \(aRefCountedObject) abcdefdhijklmn \u{01}")
      let utf16 = s.utf16

      // FIXME: if String is not stored as UTF-16 on this platform, then the
      // following operation has a non-trivial cost and needs to be replaced
      // with an operation on the native storage type.
      result = result &+ Int(utf16.last!)
      blackHole(s)
    }
    check(result == refResult)
  }
}

@inline(never)
public func run_StringInterpolationSmall(_ n: Int) {
  let reps = 100
  let refResult = reps
  let anInt: Int64 = 0x42

  for _ in 1...10*n {
    var result = 0
    for _ in 1...reps {
      let s: String = getString(
        "\(getString("int")): \(anInt) \(getString("abc")) \u{01}")
      result = result &+ Int(s.utf8.last!)
      blackHole(s)
    }
    check(result == refResult)
  }
}

@inline(never)
public func run_StringInterpolationManySmallSegments(_ n: Int) {
  let numHex = min(UInt64(n), 0x0FFF_FFFF_FFFF_FFFF)
  let numOct = min(UInt64(n), 0x0000_03FF_FFFF_FFFF)
  let numBin = min(UInt64(n), 0x7FFF)
  let segments = [
    "abc",
    String(numHex, radix: 16),
    "0123456789",
    String(Double.pi/2),
    "*barely* small!",
    String(numOct, radix: 8),
    "",
    String(numBin, radix: 2),
  ]
  assert(segments.count == 8)

  func getSegment(_ i: Int) -> String {
    return getString(segments[i])
  }

  let reps = 100
  for _ in 1...n {
    for _ in 1...reps {
      blackHole("""
        \(getSegment(0)) \(getSegment(1))/\(getSegment(2))_\(getSegment(3))
        \(getSegment(4)) \(getSegment(5)), \(getSegment(6))~~\(getSegment(7))
        """)
    }
  }
}
