//===--- IterateData.swift ------------------------------------------------===//
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

public let benchmarks =
  BenchmarkInfo(
    name: "IterateData",
    runFunction: run_IterateData,
    tags: [.validation, .api, .Data],
    setUpFunction: { blackHole(data) })

let data: Data = {
  var data = Data(count: 16 * 1024)
  let n = data.count
  data.withUnsafeMutableBytes { (ptr: UnsafeMutablePointer<UInt8>) -> () in
    for i in 0..<n {
      ptr[i] = UInt8(i % 23)
    }
  }
  return data
}()

@inline(never)
public func run_IterateData(_ n: Int) {
  for _ in 1...10*n {
    _ = data.reduce(0, &+)
  }
}
