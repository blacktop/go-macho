//===--- InsertCharacter.swift --------------------------------------------===//
//
// This source file is part of the Swift.org open source project
//
// Copyright (c) 2014 - 2018 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See https://swift.org/LICENSE.txt for license information
// See https://swift.org/CONTRIBUTORS.txt for the list of Swift project authors
//
//===----------------------------------------------------------------------===//

import TestsUtils

let t: [BenchmarkCategory] = [.validation, .api, .String]

public let benchmarks = [
  BenchmarkInfo(name: "InsertCharacterEndIndex",
    runFunction: run_InsertCharacterEndIndex, tags: t,
    setUpFunction: buildWorkload),
  BenchmarkInfo(name: "InsertCharacterTowardsEndIndex",
    runFunction: run_InsertCharacterTowardsEndIndex, tags: t,
    setUpFunction: buildWorkload),
  BenchmarkInfo(name: "InsertCharacterStartIndex",
    runFunction: run_InsertCharacterStartIndex, tags: t,
    setUpFunction: buildWorkload, legacyFactor: 5),
  BenchmarkInfo(name: "InsertCharacterEndIndexNonASCII",
    runFunction: run_InsertCharacterEndIndexNonASCII, tags: t,
    setUpFunction: buildWorkload),
  BenchmarkInfo(name: "InsertCharacterTowardsEndIndexNonASCII",
    runFunction: run_InsertCharacterTowardsEndIndexNonASCII, tags: t,
    setUpFunction: buildWorkload),
  BenchmarkInfo(name: "InsertCharacterStartIndexNonASCII",
    runFunction: run_InsertCharacterStartIndexNonASCII, tags: t,
    setUpFunction: buildWorkload)
]

let str = String(repeating: "A very long ASCII string.", count: 200)

func buildWorkload() {
  blackHole(str)
}

// Insert towards end index

@inline(__always)
func insertTowardsEndIndex(_ c: Character, in string: String, count: Int) {
  var workload = string
  var index = workload.endIndex
  for i in 0..<count {
    workload.insert(identity(c), at: index)
    if i % 1000 == 0 {
      index = workload.endIndex
    }
  }
  blackHole(workload)
}

@inline(never)
func run_InsertCharacterTowardsEndIndex(_ n: Int) {
  insertTowardsEndIndex("s", in: str, count: n * 3000)
}

@inline(never)
func run_InsertCharacterTowardsEndIndexNonASCII(_ n: Int) {
  insertTowardsEndIndex("👩🏼‍💻", in: str, count: n * 1000)
}

// Insert at end index

@inline(__always)
func insertAtEndIndex(_ c: Character, in string: String, count: Int) {
  var workload = string
  for _ in 0..<count {
    workload.insert(identity(c), at: workload.endIndex)
  }
  blackHole(workload)
}

@inline(never)
func run_InsertCharacterEndIndex(_ n: Int) {
  insertAtEndIndex("s", in: str, count: n * 3000)
}

@inline(never)
func run_InsertCharacterEndIndexNonASCII(_ n: Int) {
  insertAtEndIndex("👩🏾‍🏫", in: str, count: n * 1000)
}

// Insert at start index

@inline(__always)
func insertAtStartIndex(
  _ c: Character, in string: String, count: Int, insertions: Int) {
  var workload = str
  for _ in 0..<count {
    for _ in 0..<insertions {
      workload.insert(identity(c), at: workload.startIndex)
    }
    workload = str
  }
  blackHole(workload)
}

@inline(never)
func run_InsertCharacterStartIndex(_ n: Int) {
  insertAtStartIndex("w", in: str, count: n * 15, insertions: 50)
}

@inline(never)
func run_InsertCharacterStartIndexNonASCII(_ n: Int) {
  insertAtStartIndex("👩🏾‍🏫", in: str, count: n * 75, insertions: 25)
}
