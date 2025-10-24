//===--- SortLettersInPlace.swift -----------------------------------------===//
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

// This test checks performance and correctness of Swift sortInPlace on an
// array of letters.
import TestsUtils

public let benchmarks =
  BenchmarkInfo(
    name: "SortLettersInPlace",
    runFunction: run_SortLettersInPlace,
    tags: [.validation, .api, .algorithm, .String])

class Letter {
  let value: String
  init(_ value: String) {
    self.value = value
  }
}

@inline(never)
public func run_SortLettersInPlace(_ n: Int) {
  for _ in 1...100*n {
    var letters = [
        Letter("k"), Letter("a"), Letter("x"), Letter("i"), Letter("f"), Letter("l"),
        Letter("o"), Letter("w"), Letter("h"), Letter("p"), Letter("b"), Letter("u"),
        Letter("n"), Letter("c"), Letter("j"), Letter("t"), Letter("y"), Letter("s"),
        Letter("d"), Letter("v"), Letter("r"), Letter("e"), Letter("q"), Letter("m"),
        Letter("z"), Letter("g")
    ]

    // Sort the letters in place.
    letters.sort {
      return $0.value < $1.value
    }

    // Check whether letters are sorted.
    check(letters[0].value <= letters[letters.count/2].value)
  }
}
