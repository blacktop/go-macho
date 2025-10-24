//===--- Phonebook.swift --------------------------------------------------===//
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

// This test is based on util/benchmarks/Phonebook, with modifications
// for performance measuring.
import TestsUtils

public let benchmarks =
  BenchmarkInfo(
    name: "Phonebook",
    runFunction: run_Phonebook,
    tags: [.validation, .api, .String],
    setUpFunction: { blackHole(names) },
    legacyFactor: 7
  )

let words = [
  "James", "John", "Robert", "Michael", "William", "David", "Richard", "Joseph",
  "Charles", "Thomas", "Christopher", "Daniel", "Matthew", "Donald", "Anthony",
  "Paul", "Mark", "George", "Steven", "Kenneth", "Andrew", "Edward", "Brian",
  "Joshua", "Kevin", "Ronald", "Timothy", "Jason", "Jeffrey", "Gary", "Ryan",
  "Nicholas", "Eric", "Stephen", "Jacob", "Larry", "Frank", "Jonathan", "Scott",
]
let names: [Record] = {
  // The list of names in the phonebook.
  var names = [Record]()
  names.reserveCapacity(words.count * words.count)
  for first in words {
    for last in words {
      names.append(Record(first, last))
    }
  }
  return names
}()

// This is a phone book record.
struct Record : Comparable {
  var first: String
  var last: String

  init(_ first_ : String,_ last_ : String) {
    first = first_
    last = last_
  }
}
func ==(lhs: Record, rhs: Record) -> Bool {
  return lhs.last == rhs.last && lhs.first == rhs.first
}

func <(lhs: Record, rhs: Record) -> Bool {
  if lhs.last < rhs.last {
    return true
  }
  if lhs.last > rhs.last {
    return false
  }

  if lhs.first < rhs.first {
    return true
  }

  return false
}

@inline(never)
public func run_Phonebook(_ n: Int) {
  for _ in 1...n {
    var t = names
    t.sort()
  }
}
