// NibbleSort benchmark
//
// Source: https://gist.github.com/airspeedswift/f4daff4ea5c6de9e1fdf

import TestsUtils

public let benchmarks = [
  BenchmarkInfo(
    name: "NibbleSort",
    runFunction: run_NibbleSort,
    tags: [.validation],
    legacyFactor: 10
  ),
]

@inline(never)
public func run_NibbleSort(_ n: Int) {
  let vRef: UInt64 = 0xfeedbba000000000
  let v: UInt64 = 0xbadbeef
  var c = NibbleCollection(v)

  for _ in 1...1_000*n {
    c.val = v
    c.sort()

    if c.val != vRef {
      break
    }
  }

  check(c.val == vRef)
}

struct NibbleCollection {
  var val: UInt64
  init(_ val: UInt64) { self.val = val }
}

extension NibbleCollection: RandomAccessCollection, MutableCollection {
  typealias Index = UInt64
  var startIndex: UInt64 { return 0 }
  var endIndex: UInt64 { return 16 }

  subscript(idx: UInt64) -> UInt64 {
    get {
      return (val >> (idx*4)) & 0xf
    }
    set(n) {
      let mask = (0xf as UInt64) << (idx * 4)
      val &= ~mask
      val |= n << (idx * 4)
    }
  }
}
