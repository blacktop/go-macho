// This source file is part of the Swift.org open source project
// Copyright (c) 2014 - 2017 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See https://swift.org/LICENSE.txt for license information
// See https://swift.org/CONTRIBUTORS.txt for the list of Swift project authors

// RUN: not %target-swift-frontend %s -typecheck
}
func a<g>() -> (g, g -> g) -> g {
    var b: ((g, g -> g) -> g)!
    return b
}
func f<g : d {
    return !(a)
  enum g {
        func g
        var _ = g
