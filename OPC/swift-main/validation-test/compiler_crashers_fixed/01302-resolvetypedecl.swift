// This source file is part of the Swift.org open source project
// Copyright (c) 2014 - 2017 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See https://swift.org/LICENSE.txt for license information
// See https://swift.org/CONTRIBUTORS.txt for the list of Swift project authors

// RUN: not %target-swift-frontend %s -typecheck
struct c {
var d: b.Type
func e() {
}
}
class a<f : b, g : b where f.d == g> {
}
protocol b {
}
struct c<h : b> : b {
}
func ^(a: Boolean, Bool) -> Bool {
}
class a {
}
protocol a {
}
class b<h : c, i : c where h.g == i> : a
