// This source file is part of the Swift.org open source project
// Copyright (c) 2014 - 2017 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See https://swift.org/LICENSE.txt for license information
// See https://swift.org/CONTRIBUTORS.txt for the list of Swift project authors

// RUN: not %target-swift-frontend %s -typecheck
class e {
var _ = d() {
class A {
class func a() -> Self {
}
}
func b<T>(t: AnyObject.Type) -> T! {
}
}
class d<j : i, f : i where j.i == f> : e {
}
class d<j, f> {
}
protocol i {
}
protocol e {
}
protocol i : d { func d
