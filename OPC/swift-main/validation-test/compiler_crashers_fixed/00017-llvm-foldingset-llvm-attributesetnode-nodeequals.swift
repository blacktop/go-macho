// This source file is part of the Swift.org open source project
//
// Copyright (c) 2014 - 2017 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See https://swift.org/LICENSE.txt for license information
// See https://swift.org/CONTRIBUTORS.txt for the list of Swift project authors

// RUN: %target-swift-frontend %s -typecheck -verify

// Issue found by https://github.com/jvasileff (John Vasileff)
// This bug is NOT triggered when compiling with -O.

protocol BooleanProtocol {
  var boolValue: Bool { get }
}
extension Bool : BooleanProtocol {
  var boolValue: Bool { return self }
}
func f<T : BooleanProtocol>(_ b: T) {}
// expected-note@-1 {{required by global function 'f' where 'T' = 'any BooleanProtocol'}}

f(true as BooleanProtocol) // expected-error {{type 'any BooleanProtocol' cannot conform to 'BooleanProtocol'}} expected-note {{only concrete types such as structs, enums and classes can conform to protocols}}
