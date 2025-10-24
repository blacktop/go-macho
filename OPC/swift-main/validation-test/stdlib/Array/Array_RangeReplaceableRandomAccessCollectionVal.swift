//===----------------------------------------------------------------------===//
// Automatically Generated From validation-test/stdlib/Array/Inputs/ArrayConformanceTests.swift.gyb
// Do Not Edit Directly!
//===----------------------------------------------------------------------===//

// RUN: %enable-cow-checking %target-run-simple-swift
// REQUIRES: executable_test
// REQUIRES: optimized_stdlib

import StdlibUnittest
import StdlibCollectionUnittest


let tests = TestSuite("Array_RangeReplaceableRandomAccessCollectionVal")



do {
  var resiliencyChecks = CollectionMisuseResiliencyChecks.all
  resiliencyChecks.creatingOutOfBoundsIndicesBehavior = .none


  // Test RangeReplaceableCollectionType conformance with value type elements.
  tests.addRangeReplaceableRandomAccessCollectionTests(
    "Array.",
    makeCollection: { (elements: [OpaqueValue<Int>]) in
      return Array(elements)
    },
    wrapValue: identity,
    extractValue: identity,
    makeCollectionOfEquatable: { (elements: [MinimalEquatableValue]) in
      return Array(elements)
    },
    wrapValueIntoEquatable: identityEq,
    extractValueFromEquatable: identityEq,
    resiliencyChecks: resiliencyChecks)


} // do

runAllTests()

