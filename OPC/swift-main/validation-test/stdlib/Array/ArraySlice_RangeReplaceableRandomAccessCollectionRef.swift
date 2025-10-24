//===----------------------------------------------------------------------===//
// Automatically Generated From validation-test/stdlib/Array/Inputs/ArrayConformanceTests.swift.gyb
// Do Not Edit Directly!
//===----------------------------------------------------------------------===//

// RUN: %enable-cow-checking %target-run-simple-swift
// REQUIRES: executable_test
// REQUIRES: optimized_stdlib

import StdlibUnittest
import StdlibCollectionUnittest


let tests = TestSuite("ArraySlice_RangeReplaceableRandomAccessCollectionRef")



do {
  var resiliencyChecks = CollectionMisuseResiliencyChecks.all
  resiliencyChecks.creatingOutOfBoundsIndicesBehavior = .none


  // Test RangeReplaceableCollectionType conformance with reference type elements.
  tests.addRangeReplaceableRandomAccessSliceTests(
    "ArraySlice.",
    makeCollection: { (elements: [LifetimeTracked]) in
      return ArraySlice(elements)
    },
    wrapValue: { (element: OpaqueValue<Int>) in LifetimeTracked(element.value) },
    extractValue: { (element: LifetimeTracked) in OpaqueValue(element.value) },
    makeCollectionOfEquatable: { (elements: [MinimalEquatableValue]) in
      // FIXME: use LifetimeTracked.
      return ArraySlice(elements)
    },
    wrapValueIntoEquatable: identityEq,
    extractValueFromEquatable: identityEq,
    resiliencyChecks: resiliencyChecks)


} // do

runAllTests()

