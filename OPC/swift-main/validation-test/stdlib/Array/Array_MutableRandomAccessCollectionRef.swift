//===----------------------------------------------------------------------===//
// Automatically Generated From validation-test/stdlib/Array/Inputs/ArrayConformanceTests.swift.gyb
// Do Not Edit Directly!
//===----------------------------------------------------------------------===//

// RUN: %enable-cow-checking %target-run-simple-swift
// REQUIRES: executable_test
// REQUIRES: optimized_stdlib

import StdlibUnittest
import StdlibCollectionUnittest


let tests = TestSuite("Array_MutableRandomAccessCollectionRef")



do {
  var resiliencyChecks = CollectionMisuseResiliencyChecks.all
  resiliencyChecks.creatingOutOfBoundsIndicesBehavior = .none


  // Test MutableCollectionType conformance with reference type elements.
  tests.addMutableRandomAccessCollectionTests(
    "Array.",
    makeCollection: { (elements: [LifetimeTracked]) in
      return Array(elements)
    },
    wrapValue: { (element: OpaqueValue<Int>) in
      LifetimeTracked(element.value, identity: element.identity)
    },
    extractValue: { (element: LifetimeTracked) in
      OpaqueValue(element.value, identity: element.identity)
    },
    makeCollectionOfEquatable: { (elements: [MinimalEquatableValue]) in
      // FIXME: use LifetimeTracked.
      return Array(elements)
    },
    wrapValueIntoEquatable: identityEq,
    extractValueFromEquatable: identityEq,
    makeCollectionOfComparable: { (elements: [MinimalComparableValue]) in
      // FIXME: use LifetimeTracked.
      return Array(elements)
    },
    wrapValueIntoComparable: identityComp,
    extractValueFromComparable: identityComp,
    resiliencyChecks: resiliencyChecks,
    withUnsafeMutableBufferPointerIsSupported: true,
    isFixedLengthCollection: false)


} // do

runAllTests()

