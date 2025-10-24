// RUN: %empty-directory(%t)
// RUN: %target-build-swift -Xfrontend -disable-access-control -module-name main %s -o %t/hash
// RUN: %target-codesign %t/hash
// RUN: env %env-SWIFT_DETERMINISTIC_HASHING='' %target-run %t/hash > %t/nondeterministic.log
// RUN: env %env-SWIFT_DETERMINISTIC_HASHING='' %target-run %t/hash >> %t/nondeterministic.log
// RUN: %FileCheck --check-prefixes=RANDOM %s < %t/nondeterministic.log
// RUN: env %env-SWIFT_DETERMINISTIC_HASHING=1 %target-run %t/hash > %t/deterministic.log
// RUN: env %env-SWIFT_DETERMINISTIC_HASHING=1 %target-run %t/hash >> %t/deterministic.log
// RUN: %FileCheck --check-prefixes=STABLE %s < %t/deterministic.log

// REQUIRES: executable_test

// Freestanding doesn't support environment variables, and this test depends on SWIFT_DETERMINISTIC_HASHING=1
// UNSUPPORTED: freestanding

// This check verifies that the hash seed is randomly generated on every
// execution of a Swift program unless the SWIFT_DETERMINISTIC_HASHING
// environment variable is set.

print("Deterministic: \(Hasher._isDeterministic)")
print("Seed: (\(Hasher._executionSeed.0), \(Hasher._executionSeed.1))")
print("Hash values: <\(0.hashValue), \(1.hashValue)>")

// With randomized hashing, we get a new seed and a new set of hash values on
// each run. There is a minuscule chance that the same seed is generated on two
// separate executions; however, a test failure here is more likely to indicate
// an issue with the random number generator or the testing environment.
//   RANDOM: Deterministic: false
//   RANDOM-NEXT: Seed: [[SEED0:\([0-9]+, [0-9]+\)]]
//   RANDOM-NEXT: Hash values: [[HASH0:<-?[0-9]+, -?[0-9]+>]]
//   RANDOM-NEXT: Deterministic: false
//   RANDOM-NEXT: Seed:
//   RANDOM-NOT: [[SEED0]]
//   RANDOM-NEXT: Hash values:
//   RANDOM-NOT: [[HASH0]]

// Stable runs have known seeds, and generate the same hash values.  A test
// failure here indicates that the seed override mechanism isn't working
// correctly.
//   STABLE: Deterministic: true
//   STABLE-NEXT: Seed: (0, 0)
//   STABLE-NEXT: Hash values: [[HASH1:<-?[0-9]+, -?[0-9]+>]]
//   STABLE-NEXT: Deterministic: true
//   STABLE-NEXT: Seed: (0, 0)
//   STABLE-NEXT: Hash values: [[HASH1]]
