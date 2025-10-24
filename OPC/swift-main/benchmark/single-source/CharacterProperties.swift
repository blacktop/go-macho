//===--- CharacterProperties.swift ----------------------------------------===//
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

////////////////////////////////////////////////////////////////////////////////
// WARNING: This file is manually generated from .gyb template and should not
// be directly modified. Instead, make changes to CharacterProperties.swift.gyb
// and run scripts/generate_harness/generate_harness.py to regenerate this file.
////////////////////////////////////////////////////////////////////////////////

import TestsUtils
import Foundation

public let benchmarks = [
  BenchmarkInfo(
    name: "CharacterPropertiesFetch",
    runFunction: run_CharacterPropertiesFetch,
    tags: [.validation, .api, .String],
    setUpFunction: { blackHole(workload) },
    legacyFactor: 10),

  BenchmarkInfo(
    name: "CharacterPropertiesStashed",
    runFunction: run_CharacterPropertiesStashed,
    tags: [.validation, .api, .String],
    setUpFunction: { setupStash() },
    legacyFactor: 10),

  BenchmarkInfo(
    name: "CharacterPropertiesStashedMemo",
    runFunction: run_CharacterPropertiesStashedMemo,
    tags: [.validation, .api, .String],
    setUpFunction: { setupMemo() },
    legacyFactor: 10),

  BenchmarkInfo(
    name: "CharacterPropertiesPrecomputed",
    runFunction: run_CharacterPropertiesPrecomputed,
    tags: [.validation, .api, .String],
    setUpFunction: { setupPrecomputed() },
    legacyFactor: 10),
]

extension Character {
  var firstScalar: UnicodeScalar { return unicodeScalars.first! }
}


// Fetch the CharacterSet for every call
func isAlphanumeric(_ c: Character) -> Bool {
  return CharacterSet.alphanumerics.contains(c.firstScalar)
}
func isCapitalized(_ c: Character) -> Bool {
  return CharacterSet.capitalizedLetters.contains(c.firstScalar)
}
func isControl(_ c: Character) -> Bool {
  return CharacterSet.controlCharacters.contains(c.firstScalar)
}
func isDecimal(_ c: Character) -> Bool {
  return CharacterSet.decimalDigits.contains(c.firstScalar)
}
func isLetter(_ c: Character) -> Bool {
  return CharacterSet.letters.contains(c.firstScalar)
}
func isLowercase(_ c: Character) -> Bool {
  return CharacterSet.lowercaseLetters.contains(c.firstScalar)
}
func isUppercase(_ c: Character) -> Bool {
  return CharacterSet.uppercaseLetters.contains(c.firstScalar)
}
func isNewline(_ c: Character) -> Bool {
  return CharacterSet.newlines.contains(c.firstScalar)
}
func isWhitespace(_ c: Character) -> Bool {
  return CharacterSet.whitespaces.contains(c.firstScalar)
}
func isPunctuation(_ c: Character) -> Bool {
  return CharacterSet.punctuationCharacters.contains(c.firstScalar)
}

// Stash the set
let alphanumerics = CharacterSet.alphanumerics
func isAlphanumericStashed(_ c: Character) -> Bool {
  return alphanumerics.contains(c.firstScalar)
}
let capitalizedLetters = CharacterSet.capitalizedLetters
func isCapitalizedStashed(_ c: Character) -> Bool {
  return capitalizedLetters.contains(c.firstScalar)
}
let controlCharacters = CharacterSet.controlCharacters
func isControlStashed(_ c: Character) -> Bool {
  return controlCharacters.contains(c.firstScalar)
}
let decimalDigits = CharacterSet.decimalDigits
func isDecimalStashed(_ c: Character) -> Bool {
  return decimalDigits.contains(c.firstScalar)
}
let letters = CharacterSet.letters
func isLetterStashed(_ c: Character) -> Bool {
  return letters.contains(c.firstScalar)
}
let lowercaseLetters = CharacterSet.lowercaseLetters
func isLowercaseStashed(_ c: Character) -> Bool {
  return lowercaseLetters.contains(c.firstScalar)
}
let uppercaseLetters = CharacterSet.uppercaseLetters
func isUppercaseStashed(_ c: Character) -> Bool {
  return uppercaseLetters.contains(c.firstScalar)
}
let newlines = CharacterSet.newlines
func isNewlineStashed(_ c: Character) -> Bool {
  return newlines.contains(c.firstScalar)
}
let whitespaces = CharacterSet.whitespaces
func isWhitespaceStashed(_ c: Character) -> Bool {
  return whitespaces.contains(c.firstScalar)
}
let punctuationCharacters = CharacterSet.punctuationCharacters
func isPunctuationStashed(_ c: Character) -> Bool {
  return punctuationCharacters.contains(c.firstScalar)
}

func setupStash() {
  blackHole(workload)
    blackHole(alphanumerics)
    blackHole(capitalizedLetters)
    blackHole(controlCharacters)
    blackHole(decimalDigits)
    blackHole(letters)
    blackHole(lowercaseLetters)
    blackHole(uppercaseLetters)
    blackHole(newlines)
    blackHole(whitespaces)
    blackHole(punctuationCharacters)
}

// Memoize the stashed set
var alphanumericsMemo = Set<UInt32>()
func isAlphanumericStashedMemo(_ c: Character) -> Bool {
  let scalar = c.firstScalar
  if alphanumericsMemo.contains(scalar.value) { return true }
  if alphanumerics.contains(scalar) {
    alphanumericsMemo.insert(scalar.value)
    return true
  }
  return false
}
var capitalizedLettersMemo = Set<UInt32>()
func isCapitalizedStashedMemo(_ c: Character) -> Bool {
  let scalar = c.firstScalar
  if capitalizedLettersMemo.contains(scalar.value) { return true }
  if capitalizedLetters.contains(scalar) {
    capitalizedLettersMemo.insert(scalar.value)
    return true
  }
  return false
}
var controlCharactersMemo = Set<UInt32>()
func isControlStashedMemo(_ c: Character) -> Bool {
  let scalar = c.firstScalar
  if controlCharactersMemo.contains(scalar.value) { return true }
  if controlCharacters.contains(scalar) {
    controlCharactersMemo.insert(scalar.value)
    return true
  }
  return false
}
var decimalDigitsMemo = Set<UInt32>()
func isDecimalStashedMemo(_ c: Character) -> Bool {
  let scalar = c.firstScalar
  if decimalDigitsMemo.contains(scalar.value) { return true }
  if decimalDigits.contains(scalar) {
    decimalDigitsMemo.insert(scalar.value)
    return true
  }
  return false
}
var lettersMemo = Set<UInt32>()
func isLetterStashedMemo(_ c: Character) -> Bool {
  let scalar = c.firstScalar
  if lettersMemo.contains(scalar.value) { return true }
  if letters.contains(scalar) {
    lettersMemo.insert(scalar.value)
    return true
  }
  return false
}
var lowercaseLettersMemo = Set<UInt32>()
func isLowercaseStashedMemo(_ c: Character) -> Bool {
  let scalar = c.firstScalar
  if lowercaseLettersMemo.contains(scalar.value) { return true }
  if lowercaseLetters.contains(scalar) {
    lowercaseLettersMemo.insert(scalar.value)
    return true
  }
  return false
}
var uppercaseLettersMemo = Set<UInt32>()
func isUppercaseStashedMemo(_ c: Character) -> Bool {
  let scalar = c.firstScalar
  if uppercaseLettersMemo.contains(scalar.value) { return true }
  if uppercaseLetters.contains(scalar) {
    uppercaseLettersMemo.insert(scalar.value)
    return true
  }
  return false
}
var newlinesMemo = Set<UInt32>()
func isNewlineStashedMemo(_ c: Character) -> Bool {
  let scalar = c.firstScalar
  if newlinesMemo.contains(scalar.value) { return true }
  if newlines.contains(scalar) {
    newlinesMemo.insert(scalar.value)
    return true
  }
  return false
}
var whitespacesMemo = Set<UInt32>()
func isWhitespaceStashedMemo(_ c: Character) -> Bool {
  let scalar = c.firstScalar
  if whitespacesMemo.contains(scalar.value) { return true }
  if whitespaces.contains(scalar) {
    whitespacesMemo.insert(scalar.value)
    return true
  }
  return false
}
var punctuationCharactersMemo = Set<UInt32>()
func isPunctuationStashedMemo(_ c: Character) -> Bool {
  let scalar = c.firstScalar
  if punctuationCharactersMemo.contains(scalar.value) { return true }
  if punctuationCharacters.contains(scalar) {
    punctuationCharactersMemo.insert(scalar.value)
    return true
  }
  return false
}

func setupMemo() {
  blackHole(workload)
    blackHole(alphanumericsMemo)
    blackHole(capitalizedLettersMemo)
    blackHole(controlCharactersMemo)
    blackHole(decimalDigitsMemo)
    blackHole(lettersMemo)
    blackHole(lowercaseLettersMemo)
    blackHole(uppercaseLettersMemo)
    blackHole(newlinesMemo)
    blackHole(whitespacesMemo)
    blackHole(punctuationCharactersMemo)
}

// Precompute whole scalar set
func precompute(_ charSet: CharacterSet, capacity: Int) -> Set<UInt32> {
  var result = Set<UInt32>(minimumCapacity: capacity)
  for plane in 0...0x10 {
    guard charSet.hasMember(inPlane: UInt8(plane)) else { continue }
    let offset = plane &* 0x1_0000
    for codePoint in 0...0xFFFF {
      guard let scalar = UnicodeScalar(codePoint &+ offset) else { continue }
      if charSet.contains(scalar) {
        result.insert(scalar.value)
      }
    }
  }
  return result
}
var alphanumericsPrecomputed: Set<UInt32> =
  precompute(alphanumerics, capacity: 122647)
func isAlphanumericPrecomputed(_ c: Character) -> Bool {
  return alphanumericsPrecomputed.contains(c.firstScalar.value)
}
var capitalizedLettersPrecomputed: Set<UInt32> =
  precompute(capitalizedLetters, capacity: 31)
func isCapitalizedPrecomputed(_ c: Character) -> Bool {
  return capitalizedLettersPrecomputed.contains(c.firstScalar.value)
}
var controlCharactersPrecomputed: Set<UInt32> =
  precompute(controlCharacters, capacity: 24951)
func isControlPrecomputed(_ c: Character) -> Bool {
  return controlCharactersPrecomputed.contains(c.firstScalar.value)
}
var decimalDigitsPrecomputed: Set<UInt32> =
  precompute(decimalDigits, capacity: 590)
func isDecimalPrecomputed(_ c: Character) -> Bool {
  return decimalDigitsPrecomputed.contains(c.firstScalar.value)
}
var lettersPrecomputed: Set<UInt32> =
  precompute(letters, capacity: 121145)
func isLetterPrecomputed(_ c: Character) -> Bool {
  return lettersPrecomputed.contains(c.firstScalar.value)
}
var lowercaseLettersPrecomputed: Set<UInt32> =
  precompute(lowercaseLetters, capacity: 2063)
func isLowercasePrecomputed(_ c: Character) -> Bool {
  return lowercaseLettersPrecomputed.contains(c.firstScalar.value)
}
var uppercaseLettersPrecomputed: Set<UInt32> =
  precompute(uppercaseLetters, capacity: 1733)
func isUppercasePrecomputed(_ c: Character) -> Bool {
  return uppercaseLettersPrecomputed.contains(c.firstScalar.value)
}
var newlinesPrecomputed: Set<UInt32> =
  precompute(newlines, capacity: 7)
func isNewlinePrecomputed(_ c: Character) -> Bool {
  return newlinesPrecomputed.contains(c.firstScalar.value)
}
var whitespacesPrecomputed: Set<UInt32> =
  precompute(whitespaces, capacity: 19)
func isWhitespacePrecomputed(_ c: Character) -> Bool {
  return whitespacesPrecomputed.contains(c.firstScalar.value)
}
var punctuationCharactersPrecomputed: Set<UInt32> =
  precompute(punctuationCharacters, capacity: 770)
func isPunctuationPrecomputed(_ c: Character) -> Bool {
  return punctuationCharactersPrecomputed.contains(c.firstScalar.value)
}

func setupPrecomputed() {
  blackHole(workload)
    blackHole(alphanumericsPrecomputed)
    blackHole(capitalizedLettersPrecomputed)
    blackHole(controlCharactersPrecomputed)
    blackHole(decimalDigitsPrecomputed)
    blackHole(lettersPrecomputed)
    blackHole(lowercaseLettersPrecomputed)
    blackHole(uppercaseLettersPrecomputed)
    blackHole(newlinesPrecomputed)
    blackHole(whitespacesPrecomputed)
    blackHole(punctuationCharactersPrecomputed)
}

// Compute on the fly
//
// TODO: If UnicodeScalars ever exposes category, etc., implement the others!
func isNewlineComputed(_ c: Character) -> Bool {
  switch c.firstScalar.value {
    case 0x000A...0x000D: return true
    case 0x0085: return true
    case 0x2028...0x2029: return true
    default: return false
  }
}

let workload = """
  the quick brown 🦊 jumped over the lazy 🐶.
  в чащах юга жил-был цитрус? да, но фальшивый экземпляр
  𓀀𓀤𓁓𓁲𓃔𓃗𓃀𓃁𓃂𓃃𓆌𓆍𓆎𓆏𓆐𓆑𓆒𓆲𓁿
  🝁ꃕ躍‾∾📦⺨
  👍👩‍👩‍👧‍👧👨‍👨‍👦‍👦🇺🇸🇨🇦🇲🇽👍🏻👍🏼👍🏽👍🏾👍🏿
  Lorem ipsum something something something...
"""

@inline(never)
public func run_CharacterPropertiesFetch(_ n: Int) {
  for _ in 1...n {
    for c in workload {
        blackHole(isAlphanumeric(c))
        blackHole(isCapitalized(c))
        blackHole(isControl(c))
        blackHole(isDecimal(c))
        blackHole(isLetter(c))
        blackHole(isLowercase(c))
        blackHole(isUppercase(c))
        blackHole(isNewline(c))
        blackHole(isWhitespace(c))
        blackHole(isPunctuation(c))
    }
  }
}

@inline(never)
public func run_CharacterPropertiesStashed(_ n: Int) {
  for _ in 1...n {
    for c in workload {
        blackHole(isAlphanumericStashed(c))
        blackHole(isCapitalizedStashed(c))
        blackHole(isControlStashed(c))
        blackHole(isDecimalStashed(c))
        blackHole(isLetterStashed(c))
        blackHole(isLowercaseStashed(c))
        blackHole(isUppercaseStashed(c))
        blackHole(isNewlineStashed(c))
        blackHole(isWhitespaceStashed(c))
        blackHole(isPunctuationStashed(c))
    }
  }
}

@inline(never)
public func run_CharacterPropertiesStashedMemo(_ n: Int) {
  for _ in 1...n {
    for c in workload {
        blackHole(isAlphanumericStashedMemo(c))
        blackHole(isCapitalizedStashedMemo(c))
        blackHole(isControlStashedMemo(c))
        blackHole(isDecimalStashedMemo(c))
        blackHole(isLetterStashedMemo(c))
        blackHole(isLowercaseStashedMemo(c))
        blackHole(isUppercaseStashedMemo(c))
        blackHole(isNewlineStashedMemo(c))
        blackHole(isWhitespaceStashedMemo(c))
        blackHole(isPunctuationStashedMemo(c))
    }
  }
}

@inline(never)
public func run_CharacterPropertiesPrecomputed(_ n: Int) {
  for _ in 1...n {
    for c in workload {
        blackHole(isAlphanumericPrecomputed(c))
        blackHole(isCapitalizedPrecomputed(c))
        blackHole(isControlPrecomputed(c))
        blackHole(isDecimalPrecomputed(c))
        blackHole(isLetterPrecomputed(c))
        blackHole(isLowercasePrecomputed(c))
        blackHole(isUppercasePrecomputed(c))
        blackHole(isNewlinePrecomputed(c))
        blackHole(isWhitespacePrecomputed(c))
        blackHole(isPunctuationPrecomputed(c))
    }
  }
}



// TODO: run_CharacterPropertiesComputed

// Local Variables:
// eval: (read-only-mode 1)
// End:
