//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift.org open source project
//
// Copyright (c) 2014 - 2019 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See https://swift.org/LICENSE.txt for license information
// See https://swift.org/CONTRIBUTORS.txt for the list of Swift project authors
//
//===----------------------------------------------------------------------===//

extension String {
  /// Subscripting strings with integers is not available.
  ///
  /// The concept of "the `i`th character in a string" has
  /// different interpretations in different libraries and system
  /// components.  The correct interpretation should be selected
  /// according to the use case and the APIs involved, so `String`
  /// cannot be subscripted with an integer.
  ///
  /// Swift provides several different ways to access the character
  /// data stored inside strings.
  ///
  /// - `String.utf8` is a collection of UTF-8 code units in the
  ///   string. Use this API when converting the string to UTF-8.
  ///   Most POSIX APIs process strings in terms of UTF-8 code units.
  ///
  /// - `String.utf16` is a collection of UTF-16 code units in
  ///   string.  Most Cocoa and Cocoa touch APIs process strings in
  ///   terms of UTF-16 code units.  For example, instances of
  ///   `NSRange` used with `NSAttributedString` and
  ///   `NSRegularExpression` store substring offsets and lengths in
  ///   terms of UTF-16 code units.
  ///
  /// - `String.unicodeScalars` is a collection of Unicode scalars.
  ///   Use this API when you are performing low-level manipulation
  ///   of character data.
  ///
  /// - `String.characters` is a collection of extended grapheme
  ///   clusters, which are an approximation of user-perceived
  ///   characters.
  ///
  /// Note that when processing strings that contain human-readable
  /// text, character-by-character processing should be avoided to
  /// the largest extent possible.  Use high-level locale-sensitive
  /// Unicode algorithms instead, for example,
  /// `String.localizedStandardCompare()`,
  /// `String.localizedLowercaseString`,
  /// `String.localizedStandardRangeOfString()` etc.
  @available(
    *, unavailable,
    message: "cannot subscript String with an Int, use a String.Index instead."
  )
  public subscript(i: Int) -> Character {
    Builtin.unreachable()
  }

  /// Subscripting strings with integers is not available.
  ///
  /// The concept of "the `i`th character in a string" has
  /// different interpretations in different libraries and system
  /// components.  The correct interpretation should be selected
  /// according to the use case and the APIs involved, so `String`
  /// cannot be subscripted with an integer.
  ///
  /// Swift provides several different ways to access the character
  /// data stored inside strings.
  ///
  /// - `String.utf8` is a collection of UTF-8 code units in the
  ///   string. Use this API when converting the string to UTF-8.
  ///   Most POSIX APIs process strings in terms of UTF-8 code units.
  ///
  /// - `String.utf16` is a collection of UTF-16 code units in
  ///   string.  Most Cocoa and Cocoa touch APIs process strings in
  ///   terms of UTF-16 code units.  For example, instances of
  ///   `NSRange` used with `NSAttributedString` and
  ///   `NSRegularExpression` store substring offsets and lengths in
  ///   terms of UTF-16 code units.
  ///
  /// - `String.unicodeScalars` is a collection of Unicode scalars.
  ///   Use this API when you are performing low-level manipulation
  ///   of character data.
  ///
  /// - `String.characters` is a collection of extended grapheme
  ///   clusters, which are an approximation of user-perceived
  ///   characters.
  ///
  /// Note that when processing strings that contain human-readable
  /// text, character-by-character processing should be avoided to
  /// the largest extent possible.  Use high-level locale-sensitive
  /// Unicode algorithms instead, for example,
  /// `String.localizedStandardCompare()`,
  /// `String.localizedLowercaseString`,
  /// `String.localizedStandardRangeOfString()` etc.
  @available(
    *, unavailable,
    message: "cannot subscript String with an integer range, use a String.Index range instead."
  )
  public subscript<R: RangeExpression>(bounds: R) -> String where R.Bound == Int {
    Builtin.unreachable()
  }
}
