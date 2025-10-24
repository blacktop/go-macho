//===--- Unicode.h - Unicode utilities --------------------------*- C++ -*-===//
//
// This source file is part of the Swift.org open source project
//
// Copyright (c) 2014 - 2017 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See https://swift.org/LICENSE.txt for license information
// See https://swift.org/CONTRIBUTORS.txt for the list of Swift project authors
//
//===----------------------------------------------------------------------===//

#ifndef SWIFT_BASIC_UNICODE_H
#define SWIFT_BASIC_UNICODE_H

#include "swift/Basic/LLVM.h"
#include "llvm/ADT/StringRef.h"

namespace swift {
namespace unicode {

StringRef extractFirstExtendedGraphemeCluster(StringRef S);

static inline bool isSingleExtendedGraphemeCluster(StringRef S) {
  StringRef First = extractFirstExtendedGraphemeCluster(S);
  if (First.empty())
    return false;
  return First == S;
}

enum class GraphemeClusterBreakProperty : uint8_t {
  Other,
  CR,
  LF,
  Control,
  Extend,
  Regional_Indicator,
  Prepend,
  SpacingMark,
  L,
  V,
  T,
  LV,
  LVT,
};

/// Extended grapheme cluster boundary rules, represented as a matrix.  Indexed
/// by first code point, then by second code point in least-significant-bit
/// order.  A set bit means that a boundary is prohibited between two code
/// points.
extern const uint16_t ExtendedGraphemeClusterNoBoundaryRulesMatrix[];

/// Returns the value of the Grapheme_Cluster_Break property for a given code
/// point.
GraphemeClusterBreakProperty getGraphemeClusterBreakProperty(uint32_t C);

/// Determine if there is an extended grapheme cluster boundary between code
/// points with given Grapheme_Cluster_Break property values.
static inline bool
isExtendedGraphemeClusterBoundary(GraphemeClusterBreakProperty GCB1,
                                  GraphemeClusterBreakProperty GCB2) {
  auto RuleRow =
      ExtendedGraphemeClusterNoBoundaryRulesMatrix[static_cast<unsigned>(GCB1)];
  return !(RuleRow & (1 << static_cast<unsigned>(GCB2)));
}

bool isSingleUnicodeScalar(StringRef S);

unsigned extractFirstUnicodeScalar(StringRef S);

/// Returns true if \p S does not contain any ill-formed subsequences. This does
/// not check whether all of the characters in it are actually allocated or
/// used correctly; it just checks that every byte can be grouped into a code
/// unit (Unicode scalar).
bool isWellFormedUTF8(StringRef S);

/// Replaces any ill-formed subsequences with `u8"\ufffd"`.
std::string sanitizeUTF8(StringRef Text);

} // end namespace unicode
} // end namespace swift

#endif // SWIFT_BASIC_UNICODE_H
