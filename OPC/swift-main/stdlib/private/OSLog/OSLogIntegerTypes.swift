//===----------------- OSLogIntegerTypes.swift ----------------------------===//
//
// This source file is part of the Swift.org open source project
//
// Copyright (c) 2014 - 2020 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See https://swift.org/LICENSE.txt for license information
// See https://swift.org/CONTRIBUTORS.txt for the list of Swift project authors
//
//===----------------------------------------------------------------------===//

// This file defines extensions for interpolating integer expressions into an
// OSLogMessage. It defines `appendInterpolation` functions for standard integer
// types. It also defines extensions for serializing integer types into the
// argument buffer passed to os_log ABIs.
//
// The `appendInterpolation` functions defined in this file accept formatting,
// privacy and alignment options along with the interpolated expression as
// shown below:
//
//  1.  "\(x, format: .hex, privacy: .private, align: .right\)"
//  2.  "\(x, format: .hex(minDigits: 10), align: .right(columns: 10)\)"

import ObjectiveC

extension OSLogInterpolation {

  /// Defines interpolation for expressions of type Int.
  ///
  /// Do not call this function directly. It will be called automatically when interpolating
  /// a value of type `Int` in the string interpolations passed to the log APIs.
  ///
  /// - Parameters:
  ///   - number: The interpolated expression of type Int, which is autoclosured.
  ///   - format: A formatting option available for integer types, defined by the
  ///     type: `OSLogIntegerFormatting`. The default is `.decimal`.
  ///   - align: Left or right alignment with the minimum number of columns as
  ///     defined by the type `OSLogStringAlignment`.
  ///   - privacy: A privacy qualifier which is either private or public.
  ///     It is auto-inferred by default.
  @_semantics("constant_evaluable")
  @inlinable
  @_optimize(none)
  @_semantics("oslog.requires_constant_arguments")
  public mutating func appendInterpolation(
    _ number: @autoclosure @escaping () -> Int,
    format: OSLogIntegerFormatting = .decimal,
    align: OSLogStringAlignment = .none,
    privacy: OSLogPrivacy = .auto
  ) {
    appendInteger(number, format: format, align: align, privacy: privacy)
  }

  // Define appendInterpolation overloads for fixed-size integers.

  @_semantics("constant_evaluable")
  @inlinable
  @_optimize(none)
  @_semantics("oslog.requires_constant_arguments")
  public mutating func appendInterpolation(
    _ number: @autoclosure @escaping () -> Int32,
    format: OSLogIntegerFormatting = .decimal,
    align: OSLogStringAlignment = .none,
    privacy: OSLogPrivacy = .auto
  ) {
    appendInteger(number, format: format, align: align, privacy: privacy)
  }

  /// Defines interpolation for expressions of type UInt.
  ///
  /// Do not call this function directly. It will be called automatically when interpolating
  /// a value of type `Int` in the string interpolations passed to the log APIs.
  ///
  /// - Parameters:
  ///   - number: The interpolated expression of type UInt, which is autoclosured.
  ///   - format: A formatting option available for integer types, defined by the
  ///     type `OSLogIntegerFormatting`.
  ///   - align: Left or right alignment with the minimum number of columns as
  ///     defined by the type `OSLogStringAlignment`.
  ///   - privacy: A privacy qualifier which is either private or public.
  ///     It is auto-inferred by default.
  @_semantics("constant_evaluable")
  @inlinable
  @_optimize(none)
  @_semantics("oslog.requires_constant_arguments")
  public mutating func appendInterpolation(
    _ number: @autoclosure @escaping () -> UInt,
    format: OSLogIntegerFormatting = .decimal,
    align: OSLogStringAlignment = .none,
    privacy: OSLogPrivacy = .auto
  ) {
    appendInteger(number, format: format, align: align, privacy: privacy)
  }

  /// Given an integer, create and append a format specifier for the integer to the
  /// format string property. Also, append the integer along with necessary headers
  /// to the OSLogArguments property.
  @_semantics("constant_evaluable")
  @inlinable
  @_optimize(none)
  internal mutating func appendInteger<T>(
    _ number: @escaping () -> T,
    format: OSLogIntegerFormatting,
    align: OSLogStringAlignment,
    privacy: OSLogPrivacy
  ) where T: FixedWidthInteger {
    guard argumentCount < maxOSLogArgumentCount else { return }
    formatString +=
      format.formatSpecifier(for: T.self, align: align, privacy: privacy)

    // If minimum column width is specified, append this value first. Note that
    // the format specifier would use a '*' for width e.g. %*d.
    if let minColumns = align.minimumColumnWidth {
      appendAlignmentArgument(minColumns)
    }

    // If the privacy has a mask, append the mask argument, which is a constant payload.
    // Note that this should come after the width but before the precision.
    if privacy.hasMask {
      appendMaskArgument(privacy)
    }

    // If minimum number of digits (precision) is specified, append the
    // precision before the argument. Note that the format specifier would use
    // a '*' for precision: %.*d.
    if let minDigits = format.minDigits {
      appendPrecisionArgument(minDigits)
    }

    // Append the integer.
    addIntHeaders(privacy, sizeForEncoding(T.self))
    arguments.append(number)
    argumentCount += 1
  }

  /// Update preamble and append argument headers based on the parameters of
  /// the interpolation.
  @_semantics("constant_evaluable")
  @inlinable
  @_optimize(none)
  internal mutating func addIntHeaders(
    _ privacy: OSLogPrivacy,
    _ byteCount: Int
  ) {
    // Append argument header.
    let argumentHeader = getArgumentHeader(privacy: privacy, type: .scalar)
    arguments.append(argumentHeader)

    // Append number of bytes needed to serialize the argument.
    arguments.append(UInt8(byteCount))

    // Increment total byte size by the number of bytes needed for this
    // argument, which is the sum of the byte size of the argument and
    // two bytes needed for the headers.
    totalBytesForSerializingArguments += byteCount + 2

    preamble = getUpdatedPreamble(privacy: privacy, isScalar: true)
  }

  // Append argument indicating precision or width of a format specifier to the buffer.
  // These specify the value of the '*' in a format specifier like: %*.*ld.
  @_semantics("constant_evaluable")
  @inlinable
  @_optimize(none)
  internal mutating func appendPrecisionArgument(_ count: @escaping () -> Int) {
    appendPrecisionAlignCount(
      count,
      getArgumentHeader(privacy: .auto, type: .count))
  }

  @_semantics("constant_evaluable")
  @inlinable
  @_optimize(none)
  internal mutating func appendAlignmentArgument(_ count: @escaping () -> Int) {
    appendPrecisionAlignCount(
      count,
      getArgumentHeader(privacy: .auto, type: .scalar))
  }

  // This is made transparent to minimize compile time overheads. The function's
  // implementation also uses literals whenever possible for the same reason.
  @_transparent
  @inlinable
  internal mutating func appendPrecisionAlignCount(
    _ count: @escaping () -> Int,
    _ argumentHeader: UInt8
  ) {
    arguments.append(argumentHeader)
    // Append number of bytes needed to serialize the argument.
    arguments.append(4)
    // Increment total byte size by the number of bytes needed for this
    // argument, which is the sum of the byte size of the argument and
    // two bytes needed for the headers.
    totalBytesForSerializingArguments += 6
    // The count is expected to be a CInt.
    arguments.append({ CInt(count()) })
    argumentCount += 1
    // Note that we don't have to update the preamble here.
  }

  @_semantics("constant_evaluable")
  @inlinable
  @_optimize(none)
  internal mutating func appendMaskArgument(_ privacy: OSLogPrivacy) {
    arguments.append(getArgumentHeader(privacy: .auto, type: .mask))
    // Append number of bytes needed to serialize the mask. Mask is 64 bit payload.
    arguments.append(8)
    // Increment total byte size by the number of bytes needed for this
    // argument, which is the sum of the byte size of the argument and
    // two bytes needed for the headers.
    totalBytesForSerializingArguments += 10
    // Append the mask value. This is a compile-time constant.
    let maskValue = privacy.maskValue
    arguments.append({ maskValue })
    argumentCount += 1
    // Note that we don't have to update the preamble here.
  }
}

extension OSLogArguments {
  /// Append an (autoclosured) interpolated expression of integer type, passed to
  /// `OSLogMessage.appendInterpolation`, to the array of closures tracked
  /// by this instance.
  @_semantics("constant_evaluable")
  @inlinable
  @_optimize(none)
  internal mutating func append<T>(
    _ value: @escaping () -> T
  ) where T: FixedWidthInteger {
    argumentClosures.append({ (position, _, _) in
      serialize(value(), at: &position)
    })
  }
}

/// Return the number of bytes needed for serializing an integer argument as
/// specified by os_log. This function must be constant evaluable. Note that
/// it is marked transparent instead of @inline(__always) as it is used in
/// optimize(none) functions.
@_transparent
@_alwaysEmitIntoClient
internal func sizeForEncoding<T>(
  _ type: T.Type
) -> Int where T : FixedWidthInteger  {
  return type.bitWidth &>> logBitsPerByte
}

/// Serialize an integer at the buffer location that `position` points to and
/// increment `position` by the byte size of `T`.
@_alwaysEmitIntoClient
@inline(__always)
internal func serialize<T>(
  _ value: T,
  at bufferPosition: inout ByteBufferPointer
) where T : FixedWidthInteger {
  let byteCount = sizeForEncoding(T.self)
  let dest =
    UnsafeMutableRawBufferPointer(start: bufferPosition, count: byteCount)
  withUnsafeBytes(of: value) { dest.copyMemory(from: $0) }
  bufferPosition += byteCount
}
