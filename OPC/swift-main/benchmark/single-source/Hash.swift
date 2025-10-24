//===--- Hash.swift -------------------------------------------------------===//
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

// Derived from the C samples in:
// Source: http://en.wikipedia.org/wiki/MD5 and
//         http://en.wikipedia.org/wiki/SHA-1
import TestsUtils

public let benchmarks = [
  BenchmarkInfo(
    name: "HashTest",
    runFunction: run_HashTest,
    tags: [.validation, .algorithm],
    legacyFactor: 10),
]

class Hash {
  /// C'tor.
  init(_ bs: Int) {
    blocksize = bs
    messageLength = 0
    dataLength = 0
    assert(blocksize <= 64, "Invalid block size")
  }

  /// Add the bytes in \p Msg to the hash.
  func update(_ Msg: String) {
    for c in Msg.unicodeScalars {
      data[dataLength] = UInt8(ascii: c)
      dataLength += 1
      messageLength += 1
      if dataLength == blocksize { hash() }
    }
  }

  /// Add the bytes in \p Msg to the hash.
  func update(_ Msg: [UInt8]) {
    for c in Msg {
      data[dataLength] = c
      dataLength += 1
      messageLength += 1
      if dataLength == blocksize { hash() }
    }
  }

  /// \returns the hash of the data that was updated.
  func digest() -> String {
    fillBlock()
    hash()
    let x  = hashState()
    return x
  }

  // private:

  // Hash state:
  final var messageLength: Int = 0
  final var dataLength: Int = 0
  final var data = [UInt8](repeating: 0, count: 64)
  final var blocksize: Int

  /// Hash the internal data.
  func hash() {
    fatalError("Pure virtual")
  }

  /// \returns a string representation of the state.
  func hashState() -> String {
    fatalError("Pure virtual")
  }
  func hashStateFast(_ res: inout [UInt8]) {
    fatalError("Pure virtual")
  }

  /// Blow the data to fill the block.
  func fillBlock() {
    fatalError("Pure virtual")
  }

  var hexTable = ["0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"]
  final
  var hexTableFast : [UInt8] = [48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102]

  /// Convert a 4-byte integer to a hex string.
  final
  func toHex(_ input: UInt32) -> String {
    var input = input
    var res = ""
    for _ in 0..<8 {
      res = hexTable[Int(input & 0xF)] + res
      input = input >> 4
    }
    return res
  }

  final
  func toHexFast(_ input: UInt32, _ res: inout Array<UInt8>, _ index : Int) {
    var input = input
    for i in 0..<4 {
      // Convert one byte each iteration.
      res[index + 2*i] = hexTableFast[Int(input >> 4) & 0xF]
      res[index + 2*i + 1] = hexTableFast[Int(input & 0xF)]
      input = input >> 8
    }
  }

  /// Left-rotate \p x by \p c.
  final
  func rol(_ x: UInt32, _ c: UInt32) -> UInt32 {
    return x &<< c | x &>> (32 &- c)
  }

  /// Right-rotate \p x by \p c.
  final
  func ror(_ x: UInt32, _ c: UInt32) -> UInt32 {
    return x &>> c | x &<< (32 &- c)
  }
}

final
class MD5 : Hash {
  // Integer part of the sines of integers (in radians) * 2^32.
  let k : [UInt32] = [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee ,
                      0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501 ,
                      0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be ,
                      0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821 ,
                      0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa ,
                      0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8 ,
                      0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed ,
                      0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a ,
                      0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c ,
                      0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70 ,
                      0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05 ,
                      0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665 ,
                      0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039 ,
                      0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1 ,
                      0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1 ,
                      0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 ]

  // Per-round shift amounts
  let r : [UInt32] = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                      5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

  // State
  var h0: UInt32 = 0
  var h1: UInt32 = 0
  var h2: UInt32 = 0
  var h3: UInt32 = 0

  init() {
    super.init(64)
    reset()
  }

  func reset() {
    // Set the initial values.
    h0 = 0x67452301
    h1 = 0xefcdab89
    h2 = 0x98badcfe
    h3 = 0x10325476
    messageLength = 0
    dataLength = 0
  }

  func appendBytes(_ val: Int, _ message: inout Array<UInt8>, _ offset : Int) {
    message[offset] = UInt8(truncatingIfNeeded: val)
    message[offset + 1] = UInt8(truncatingIfNeeded: val >> 8)
    message[offset + 2] = UInt8(truncatingIfNeeded: val >> 16)
    message[offset + 3] = UInt8(truncatingIfNeeded: val >> 24)
  }

  override
  func fillBlock() {
    // Pre-processing:
    // Append "1" bit to message
    // Append "0" bits until message length in bits -> 448 (mod 512)
    // Append length mod (2^64) to message

    var new_len = messageLength + 1
    while (new_len % (512/8) != 448/8) {
      new_len += 1
    }

    // Append the "1" bit - most significant bit is "first"
    data[dataLength] = UInt8(0x80)
    dataLength += 1

    // Append "0" bits
    for _ in 0..<(new_len - (messageLength + 1)) {
      if dataLength == blocksize { hash() }
      data[dataLength] = UInt8(0)
      dataLength += 1
    }

    // Append the len in bits at the end of the buffer.
    // initial_len>>29 == initial_len*8>>32, but avoids overflow.
    appendBytes(messageLength * 8, &data, dataLength)
    appendBytes(messageLength>>29 * 8, &data, dataLength+4)
    dataLength += 8
  }

  func toUInt32(_ message: Array<UInt8>, _ offset: Int) -> UInt32 {
    let first = UInt32(message[offset + 0])
    let second = UInt32(message[offset + 1]) << 8
    let third = UInt32(message[offset + 2]) << 16
    let fourth = UInt32(message[offset + 3]) << 24
    return first | second | third | fourth
  }

  var w = [UInt32](repeating: 0, count: 16)
  override
  func hash() {
    assert(dataLength == blocksize, "Invalid block size")

    // Break chunk into sixteen 32-bit words w[j], 0 ≤ j ≤ 15
    for i in 0..<16 {
      w[i] = toUInt32(data, i*4)
    }

    // We don't need the original data anymore.
    dataLength = 0

    var a = h0
    var b = h1
    var c = h2
    var d = h3
    var f, g: UInt32

    // Main loop:
    for i in 0..<64 {
      if i < 16 {
        f = (b & c) | ((~b) & d)
        g = UInt32(i)
      } else if i < 32 {
        f = (d & b) | ((~d) & c)
        g = UInt32(5*i + 1) % 16
      } else if i < 48 {
        f = b ^ c ^ d
        g = UInt32(3*i + 5) % 16
      } else {
        f = c ^ (b | (~d))
        g = UInt32(7*i) % 16
      }

      let temp = d
      d = c
      c = b
      b = b &+ rol(a &+ f &+ k[i] &+ w[Int(g)], r[i])
      a = temp
    }

    // Add this chunk's hash to result so far:
    h0 = a &+ h0
    h1 = b &+ h1
    h2 = c &+ h2
    h3 = d &+ h3
  }

  func reverseBytes(_ input: UInt32) -> UInt32 {
    let b0 = (input >> 0 ) & 0xFF
    let b1 = (input >> 8 ) & 0xFF
    let b2 = (input >> 16) & 0xFF
    let b3 = (input >> 24) & 0xFF
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
  }

  override
  func hashState() -> String {
    var s = ""
    for h in [h0, h1, h2, h3] {
      s += toHex(reverseBytes(h))
    }
    return s
  }

  override
  func hashStateFast(_ res: inout [UInt8]) {
#if !NO_RANGE
    var idx: Int = 0
    for h in [h0, h1, h2, h3] {
      toHexFast(h, &res, idx)
      idx += 8
    }
#else
    toHexFast(h0, &res, 0)
    toHexFast(h1, &res, 8)
    toHexFast(h2, &res, 16)
    toHexFast(h3, &res, 24)
#endif
  }

}

class SHA1 : Hash {
  // State
  var h0: UInt32 = 0
  var h1: UInt32 = 0
  var h2: UInt32 = 0
  var h3: UInt32 = 0
  var h4: UInt32 = 0

  init() {
    super.init(64)
    reset()
  }

  func reset() {
    // Set the initial values.
    h0  = 0x67452301
    h1  = 0xEFCDAB89
    h2  = 0x98BADCFE
    h3  = 0x10325476
    h4  = 0xC3D2E1F0
    messageLength = 0
    dataLength = 0
  }

  override
  func fillBlock() {
    // Append a 1 to the message.
    data[dataLength] = UInt8(0x80)
    dataLength += 1

    var new_len = messageLength + 1
    while ((new_len % 64) != 56) {
      new_len += 1
    }

    for _ in 0..<new_len - (messageLength + 1) {
      if dataLength == blocksize { hash() }
      data[dataLength] = UInt8(0x0)
      dataLength += 1
    }

    // Append the original message length as 64bit big endian:
    let len_in_bits = Int64(messageLength)*8
    for i in 0..<(8 as Int64) {
      let val = (len_in_bits >> ((7-i)*8)) & 0xFF
      data[dataLength] = UInt8(val)
      dataLength += 1
    }
  }

  override
  func hash() {
    assert(dataLength == blocksize, "Invalid block size")

    // Init the "W" buffer.
    var w = [UInt32](repeating: 0, count: 80)

    // Convert the Byte array to UInt32 array.
    var word: UInt32 = 0
    for i in 0..<64 {
      word = word << 8
      word = word &+ UInt32(data[i])
      if i%4 == 3 { w[i/4] = word; word = 0 }
    }

    // Init the rest of the "W" buffer.
    for t in 16..<80 {
      // splitting into 2 subexpressions to help typechecker
      let lhs = w[t-3] ^ w[t-8]
      let rhs = w[t-14] ^ w[t-16]
      w[t] = rol(lhs ^ rhs, 1)
    }

    dataLength = 0

    var a = h0
    var b = h1
    var c = h2
    var d = h3
    var e = h4
    var k: UInt32, f: UInt32

    for t in 0..<80 {
      if t < 20 {
        k = 0x5a827999
        f = (b & c) | ((b ^ 0xFFFFFFFF) & d)
      } else if t < 40 {
        k = 0x6ed9eba1
        f = b ^ c ^ d
      } else if t < 60 {
        k = 0x8f1bbcdc
        f = (b & c) | (b & d) | (c & d)
      } else {
        k = 0xca62c1d6
        f = b ^ c ^ d
      }
      let temp: UInt32 = rol(a,5) &+ f &+ e &+ w[t] &+ k

      e = d
      d = c
      c = rol(b,30)
      b = a
      a = temp
    }

    h0 = h0 &+ a
    h1 = h1 &+ b
    h2 = h2 &+ c
    h3 = h3 &+ d
    h4 = h4 &+ e
  }

  override
  func hashState() -> String {
    var res: String = ""
    for state in [h0, h1, h2, h3, h4] {
      res += toHex(state)
    }
    return res
  }
}

class SHA256 :  Hash {
  // State
  var h0: UInt32 = 0
  var h1: UInt32 = 0
  var h2: UInt32 = 0
  var h3: UInt32 = 0
  var h4: UInt32 = 0
  var h5: UInt32 = 0
  var h6: UInt32 = 0
  var h7: UInt32 = 0

  let k : [UInt32] = [
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

  init() {
    super.init(64)
    reset()
  }

  func reset() {
    // Set the initial values.
    h0 =  0x6a09e667
    h1 =  0xbb67ae85
    h2 =  0x3c6ef372
    h3 =  0xa54ff53a
    h4 =  0x510e527f
    h5 =  0x9b05688c
    h6 =  0x1f83d9ab
    h7 =  0x5be0cd19
    messageLength = 0
    dataLength = 0
  }

  override
  func fillBlock() {
    // Append a 1 to the message.
    data[dataLength] = UInt8(0x80)
    dataLength += 1

    var new_len = messageLength + 1
    while ((new_len % 64) != 56) {
      new_len += 1
    }

    for _ in 0..<new_len - (messageLength+1) {
      if dataLength == blocksize { hash() }
      data[dataLength] = UInt8(0)
      dataLength += 1
    }

    // Append the original message length as 64bit big endian:
    let len_in_bits = Int64(messageLength)*8
    for i in 0..<(8 as Int64) {
      let val = (len_in_bits >> ((7-i)*8)) & 0xFF
      data[dataLength] = UInt8(val)
      dataLength += 1
    }
  }

  override
  func hash() {
    assert(dataLength == blocksize, "Invalid block size")

    // Init the "W" buffer.
    var w = [UInt32](repeating: 0, count: 64)

    // Convert the Byte array to UInt32 array.
    var word: UInt32 = 0
    for i in 0..<64 {
      word = word << 8
      word = word &+ UInt32(data[i])
      if i%4 == 3 { w[i/4] = word; word = 0 }
    }

    // Init the rest of the "W" buffer.
    for i in 16..<64 {
      let s0 = ror(w[i-15], 7) ^ ror(w[i-15], 18) ^ (w[i-15] >> 3)
      let s1 = ror(w[i-2], 17) ^ ror(w[i-2], 19) ^ (w[i-2] >> 10)
      w[i] = w[i-16] &+ s0 &+ w[i-7] &+ s1
    }

    dataLength = 0

    var a = h0
    var b = h1
    var c = h2
    var d = h3
    var e = h4
    var f = h5
    var g = h6
    var h = h7

    for i in 0..<64 {
      let s1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)
      let ch = (e & f) ^ ((~e) & g)
      let temp1 = h &+ s1 &+ ch &+ k[i] &+ w[i]
      let s0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)
      let maj = (a & b) ^ (a & c) ^ (b & c)
      let temp2 = s0 &+ maj

      h = g
      g = f
      f = e
      e = d &+ temp1
      d = c
      c = b
      b = a
      a = temp1 &+ temp2
    }

    h0 = h0 &+ a
    h1 = h1 &+ b
    h2 = h2 &+ c
    h3 = h3 &+ d
    h4 = h4 &+ e
    h5 = h5 &+ f
    h6 = h6 &+ g
    h7 = h7 &+ h
  }

  override
  func hashState() -> String {
    var res: String = ""
    for state in [h0, h1, h2, h3, h4, h5, h6, h7] {
      res += toHex(state)
    }
    return res
  }
}

func == (lhs: [UInt8], rhs: [UInt8]) -> Bool {
  if lhs.count != rhs.count { return false }
  for idx in 0..<lhs.count {
    if lhs[idx] != rhs[idx] { return false }
  }
  return true
}

@inline(never)
public func run_HashTest(_ n: Int) {
  let testMD5 = [""                                : "d41d8cd98f00b204e9800998ecf8427e",
    "The quick brown fox jumps over the lazy dog." : "e4d909c290d0fb1ca068ffaddf22cbd0",
    "The quick brown fox jumps over the lazy cog." : "68aa5deab43e4df2b5e1f80190477fb0"]

  let testSHA1 = [""                              : "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "The quick brown fox jumps over the lazy dog" : "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
    "The quick brown fox jumps over the lazy cog" : "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"]

  let testSHA256 = [""                             : "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "The quick brown fox jumps over the lazy dog"  : "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
    "The quick brown fox jumps over the lazy dog." : "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c"]
  let size = 50

  for _ in 1...n {
    // Check for precomputed values.
    let md = MD5()
    for (k, v) in testMD5 {
      md.update(k)
      check(md.digest() == v)
      md.reset()
    }

    // Check that we don't crash on large strings.
    var s: String = ""
    for _ in 1...size {
      s += "a"
      md.reset()
      md.update(s)
    }

    // Check that the order in which we push values does not change the result.
    md.reset()
    var l: String = ""
    for _ in 1...size {
      l += "a"
      md.update("a")
    }
    let md2 = MD5()
    md2.update(l)
    check(md.digest() == md2.digest())

    // Test the famous md5 collision from 2009: http://www.mscs.dal.ca/~selinger/md5collision/
    let src1 : [UInt8] =
    [0xd1, 0x31, 0xdd, 0x02, 0xc5, 0xe6, 0xee, 0xc4, 0x69, 0x3d, 0x9a, 0x06, 0x98, 0xaf, 0xf9, 0x5c, 0x2f, 0xca, 0xb5, 0x87, 0x12, 0x46, 0x7e, 0xab, 0x40, 0x04, 0x58, 0x3e, 0xb8, 0xfb, 0x7f, 0x89,
     0x55, 0xad, 0x34, 0x06, 0x09, 0xf4, 0xb3, 0x02, 0x83, 0xe4, 0x88, 0x83, 0x25, 0x71, 0x41, 0x5a, 0x08, 0x51, 0x25, 0xe8, 0xf7, 0xcd, 0xc9, 0x9f, 0xd9, 0x1d, 0xbd, 0xf2, 0x80, 0x37, 0x3c, 0x5b,
     0xd8, 0x82, 0x3e, 0x31, 0x56, 0x34, 0x8f, 0x5b, 0xae, 0x6d, 0xac, 0xd4, 0x36, 0xc9, 0x19, 0xc6, 0xdd, 0x53, 0xe2, 0xb4, 0x87, 0xda, 0x03, 0xfd, 0x02, 0x39, 0x63, 0x06, 0xd2, 0x48, 0xcd, 0xa0,
     0xe9, 0x9f, 0x33, 0x42, 0x0f, 0x57, 0x7e, 0xe8, 0xce, 0x54, 0xb6, 0x70, 0x80, 0xa8, 0x0d, 0x1e, 0xc6, 0x98, 0x21, 0xbc, 0xb6, 0xa8, 0x83, 0x93, 0x96, 0xf9, 0x65, 0x2b, 0x6f, 0xf7, 0x2a, 0x70]

    let src2 : [UInt8] =
    [0xd1, 0x31, 0xdd, 0x02, 0xc5, 0xe6, 0xee, 0xc4, 0x69, 0x3d, 0x9a, 0x06, 0x98, 0xaf, 0xf9, 0x5c, 0x2f, 0xca, 0xb5, 0x07, 0x12, 0x46, 0x7e, 0xab, 0x40, 0x04, 0x58, 0x3e, 0xb8, 0xfb, 0x7f, 0x89,
     0x55, 0xad, 0x34, 0x06, 0x09, 0xf4, 0xb3, 0x02, 0x83, 0xe4, 0x88, 0x83, 0x25, 0xf1, 0x41, 0x5a, 0x08, 0x51, 0x25, 0xe8, 0xf7, 0xcd, 0xc9, 0x9f, 0xd9, 0x1d, 0xbd, 0x72, 0x80, 0x37, 0x3c, 0x5b,
     0xd8, 0x82, 0x3e, 0x31, 0x56, 0x34, 0x8f, 0x5b, 0xae, 0x6d, 0xac, 0xd4, 0x36, 0xc9, 0x19, 0xc6, 0xdd, 0x53, 0xe2, 0x34, 0x87, 0xda, 0x03, 0xfd, 0x02, 0x39, 0x63, 0x06, 0xd2, 0x48, 0xcd, 0xa0,
     0xe9, 0x9f, 0x33, 0x42, 0x0f, 0x57, 0x7e, 0xe8, 0xce, 0x54, 0xb6, 0x70, 0x80, 0x28, 0x0d, 0x1e, 0xc6, 0x98, 0x21, 0xbc, 0xb6, 0xa8, 0x83, 0x93, 0x96, 0xf9, 0x65, 0xab, 0x6f, 0xf7, 0x2a, 0x70]

    let h1 = MD5()
    let h2 = MD5()

    h1.update(src1)
    h2.update(src2)
    let a1 = h1.digest()
    let a2 = h2.digest()
    check(a1 == a2)
    check(a1 == "79054025255fb1a26e4bc422aef54eb4")
    h1.reset()
    h2.reset()

    let sh = SHA1()
    let sh256 = SHA256()
    for (k, v) in testSHA1 {
      sh.update(k)
      check(sh.digest() == v)
      sh.reset()
    }

    for (k, v) in testSHA256 {
      sh256.update(k)
      check(sh256.digest() == v)
      sh256.reset()
    }

    // Check that we don't crash on large strings.
    s = ""
    for _ in 1...size {
      s += "a"
      sh.reset()
      sh.update(s)
    }

    // Check that the order in which we push values does not change the result.
    sh.reset()
    l = ""
    for _ in 1...size {
      l += "a"
      sh.update("a")
    }
    let sh2 = SHA1()
    sh2.update(l)
    check(sh.digest() == sh2.digest())
  }
}
