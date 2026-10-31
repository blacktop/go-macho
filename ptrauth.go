package macho

import (
	"encoding/binary"
	"math/bits"
)

// pointerAuthStringDiscriminator implements arm64e's
// ptrauth_string_discriminator: SipHash-2-4 with the ABI's fixed key, reduced
// to the non-zero 16-bit discriminator range.
func pointerAuthStringDiscriminator(value string) uint16 {
	const (
		key0 = uint64(0x794a1079ebc9d4b5)
		key1 = uint64(0xd48187421b8bec6f)
	)

	v0 := key0 ^ 0x736f6d6570736575
	v1 := key1 ^ 0x646f72616e646f6d
	v2 := key0 ^ 0x6c7967656e657261
	v3 := key1 ^ 0x7465646279746573
	round := func() {
		v0 += v1
		v1 = bits.RotateLeft64(v1, 13) ^ v0
		v0 = bits.RotateLeft64(v0, 32)
		v2 += v3
		v3 = bits.RotateLeft64(v3, 16) ^ v2
		v0 += v3
		v3 = bits.RotateLeft64(v3, 21) ^ v0
		v2 += v1
		v1 = bits.RotateLeft64(v1, 17) ^ v2
		v2 = bits.RotateLeft64(v2, 32)
	}

	data := []byte(value)
	for len(data) >= 8 {
		message := binary.LittleEndian.Uint64(data)
		v3 ^= message
		round()
		round()
		v0 ^= message
		data = data[8:]
	}
	tail := uint64(len(value)) << 56
	for index, value := range data {
		tail |= uint64(value) << (index * 8)
	}
	v3 ^= tail
	round()
	round()
	v0 ^= tail
	v2 ^= 0xff
	for index := 0; index < 4; index++ {
		round()
	}

	hash := v0 ^ v1 ^ v2 ^ v3
	return uint16(hash%65535 + 1)
}
