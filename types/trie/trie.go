package trie

import (
	"bytes"
	"fmt"
	"io"
)

func ReadUleb128(r *bytes.Reader) (uint64, error) {
	var result uint64
	var shift uint64

	for {
		b, err := r.ReadByte()
		if err == io.EOF {
			return 0, err
		}
		if err != nil {
			return 0, fmt.Errorf("could not parse ULEB128 value: %v", err)
		}

		result |= uint64((uint(b) & 0x7f) << shift)

		// If high order bit is 1.
		if (b & 0x80) == 0 {
			break
		}

		shift += 7
	}

	return result, nil
}

func ReadUleb128FromBuffer(buf *bytes.Buffer) (uint64, int, error) {

	var (
		result uint64
		shift  uint64
		length int
	)

	if buf.Len() == 0 {
		return 0, 0, nil
	}

	for {
		b, err := buf.ReadByte()
		if err != nil {
			return 0, 0, fmt.Errorf("could not parse ULEB128 value: %v", err)
		}
		length++

		result |= uint64((uint(b) & 0x7f) << shift)

		// If high order bit is 1.
		if (b & 0x80) == 0 {
			break
		}

		shift += 7
	}

	return result, length, nil
}
