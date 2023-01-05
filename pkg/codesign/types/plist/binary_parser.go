package plist

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"time"
	"unicode/utf16"
)

// plistTrailer is the last 32 bytes of a binary plist
// See definition of CFBinaryPlistTrailer here
// https://opensource.apple.com/source/CF/CF-550.29/ForFoundationOnly.h
type plistTrailer struct {
	_                 [5]byte // unused padding
	SortVersion       uint8   // seems to be unused (always zero)
	OffsetIntSize     uint8   // byte size of offset ints in offset table
	ObjectRefSize     uint8   // byte size of object refs in arrays and dicts
	NumObjects        uint64  // number of objects (also number of offsets in offset table)
	RootObject        uint64  // object ref of top level object
	OffsetTableOffset uint64  // offset of the offset table
}

type binaryParser struct {
	OffsetTable   []uint64 // array of offsets for each object in plist
	plistTrailer           // last 32 bytes of plist
	io.ReadSeeker          // reader for plist data
}

const numObjectsMax = 4 << 20

// newBinaryParser takes in a ReadSeeker for the bytes of a binary plist and
// returns a parser after reading the offset table and trailer.
func newBinaryParser(r io.ReadSeeker) (*binaryParser, error) {
	var bp binaryParser
	bp.ReadSeeker = r

	// Read the trailer.
	if _, err := bp.Seek(-32, io.SeekEnd); err != nil {
		return nil, fmt.Errorf("plist: couldn't seek to start of trailer: %v", err)
	}
	if err := binary.Read(bp, binary.BigEndian, &bp.plistTrailer); err != nil {
		return nil, fmt.Errorf("plist: couldn't read trailer: %v", err)
	}

	// Read the offset table.
	if _, err := bp.Seek(int64(bp.OffsetTableOffset), io.SeekStart); err != nil {
		return nil, fmt.Errorf("plist: couldn't seek to start of offset table: %v", err)
	}

	// numObjectsMax is arbitrary. Please fix.
	// TODO(github.com/groob/plist/issues/28)
	if bp.NumObjects > numObjectsMax {
		return nil, fmt.Errorf("plist: offset size larger than expected %d", numObjectsMax)
	}

	bp.OffsetTable = make([]uint64, bp.NumObjects)
	if bp.OffsetIntSize > 8 {
		return nil, fmt.Errorf("plist: can't decode when offset int size (%d) is greater than 8", bp.OffsetIntSize)
	}
	for i := uint64(0); i < bp.NumObjects; i++ {
		buf := make([]byte, 8)
		if _, err := bp.Read(buf[8-bp.OffsetIntSize:]); err != nil {
			return nil, fmt.Errorf("plist: couldn't read offset table: %v", err)
		}
		bp.OffsetTable[i] = uint64(binary.BigEndian.Uint64(buf))
	}

	return &bp, nil
}

// parseDocument parses the entire binary plist starting from the root object
// and returns a plistValue representing the root object.
func (bp *binaryParser) parseDocument() (*plistValue, error) {
	// Decode and return the root object.
	return bp.parseObjectRef(bp.RootObject)
}

// parseObjectRef decodes and returns the plist object with the given index.
// Index 0 is the first object in the object table, 1 is the second, etc.
// This function restores the current plist offset when it's done so that you
// may call it while decoding a collection object without losing your place.
func (bp *binaryParser) parseObjectRef(index uint64) (val *plistValue, err error) {
	// Save the current offset.
	offset, err := bp.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}
	// Then restore the original offset in a defer.
	defer func() {
		_, err2 := bp.Seek(offset, io.SeekStart)
		if err2 != nil {
			err = err2
		}
	}()

	if index > uint64(len(bp.OffsetTable)) {
		return nil, fmt.Errorf("plist: offset too large: %d", index)
	}
	// Move to the start of the object we want to decode.
	if _, err := bp.Seek(int64(bp.OffsetTable[index]), io.SeekStart); err != nil {
		return nil, err
	}
	// The first byte of the object is its marker byte.
	// High 4 bits of marker byte indicates the object type.
	// Low 4 bits contain additional info, typically a count.
	// Defined here: https://opensource.apple.com/source/CF/CF-550.29/CFBinaryPList.c
	// (using Read instead of ReadByte so that we can accept a ReadSeeker)
	b := make([]byte, 1)
	if _, err := bp.Read(b); err != nil {
		return nil, err
	}
	marker := b[0]
	switch marker >> 4 {
	case 0x0: // null, bool, or fill
		return bp.parseSingleton(marker)
	case 0x1: // integer
		return bp.parseInteger(marker)
	case 0x2: // real
		return bp.parseReal(marker)
	case 0x3: // date
		return bp.parseDate(marker)
	case 0x4: // data
		return bp.parseData(marker)
	case 0x5: // ascii string
		return bp.parseASCII(marker)
	case 0x6: // unicode (utf-16) string
		return bp.parseUTF16(marker)
	case 0x8: // uid (not supported)
		return &plistValue{Invalid, nil}, nil
	case 0xa: // array
		return bp.parseArray(marker)
	case 0xc: // set (not supported)
		return &plistValue{Invalid, nil}, nil
	case 0xd: // dictionary
		return bp.parseDict(marker)
	}
	return nil, fmt.Errorf("plist: unknown object type %x", marker>>4)
}

func (bp *binaryParser) parseSingleton(marker byte) (*plistValue, error) {
	switch marker & 0xf {
	case 0x0: // null (not supported)
		return &plistValue{Invalid, nil}, nil
	case 0x8: // bool false
		return &plistValue{Boolean, false}, nil
	case 0x9: // bool true
		return &plistValue{Boolean, true}, nil
	case 0xf: // fill (not supported)
		return &plistValue{Invalid, nil}, nil
	}
	return nil, fmt.Errorf("plist: unrecognized singleton type %x", marker&0xf)
}

func (bp *binaryParser) parseInteger(marker byte) (*plistValue, error) {
	// Integers are always stored as signed 64-bit integer, with leading zeros
	// removed, so that the serialized form is either 1, 2, 4, or 8 bytes in
	// length.
	// See: https://opensource.apple.com/source/CF/CF-550.29/CFBinaryPList.c
	//
	// There is some discussion regarding 128-bit number support in the Python
	// bug report below.  The conclusion was that public APIs only allow plists
	// to contain up to 64-bit values.
	//
	// There is also an example of a bplist containing an unsigned value
	// 0xffffffffffffffff [1], but when you look at its encoding, it is crafted
	// using a 128bit field, with the upper 8 bytes all zeros.  Loading it into
	// the Xcode plist editor, it appears as -1!  That must be a cosmetic bug
	// in Xcode because if you then export the same plist as XML, you get the full
	// value, 18446744073709551615 [2].
	//
	// So that we can decode such bplists, we will allow 16-byte integer values,
	// but they will always be truncated to 64 bits.
	//
	// If you try and create a new plist in the Xcode editor, and paste in the
	// 64-bit number 18446744073709551615, Xcode automatically rewrites it as
	// the truncated 63-bit number 9223372036854775807.
	//
	// Separately, if you now create another new plist in the Xcode editor with
	// the value -1, you get [3] and [4]: both negative values.
	//
	// [1] "hand crafted" bplist with 128-bit value.
	// 00000000  62 70 6c 69 73 74 30 30  d1 01 02 53 6b 65 79 14  |bplist00...Skey.|
	// 00000010  00 00 00 00 00 00 00 00  ff ff ff ff ff ff ff ff  |................|
	// 00000020  08 0b 0f 00 00 00 00 00  00 01 01 00 00 00 00 00  |................|
	// 00000030  00 00 03 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
	// 00000040  00 00 20                                          |.. |
	//
	// [2] export of [1] to XML form, using Xcode.
	// <?xml version="1.0" encoding="UTF-8"?>
	// <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
	// <plist version="1.0">
	// <dict>
	// 	<key>key</key>
	// 	<integer>18446744073709551615</integer>
	// </dict>
	// </plist>
	//
	// [3] bplist with a value of -1, created with Xcode.
	// 00000000  62 70 6c 69 73 74 30 30  d1 01 02 53 6b 65 79 13  |bplist00...Skey.|
	// 00000010  ff ff ff ff ff ff ff ff  08 0b 0f 00 00 00 00 00  |................|
	// 00000020  00 01 01 00 00 00 00 00  00 00 03 00 00 00 00 00  |................|
	// 00000030  00 00 00 00 00 00 00 00  00 00 18                 |...........|
	//
	// [4] export of [3] to XML form, using Xcode.
	// <?xml version="1.0" encoding="UTF-8"?>
	// <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
	// <plist version="1.0">
	// <dict>
	// 	<key>key</key>
	// 	<integer>-1</integer>
	// </dict>
	// </plist>
	//
	// We have two choices here: restrict unsigned values to 63-bits, or just
	// let the package user interpret the serialized value.  This implementation
	// lets the user decide: if they want to unmarshal into a uint64 value,
	// we give them the full 8-bytes as such.  If they unmarshal into a signed
	// int64 value, we again give them the full 8-bytes as such, which will be
	// interpreted as negative if the top bit is set.  This is achieved by
	// setting the signed field of the signedInt value below to false
	// unconditionally. That way, the Decoder.unmarshalInteger method will do
	// the right thing.
	//
	// For XML property list unmarshaling, the presence of the "negative sign"
	// on an integer value makes the above unambigious, and the current practice
	// of using signedInt.signed = true in that case remains valid; see the
	// xmlParser.parseInteger implementation.
	//
	// See: https://bugs.python.org/issue14455
	nbytes := 1 << (marker & 0xf)
	if nbytes > 16 {
		return nil, fmt.Errorf("plist: cannot decode integers longer than 16 bytes (%d)", nbytes)
	}
	// Read into the right-most bytes of a 16-byte zero-valued buffer.
	buf := make([]byte, 16)
	_, err := bp.Read(buf[16-nbytes:])
	if err != nil {
		return nil, err
	}
	// Truncate values to 64 bits (8 bytes), and treat them all as "unsigned",
	// so they can be unmarshaled to unsigned and signed integers alike as
	// discussed above.
	result := signedInt{binary.BigEndian.Uint64(buf[8:]), false}

	return &plistValue{Integer, result}, nil
}

func (bp *binaryParser) parseReal(marker byte) (*plistValue, error) {
	nbytes := 1 << (marker & 0xf)
	buf := make([]byte, nbytes)
	if _, err := bp.Read(buf); err != nil {
		return nil, err
	}
	var r float64
	if err := binary.Read(bytes.NewReader(buf), binary.BigEndian, &r); err != nil {
		return nil, err
	}
	return &plistValue{Real, sizedFloat{r, nbytes * 8}}, nil
}

func (bp *binaryParser) parseDate(marker byte) (*plistValue, error) {
	if marker&0xf != 0x3 {
		return nil, fmt.Errorf("plist: invalid marker byte for date: %x", marker)
	}
	buf := make([]byte, 8)
	if _, err := bp.Read(buf); err != nil {
		return nil, err
	}
	var t float64
	if err := binary.Read(bytes.NewReader(buf), binary.BigEndian, &t); err != nil {
		return nil, err
	}
	// The float time is Apple Epoch time (secs since Jan 1, 2001 GMT) but we
	// need to convert it to Unix Epoch time (secs since Jan 1, 1970 GMT)
	t += 978307200
	secs := int64(t)
	nsecs := int64((t - float64(secs)) * 1e9)
	return &plistValue{Date, time.Unix(secs, nsecs)}, nil
}

func (bp *binaryParser) parseData(marker byte) (*plistValue, error) {
	count, err := bp.readCount(marker)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, count)
	if _, err := bp.Read(buf); err != nil {
		return nil, err
	}
	return &plistValue{Data, buf}, nil
}

func (bp *binaryParser) parseASCII(marker byte) (*plistValue, error) {
	count, err := bp.readCount(marker)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, count)
	if _, err := bp.Read(buf); err != nil {
		return nil, err
	}
	return &plistValue{String, string(buf)}, nil
}

func (bp *binaryParser) parseUTF16(marker byte) (*plistValue, error) {
	count, err := bp.readCount(marker)
	if err != nil {
		return nil, err
	}
	// Each character in the UTF16 string is 2 bytes.  First we read everything
	// into a byte slice, then convert this into a slice of uint16, then this
	// gets converted into a slice of rune, which gets converted to a string.
	buf := make([]byte, 2*count)
	if _, err := bp.Read(buf); err != nil {
		return nil, err
	}
	uni := make([]uint16, count)
	if err := binary.Read(bytes.NewReader(buf), binary.BigEndian, uni); err != nil {
		return nil, err
	}
	return &plistValue{String, string(utf16.Decode(uni))}, nil
}

func (bp *binaryParser) parseArray(marker byte) (*plistValue, error) {
	count, err := bp.readCount(marker)
	if err != nil {
		return nil, err
	}
	// A list of count object refs representing the items in the array follow.
	list, err := bp.readObjectList(count)
	if err != nil {
		return nil, err
	}
	return &plistValue{Array, list}, nil
}

func (bp *binaryParser) parseDict(marker byte) (*plistValue, error) {
	count, err := bp.readCount(marker)
	if err != nil {
		return nil, err
	}
	// A list of 2*count object refs follow.  All of the keys are listed first,
	// followed by all of the values.
	keys, err := bp.readObjectList(count)
	if err != nil {
		return nil, err
	}
	vals, err := bp.readObjectList(count)
	if err != nil {
		return nil, err
	}
	m := make(map[string]*plistValue)
	for i := uint64(0); i < count; i++ {
		if keys[i].kind != String {
			return nil, fmt.Errorf("plist: dictionary key is not a string: %v", keys[i])
		}
		m[keys[i].value.(string)] = vals[i]
	}
	return &plistValue{Dictionary, &dictionary{m: m}}, nil
}

// readCount reads the variable-length encoded integer count
// used by data, strings, arrays, and dicts
func (bp *binaryParser) readCount(marker byte) (uint64, error) {
	// Check marker for count < 15 in lower 4 bits.
	if marker&0xf != 0xf {
		return uint64(marker & 0xf), nil
	}
	// Otherwise must read additional bytes to get count.  Read first byte:
	// (using Read instead of ReadByte so that we can accept a ReadSeeker)
	b := make([]byte, 1)
	if _, err := bp.Read(b); err != nil {
		return 0, err
	}
	first := b[0]
	// The lower 4 bits of indicate how many additional bytes to read:
	//   0 means 1 additional byte
	//   1 means 2 additional bytes
	//   2 means 4 additional bytes
	//   3 means 8 additional bytes
	nbytes := 1 << (first & 0x0f)
	// Number of bytes in count should be at most 8.
	if nbytes > 8 {
		return 0, fmt.Errorf("plist: invalid nbytes (%d) in readCount", nbytes)
	}
	buf := make([]byte, 8)
	// Shove these bytes into the low end of an 8-byte buffer.
	if _, err := bp.Read(buf[8-nbytes:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(buf), nil
}

// readObjectRef reads the next ObjectRefSize bytes from the binary plist
// and returns the bytes decoded into an integer value.
func (bp *binaryParser) readObjectRef() (uint64, error) {
	buf := make([]byte, 8)
	if _, err := bp.Read(buf[8-bp.ObjectRefSize:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(buf), nil
}

// readObjectList is a helper function for parseArray and parseDict.
// It decodes a sequence of object refs from the current offset in the plist
// and returns the decoded objects in a slice.
func (bp *binaryParser) readObjectList(count uint64) ([]*plistValue, error) {
	list := make([]*plistValue, count)
	for i := uint64(0); i < count; i++ {
		// Read index of object in offset table.
		ref, err := bp.readObjectRef()
		if err != nil {
			return nil, err
		}
		// Find and decode the object in object table, then add it to list.
		v, err := bp.parseObjectRef(ref)
		if err != nil {
			return nil, err
		}
		list[i] = v
	}
	return list, nil
}
