package types

//go:generate stringer -type=Platform,Tool,DiceKind -output types_string.go

import (
	"encoding/binary"
	"fmt"
	"strconv"
)

type VmProtection int32

func (v VmProtection) Read() bool {
	return (v & 0x01) != 0
}

func (v VmProtection) Write() bool {
	return (v & 0x02) != 0
}

func (v VmProtection) Execute() bool {
	return (v & 0x04) != 0
}

func (v VmProtection) String() string {
	var protStr string
	if v.Read() {
		protStr += "r"
	} else {
		protStr += "-"
	}
	if v.Write() {
		protStr += "w"
	} else {
		protStr += "-"
	}
	if v.Execute() {
		protStr += "x"
	} else {
		protStr += "-"
	}
	return protStr
}

// UUID is a macho uuid object
type UUID [16]byte

func (u UUID) String() string {
	return fmt.Sprintf("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15])
}

// Platform is a macho platform object
type Platform uint32

const (
	unknown          Platform = 0
	macOS            Platform = 1  // PLATFORM_MACOS
	iOS              Platform = 2  // PLATFORM_IOS
	tvOS             Platform = 3  // PLATFORM_TVOS
	watchOS          Platform = 4  // PLATFORM_WATCHOS
	bridgeOS         Platform = 5  // PLATFORM_BRIDGEOS
	macCatalyst      Platform = 6  // PLATFORM_MACCATALYST
	iOSSimulator     Platform = 7  // PLATFORM_IOSSIMULATOR
	tvOSSimulator    Platform = 8  // PLATFORM_TVOSSIMULATOR
	watchOSSimulator Platform = 9  // PLATFORM_WATCHOSSIMULATOR
	driverKit        Platform = 10 // PLATFORM_DRIVERKIT
)

type Version uint32

func (v Version) String() string {
	s := make([]byte, 4)
	binary.BigEndian.PutUint32(s, uint32(v))
	return fmt.Sprintf("%d.%d.%d", binary.BigEndian.Uint16(s[:2]), s[2], s[3])
}

type SrcVersion uint64

func (sv SrcVersion) String() string {
	a := sv >> 40
	b := (sv >> 30) & 0x3ff
	c := (sv >> 20) & 0x3ff
	d := (sv >> 10) & 0x3ff
	e := sv & 0x3ff
	return fmt.Sprintf("%d.%d.%d.%d.%d", a, b, c, d, e)
}

type Tool uint32

const (
	clang Tool = 1 // TOOL_CLANG
	swift Tool = 2 // TOOL_SWIFT
	ld    Tool = 3 // TOOL_LD
)

type BuildToolVersion struct {
	Tool    Tool    /* enum for the tool */
	Version Version /* version number of the tool */
}

type DataInCodeEntry struct {
	Offset uint32
	Length uint16
	Kind   DiceKind
}

type DiceKind uint16

const (
	KindData           DiceKind = 0x0001
	KindJumpTable8     DiceKind = 0x0002
	KindJumpTable16    DiceKind = 0x0003
	KindJumpTable32    DiceKind = 0x0004
	KindAbsJumpTable32 DiceKind = 0x0005
)

type intName struct {
	i uint32
	s string
}

func stringName(i uint32, names []intName, goSyntax bool) string {
	for _, n := range names {
		if n.i == i {
			if goSyntax {
				return "macho." + n.s
			}
			return n.s
		}
	}
	return "0x" + strconv.FormatUint(uint64(i), 16)
}

var lsb64Mtable = [65]uint64{
	0x0000000000000000, 0x0000000000000001, 0x0000000000000003,
	0x0000000000000007, 0x000000000000000f, 0x000000000000001f,
	0x000000000000003f, 0x000000000000007f, 0x00000000000000ff,
	0x00000000000001ff, 0x00000000000003ff, 0x00000000000007ff,
	0x0000000000000fff, 0x0000000000001fff, 0x0000000000003fff,
	0x0000000000007fff, 0x000000000000ffff, 0x000000000001ffff,
	0x000000000003ffff, 0x000000000007ffff, 0x00000000000fffff,
	0x00000000001fffff, 0x00000000003fffff, 0x00000000007fffff,
	0x0000000000ffffff, 0x0000000001ffffff, 0x0000000003ffffff,
	0x0000000007ffffff, 0x000000000fffffff, 0x000000001fffffff,
	0x000000003fffffff, 0x000000007fffffff, 0x00000000ffffffff,
	0x00000001ffffffff, 0x00000003ffffffff, 0x00000007ffffffff,
	0x0000000fffffffff, 0x0000001fffffffff, 0x0000003fffffffff,
	0x0000007fffffffff, 0x000000ffffffffff, 0x000001ffffffffff,
	0x000003ffffffffff, 0x000007ffffffffff, 0x00000fffffffffff,
	0x00001fffffffffff, 0x00003fffffffffff, 0x00007fffffffffff,
	0x0000ffffffffffff, 0x0001ffffffffffff, 0x0003ffffffffffff,
	0x0007ffffffffffff, 0x000fffffffffffff, 0x001fffffffffffff,
	0x003fffffffffffff, 0x007fffffffffffff, 0x00ffffffffffffff,
	0x01ffffffffffffff, 0x03ffffffffffffff, 0x07ffffffffffffff,
	0x0fffffffffffffff, 0x1fffffffffffffff, 0x3fffffffffffffff,
	0x7fffffffffffffff, 0xffffffffffffffff,
}

func MaskLSB64(x uint64, nbits uint8) uint64 {
	return x & lsb64Mtable[nbits]
}

func ExtractBits(x uint64, start, nbits int32) uint64 {
	return MaskLSB64(x>>start, uint8(nbits))
}

type FilePointer struct {
	VMAdder uint64
	Offset  uint64
}
