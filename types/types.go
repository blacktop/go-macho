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

type DyldChainedImport uint32
type DyldChainedSymbolsFmt uint32

const (
	DC_IMPORT          DyldChainedImport = 1
	DC_IMPORT_ADDEND   DyldChainedImport = 2
	DC_IMPORT_ADDEND64 DyldChainedImport = 3
)

const (
	DC_SFORMAT_UNCOMPRESSED    DyldChainedSymbolsFmt = 0
	DC_SFORMAT_ZLIB_COMPRESSED DyldChainedSymbolsFmt = 1
)

// DyldChainedFixups object is the header of the LC_DYLD_CHAINED_FIXUPS payload
type DyldChainedFixups struct {
	FixupsVersion uint32                // 0
	StartsOffset  uint32                // offset of dyld_chained_starts_in_image in chain_data
	ImportsOffset uint32                // offset of imports table in chain_data
	SymbolsOffset uint32                // offset of symbol strings in chain_data
	ImportsCount  uint32                // number of imported symbol names
	ImportsFormat DyldChainedImport     // DYLD_CHAINED_IMPORT*
	SymbolsFormat DyldChainedSymbolsFmt // 0 => uncompressed, 1 => zlib compressed
}

type DyldChainedPtrKind uint16

const (
	DYLD_CHAINED_PTR_ARM64E              DyldChainedPtrKind = 1 // stride 8, unauth target is vmaddr
	DYLD_CHAINED_PTR_64                  DyldChainedPtrKind = 2 // target is vmaddr
	DYLD_CHAINED_PTR_32                  DyldChainedPtrKind = 3
	DYLD_CHAINED_PTR_32_CACHE            DyldChainedPtrKind = 4
	DYLD_CHAINED_PTR_32_FIRMWARE         DyldChainedPtrKind = 5
	DYLD_CHAINED_PTR_64_OFFSET           DyldChainedPtrKind = 6 // target is vm offset
	DYLD_CHAINED_PTR_ARM64E_OFFSET       DyldChainedPtrKind = 7 // old name
	DYLD_CHAINED_PTR_ARM64E_KERNEL       DyldChainedPtrKind = 7 // stride 4, unauth target is vm offset
	DYLD_CHAINED_PTR_64_KERNEL_CACHE     DyldChainedPtrKind = 8
	DYLD_CHAINED_PTR_ARM64E_USERLAND     DyldChainedPtrKind = 9      // stride 8, unauth target is vm offset
	DYLD_CHAINED_PTR_ARM64E_FIRMWARE     DyldChainedPtrKind = 10     // stride 4, unauth target is vmaddr
	DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE DyldChainedPtrKind = 11     // stride 1, x86_64 kernel caches
	DYLD_CHAINED_PTR_ARM64E_USERLAND24   DyldChainedPtrKind = 12     // stride 8, unauth target is vm offset, 24-bit bind
	DYLD_CHAINED_PTR_START_NONE          DyldChainedPtrKind = 0xFFFF // used in page_start[] to denote a page with no fixups
	DYLD_CHAINED_PTR_START_MULTI         DyldChainedPtrKind = 0x8000 // used in page_start[] to denote a page which has multiple starts
	DYLD_CHAINED_PTR_START_LAST          DyldChainedPtrKind = 0x8000 // used in chain_starts[] to denote last start in list for page
)

// DyldChainedStartsInSegment object is embedded in dyld_chain_starts_in_image
// and passed down to the kernel for page-in linking
type DyldChainedStartsInSegment struct {
	Size            uint32             // size of this (amount kernel needs to copy)
	PageSize        uint16             // 0x1000 or 0x4000
	PointerFormat   DyldChainedPtrKind // DYLD_CHAINED_PTR_*
	SegmentOffset   uint64             // offset in memory to start of segment
	MaxValidPointer uint32             // for 32-bit OS, any value beyond this is not a pointer
	PageCount       uint16             // how many pages are in array
	// uint16_t    page_start[1]      // each entry is offset in each page of first element in chain
	//                                 // or DYLD_CHAINED_PTR_START_NONE if no fixups on page
}
