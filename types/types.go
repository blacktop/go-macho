package types

//go:generate stringer -type=Platform,Tool,DiceKind -output types_string.go

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode"
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

// IsNull returns true if UUID is 00000000-0000-0000-0000-000000000000
func (u UUID) IsNull() bool {
	return u == [16]byte{0}
}

func (u UUID) String() string {
	return fmt.Sprintf("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15])
}

// Platform is a macho platform object
type Platform uint32

const (
	unknown            Platform = 0          // PLATFORM_UNKNOWN
	macOS              Platform = 1          // PLATFORM_MACOS
	iOS                Platform = 2          // PLATFORM_IOS
	tvOS               Platform = 3          // PLATFORM_TVOS
	watchOS            Platform = 4          // PLATFORM_WATCHOS
	bridgeOS           Platform = 5          // PLATFORM_BRIDGEOS
	macCatalyst        Platform = 6          // PLATFORM_MACCATALYST
	iOSSimulator       Platform = 7          // PLATFORM_IOSSIMULATOR
	tvOSSimulator      Platform = 8          // PLATFORM_TVOSSIMULATOR
	watchOSSimulator   Platform = 9          // PLATFORM_WATCHOSSIMULATOR
	driverKit          Platform = 10         // PLATFORM_DRIVERKIT
	realityOS          Platform = 11         // PLATFORM_REALITYOS
	realityOSSimulator Platform = 12         // PLATFORM_REALITYOSSIMULATOR
	firmware           Platform = 13         // PLATFORM_FIRMWARE
	sepOS              Platform = 14         // PLATFORM_SEPOS
	any                Platform = 0xFFFFFFFF // PLATFORM_ANY
)

type Version uint32

func (v Version) String() string {
	s := make([]byte, 4)
	binary.BigEndian.PutUint32(s, uint32(v))
	if (s[3] & 0xFF) == 0 {
		return fmt.Sprintf("%d.%d", binary.BigEndian.Uint16(s[:2]), s[2])
	}
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
	none  Tool = 0
	clang Tool = 1 // TOOL_CLANG
	swift Tool = 2 // TOOL_SWIFT
	ld    Tool = 3 // TOOL_LD
	lld   Tool = 4 // TOOL_LLD
	/* values for gpu tools (1024 to 1048) */
	Metal          Tool = 1024
	AirLld         Tool = 1025
	AirNt          Tool = 1026
	AirNtPlugin    Tool = 1027
	AirPack        Tool = 1028
	GpuArchiver    Tool = 1031
	MetalFramework Tool = 1032
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

type Function struct {
	Name      string
	StartAddr uint64
	EndAddr   uint64
}

/*
******
HELPERS
*******
*/
func PutAtMost16Bytes(b []byte, n string) {
	for i := range n { // at most 16 bytes
		if i == 16 {
			break
		}
		b[i] = n[i]
	}
}

func RoundUp(x, align uint64) uint64 {
	return uint64((x + align - 1) & -align)
}

func IsASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}

type IntName struct {
	I uint32
	S string
}

type Int64Name struct {
	I uint64
	S string
}

func StringName(i uint32, names []IntName, goSyntax bool) string {
	for _, n := range names {
		if n.I == i {
			if goSyntax {
				return "macho." + n.S
			}
			return n.S
		}
	}
	return "0x" + strconv.FormatUint(uint64(i), 16)
}

func StringName64(i uint64, names []Int64Name, goSyntax bool) string {
	for _, n := range names {
		if n.I == i {
			if goSyntax {
				return "macho." + n.S
			}
			return n.S
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

type VMAddrConverter struct {
	PreferredLoadAddress            uint64
	Slide                           int64
	ChainedPointerFormat            uint16
	IsContentRebased                bool
	SharedCacheChainedPointerFormat uint8
	Converter                       func(uint64) uint64
	VMAddr2Offet                    func(uint64) (uint64, error)
	Offet2VMAddr                    func(uint64) (uint64, error)
}

func (v *VMAddrConverter) Convert(addr uint64) uint64 {
	return v.Converter(addr)
}

// GetOffset returns the file offset for a given virtual address
func (v *VMAddrConverter) GetOffset(address uint64) (uint64, error) {
	return v.VMAddr2Offet(address)
}

// GetVMAddress returns the virtal address for a given file offset
func (v *VMAddrConverter) GetVMAddress(offset uint64) (uint64, error) {
	return v.Offet2VMAddr(offset)
}

// MachoReader is a custom io.SectionReader interface with virtual address support
type MachoReader interface {
	io.ReadSeeker
	io.ReaderAt
	SeekToAddr(addr uint64) error
	ReadAtAddr(buf []byte, addr uint64) (int, error)
}

// NewCustomSectionReader returns a CustomSectionReader that reads from r
// starting at offset off and stops with EOF after n bytes.
func NewCustomSectionReader(r io.ReaderAt, vma *VMAddrConverter, off int64, n int64) *CustomSectionReader {
	return &CustomSectionReader{r, vma, off, off, off + n}
}

// CustomSectionReader implements Read, Seek, and ReadAt on a section
// of an underlying ReaderAt.
// It also stubs out the MachoReader required SeekToAddr and ReadAtAddr
type CustomSectionReader struct {
	r     io.ReaderAt
	vma   *VMAddrConverter
	base  int64
	off   int64
	limit int64
}

func (s *CustomSectionReader) Read(p []byte) (n int, err error) {
	if s.off >= s.limit {
		return 0, io.EOF
	}
	if max := s.limit - s.off; int64(len(p)) > max {
		p = p[0:max]
	}
	n, err = s.r.ReadAt(p, s.off)
	s.off += int64(n)
	return
}

func (s *CustomSectionReader) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	default:
		return 0, errors.New("Seek: invalid whence")
	case io.SeekStart:
		offset += s.base
	case io.SeekCurrent:
		offset += s.off
	case io.SeekEnd:
		offset += s.limit
	}
	if offset < s.base {
		return 0, errors.New("Seek: invalid offset")
	}
	s.off = offset
	return offset - s.base, nil
}

func (s *CustomSectionReader) ReadAt(p []byte, off int64) (n int, err error) {
	if off < 0 || off >= s.limit-s.base {
		return 0, io.EOF
	}
	off += s.base
	if max := s.limit - off; int64(len(p)) > max {
		p = p[0:max]
		n, err = s.r.ReadAt(p, off)
		if err == nil {
			err = io.EOF
		}
		return n, err
	}
	return s.r.ReadAt(p, off)
}

// Size returns the size of the section in bytes.
func (s *CustomSectionReader) Size() int64 { return s.limit - s.base }

func (s *CustomSectionReader) SeekToAddr(addr uint64) error {
	off, err := s.vma.VMAddr2Offet(addr)
	if err != nil {
		return err
	}
	_, err = s.Seek(int64(off), io.SeekStart)
	return err
}

func (s *CustomSectionReader) ReadAtAddr(buf []byte, addr uint64) (int, error) {
	off, err := s.vma.VMAddr2Offet(addr)
	if err != nil {
		return 0, err
	}
	return s.ReadAt(buf, int64(off))
}
