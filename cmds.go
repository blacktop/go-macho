package macho

import (
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"unsafe"

	ctypes "github.com/blacktop/go-macho/pkg/codesign/types"
	"github.com/blacktop/go-macho/types"
)

// A Load represents any Mach-O load command.
type Load interface {
	Raw() []byte
	String() string
	Command() types.LoadCmd
	LoadSize(*FileTOC) uint32 // Need the TOC for alignment, sigh.
	Put([]byte, binary.ByteOrder) int
}

// LoadCmdBytes is a command-tagged sequence of bytes.
// This is used for Load Commands that are not (yet)
// interesting to us, and to common up this behavior for
// all those that are.
type LoadCmdBytes struct {
	types.LoadCmd
	LoadBytes
}

func (s LoadCmdBytes) String() string {
	return s.LoadCmd.String() + ": " + s.LoadBytes.String()
}
func (s LoadCmdBytes) Copy() LoadCmdBytes {
	return LoadCmdBytes{LoadCmd: s.LoadCmd, LoadBytes: s.LoadBytes.Copy()}
}

// A LoadBytes is the uninterpreted bytes of a Mach-O load command.
type LoadBytes []byte

func (b LoadBytes) String() string {
	s := "["
	for i, a := range b {
		if i > 0 {
			s += " "
			if len(b) > 48 && i >= 16 {
				s += fmt.Sprintf("... (%d bytes)", len(b))
				break
			}
		}
		s += fmt.Sprintf("%x", a)
	}
	s += "]"
	return s
}
func (b LoadBytes) Raw() []byte                { return b }
func (b LoadBytes) Copy() LoadBytes            { return LoadBytes(append([]byte{}, b...)) }
func (b LoadBytes) LoadSize(t *FileTOC) uint32 { return uint32(len(b)) }

/*******************************************************************************
 * SEGMENT
 *******************************************************************************/

// A SegmentHeader is the header for a Mach-O 32-bit or 64-bit load segment command.
type SegmentHeader struct {
	types.LoadCmd
	Len       uint32
	Name      string
	Addr      uint64
	Memsz     uint64
	Offset    uint64
	Filesz    uint64
	Maxprot   types.VmProtection
	Prot      types.VmProtection
	Nsect     uint32
	Flag      types.SegFlag
	Firstsect uint32
}

func (s *SegmentHeader) String() string {
	return fmt.Sprintf(
		"Seg %s, len=0x%x, addr=0x%x, memsz=0x%x, offset=0x%x, filesz=0x%x, maxprot=0x%x, prot=0x%x, nsect=%d, flag=0x%x, firstsect=%d",
		s.Name, s.Len, s.Addr, s.Memsz, s.Offset, s.Filesz, s.Maxprot, s.Prot, s.Nsect, s.Flag, s.Firstsect)
}

// A Segment represents a Mach-O 32-bit or 64-bit load segment command.
type Segment struct {
	SegmentHeader
	LoadBytes
	// Embed ReaderAt for ReadAt method.
	// Do not embed SectionReader directly
	// to avoid having Read and Seek.
	// If a client wants Read and Seek it must use
	// Open() to avoid fighting over the seek offset
	// with other clients.
	io.ReaderAt
	sr *io.SectionReader
}

func (s *Segment) String() string {
	return fmt.Sprintf(
		"Seg %s, len=0x%x, addr=0x%x, memsz=0x%x, offset=0x%x, filesz=0x%x, maxprot=0x%x, prot=0x%x, nsect=%d, flag=0x%x, firstsect=%d",
		s.Name, s.Len, s.Addr, s.Memsz, s.Offset, s.Filesz, s.Maxprot, s.Prot, s.Nsect, s.Flag, s.Firstsect)
}

func (s *Segment) Put32(b []byte, o binary.ByteOrder) int {
	o.PutUint32(b[0*4:], uint32(s.LoadCmd))
	o.PutUint32(b[1*4:], s.Len)
	types.PutAtMost16Bytes(b[2*4:], s.Name)
	o.PutUint32(b[6*4:], uint32(s.Addr))
	o.PutUint32(b[7*4:], uint32(s.Memsz))
	o.PutUint32(b[8*4:], uint32(s.Offset))
	o.PutUint32(b[9*4:], uint32(s.Filesz))
	o.PutUint32(b[10*4:], uint32(s.Maxprot))
	o.PutUint32(b[11*4:], uint32(s.Prot))
	o.PutUint32(b[12*4:], s.Nsect)
	o.PutUint32(b[13*4:], uint32(s.Flag))
	return 14 * 4
}

func (s *Segment) Put64(b []byte, o binary.ByteOrder) int {
	o.PutUint32(b[0*4:], uint32(s.LoadCmd))
	o.PutUint32(b[1*4:], s.Len)
	types.PutAtMost16Bytes(b[2*4:], s.Name)
	o.PutUint64(b[6*4+0*8:], s.Addr)
	o.PutUint64(b[6*4+1*8:], s.Memsz)
	o.PutUint64(b[6*4+2*8:], s.Offset)
	o.PutUint64(b[6*4+3*8:], s.Filesz)
	o.PutUint32(b[6*4+4*8:], uint32(s.Maxprot))
	o.PutUint32(b[7*4+4*8:], uint32(s.Prot))
	o.PutUint32(b[8*4+4*8:], s.Nsect)
	o.PutUint32(b[9*4+4*8:], uint32(s.Flag))
	return 10*4 + 4*8
}

// Data reads and returns the contents of the segment.
func (s *Segment) Data() ([]byte, error) {
	dat := make([]byte, s.sr.Size())
	n, err := s.sr.ReadAt(dat, 0)
	if n == len(dat) {
		err = nil
	}
	return dat[0:n], err
}

// UncompressedSize returns the size of the segment with its sections uncompressed, ignoring
// its offset within the file.  The returned size is rounded up to the power of two in align.
func (s *Segment) UncompressedSize(t *FileTOC, align uint64) uint64 {
	sz := uint64(0)
	for j := uint32(0); j < s.Nsect; j++ {
		c := t.Sections[j+s.Firstsect]
		sz += c.UncompressedSize()
	}
	return (sz + align - 1) & uint64(-int64(align))
}

func (s *Segment) Copy() *Segment {
	r := &Segment{SegmentHeader: s.SegmentHeader}
	return r
}
func (s *Segment) CopyZeroed() *Segment {
	r := s.Copy()
	r.Filesz = 0
	r.Offset = 0
	r.Nsect = 0
	r.Firstsect = 0
	if s.Command() == types.LC_SEGMENT_64 {
		r.Len = uint32(unsafe.Sizeof(types.Segment64{}))
	} else {
		r.Len = uint32(unsafe.Sizeof(types.Segment32{}))
	}
	return r
}

func (s *Segment) LoadSize(t *FileTOC) uint32 {
	if s.Command() == types.LC_SEGMENT_64 {
		return uint32(unsafe.Sizeof(types.Segment64{})) + uint32(s.Nsect)*uint32(unsafe.Sizeof(types.Section64{}))
	}
	return uint32(unsafe.Sizeof(types.Segment32{})) + uint32(s.Nsect)*uint32(unsafe.Sizeof(types.Section32{}))
}

// Open returns a new ReadSeeker reading the segment.
func (s *Segment) Open() io.ReadSeeker { return io.NewSectionReader(s.sr, 0, 1<<63-1) }

/*******************************************************************************
 * SECTION
 *******************************************************************************/

type SectionHeader struct {
	Name      string
	Seg       string
	Addr      uint64
	Size      uint64
	Offset    uint32
	Align     uint32
	Reloff    uint32
	Nreloc    uint32
	Flags     types.SectionFlag
	Reserved1 uint32
	Reserved2 uint32
	Reserved3 uint32 // only present if original was 64-bit
}

// A Reloc represents a Mach-O relocation.
type Reloc struct {
	Addr  uint32
	Value uint32
	// when Scattered == false && Extern == true, Value is the symbol number.
	// when Scattered == false && Extern == false, Value is the section number.
	// when Scattered == true, Value is the value that this reloc refers to.
	Type      uint8
	Len       uint8 // 0=byte, 1=word, 2=long, 3=quad
	Pcrel     bool
	Extern    bool // valid if Scattered == false
	Scattered bool
}

type relocInfo struct {
	Addr   uint32
	Symnum uint32
}

type Section struct {
	SectionHeader
	Relocs []Reloc

	// Embed ReaderAt for ReadAt method.
	// Do not embed SectionReader directly
	// to avoid having Read and Seek.
	// If a client wants Read and Seek it must use
	// Open() to avoid fighting over the seek offset
	// with other clients.
	io.ReaderAt
	sr *io.SectionReader
}

// Data reads and returns the contents of the Mach-O section.
func (s *Section) Data() ([]byte, error) {
	dat := make([]byte, s.sr.Size())
	n, err := s.sr.ReadAt(dat, 0)
	if n == len(dat) {
		err = nil
	}
	return dat[0:n], err
}

func (s *Section) Put32(b []byte, o binary.ByteOrder) int {
	types.PutAtMost16Bytes(b[0:], s.Name)
	types.PutAtMost16Bytes(b[16:], s.Seg)
	o.PutUint32(b[8*4:], uint32(s.Addr))
	o.PutUint32(b[9*4:], uint32(s.Size))
	o.PutUint32(b[10*4:], s.Offset)
	o.PutUint32(b[11*4:], s.Align)
	o.PutUint32(b[12*4:], s.Reloff)
	o.PutUint32(b[13*4:], s.Nreloc)
	o.PutUint32(b[14*4:], uint32(s.Flags))
	o.PutUint32(b[15*4:], s.Reserved1)
	o.PutUint32(b[16*4:], s.Reserved2)
	a := 17 * 4
	return a + s.PutRelocs(b[a:], o)
}

func (s *Section) Put64(b []byte, o binary.ByteOrder) int {
	types.PutAtMost16Bytes(b[0:], s.Name)
	types.PutAtMost16Bytes(b[16:], s.Seg)
	o.PutUint64(b[8*4+0*8:], s.Addr)
	o.PutUint64(b[8*4+1*8:], s.Size)
	o.PutUint32(b[8*4+2*8:], s.Offset)
	o.PutUint32(b[9*4+2*8:], s.Align)
	o.PutUint32(b[10*4+2*8:], s.Reloff)
	o.PutUint32(b[11*4+2*8:], s.Nreloc)
	o.PutUint32(b[12*4+2*8:], uint32(s.Flags))
	o.PutUint32(b[13*4+2*8:], s.Reserved1)
	o.PutUint32(b[14*4+2*8:], s.Reserved2)
	o.PutUint32(b[15*4+2*8:], s.Reserved3)
	a := 16*4 + 2*8
	return a + s.PutRelocs(b[a:], o)
}

func (s *Section) PutRelocs(b []byte, o binary.ByteOrder) int {
	a := 0
	for _, r := range s.Relocs {
		var ri relocInfo
		typ := uint32(r.Type) & (1<<4 - 1)
		len := uint32(r.Len) & (1<<2 - 1)
		pcrel := uint32(0)
		if r.Pcrel {
			pcrel = 1
		}
		ext := uint32(0)
		if r.Extern {
			ext = 1
		}
		switch {
		case r.Scattered:
			ri.Addr = r.Addr&(1<<24-1) | typ<<24 | len<<28 | 1<<31 | pcrel<<30
			ri.Symnum = r.Value
		case o == binary.LittleEndian:
			ri.Addr = r.Addr
			ri.Symnum = r.Value&(1<<24-1) | pcrel<<24 | len<<25 | ext<<27 | typ<<28
		case o == binary.BigEndian:
			ri.Addr = r.Addr
			ri.Symnum = r.Value<<8 | pcrel<<7 | len<<5 | ext<<4 | typ
		}
		o.PutUint32(b, ri.Addr)
		o.PutUint32(b[4:], ri.Symnum)
		a += 8
		b = b[8:]
	}
	return a
}

func (s *Section) UncompressedSize() uint64 {
	if !strings.HasPrefix(s.Name, "__z") {
		return s.Size
	}
	b := make([]byte, 12)
	n, err := s.sr.ReadAt(b, 0)
	if err != nil {
		panic("Malformed object file")
	}
	if n != len(b) {
		return s.Size
	}
	if string(b[:4]) == "ZLIB" {
		return binary.BigEndian.Uint64(b[4:12])
	}
	return s.Size
}

func (s *Section) PutData(b []byte) {
	bb := b[0:s.Size]
	n, err := s.sr.ReadAt(bb, 0)
	if err != nil || uint64(n) != s.Size {
		panic("Malformed object file (ReadAt error)")
	}
}

func (s *Section) PutUncompressedData(b []byte) {
	if strings.HasPrefix(s.Name, "__z") {
		bb := make([]byte, 12)
		n, err := s.sr.ReadAt(bb, 0)
		if err != nil {
			panic("Malformed object file")
		}
		if n == len(bb) && string(bb[:4]) == "ZLIB" {
			size := binary.BigEndian.Uint64(bb[4:12])
			// Decompress starting at b[12:]
			r, err := zlib.NewReader(io.NewSectionReader(s, 12, int64(size)-12))
			if err != nil {
				panic("Malformed object file (zlib.NewReader error)")
			}
			n, err := io.ReadFull(r, b[0:size])
			if err != nil {
				panic("Malformed object file (ReadFull error)")
			}
			if uint64(n) != size {
				panic(fmt.Sprintf("PutUncompressedData, expected to read %d bytes, instead read %d", size, n))
			}
			if err := r.Close(); err != nil {
				panic("Malformed object file (Close error)")
			}
			return
		}
	}
	// Not compressed
	s.PutData(b)
}

func (s *Section) Copy() *Section {
	return &Section{SectionHeader: s.SectionHeader}
}

// Open returns a new ReadSeeker reading the Mach-O section.
func (s *Section) Open() io.ReadSeeker { return io.NewSectionReader(s.sr, 0, 1<<63-1) }

/*******************************************************************************
 * LC_SYMTAB
 *******************************************************************************/

// A Symtab represents a Mach-O symbol table command.
type Symtab struct {
	LoadBytes
	types.SymtabCmd
	Syms []Symbol
}

func (s *Symtab) String() string {
	if s.Nsyms == 0 && s.Strsize == 0 {
		return "Symbols stripped"
	}
	return fmt.Sprintf("Symbol offset=0x%08X, Num Syms: %d, String offset=0x%08X-0x%08X", s.Symoff, s.Nsyms, s.Stroff, s.Stroff+s.Strsize)
}
func (s *Symtab) Copy() *Symtab {
	return &Symtab{SymtabCmd: s.SymtabCmd, Syms: append([]Symbol{}, s.Syms...)}
}
func (s *Symtab) LoadSize(t *FileTOC) uint32 {
	return uint32(unsafe.Sizeof(types.SymtabCmd{}))
}
func (s *Symtab) Put(b []byte, o binary.ByteOrder) int {
	o.PutUint32(b[0*4:], uint32(s.LoadCmd))
	o.PutUint32(b[1*4:], s.Len)
	o.PutUint32(b[2*4:], s.Symoff)
	o.PutUint32(b[3*4:], s.Nsyms)
	o.PutUint32(b[4*4:], s.Stroff)
	o.PutUint32(b[5*4:], s.Strsize)
	return 6 * 4
}

// A Symbol is a Mach-O 32-bit or 64-bit symbol table entry.
type Symbol struct {
	Name  string
	Type  types.NLType
	Sect  uint8
	Desc  uint16
	Value uint64
}

/*******************************************************************************
 * LC_SYMSEG
 *******************************************************************************/

// TODO: LC_SYMSEG	0x3	/* link-edit gdb symbol table info (obsolete) */

/*******************************************************************************
 * LC_THREAD
 *******************************************************************************/

// TODO: LC_THREAD	0x4	/* thread */

/*******************************************************************************
 * LC_UNIXTHREAD
 *******************************************************************************/

// A UnixThread represents a Mach-O unix thread command.
type UnixThread struct {
	LoadBytes
	types.UnixThreadCmd
	EntryPoint uint64
}

func (u *UnixThread) String() string {
	return fmt.Sprintf("Entry Point: 0x%016x", u.EntryPoint)
}

// TODO: LC_LOADFVMLIB	0x6	/* load a specified fixed VM shared library */
// TODO: LC_IDFVMLIB	0x7	/* fixed VM shared library identification */
// TODO: LC_IDENT	    0x8	/* object identification info (obsolete) */
// TODO: LC_FVMFILE	    0x9	/* fixed VM file inclusion (internal use) */
// TODO: LC_PREPAGE     0xa /* prepage command (internal use) */

/*******************************************************************************
 * LC_DYSYMTAB
 *******************************************************************************/

// A Dysymtab represents a Mach-O dynamic symbol table command.
type Dysymtab struct {
	LoadBytes
	types.DysymtabCmd
	IndirectSyms []uint32 // indices into Symtab.Syms
}

func (d *Dysymtab) String() string {
	// TODO make this like jtool
	// 1 local symbols at index     0
	// 29 external symbols at index  1
	// 709 undefined symbols at index 30
	// No TOC
	// No modtab
	// 1149 Indirect symbols at offset 0x1695f0
	return fmt.Sprintf("%d Indirect symbols at offset 0x%08X", d.Nindirectsyms, d.Indirectsymoff)
}

/*******************************************************************************
 * LC_ID_DYLIB, LC_LOAD_{,WEAK_}DYLIB,LC_REEXPORT_DYLIB
 *******************************************************************************/

// A Dylib represents a Mach-O load dynamic library command.
type Dylib struct {
	LoadBytes
	types.DylibCmd
	Name           string
	Time           uint32
	CurrentVersion string
	CompatVersion  string
}

func (d *Dylib) String() string {
	return fmt.Sprintf("%s (%s)", d.Name, d.CurrentVersion)
}

/*******************************************************************************
 * LC_ID_DYLIB
 *******************************************************************************/

// A DylibID represents a Mach-O load dynamic library ident command.
type DylibID Dylib

func (d *DylibID) String() string {
	return fmt.Sprintf("%s (%s)", d.Name, d.CurrentVersion)
}

/*******************************************************************************
 * LC_LOAD_DYLINKER
 *******************************************************************************/

type LoadDylinker struct {
	LoadBytes
	types.DylinkerCmd
	Name string
}

func (d *LoadDylinker) String() string {
	return d.Name
}

// TODO: LC_ID_DYLINKER	0xf	/* dynamic linker identification */
// TODO: LC_PREBOUND_DYLIB 0x10	/* modules prebound for a dynamically */
// 				/*  linked shared library */
// TODO: LC_ROUTINES	0x11	/* image routines */

/*******************************************************************************
 * LC_SUB_FRAMEWORK
 *******************************************************************************/

type SubFramework struct {
	LoadBytes
	types.SubFrameworkCmd
	Framework string
}

// TODO: LC_SUB_UMBRELLA 0x13	/* sub umbrella */

/*******************************************************************************
 * LC_SUB_CLIENT
 *******************************************************************************/

// A SubClient is a Mach-O dynamic sub client command.
type SubClient struct {
	LoadBytes
	types.SubClientCmd
	Name string
}

func (d *SubClient) String() string {
	return d.Name
}

// TODO: LC_SUB_LIBRARY  0x15	/* sub library */
// TODO: LC_TWOLEVEL_HINTS 0x16	/* two-level namespace lookup hints */
// TODO: LC_PREBIND_CKSUM  0x17	/* prebind checksum */

/*******************************************************************************
 * LC_LOAD_WEAK_DYLIB
 *******************************************************************************/

// A WeakDylib represents a Mach-O load weak dynamic library command.
type WeakDylib Dylib

func (d *WeakDylib) String() string {
	return fmt.Sprintf("%s (%s)", d.Name, d.CurrentVersion)
}

/*******************************************************************************
 * LC_ROUTINES_64
 *******************************************************************************/

type Routines64 struct {
	LoadBytes
	types.Routines64Cmd
	InitAddress uint64
	InitModule  uint64
}

/*******************************************************************************
 * LC_UUID
 *******************************************************************************/

// UUID represents a Mach-O uuid command.
type UUID struct {
	LoadBytes
	types.UUIDCmd
	ID string
}

func (s *UUID) String() string {
	return s.ID
}
func (s *UUID) Copy() *UUID {
	return &UUID{UUIDCmd: s.UUIDCmd}
}
func (s *UUID) LoadSize(t *FileTOC) uint32 {
	return uint32(unsafe.Sizeof(types.UUIDCmd{}))
}
func (s *UUID) Put(b []byte, o binary.ByteOrder) int {
	o.PutUint32(b[0*4:], uint32(s.LoadCmd))
	o.PutUint32(b[1*4:], s.Len)
	copy(b[2*4:], s.UUID[0:])
	return int(s.Len)
}

/*******************************************************************************
 * LC_RPATH
 *******************************************************************************/

// A Rpath represents a Mach-O rpath command.
type Rpath struct {
	LoadBytes
	types.RpathCmd
	Path string
}

func (r *Rpath) String() string {
	return r.Path
}

/*******************************************************************************
 * LC_CODE_SIGNATURE
 *******************************************************************************/

type CodeSignature struct {
	LoadBytes
	types.CodeSignatureCmd
	Offset uint32
	Size   uint32
	ctypes.CodeSignature
}

func (c *CodeSignature) String() string {
	// TODO: fix this once codesigs are done
	// return fmt.Sprintf("offset=0x%08x-0x%08x, size=%d, ID:   %s", c.Offset, c.Offset+c.Size, c.Size, c.ID)
	return fmt.Sprintf("offset=0x%08x-0x%08x, size=%5d", c.Offset, c.Offset+c.Size, c.Size)
}

/*******************************************************************************
 * LC_SEGMENT_SPLIT_INFO
 *******************************************************************************/

type SplitInfo struct {
	LoadBytes
	types.SegmentSplitInfoCmd
	Offset uint32
	Size   uint32
}

func (s *SplitInfo) String() string {
	return fmt.Sprintf("offset=0x%08x-0x%08x, size=%5d", s.Offset, s.Offset+s.Size, s.Size)
}

/*******************************************************************************
 * LC_REEXPORT_DYLIB
 *******************************************************************************/

type ReExportDylib Dylib

func (d *ReExportDylib) String() string {
	return fmt.Sprintf("%s (%s)", d.Name, d.CurrentVersion)
}

// TODO: LC_LAZY_LOAD_DYLIB 0x20	/* delay load of dylib until first use */
// TODO: LC_ENCRYPTION_INFO 0x21	/* encrypted segment information */

/*******************************************************************************
 * LC_DYLD_INFO
 *******************************************************************************/

// A DyldInfo represents a Mach-O id dyld info command.
type DyldInfo struct {
	LoadBytes
	types.DyldInfoCmd
	RebaseOff    uint32 // file offset to rebase info
	RebaseSize   uint32 //  size of rebase info
	BindOff      uint32 // file offset to binding info
	BindSize     uint32 // size of binding info
	WeakBindOff  uint32 // file offset to weak binding info
	WeakBindSize uint32 //  size of weak binding info
	LazyBindOff  uint32 // file offset to lazy binding info
	LazyBindSize uint32 //  size of lazy binding info
	ExportOff    uint32 // file offset to export info
	ExportSize   uint32 //  size of export info
}

func (d *DyldInfo) String() string {
	return fmt.Sprintf(
		"\n"+
			"\t\tRebase info: %5d bytes at offset:  0x%08X -> 0x%08X\n"+
			"\t\tBind info:   %5d bytes at offset:  0x%08X -> 0x%08X\n"+
			"\t\tWeak info:   %5d bytes at offset:  0x%08X -> 0x%08X\n"+
			"\t\tLazy info:   %5d bytes at offset:  0x%08X -> 0x%08X\n"+
			"\t\tExport info: %5d bytes at offset:  0x%08X -> 0x%08X",
		d.RebaseSize, d.RebaseOff, d.RebaseOff+d.RebaseSize,
		d.BindSize, d.BindOff, d.BindOff+d.BindSize,
		d.WeakBindSize, d.WeakBindOff, d.WeakBindOff+d.WeakBindSize,
		d.LazyBindSize, d.LazyBindOff, d.LazyBindOff+d.LazyBindSize,
		d.ExportSize, d.ExportOff, d.ExportOff+d.ExportSize,
	)
}
func (d *DyldInfo) Copy() *DyldInfo {
	return &DyldInfo{DyldInfoCmd: d.DyldInfoCmd}
}
func (d *DyldInfo) LoadSize(t *FileTOC) uint32 {
	return uint32(unsafe.Sizeof(types.UUIDCmd{}))
}
func (d *DyldInfo) Put(b []byte, o binary.ByteOrder) int {
	o.PutUint32(b[0*4:], uint32(d.LoadCmd))
	o.PutUint32(b[1*4:], d.Len)
	o.PutUint32(b[2*4:], d.RebaseOff)
	o.PutUint32(b[3*4:], d.RebaseSize)
	o.PutUint32(b[4*4:], d.BindOff)
	o.PutUint32(b[5*4:], d.BindSize)
	o.PutUint32(b[6*4:], d.WeakBindOff)
	o.PutUint32(b[7*4:], d.WeakBindSize)
	o.PutUint32(b[8*4:], d.LazyBindOff)
	o.PutUint32(b[9*4:], d.LazyBindSize)
	o.PutUint32(b[10*4:], d.ExportOff)
	o.PutUint32(b[11*4:], d.ExportSize)
	return int(d.Len)
}

/*******************************************************************************
 * LC_DYLD_INFO
 *******************************************************************************/

// DyldInfoOnly is compressed dyld information only
type DyldInfoOnly struct {
	LoadBytes
	types.DyldInfoOnlyCmd
	RebaseOff    uint32 // file offset to rebase info
	RebaseSize   uint32 //  size of rebase info
	BindOff      uint32 // file offset to binding info
	BindSize     uint32 // size of binding info
	WeakBindOff  uint32 // file offset to weak binding info
	WeakBindSize uint32 //  size of weak binding info
	LazyBindOff  uint32 // file offset to lazy binding info
	LazyBindSize uint32 //  size of lazy binding info
	ExportOff    uint32 // file offset to export info
	ExportSize   uint32 //  size of export info
}

func (d *DyldInfoOnly) String() string {
	return fmt.Sprintf(
		"\n"+
			"\t\tRebase info: %5d bytes at offset:  0x%08X -> 0x%08X\n"+
			"\t\tBind info:   %5d bytes at offset:  0x%08X -> 0x%08X\n"+
			"\t\tWeak info:   %5d bytes at offset:  0x%08X -> 0x%08X\n"+
			"\t\tLazy info:   %5d bytes at offset:  0x%08X -> 0x%08X\n"+
			"\t\tExport info: %5d bytes at offset:  0x%08X -> 0x%08X",
		d.RebaseSize, d.RebaseOff, d.RebaseOff+d.RebaseSize,
		d.BindSize, d.BindOff, d.BindOff+d.BindSize,
		d.WeakBindSize, d.WeakBindOff, d.WeakBindOff+d.WeakBindSize,
		d.LazyBindSize, d.LazyBindOff, d.LazyBindOff+d.LazyBindSize,
		d.ExportSize, d.ExportOff, d.ExportOff+d.ExportSize,
	)
}
func (d *DyldInfoOnly) Copy() *DyldInfoOnly {
	return &DyldInfoOnly{DyldInfoOnlyCmd: d.DyldInfoOnlyCmd}
}
func (d *DyldInfoOnly) LoadSize(t *FileTOC) uint32 {
	return uint32(unsafe.Sizeof(types.UUIDCmd{}))
}
func (d *DyldInfoOnly) Put(b []byte, o binary.ByteOrder) int {
	o.PutUint32(b[0*4:], uint32(d.LoadCmd))
	o.PutUint32(b[1*4:], d.Len)
	o.PutUint32(b[2*4:], d.RebaseOff)
	o.PutUint32(b[3*4:], d.RebaseSize)
	o.PutUint32(b[4*4:], d.BindOff)
	o.PutUint32(b[5*4:], d.BindSize)
	o.PutUint32(b[6*4:], d.WeakBindOff)
	o.PutUint32(b[7*4:], d.WeakBindSize)
	o.PutUint32(b[8*4:], d.LazyBindOff)
	o.PutUint32(b[9*4:], d.LazyBindSize)
	o.PutUint32(b[10*4:], d.ExportOff)
	o.PutUint32(b[11*4:], d.ExportSize)
	return int(d.Len)
}

/*******************************************************************************
 * LC_LOAD_UPWARD_DYLIB
 *******************************************************************************/

// A UpwardDylib represents a Mach-O load upward dylib command.
type UpwardDylib Dylib

func (d *UpwardDylib) String() string {
	return fmt.Sprintf("%s (%s)", d.Name, d.CurrentVersion)
}

/*******************************************************************************
 * LC_VERSION_MIN_MACOSX
 *******************************************************************************/

// VersionMinMacOSX build for MacOSX min OS version
type VersionMinMacOSX struct {
	LoadBytes
	types.VersionMinMacOSCmd
	Version string
	Sdk     string
}

func (v *VersionMinMacOSX) String() string {
	return fmt.Sprintf("Version=%s, SDK=%s", v.Version, v.Sdk)
}

/*******************************************************************************
 * LC_VERSION_MIN_IPHONEOS
 *******************************************************************************/

// VersionMiniPhoneOS build for iPhoneOS min OS version
type VersionMiniPhoneOS struct {
	LoadBytes
	types.VersionMinIPhoneOSCmd
	Version string
	Sdk     string
}

func (v *VersionMiniPhoneOS) String() string {
	return fmt.Sprintf("Version=%s, SDK=%s", v.Version, v.Sdk)
}

/*******************************************************************************
 * LC_FUNCTION_STARTS
 *******************************************************************************/

// A FunctionStarts represents a Mach-O function starts command.
type FunctionStarts struct {
	LoadBytes
	types.FunctionStartsCmd
	Offset          uint32
	Size            uint32
	StartOffset     uint64
	NextFuncOffsets []uint64
	VMAddrs         []uint64
}

func (f *FunctionStarts) String() string {
	return fmt.Sprintf("offset=0x%08x-0x%08x, size=%5d, count=%d", f.Offset, f.Offset+f.Size, f.Size, len(f.VMAddrs))
}

/*******************************************************************************
 * LC_DYLD_ENVIRONMENT
 *******************************************************************************/

// A DyldEnvironment is a string for dyld to treat like environment variable
type DyldEnvironment struct {
	LoadBytes
	types.DyldEnvironmentCmd
	Name string
}

func (d *DyldEnvironment) String() string {
	return d.Name
}

/*******************************************************************************
 * LC_MAIN
 *******************************************************************************/

type EntryPoint struct {
	LoadBytes
	types.EntryPointCmd
	EntryOffset uint64
	StackSize   uint64
}

func (e *EntryPoint) String() string {
	return fmt.Sprintf("Entry Point: 0x%016x, Stack Size: 0x%x", e.EntryOffset, e.StackSize)
}
func (e *EntryPoint) Copy() *EntryPoint {
	return &EntryPoint{EntryPointCmd: e.EntryPointCmd}
}
func (e *EntryPoint) LoadSize(t *FileTOC) uint32 {
	return uint32(unsafe.Sizeof(types.UUIDCmd{}))
}
func (e *EntryPoint) Put(b []byte, o binary.ByteOrder) int {
	o.PutUint32(b[0*4:], uint32(e.LoadCmd))
	o.PutUint32(b[1*4:], e.Len)
	o.PutUint64(b[2*8:], e.EntryOffset)
	o.PutUint64(b[3*8:], e.StackSize)
	return int(e.Len)
}

/*******************************************************************************
 * LC_DATA_IN_CODE
 *******************************************************************************/

// A DataInCode represents a Mach-O data in code command.
type DataInCode struct {
	LoadBytes
	types.DataInCodeCmd
	Offset  uint32
	Size    uint32
	Entries []types.DataInCodeEntry
}

func (d *DataInCode) String() string {
	return fmt.Sprintf("offset=0x%08x-0x%08x, size=%5d, entries=%d", d.Offset, d.Offset+d.Size, d.Size, len(d.Entries))
}

/*******************************************************************************
 * LC_SOURCE_VERSION
 *******************************************************************************/

// A SourceVersion represents a Mach-O source version.
type SourceVersion struct {
	LoadBytes
	types.SourceVersionCmd
	Version string
}

func (s *SourceVersion) String() string {
	return s.Version
}

// TODO: LC_DYLIB_CODE_SIGN_DRS 0x2B /* Code signing DRs copied from linked dylibs */

/*******************************************************************************
 * LC_ENCRYPTION_INFO_64
 *******************************************************************************/

// A EncryptionInfo64 represents a Mach-O 64-bit encrypted segment information
type EncryptionInfo64 struct {
	LoadBytes
	types.EncryptionInfo64Cmd
	Offset  uint32                 // file offset of encrypted range
	Size    uint32                 // file size of encrypted range
	CryptID types.EncryptionSystem // which enryption system, 0 means not-encrypted yet
}

func (e *EncryptionInfo64) String() string {
	if e.CryptID == 0 {
		return fmt.Sprintf("Offset: 0x%x, Size: 0x%x (not-encrypted yet)", e.Offset, e.Size)
	}
	return fmt.Sprintf("Offset: 0x%x, Size: 0x%x, CryptID: 0x%x", e.Offset, e.Size, e.CryptID)
}
func (e *EncryptionInfo64) Copy() *EncryptionInfo64 {
	return &EncryptionInfo64{EncryptionInfo64Cmd: e.EncryptionInfo64Cmd}
}
func (e *EncryptionInfo64) LoadSize(t *FileTOC) uint32 {
	return uint32(unsafe.Sizeof(types.EncryptionInfo64Cmd{}))
}
func (e *EncryptionInfo64) Put(b []byte, o binary.ByteOrder) int {
	o.PutUint32(b[0*4:], uint32(e.LoadCmd))
	o.PutUint32(b[1*4:], e.Len)
	o.PutUint32(b[2*4:], e.Offset)
	o.PutUint32(b[3*4:], e.Size)
	o.PutUint32(b[3*4:], uint32(e.CryptID))
	o.PutUint32(b[3*4:], e.Pad)

	return int(e.Len)
}

// TODO: LC_LINKER_OPTION 0x2D /* linker options in MH_OBJECT files */
// TODO: LC_LINKER_OPTIMIZATION_HINT 0x2E /* optimization hints in MH_OBJECT files */

/*******************************************************************************
 * LC_VERSION_MIN_TVOS
 *******************************************************************************/

// VersionMinTvOS build for AppleTV min OS version
type VersionMinTvOS struct {
	LoadBytes
	types.VersionMinIPhoneOSCmd
	Version string
	Sdk     string
}

func (v *VersionMinTvOS) String() string {
	return fmt.Sprintf("Version=%s, SDK=%s", v.Version, v.Sdk)
}

/*******************************************************************************
 * LC_VERSION_MIN_WATCHOS
 *******************************************************************************/

// VersionMinWatchOS build for Watch min OS version
type VersionMinWatchOS struct {
	LoadBytes
	types.VersionMinIPhoneOSCmd
	Version string
	Sdk     string
}

func (v *VersionMinWatchOS) String() string {
	return fmt.Sprintf("Version=%s, SDK=%s", v.Version, v.Sdk)
}

// TODO: LC_NOTE 0x31 /* arbitrary data included within a Mach-O file */

/*******************************************************************************
 * LC_BUILD_VERSION
 *******************************************************************************/

// A BuildVersion represents a Mach-O build for platform min OS version.
type BuildVersion struct {
	LoadBytes
	types.BuildVersionCmd
	Platform    string /* platform */
	Minos       string /* X.Y.Z is encoded in nibbles xxxx.yy.zz */
	Sdk         string /* X.Y.Z is encoded in nibbles xxxx.yy.zz */
	NumTools    uint32 /* number of tool entries following this */
	Tool        string
	ToolVersion string
}

func (b *BuildVersion) String() string {
	return fmt.Sprintf("Platform: %s, SDK: %s, Tool: %s (%s)",
		b.Platform,
		b.Sdk,
		b.Tool,
		b.ToolVersion)
}

/*******************************************************************************
 * LC_DYLD_EXPORTS_TRIE
 *******************************************************************************/

// A DyldExportsTrie used with linkedit_data_command, payload is trie
type DyldExportsTrie struct {
	LoadBytes
	types.DyldExportsTrieCmd
	Offset uint32
	Size   uint32
}

func (t *DyldExportsTrie) String() string {
	return fmt.Sprintf("Offset: 0x%x, Size: 0x%x", t.Offset, t.Size)
}

/*******************************************************************************
 * LC_DYLD_CHAINED_FIXUPS
 *******************************************************************************/

// A DyldChainedFixups used with linkedit_data_command
type DyldChainedFixups struct {
	LoadBytes
	types.DyldChainedFixupsCmd
	Offset  uint32
	Size    uint32
	Imports []types.DcfImport
	Fixups  []interface{}
}

func (cf *DyldChainedFixups) String() string {
	return fmt.Sprintf("Offset: 0x%x, Size: 0x%x, Imports: %d", cf.Offset, cf.Size, len(cf.Imports))
}

/*******************************************************************************
 * LC_FILESET_ENTRY
 *******************************************************************************/

// FilesetEntry used with fileset_entry_command
type FilesetEntry struct {
	LoadBytes
	types.FilesetEntryCmd
	Addr    uint64 // memory address of the entry
	Offset  uint64 // file offset of the entry
	EntryID string // contained entry id
}

func (f *FilesetEntry) String() string {
	return fmt.Sprintf("Addr: 0x%016x, Offset: 0x%09x, EntryID: %s", f.Addr, f.Offset, f.EntryID)
}

/*******************************************************************************
 * LC_CODE_SIGNATURE, LC_SEGMENT_SPLIT_INFO,
 * LC_FUNCTION_STARTS, LC_DATA_IN_CODE,
 * LC_DYLIB_CODE_SIGN_DRS,
 * LC_LINKER_OPTIMIZATION_HINT,
 * LC_DYLD_EXPORTS_TRIE, or
 * LC_DYLD_CHAINED_FIXUPS.
 *******************************************************************************/

// A LinkEditData represents a Mach-O linkedit data command.
type LinkEditData struct {
	LoadBytes
	types.LinkEditDataCmd
	Offset uint32
	Size   uint32
}
