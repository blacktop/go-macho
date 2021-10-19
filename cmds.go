package macho

import (
	"bytes"
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
	Write(buf *bytes.Buffer, o binary.ByteOrder) error
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
func (b LoadBytes) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	_, err := buf.Write(b)
	return err
}

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
		"Seg %s, len=%#x, addr=%#x, memsz=%#x, offset=%#x, filesz=%#x, maxprot=%#x, prot=%#x, nsect=%d, flag=%#x, firstsect=%d",
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
	return fmt.Sprintf("LC_SEGMENT: sz=0x%08x off=0x%08x-0x%08x addr=0x%09x-0x%09x %s/%s   %s%s%s", s.Filesz, s.Offset, s.Offset+s.Filesz, s.Addr, s.Addr+s.Memsz, s.Prot, s.Maxprot, s.Name, pad(20-len(s.Name)), s.Flag)
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

func (s *Segment) LessThan(o *Segment) bool {
	return s.Addr < o.Addr
}

func (s *Segment) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	var name [16]byte
	copy(name[:], s.Name)

	switch s.Command() {
	case types.LC_SEGMENT:
		if err := binary.Write(buf, o, types.Segment32{
			LoadCmd: s.LoadCmd,        //              /* LC_SEGMENT */
			Len:     s.Len,            // uint32       /* includes sizeof section_64 structs */
			Name:    name,             // [16]byte     /* segment name */
			Addr:    uint32(s.Addr),   // uint32       /* memory address of this segment */
			Memsz:   uint32(s.Memsz),  // uint32       /* memory size of this segment */
			Offset:  uint32(s.Offset), // uint32       /* file offset of this segment */
			Filesz:  uint32(s.Filesz), // uint32       /* amount to map from the file */
			Maxprot: s.Maxprot,        // VmProtection /* maximum VM protection */
			Prot:    s.Prot,           // VmProtection /* initial VM protection */
			Nsect:   s.Nsect,          // uint32       /* number of sections in segment */
			Flag:    s.Flag,           // SegFlag      /* flags */
		}); err != nil {
			return fmt.Errorf("failed to write LC_SEGMENT to buffer: %v", err)
		}
	case types.LC_SEGMENT_64:
		if err := binary.Write(buf, o, types.Segment64{
			LoadCmd: s.LoadCmd, //              /* LC_SEGMENT_64 */
			Len:     s.Len,     // uint32       /* includes sizeof section_64 structs */
			Name:    name,      // [16]byte     /* segment name */
			Addr:    s.Addr,    // uint64       /* memory address of this segment */
			Memsz:   s.Memsz,   // uint64       /* memory size of this segment */
			Offset:  s.Offset,  // uint64       /* file offset of this segment */
			Filesz:  s.Filesz,  // uint64       /* amount to map from the file */
			Maxprot: s.Maxprot, // VmProtection /* maximum VM protection */
			Prot:    s.Prot,    // VmProtection /* initial VM protection */
			Nsect:   s.Nsect,   // uint32       /* number of sections in segment */
			Flag:    s.Flag,    // SegFlag      /* flags */
		}); err != nil {
			return fmt.Errorf("failed to write LC_SEGMENT to buffer: %v", err)
		}
	default:
		return fmt.Errorf("found unknown segment command: %s", s.Command().String())
	}

	return nil
}

// Data reads and returns the contents of the segment.
func (s *Segment) Data() ([]byte, error) {
	dat := make([]byte, s.Filesz)
	n, err := s.ReadAt(dat, int64(s.Offset))
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

type Segments []*Segment

func (v Segments) Len() int {
	return len(v)
}

func (v Segments) Less(i, j int) bool {
	return v[i].LessThan(v[j])
}

func (v Segments) Swap(i, j int) {
	v[i], v[j] = v[j], v[i]
}

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
	Type      uint8
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
	dat := make([]byte, s.Size)
	n, err := s.ReadAt(dat, int64(s.Offset))
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

func (s *Section) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	var name [16]byte
	var seg [16]byte
	copy(name[:], s.Name)
	copy(seg[:], s.Seg)

	if s.Type == 32 {
		if err := binary.Write(buf, o, types.Section32{
			Name:     name,           // [16]byte
			Seg:      seg,            // [16]byte
			Addr:     uint32(s.Addr), // uint32
			Size:     uint32(s.Size), // uint32
			Offset:   s.Offset,       // uint32
			Align:    s.Align,        // uint32
			Reloff:   s.Reloff,       // uint32
			Nreloc:   s.Nreloc,       // uint32
			Flags:    s.Flags,        // SectionFlag
			Reserve1: s.Reserved1,    // uint32
			Reserve2: s.Reserved2,    // uint32
		}); err != nil {
			return fmt.Errorf("failed to write 32bit Section %s data to buffer: %v", s.Name, err)
		}
	} else { // 64
		if err := binary.Write(buf, o, types.Section64{
			Name:     name,        // [16]byte
			Seg:      seg,         // [16]byte
			Addr:     s.Addr,      // uint64
			Size:     s.Size,      // uint64
			Offset:   s.Offset,    // uint32
			Align:    s.Align,     // uint32
			Reloff:   s.Reloff,    // uint32
			Nreloc:   s.Nreloc,    // uint32
			Flags:    s.Flags,     // SectionFlag
			Reserve1: s.Reserved1, // uint32
			Reserve2: s.Reserved2, // uint32
			Reserve3: s.Reserved3, // uint32
		}); err != nil {
			return fmt.Errorf("failed to write 64bit Section %s data to buffer: %v", s.Name, err)
		}
	}

	return nil
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

// A Symtab represents a Mach-O LC_SYMTAB command.
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
func (s *Symtab) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, types.SymtabCmd{
		LoadCmd: s.LoadCmd,
		Len:     s.Len,
		Symoff:  s.Symoff,
		Nsyms:   s.Nsyms,
		Stroff:  s.Stroff,
		Strsize: s.Strsize,
	}); err != nil {
		return fmt.Errorf("failed to write LC_SYMTAB to buffer: %v", err)
	}
	return nil
}

// A Symbol is a Mach-O 32-bit or 64-bit symbol table entry.
type Symbol struct {
	Name  string
	Type  types.NType
	Sect  uint8
	Desc  types.NDescType
	Value uint64
}

func (s Symbol) String(m *File) string {
	var sec string
	if s.Sect > 0 && int(s.Sect) <= len(m.Sections) {
		sec = fmt.Sprintf("%s.%s", m.Sections[s.Sect-1].Seg, m.Sections[s.Sect-1].Name)
	}
	return fmt.Sprintf("0x%016X \t <type:%s,desc:%s> \t %s", s.Value, s.Type.String(sec), s.Desc, s.Name)
}

/*******************************************************************************
 * LC_SYMSEG - link-edit gdb symbol table info (obsolete)
 *******************************************************************************/

// A SymSeg represents a Mach-O LC_SYMSEG command.
type SymSeg struct {
	LoadBytes
	types.SymsegCommand
	Offset uint32
	Size   uint32
}

func (s *SymSeg) String() string {
	return fmt.Sprintf("offset=0x%08x-0x%08x size=%5d", s.Offset, s.Offset+s.Size, s.Size)
}

/*******************************************************************************
 * LC_THREAD
 *******************************************************************************/

// A Thread represents a Mach-O LC_THREAD command.
type Thread struct {
	LoadBytes
	types.Thread
	Type uint32
	Data []uint32
}

func (t *Thread) String() string {
	return fmt.Sprintf("Type: %d", t.Type)
}

/*******************************************************************************
 * LC_UNIXTHREAD
 *******************************************************************************/

// A UnixThread represents a Mach-O LC_UNIXTHREAD command.
type UnixThread struct {
	LoadBytes
	types.UnixThreadCmd
	EntryPoint uint64
}

func (u *UnixThread) String() string {
	return fmt.Sprintf("Entry Point: 0x%016x", u.EntryPoint)
}

/*******************************************************************************
 * LC_LOADFVMLIB - load a specified fixed VM shared library
 *******************************************************************************/

// A LoadFvmlib represents a Mach-O LC_LOADFVMLIB command.
type LoadFvmlib struct {
	LoadBytes
	types.LoadFvmLibCmd
	Name          string
	MinorVersion  types.Version
	HeaderAddress uint32
}

func (l *LoadFvmlib) String() string {
	return fmt.Sprintf("%s (%s), Header Addr: %#08x", l.Name, l.MinorVersion, l.HeaderAddr)
}

/*******************************************************************************
 * LC_IDFVMLIB - fixed VM shared library identification
 *******************************************************************************/

// A IDFvmlib represents a Mach-O LC_IDFVMLIB command.
type IDFvmlib struct {
	LoadBytes
	types.IDFvmLibCmd
	Name          string
	MinorVersion  types.Version
	HeaderAddress uint32
}

func (l *IDFvmlib) String() string {
	return fmt.Sprintf("%s (%s), Header Addr: %#08x", l.Name, l.MinorVersion, l.HeaderAddr)
}

/*******************************************************************************
 * LC_IDENT - object identification info (obsolete)
 *******************************************************************************/

// A Ident represents a Mach-O LC_IDENT command.
type Ident struct {
	LoadBytes
	types.IdentCmd
	Length uint32
}

func (i *Ident) String() string {
	return fmt.Sprintf("len=%d", i.Length)
}

/*******************************************************************************
 * LC_FVMFILE - fixed VM file inclusion (internal use)
 *******************************************************************************/

// A FvmFile represents a Mach-O LC_FVMFILE command.
type FvmFile struct {
	LoadBytes
	types.FvmFileCmd
	Name          string
	HeaderAddress uint32
}

func (l *FvmFile) String() string {
	return fmt.Sprintf("%s, Header Addr: %#08x", l.Name, l.HeaderAddr)
}

/*******************************************************************************
 * LC_PREPAGE - prepage command (internal use)
 *******************************************************************************/

// A Prepage represents a Mach-O LC_PREPAGE command.
type Prepage struct {
	LoadBytes
	types.PrePageCmd
}

/*******************************************************************************
 * LC_DYSYMTAB
 *******************************************************************************/

// A Dysymtab represents a Mach-O LC_DYSYMTAB command.
type Dysymtab struct {
	LoadBytes
	types.DysymtabCmd
	IndirectSyms []uint32 // indices into Symtab.Syms
}

func (d *Dysymtab) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, types.DysymtabCmd{
		LoadCmd:        d.LoadCmd,
		Len:            d.Len,
		Ilocalsym:      d.Ilocalsym,
		Nlocalsym:      d.Nlocalsym,
		Iextdefsym:     d.Iextdefsym,
		Nextdefsym:     d.Nextdefsym,
		Iundefsym:      d.Iundefsym,
		Nundefsym:      d.Nundefsym,
		Tocoffset:      d.Tocoffset,
		Ntoc:           d.Ntoc,
		Modtaboff:      d.Modtaboff,
		Nmodtab:        d.Nmodtab,
		Extrefsymoff:   d.Extrefsymoff,
		Nextrefsyms:    d.Nextrefsyms,
		Indirectsymoff: d.Indirectsymoff,
		Nindirectsyms:  d.Nindirectsyms,
		Extreloff:      d.Extreloff,
		Nextrel:        d.Nextrel,
		Locreloff:      d.Locreloff,
		Nlocrel:        d.Nlocrel,
	}); err != nil {
		return fmt.Errorf("failed to write LC_DYSYMTAB to buffer: %v", err)
	}
	return nil
}

func (d *Dysymtab) String() string {
	var tocStr, modStr, extSymStr, indirSymStr, extRelStr, locRelStr string
	if d.Ntoc == 0 {
		tocStr = "No"
	} else {
		tocStr = fmt.Sprintf("%d at 0x%08x", d.Ntoc, d.Tocoffset)
	}
	if d.Nmodtab == 0 {
		modStr = "No"
	} else {
		modStr = fmt.Sprintf("%d at 0x%08x", d.Nmodtab, d.Modtaboff)
	}
	if d.Nextrefsyms == 0 {
		extSymStr = "None"
	} else {
		extSymStr = fmt.Sprintf("%d at 0x%08x", d.Nextrefsyms, d.Extrefsymoff)
	}
	if d.Nindirectsyms == 0 {
		indirSymStr = "None"
	} else {
		indirSymStr = fmt.Sprintf("%d at 0x%08x", d.Nindirectsyms, d.Indirectsymoff)
	}
	if d.Nextrel == 0 {
		extRelStr = "None"
	} else {
		extRelStr = fmt.Sprintf("%d at 0x%08x", d.Nextrel, d.Extreloff)
	}
	if d.Nlocrel == 0 {
		locRelStr = "None"
	} else {
		locRelStr = fmt.Sprintf("%d at 0x%08x", d.Nlocrel, d.Locreloff)
	}
	return fmt.Sprintf(
		"\n"+
			"\t             Local Syms: %d at %d\n"+
			"\t          External Syms: %d at %d\n"+
			"\t         Undefined Syms: %d at %d\n"+
			"\t                    TOC: %s\n"+
			"\t                 Modtab: %s\n"+
			"\tExternal symtab Entries: %s\n"+
			"\tIndirect symtab Entries: %s\n"+
			"\t External Reloc Entries: %s\n"+
			"\t    Local Reloc Entries: %s",
		d.Nlocalsym, d.Ilocalsym,
		d.Nextdefsym, d.Iextdefsym,
		d.Nundefsym, d.Iundefsym,
		tocStr,
		modStr,
		extSymStr,
		indirSymStr,
		extRelStr,
		locRelStr)
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

// A DylibID represents a Mach-O LC_ID_DYLIB command.
type DylibID Dylib

func (d *DylibID) String() string {
	return fmt.Sprintf("%s (%s)", d.Name, d.CurrentVersion)
}

/*******************************************************************************
 * LC_LOAD_DYLINKER
 *******************************************************************************/

// A LoadDylinker represents a Mach-O LC_LOAD_DYLINKER command.
type LoadDylinker struct {
	LoadBytes
	types.DylinkerCmd
	Name string
}

func (d *LoadDylinker) String() string {
	return d.Name
}

/*******************************************************************************
 * LC_ID_DYLINKER
 *******************************************************************************/

// DylinkerID represents a Mach-O LC_ID_DYLINKER command.
type DylinkerID struct {
	LoadBytes
	types.DylinkerIDCmd
	Name string
}

func (d *DylinkerID) String() string {
	return d.Name
}

/*******************************************************************************
 * LC_PREBOUND_DYLIB - modules prebound for a dynamically linked shared library
 *******************************************************************************/

// PreboundDylib represents a Mach-O LC_PREBOUND_DYLIB command.
type PreboundDylib struct {
	LoadBytes
	types.PreboundDylibCmd
	Name          string
	NumModules    uint32
	LinkedModules string
}

func (d *PreboundDylib) String() string {
	return fmt.Sprintf("%s, NumModules=%d, LinkedModules=%s", d.Name, d.NumModules, d.LinkedModules)
}

/*******************************************************************************
 * LC_ROUTINES - image routines
 *******************************************************************************/

// A Routines is a Mach-O LC_ROUTINES command.
type Routines struct {
	LoadBytes
	types.Routines64Cmd
	InitAddress uint32
	InitModule  uint32
}

func (r *Routines) String() string {
	return fmt.Sprintf("Address: %#08x, Module: %d", r.InitAddress, r.InitModule)
}

/*******************************************************************************
 * LC_SUB_FRAMEWORK
 *******************************************************************************/

// A SubFramework is a Mach-O LC_SUB_FRAMEWORK command.
type SubFramework struct {
	LoadBytes
	types.SubFrameworkCmd
	Framework string
}

func (s *SubFramework) String() string { return s.Framework }

/*******************************************************************************
 * LC_SUB_UMBRELLA - sub umbrella
 *******************************************************************************/

// A SubUmbrella is a Mach-O LC_SUB_UMBRELLA command.
type SubUmbrella struct {
	LoadBytes
	types.SubFrameworkCmd
	Umbrella string
}

func (s *SubUmbrella) String() string { return s.Umbrella }

/*******************************************************************************
 * LC_SUB_CLIENT
 *******************************************************************************/

// A SubClient is a Mach-O LC_SUB_CLIENT command.
type SubClient struct {
	LoadBytes
	types.SubClientCmd
	Name string
}

func (d *SubClient) String() string {
	return d.Name
}

/*******************************************************************************
 * LC_SUB_LIBRARY - sub library
 *******************************************************************************/

// A SubLibrary is a Mach-O LC_SUB_LIBRARY command.
type SubLibrary struct {
	LoadBytes
	types.SubFrameworkCmd
	Library string
}

func (s *SubLibrary) String() string { return s.Library }

/*******************************************************************************
 * LC_TWOLEVEL_HINTS - two-level namespace lookup hints
 *******************************************************************************/

// A TwolevelHints  is a Mach-O LC_TWOLEVEL_HINTS command.
type TwolevelHints struct {
	LoadBytes
	types.TwolevelHintsCmd
	Offset uint32
	Hints  []types.TwolevelHint
}

func (s *TwolevelHints) String() string {
	return fmt.Sprintf("Offset: %#08x, Num of Hints: %d", s.Offset, len(s.Hints))
}

/*******************************************************************************
 * LC_PREBIND_CKSUM - prebind checksum
 *******************************************************************************/

// A PrebindCksum  is a Mach-O LC_PREBIND_CKSUM command.
type PrebindCksum struct {
	LoadBytes
	types.PrebindCksumCmd
	CheckSum uint32
}

func (p *PrebindCksum) String() string {
	return fmt.Sprintf("CheckSum: %#08x", p.CheckSum)
}

/*******************************************************************************
 * LC_LOAD_WEAK_DYLIB
 *******************************************************************************/

// A WeakDylib represents a Mach-O LC_LOAD_WEAK_DYLIB command.
type WeakDylib Dylib

func (d *WeakDylib) String() string {
	return fmt.Sprintf("%s (%s)", d.Name, d.CurrentVersion)
}

/*******************************************************************************
 * LC_ROUTINES_64
 *******************************************************************************/

// A Routines64 is a Mach-O LC_ROUTINES_64 command.
type Routines64 struct {
	LoadBytes
	types.Routines64Cmd
	InitAddress uint64
	InitModule  uint64
}

func (r *Routines64) String() string {
	return fmt.Sprintf("Address: %#016x, Module: %d", r.InitAddress, r.InitModule)
}

/*******************************************************************************
 * LC_UUID
 *******************************************************************************/

// UUID represents a Mach-O LC_UUID command.
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

// A Rpath represents a Mach-O LC_RPATH command.
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

// A CodeSignature represents a Mach-O LC_CODE_SIGNATURE command.
type CodeSignature struct {
	LoadBytes
	types.CodeSignatureCmd
	Offset uint32
	Size   uint32
	ctypes.CodeSignature
}

func (c *CodeSignature) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, types.CodeSignatureCmd{
		LoadCmd: c.LoadCmd,
		Len:     c.Len,
		Offset:  c.Offset,
		Size:    c.Size,
	}); err != nil {
		return fmt.Errorf("failed to write LC_CODE_SIGNATURE to buffer: %v", err)
	}
	return nil
}

func (c *CodeSignature) String() string {
	// TODO: fix this once codesigs are done
	// return fmt.Sprintf("offset=0x%08x-0x%08x, size=%d, ID:   %s", c.Offset, c.Offset+c.Size, c.Size, c.ID)
	return fmt.Sprintf("offset=0x%08x-0x%08x size=%5d", c.Offset, c.Offset+c.Size, c.Size)
}

/*******************************************************************************
 * LC_SEGMENT_SPLIT_INFO
 *******************************************************************************/

// A SplitInfo represents a Mach-O LC_SEGMENT_SPLIT_INFO command.
type SplitInfo struct {
	LoadBytes
	types.SegmentSplitInfoCmd
	Offset  uint32
	Size    uint32
	Version uint8
	Offsets []uint64
}

func (s *SplitInfo) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, types.SegmentSplitInfoCmd{
		LoadCmd: s.LoadCmd,
		Len:     s.Len,
		Offset:  s.Offset,
		Size:    s.Size,
	}); err != nil {
		return fmt.Errorf("failed to write LC_SEGMENT_SPLIT_INFO to buffer: %v", err)
	}
	return nil
}

func (s *SplitInfo) String() string {
	version := "1"
	if s.Version == types.DYLD_CACHE_ADJ_V2_FORMAT {
		version = "format=v2"
	} else {
		version = fmt.Sprintf("kind=%#x", s.Version)
	}
	return fmt.Sprintf("offset=0x%08x-0x%08x size=%5d, %s", s.Offset, s.Offset+s.Size, s.Size, version)
}

/*******************************************************************************
 * LC_REEXPORT_DYLIB
 *******************************************************************************/

// A ReExportDylib represents a Mach-O LC_REEXPORT_DYLIB command.
type ReExportDylib Dylib

func (d *ReExportDylib) String() string {
	return fmt.Sprintf("%s (%s)", d.Name, d.CurrentVersion)
}

/*******************************************************************************
 * LC_LAZY_LOAD_DYLIB - delay load of dylib until first use
 *******************************************************************************/

// A LazyLoadDylib represents a Mach-O LC_LAZY_LOAD_DYLIB command.
type LazyLoadDylib Dylib

func (d *LazyLoadDylib) String() string {
	return fmt.Sprintf("%s (%s)", d.Name, d.CurrentVersion)
}

/*******************************************************************************
 * LC_ENCRYPTION_INFO
 *******************************************************************************/

// A EncryptionInfo represents a Mach-O 32-bit encrypted segment information
type EncryptionInfo struct {
	LoadBytes
	types.EncryptionInfoCmd
	Offset  uint32                 // file offset of encrypted range
	Size    uint32                 // file size of encrypted range
	CryptID types.EncryptionSystem // which enryption system, 0 means not-encrypted yet
}

func (l *EncryptionInfo) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, types.EncryptionInfoCmd{
		LoadCmd: l.LoadCmd,
		Len:     l.Len,
		Offset:  l.Offset,
		Size:    l.Size,
		CryptID: l.CryptID,
	}); err != nil {
		return fmt.Errorf("failed to write LC_ENCRYPTION_INFO to buffer: %v", err)
	}
	return nil
}

func (e *EncryptionInfo) String() string {
	if e.CryptID == 0 {
		return fmt.Sprintf("offset=%#x size=%#x (not-encrypted yet)", e.Offset, e.Size)
	}
	return fmt.Sprintf("offset=%#x size=%#x CryptID: %#x", e.Offset, e.Size, e.CryptID)
}
func (e *EncryptionInfo) Copy() *EncryptionInfo {
	return &EncryptionInfo{EncryptionInfoCmd: e.EncryptionInfoCmd}
}
func (e *EncryptionInfo) LoadSize(t *FileTOC) uint32 {
	return uint32(unsafe.Sizeof(types.EncryptionInfoCmd{}))
}
func (e *EncryptionInfo) Put(b []byte, o binary.ByteOrder) int {
	o.PutUint32(b[0*4:], uint32(e.LoadCmd))
	o.PutUint32(b[1*4:], e.Len)
	o.PutUint32(b[2*4:], e.Offset)
	o.PutUint32(b[3*4:], e.Size)
	o.PutUint32(b[3*4:], uint32(e.CryptID))

	return int(e.Len)
}

/*******************************************************************************
 * LC_DYLD_INFO
 *******************************************************************************/

// A DyldInfo represents a Mach-O LC_DYLD_INFO command.
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
func (l *DyldInfo) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, types.DyldInfoCmd{
		LoadCmd:      l.LoadCmd,
		Len:          l.Len,
		RebaseOff:    l.RebaseOff,
		RebaseSize:   l.RebaseSize,
		BindOff:      l.BindOff,
		BindSize:     l.BindSize,
		WeakBindOff:  l.WeakBindOff,
		WeakBindSize: l.WeakBindSize,
		LazyBindOff:  l.LazyBindOff,
		LazyBindSize: l.LazyBindSize,
		ExportOff:    l.ExportOff,
		ExportSize:   l.ExportSize,
	}); err != nil {
		return fmt.Errorf("failed to write LC_DYLD_INFO to buffer: %v", err)
	}
	return nil
}

/*******************************************************************************
 * LC_DYLD_INFO_ONLY
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
func (l *DyldInfoOnly) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, types.DyldInfoOnlyCmd{
		LoadCmd:      l.LoadCmd,
		Len:          l.Len,
		RebaseOff:    l.RebaseOff,
		RebaseSize:   l.RebaseSize,
		BindOff:      l.BindOff,
		BindSize:     l.BindSize,
		WeakBindOff:  l.WeakBindOff,
		WeakBindSize: l.WeakBindSize,
		LazyBindOff:  l.LazyBindOff,
		LazyBindSize: l.LazyBindSize,
		ExportOff:    l.ExportOff,
		ExportSize:   l.ExportSize,
	}); err != nil {
		return fmt.Errorf("failed to write LC_DYLD_INFO_ONLY to buffer: %v", err)
	}
	return nil
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

func (l *FunctionStarts) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, types.FunctionStartsCmd{
		LoadCmd: l.LoadCmd,
		Len:     l.Len,
		Offset:  l.Offset,
		Size:    l.Size,
	}); err != nil {
		return fmt.Errorf("failed to write LC_FUNCTION_STARTS to buffer: %v", err)
	}
	return nil
}

func (f *FunctionStarts) String() string {
	return fmt.Sprintf("offset=0x%08x-0x%08x size=%5d", f.Offset, f.Offset+f.Size, f.Size)
	// return fmt.Sprintf("offset=0x%08x-0x%08x size=%5d count=%d", f.Offset, f.Offset+f.Size, f.Size, len(f.VMAddrs))
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

// EntryPoint represents a Mach-O LC_MAIN command.
type EntryPoint struct {
	LoadBytes
	types.EntryPointCmd
	EntryOffset uint64
	StackSize   uint64
}

func (e *EntryPoint) String() string {
	return fmt.Sprintf("Entry Point: 0x%016x, Stack Size: %#x", e.EntryOffset, e.StackSize)
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
func (e *EntryPoint) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, types.EntryPointCmd{
		LoadCmd:   e.LoadCmd,
		Len:       e.Len,
		Offset:    e.Offset,
		StackSize: e.StackSize,
	}); err != nil {
		return fmt.Errorf("failed to write LC_MAIN to buffer: %v", err)
	}
	return nil
}

/*******************************************************************************
 * LC_DATA_IN_CODE
 *******************************************************************************/

// A DataInCode represents a Mach-O LC_DATA_IN_CODE command.
type DataInCode struct {
	LoadBytes
	types.DataInCodeCmd
	Offset  uint32
	Size    uint32
	Entries []types.DataInCodeEntry
}

func (d *DataInCode) String() string {
	return fmt.Sprintf("offset=0x%08x-0x%08x size=%5d entries=%d", d.Offset, d.Offset+d.Size, d.Size, len(d.Entries))
}

func (l *DataInCode) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, types.DataInCodeCmd{
		LoadCmd: l.LoadCmd,
		Len:     l.Len,
		Offset:  l.Offset,
		Size:    l.Size,
	}); err != nil {
		return fmt.Errorf("failed to write LC_DATA_IN_CODE to buffer: %v", err)
	}
	return nil
}

/*******************************************************************************
 * LC_SOURCE_VERSION
 *******************************************************************************/

// A SourceVersion represents a Mach-O LC_SOURCE_VERSION command.
type SourceVersion struct {
	LoadBytes
	types.DylibCodeSignDrsCmd
	Version string
}

func (s *SourceVersion) String() string {
	return s.Version
}

/*******************************************************************************
 * LC_DYLIB_CODE_SIGN_DRS Code signing DRs copied from linked dylibs
 *******************************************************************************/

type DylibCodeSignDrs struct {
	LoadBytes
	types.DylibCodeSignDrsCmd
	Offset uint32
	Size   uint32
}

func (d *DylibCodeSignDrs) String() string {
	return fmt.Sprintf("offset=0x%08x-0x%08x size=%5d", d.Offset, d.Offset+d.Size, d.Size)
}

func (l *DylibCodeSignDrs) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, types.DylibCodeSignDrsCmd{
		LoadCmd: l.LoadCmd,
		Len:     l.Len,
		Offset:  l.Offset,
		Size:    l.Size,
	}); err != nil {
		return fmt.Errorf("failed to write LC_DYLIB_CODE_SIGN_DRS to buffer: %v", err)
	}
	return nil
}

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
		return fmt.Sprintf("offset=0x%09x  size=%#x (not-encrypted yet)", e.Offset, e.Size)
	}
	return fmt.Sprintf("offset=0x%09x  size=%#x CryptID: %#x", e.Offset, e.Size, e.CryptID)
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
func (e *EncryptionInfo64) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, types.EncryptionInfo64Cmd{
		LoadCmd: e.LoadCmd,
		Len:     e.Len,
		Offset:  e.Offset,
		Size:    e.Size,
		CryptID: e.CryptID,
		Pad:     e.Pad,
	}); err != nil {
		return fmt.Errorf("failed to write LC_ENCRYPTION_INFO_64 to buffer: %v", err)
	}
	return nil
}

/*******************************************************************************
 * LC_LINKER_OPTION - linker options in MH_OBJECT files
 *******************************************************************************/

// A LinkerOption represents a Mach-O LC_LINKER_OPTION command.
type LinkerOption struct {
	LoadBytes
	types.LinkerOptionCmd
	Options []string
}

func (o *LinkerOption) String() string {
	return fmt.Sprintf("Options=%s", strings.Join(o.Options, ","))
}

/*******************************************************************************
 * LC_LINKER_OPTIMIZATION_HINT - linker options in MH_OBJECT files
 *******************************************************************************/

type LinkerOptimizationHint struct {
	LoadBytes
	types.LinkerOptimizationHintCmd
	Offset uint32
	Size   uint32
}

func (l *LinkerOptimizationHint) String() string {
	return fmt.Sprintf("offset=0x%08x-0x%08x size=%5d", l.Offset, l.Offset+l.Size, l.Size)
}

func (l *LinkerOptimizationHint) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, types.LinkerOptimizationHintCmd{
		LoadCmd: l.LoadCmd,
		Len:     l.Len,
		Offset:  l.Offset,
		Size:    l.Size,
	}); err != nil {
		return fmt.Errorf("failed to write LC_LINKER_OPTIMIZATION_HINT to buffer: %v", err)
	}
	return nil
}

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

/*******************************************************************************
 * LC_NOTE - arbitrary data included within a Mach-O file
 *******************************************************************************/

// A Note represents a Mach-O LC_NOTE command.
type Note struct {
	LoadBytes
	types.NoteCmd
	DataOwner string
	Offset    uint64
	Size      uint64
}

func (n *Note) String() string {
	return fmt.Sprintf("DataOwner=%s, offset=0x%08x-0x%08x size=%5d", n.DataOwner, n.Offset, n.Offset+n.Size, n.Size)
}

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
	if b.NumTools > 0 {
		return fmt.Sprintf("Platform: %s, SDK: %s, Tool: %s (%s)",
			b.Platform,
			b.Sdk,
			b.Tool,
			b.ToolVersion)
	}
	return fmt.Sprintf("Platform: %s, SDK: %s",
		b.Platform,
		b.Sdk)
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

func (t *DyldExportsTrie) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, types.DyldExportsTrieCmd{
		LoadCmd: t.LoadCmd,
		Len:     t.Len,
		Offset:  t.Offset,
		Size:    t.Size,
	}); err != nil {
		return fmt.Errorf("failed to write LC_DYLD_EXPORTS_TRIE to buffer: %v", err)
	}
	return nil
}

func (t *DyldExportsTrie) String() string {
	return fmt.Sprintf("offset=0x%09x  size=%#x", t.Offset, t.Size)
}

/*******************************************************************************
 * LC_DYLD_CHAINED_FIXUPS
 *******************************************************************************/

// A DyldChainedFixups used with linkedit_data_command
type DyldChainedFixups struct {
	LoadBytes
	types.DyldChainedFixupsCmd
	Offset uint32
	Size   uint32
}

func (s *DyldChainedFixups) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, types.DyldChainedFixupsCmd{
		LoadCmd: s.LoadCmd,
		Len:     s.Len,
		Offset:  s.Offset,
		Size:    s.Size,
	}); err != nil {
		return fmt.Errorf("failed to write LC_DYLD_CHAINED_FIXUPS to buffer: %v", err)
	}
	return nil
}

func (cf *DyldChainedFixups) String() string {
	return fmt.Sprintf("offset=0x%09x  size=%#x", cf.Offset, cf.Size)
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

func (l *FilesetEntry) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, types.FilesetEntryCmd{
		LoadCmd:  l.LoadCmd,
		Len:      l.Len,
		Addr:     l.Addr,
		Offset:   l.Offset,
		EntryID:  32, // it is always 0x20
		Reserved: l.Reserved,
	}); err != nil {
		return fmt.Errorf("failed to write LC_FILESET_ENTRY to buffer: %v", err)
	}
	return nil
}

func (f *FilesetEntry) String() string {
	return fmt.Sprintf("offset=0x%09x addr=0x%016x %s", f.Offset, f.Addr, f.EntryID)
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

func (l *LinkEditData) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, types.LinkEditDataCmd{
		LoadCmd: l.LoadCmd,
		Len:     l.Len,
		Offset:  l.Offset,
		Size:    l.Size,
	}); err != nil {
		return fmt.Errorf("failed to write linkedit_data_command to buffer: %v", err)
	}
	return nil
}
