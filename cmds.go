package macho

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"unsafe"

	ctypes "github.com/blacktop/go-macho/pkg/codesign/types"
	"github.com/blacktop/go-macho/types"
)

// A Load represents any Mach-O load command.
type Load interface {
	Command() types.LoadCmd
	LoadSize() uint32 // Need the TOC for alignment, sigh.
	Raw() []byte
	Write(buf *bytes.Buffer, o binary.ByteOrder) error
	String() string
	MarshalJSON() ([]byte, error)
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
func (b LoadBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		LoadCmd string `json:"load_cmd"`
		Data    []byte `json:"data,omitempty"`
	}{
		LoadCmd: "unknown",
		Data:    b,
	})
}
func (b LoadBytes) Raw() []byte      { return b }
func (b LoadBytes) Copy() LoadBytes  { return LoadBytes(append([]byte{}, b...)) }
func (b LoadBytes) LoadSize() uint32 { return uint32(len(b)) }
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
		"[SegmentHeader] %s, len=%#x, addr=%#x, memsz=%#x, offset=%#x, filesz=%#x, maxprot=%#x, prot=%#x, nsect=%d, flag=%#x, firstsect=%d",
		s.Name, s.Len, s.Addr, s.Memsz, s.Offset, s.Filesz, s.Maxprot, s.Prot, s.Nsect, s.Flag, s.Firstsect)
}

// A Segment represents a Mach-O 32-bit or 64-bit load segment command.
type Segment struct {
	SegmentHeader
	LoadBytes

	sections []*types.Section

	// Embed ReaderAt for ReadAt method.
	// Do not embed SectionReader directly
	// to avoid having Read and Seek.
	// If a client wants Read and Seek it must use
	// Open() to avoid fighting over the seek offset
	// with other clients.
	io.ReaderAt
	sr *io.SectionReader
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

// Open returns a new ReadSeeker reading the segment.
func (s *Segment) Open() io.ReadSeeker { return io.NewSectionReader(s.sr, 0, 1<<63-1) }

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
func (s *Segment) LoadSize() uint32 {
	if s.Command() == types.LC_SEGMENT_64 {
		return uint32(unsafe.Sizeof(types.Segment64{})) + uint32(s.Nsect)*uint32(unsafe.Sizeof(types.Section64{}))
	}
	return uint32(unsafe.Sizeof(types.Segment32{})) + uint32(s.Nsect)*uint32(unsafe.Sizeof(types.Section32{}))
}

func (s *Segment) String() string {
	return fmt.Sprintf("%s sz=0x%08x off=0x%08x-0x%08x addr=0x%09x-0x%09x %s/%s   %-18s%s",
		s.Command(),
		s.Filesz,
		s.Offset,
		s.Offset+s.Filesz,
		s.Addr,
		s.Addr+s.Memsz,
		s.Prot,
		s.Maxprot,
		s.Name,
		s.Flag)
}

func (s *Segment) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		LoadCmd string   `json:"load_cmd"`
		Len     uint32   `json:"len,omitempty"`
		Name    string   `json:"name,omitempty"`
		Addr    uint64   `json:"addr,omitempty"`
		Memsz   uint64   `json:"memsz,omitempty"`
		Offset  uint64   `json:"offset,omitempty"`
		Filesz  uint64   `json:"filesz,omitempty"`
		Maxprot string   `json:"maxprot,omitempty"`
		Prot    string   `json:"prot,omitempty"`
		Nsect   uint32   `json:"nsect,omitempty"`
		Flags   []string `json:"flags,omitempty"`
	}{
		LoadCmd: s.SegmentHeader.LoadCmd.String(),
		Len:     s.SegmentHeader.Len,
		Name:    s.SegmentHeader.Name,
		Addr:    s.SegmentHeader.Addr,
		Memsz:   s.SegmentHeader.Memsz,
		Offset:  s.SegmentHeader.Offset,
		Filesz:  s.SegmentHeader.Filesz,
		Maxprot: s.SegmentHeader.Maxprot.String(),
		Prot:    s.SegmentHeader.Prot.String(),
		Nsect:   s.SegmentHeader.Nsect,
		Flags:   s.SegmentHeader.Flag.List(),
	})
}

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
 * LC_SYMTAB
 *******************************************************************************/

// A Symtab represents a Mach-O LC_SYMTAB command.
type Symtab struct {
	LoadBytes
	types.SymtabCmd
	Syms []Symbol
}

func (s *Symtab) Copy() *Symtab {
	return &Symtab{SymtabCmd: s.SymtabCmd, Syms: append([]Symbol{}, s.Syms...)}
}
func (s *Symtab) LoadSize() uint32 {
	return uint32(binary.Size(s.SymtabCmd))
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
func (s *Symtab) Search(name string) (*Symbol, error) {
	i := sort.Search(len(s.Syms), func(i int) bool { return s.Syms[i].Name >= name })
	if i < len(s.Syms) && s.Syms[i].Name == name {
		return &s.Syms[i], nil
	}
	return nil, fmt.Errorf("%s not found in symtab", name)
}
func (s *Symtab) String() string {
	if s.Nsyms == 0 && s.Strsize == 0 {
		return "Symbols stripped"
	}
	return fmt.Sprintf("Symbol offset=0x%08X, Num Syms: %d, String offset=0x%08X-0x%08X", s.Symoff, s.Nsyms, s.Stroff, s.Stroff+s.Strsize)
}
func (s *Symtab) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		LoadCmd string `json:"load_cmd"`
		Len     uint32 `json:"len,omitempty"`
		Symoff  uint32 `json:"symoff,omitempty"`
		Nsyms   uint32 `json:"nsyms,omitempty"`
		Stroff  uint32 `json:"stroff,omitempty"`
		Strsize uint32 `json:"strsize,omitempty"`
	}{
		LoadCmd: s.LoadCmd.String(),
		Len:     s.Len,
		Symoff:  s.Symoff,
		Nsyms:   s.Nsyms,
		Stroff:  s.Stroff,
		Strsize: s.Strsize,
	})
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
	if s.Sect != types.NO_SECT && int(s.Sect) <= len(m.Sections) {
		sec = fmt.Sprintf("%s.%s", m.Sections[s.Sect-1].Seg, m.Sections[s.Sect-1].Name)
	}
	var lib string
	if s.Desc.GetLibraryOrdinal() != types.SELF_LIBRARY_ORDINAL && s.Desc.GetLibraryOrdinal() < types.MAX_LIBRARY_ORDINAL {
		if s.Desc.GetLibraryOrdinal() <= uint16(len(m.ImportedLibraries())) {
			lib = m.ImportedLibraries()[s.Desc.GetLibraryOrdinal()-1]
			return fmt.Sprintf("0x%016X\t<type:%s, desc:%s>\t%s\t(from %s)", s.Value, s.Type.String(sec), s.Desc, s.Name, filepath.Base(lib))
		}
	}
	return fmt.Sprintf("0x%016X\t<type:%s, desc:%s>\t%s", s.Value, s.Type.String(sec), s.Desc, s.Name)
}
func (s *Symbol) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Name  string `json:"name"`
		Type  string `json:"type"`
		Sect  uint8  `json:"sect"`
		Desc  string `json:"desc"`
		Value uint64 `json:"value"`
	}{
		Name:  s.Name,
		Type:  s.Type.String(fmt.Sprintf("sect_num=%d", s.Sect)),
		Sect:  s.Sect,
		Desc:  s.Desc.String(),
		Value: s.Value,
	})
}

/*******************************************************************************
 * LC_SYMSEG - link-edit gdb symbol table info (obsolete)
 *******************************************************************************/

// A SymSeg represents a Mach-O LC_SYMSEG command.
type SymSeg struct {
	LoadBytes
	types.SymsegCmd
	Offset uint32
	Size   uint32
}

func (s *SymSeg) LoadSize() uint32 {
	return uint32(binary.Size(s.SymsegCmd))
}
func (s *SymSeg) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, s.SymsegCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", s.Command(), err)
	}
	return nil
}
func (s *SymSeg) String() string {
	return fmt.Sprintf("offset=0x%08x-0x%08x size=%5d", s.Offset, s.Offset+s.Size, s.Size)
}
func (s *SymSeg) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
}

/*******************************************************************************
 * LC_THREAD
 *******************************************************************************/

// A Thread represents a Mach-O LC_THREAD command.
type Thread struct {
	LoadBytes
	types.ThreadCmd
	Type uint32
	Data []uint32
}

func (t *Thread) LoadSize() uint32 {
	return uint32(binary.Size(t.ThreadCmd))
}
func (t *Thread) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, t.ThreadCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", t.Command(), err)
	}
	return nil
}
func (t *Thread) String() string {
	return fmt.Sprintf("Type: %d", t.Type)
}
func (t *Thread) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
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

func (u *UnixThread) LoadSize() uint32 {
	return uint32(binary.Size(u.UnixThreadCmd))
}
func (u *UnixThread) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, u.UnixThreadCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", u.Command(), err)
	}
	return nil
}
func (u *UnixThread) String() string {
	return fmt.Sprintf("Entry Point: 0x%016x", u.EntryPoint)
}
func (u *UnixThread) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
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

func (l *LoadFvmlib) LoadSize() uint32 {
	return uint32(binary.Size(l.LoadFvmLibCmd))
}
func (l *LoadFvmlib) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, l.LoadFvmLibCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", l.Command(), err)
	}
	return nil
}
func (l *LoadFvmlib) String() string {
	return fmt.Sprintf("%s (%s), Header Addr: %#08x", l.Name, l.MinorVersion, l.HeaderAddr)
}
func (l *LoadFvmlib) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
}

/*******************************************************************************
 * LC_IDFVMLIB - fixed VM shared library identification
 *******************************************************************************/

// A IDFvmlib represents a Mach-O LC_IDFVMLIB command.
type IDFvmlib LoadFvmlib

/*******************************************************************************
 * LC_IDENT - object identification info (obsolete)
 *******************************************************************************/

// A Ident represents a Mach-O LC_IDENT command.
type Ident struct {
	LoadBytes
	types.IdentCmd
	Length uint32
}

func (i *Ident) LoadSize() uint32 {
	return uint32(binary.Size(i.IdentCmd))
}
func (i *Ident) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, i.IdentCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", i.Command(), err)
	}
	return nil
}
func (i *Ident) String() string {
	return fmt.Sprintf("len=%d", i.Length)
}
func (i *Ident) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
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

func (l *FvmFile) LoadSize() uint32 {
	return uint32(binary.Size(l.FvmFileCmd))
}
func (l *FvmFile) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, l.FvmFileCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", l.Command(), err)
	}
	return nil
}
func (l *FvmFile) String() string {
	return fmt.Sprintf("%s, Header Addr: %#08x", l.Name, l.HeaderAddr)
}
func (l *FvmFile) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
}

/*******************************************************************************
 * LC_PREPAGE - prepage command (internal use)
 *******************************************************************************/

// A Prepage represents a Mach-O LC_PREPAGE command.
type Prepage struct {
	LoadBytes
	types.PrePageCmd
}

func (c *Prepage) LoadSize() uint32 {
	return uint32(binary.Size(c.PrePageCmd))
}
func (c *Prepage) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, c.PrePageCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", c.Command(), err)
	}
	return nil
}
func (c *Prepage) String() string {
	return fmt.Sprintf("size=%d", c.Len)
}
func (c *Prepage) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
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

func (d *Dysymtab) LoadSize() uint32 {
	return uint32(binary.Size(d.DysymtabCmd))
}
func (d *Dysymtab) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, d.DysymtabCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", d.Command(), err)
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
func (d *Dysymtab) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
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
	CurrentVersion types.Version
	CompatVersion  types.Version
}

func (d *Dylib) LoadSize() uint32 {
	return uint32(binary.Size(d.DylibCmd))
}
func (d *Dylib) Put(b []byte, o binary.ByteOrder) int {
	o.PutUint32(b[0*4:], uint32(d.LoadCmd))
	o.PutUint32(b[1*4:], d.Len)
	o.PutUint32(b[2*4:], d.NameOffset)
	o.PutUint32(b[3*4:], d.Time)
	o.PutUint32(b[4*4:], uint32(d.CurrentVersion))
	o.PutUint32(b[5*4:], uint32(d.CompatVersion))
	return 6 * binary.Size(uint32(0))
}
func (d *Dylib) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, d.DylibCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", d.Command(), err)
	}
	return nil
}
func (d *Dylib) String() string {
	return fmt.Sprintf("%s (%s)", d.Name, d.CurrentVersion)
}
func (d *Dylib) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
}

/*******************************************************************************
 * LC_ID_DYLIB
 *******************************************************************************/

// A IDDylib represents a Mach-O LC_ID_DYLIB command.
type IDDylib Dylib

/*******************************************************************************
 * LC_LOAD_DYLINKER
 *******************************************************************************/

// A LoadDylinker represents a Mach-O LC_LOAD_DYLINKER command.
type LoadDylinker struct {
	LoadBytes
	types.DylinkerCmd
	Name string
}

func (d *LoadDylinker) LoadSize() uint32 {
	return uint32(binary.Size(d.DylinkerCmd))
}
func (d *LoadDylinker) Put(b []byte, o binary.ByteOrder) int {
	o.PutUint32(b[0*4:], uint32(d.LoadCmd))
	o.PutUint32(b[1*4:], d.Len)
	o.PutUint32(b[2*4:], d.NameOffset)
	return 3 * binary.Size(uint32(0))
}
func (d *LoadDylinker) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, d.DylinkerCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", d.Command(), err)
	}
	return nil
}
func (d *LoadDylinker) String() string {
	return d.Name
}
func (d *LoadDylinker) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
}

/*******************************************************************************
 * LC_ID_DYLINKER
 *******************************************************************************/

// DylinkerID represents a Mach-O LC_ID_DYLINKER command.
type DylinkerID LoadDylinker

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

func (d *PreboundDylib) LoadSize() uint32 {
	return uint32(binary.Size(d.PreboundDylibCmd))
}
func (d *PreboundDylib) Put(b []byte, o binary.ByteOrder) int {
	o.PutUint32(b[0*4:], uint32(d.LoadCmd))
	o.PutUint32(b[1*4:], d.Len)
	o.PutUint32(b[2*4:], d.NameOffset)
	o.PutUint32(b[3*4:], d.NumModules)
	o.PutUint32(b[4*4:], d.LinkedModulesOffset)
	return 5 * binary.Size(uint32(0))
}
func (d *PreboundDylib) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, d.PreboundDylibCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", d.Command(), err)
	}
	return nil
}
func (d *PreboundDylib) String() string {
	return fmt.Sprintf("%s, NumModules=%d, LinkedModules=%s", d.Name, d.NumModules, d.LinkedModules)
}
func (d *PreboundDylib) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
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

func (l *Routines) LoadSize() uint32 {
	return uint32(binary.Size(l.Routines64Cmd))
}
func (l *Routines) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, l.Routines64Cmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", l.Command(), err)
	}
	return nil
}
func (l *Routines) String() string {
	return fmt.Sprintf("Address: %#08x, Module: %d", l.InitAddress, l.InitModule)
}
func (l *Routines) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
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

func (l *SubFramework) LoadSize() uint32 {
	return uint32(binary.Size(l.SubFrameworkCmd))
}
func (l *SubFramework) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, l.SubFrameworkCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", l.Command(), err)
	}
	return nil
}
func (l *SubFramework) String() string { return l.Framework }
func (l *SubFramework) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
}

/*******************************************************************************
 * LC_SUB_UMBRELLA - sub umbrella
 *******************************************************************************/

// A SubUmbrella is a Mach-O LC_SUB_UMBRELLA command.
type SubUmbrella struct {
	LoadBytes
	types.SubFrameworkCmd
	Umbrella string
}

func (l *SubUmbrella) LoadSize() uint32 {
	return uint32(binary.Size(l.SubFrameworkCmd))
}
func (l *SubUmbrella) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, l.SubFrameworkCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", l.Command(), err)
	}
	return nil
}
func (l *SubUmbrella) String() string { return l.Umbrella }
func (l *SubUmbrella) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
}

/*******************************************************************************
 * LC_SUB_CLIENT
 *******************************************************************************/

// A SubClient is a Mach-O LC_SUB_CLIENT command.
type SubClient struct {
	LoadBytes
	types.SubClientCmd
	Name string
}

func (l *SubClient) LoadSize() uint32 {
	return uint32(binary.Size(l.SubClientCmd))
}
func (l *SubClient) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, l.SubClientCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", l.Command(), err)
	}
	return nil
}
func (l *SubClient) String() string {
	return l.Name
}
func (l *SubClient) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
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

func (l *SubLibrary) LoadSize() uint32 {
	return uint32(binary.Size(l.SubFrameworkCmd))
}
func (l *SubLibrary) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, l.SubFrameworkCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", l.Command(), err)
	}
	return nil
}
func (l *SubLibrary) String() string { return l.Library }
func (l *SubLibrary) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
}

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

func (l *TwolevelHints) LoadSize() uint32 {
	return uint32(binary.Size(l.TwolevelHintsCmd))
}
func (l *TwolevelHints) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, l.TwolevelHintsCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", l.Command(), err)
	}
	return nil
}
func (l *TwolevelHints) String() string {
	return fmt.Sprintf("Offset: %#08x, Num of Hints: %d", l.Offset, len(l.Hints))
}
func (l *TwolevelHints) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
}

/*******************************************************************************
 * LC_PREBIND_CKSUM - prebind checksum
 *******************************************************************************/

// A PrebindCheckSum  is a Mach-O LC_PREBIND_CKSUM command.
type PrebindCheckSum struct {
	LoadBytes
	types.PrebindCksumCmd
	CheckSum uint32
}

func (l *PrebindCheckSum) LoadSize() uint32 {
	return uint32(binary.Size(l.PrebindCksumCmd))
}
func (l *PrebindCheckSum) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, l.PrebindCksumCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", l.Command(), err)
	}
	return nil
}
func (l *PrebindCheckSum) String() string {
	return fmt.Sprintf("CheckSum: %#08x", l.CheckSum)
}
func (l *PrebindCheckSum) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
}

/*******************************************************************************
 * LC_LOAD_WEAK_DYLIB
 *******************************************************************************/

// A WeakDylib represents a Mach-O LC_LOAD_WEAK_DYLIB command.
type WeakDylib Dylib

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

func (l *Routines64) LoadSize() uint32 {
	return uint32(binary.Size(l.Routines64Cmd))
}
func (l *Routines64) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, l.Routines64Cmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", l.Command(), err)
	}
	return nil
}
func (l *Routines64) String() string {
	return fmt.Sprintf("Address: %#016x, Module: %d", l.InitAddress, l.InitModule)
}
func (l *Routines64) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
}

/*******************************************************************************
 * LC_UUID
 *******************************************************************************/

// UUID represents a Mach-O LC_UUID command.
type UUID struct {
	LoadBytes
	types.UUIDCmd
}

func (l *UUID) LoadSize() uint32 {
	return uint32(binary.Size(l.UUIDCmd))
}
func (l *UUID) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, l.UUIDCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", l.Command(), err)
	}
	return nil
}
func (l *UUID) String() string {
	return l.UUID.String()
}
func (l *UUID) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
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

func (r *Rpath) LoadSize() uint32 {
	return uint32(binary.Size(r.RpathCmd))
}
func (r *Rpath) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, r.RpathCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", r.Command(), err)
	}
	return nil
}
func (r *Rpath) String() string {
	return r.Path
}
func (r *Rpath) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
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

func (l *CodeSignature) LoadSize() uint32 {
	return uint32(binary.Size(l.CodeSignatureCmd))
}
func (l *CodeSignature) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, l.CodeSignatureCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", l.Command(), err)
	}
	return nil
}
func (l *CodeSignature) String() string { // TODO: add more info
	return fmt.Sprintf("offset=0x%09x  size=%#x", l.Offset, l.Size)
}
func (l *CodeSignature) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
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

func (l *SplitInfo) LoadSize() uint32 {
	return uint32(binary.Size(l.SegmentSplitInfoCmd))
}
func (l *SplitInfo) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, l.SegmentSplitInfoCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", l.Command(), err)
	}
	return nil
}
func (s *SplitInfo) String() string {
	version := "format=v1"
	if s.Version == types.DYLD_CACHE_ADJ_V2_FORMAT {
		version = "format=v2"
	} else {
		version = fmt.Sprintf("kind=%#x", s.Version)
	}
	return fmt.Sprintf("offset=0x%08x-0x%08x size=%5d, %s", s.Offset, s.Offset+s.Size, s.Size, version)
}
func (l *SplitInfo) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
}

/*******************************************************************************
 * LC_REEXPORT_DYLIB
 *******************************************************************************/

// A ReExportDylib represents a Mach-O LC_REEXPORT_DYLIB command.
type ReExportDylib Dylib

/*******************************************************************************
 * LC_LAZY_LOAD_DYLIB - delay load of dylib until first use
 *******************************************************************************/

// A LazyLoadDylib represents a Mach-O LC_LAZY_LOAD_DYLIB command.
type LazyLoadDylib Dylib

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

func (e *EncryptionInfo) LoadSize() uint32 {
	return uint32(binary.Size(e.EncryptionInfoCmd))
}
func (e *EncryptionInfo) Put(b []byte, o binary.ByteOrder) int {
	o.PutUint32(b[0*4:], uint32(e.LoadCmd))
	o.PutUint32(b[1*4:], e.Len)
	o.PutUint32(b[2*4:], e.Offset)
	o.PutUint32(b[3*4:], e.Size)
	o.PutUint32(b[3*4:], uint32(e.CryptID))

	return int(e.Len)
}
func (l *EncryptionInfo) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, l.EncryptionInfoCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", l.Command(), err)
	}
	return nil
}
func (e *EncryptionInfo) String() string {
	if e.CryptID == 0 {
		return fmt.Sprintf("offset=%#x size=%#x (not-encrypted yet)", e.Offset, e.Size)
	}
	return fmt.Sprintf("offset=%#x size=%#x CryptID: %#x", e.Offset, e.Size, e.CryptID)
}
func (l *EncryptionInfo) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
}

/*******************************************************************************
 * LC_DYLD_INFO
 *******************************************************************************/

// A DyldInfo represents a Mach-O LC_DYLD_INFO command.
type DyldInfo struct {
	LoadBytes
	types.DyldInfoCmd
}

func (d *DyldInfo) LoadSize() uint32 {
	return uint32(binary.Size(d.DyldInfoCmd))
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
	if err := binary.Write(buf, o, l.DyldInfoCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", l.Command(), err)
	}
	return nil
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
func (l *DyldInfo) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
}

/*******************************************************************************
 * LC_DYLD_INFO_ONLY
 *******************************************************************************/

// DyldInfoOnly is compressed dyld information only
type DyldInfoOnly DyldInfo

/*******************************************************************************
 * LC_LOAD_UPWARD_DYLIB
 *******************************************************************************/

// A UpwardDylib represents a Mach-O LC_LOAD_UPWARD_DYLIB load command.
type UpwardDylib Dylib

/*******************************************************************************
 * LC_VERSION_MIN_MACOSX
 *******************************************************************************/

// VersionMinMacOSX build for MacOSX min OS version
type VersionMinMacOSX VersionMin

/*******************************************************************************
 * LC_VERSION_MIN_IPHONEOS
 *******************************************************************************/

// VersionMiniPhoneOS build for iPhoneOS min OS version
type VersionMiniPhoneOS VersionMin

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

func (l *FunctionStarts) LoadSize() uint32 {
	return uint32(binary.Size(l.FunctionStartsCmd))
}
func (l *FunctionStarts) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, l.FunctionStartsCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", l.Command(), err)
	}
	return nil
}
func (l *FunctionStarts) String() string {
	return fmt.Sprintf("offset=0x%08x-0x%08x size=%5d", l.Offset, l.Offset+l.Size, l.Size)
	// return fmt.Sprintf("offset=0x%08x-0x%08x size=%5d count=%d", f.Offset, f.Offset+f.Size, f.Size, len(f.VMAddrs))
}
func (l *FunctionStarts) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
}

/*******************************************************************************
 * LC_DYLD_ENVIRONMENT
 *******************************************************************************/

// DyldEnvironment represents a Mach-O LC_DYLD_ENVIRONMENT command.
type DyldEnvironment LoadDylinker

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

func (e *EntryPoint) LoadSize() uint32 {
	return uint32(binary.Size(e.EntryPointCmd))
}
func (e *EntryPoint) Put(b []byte, o binary.ByteOrder) int {
	o.PutUint32(b[0*4:], uint32(e.LoadCmd))
	o.PutUint32(b[1*4:], e.Len)
	o.PutUint64(b[2*8:], e.EntryOffset)
	o.PutUint64(b[3*8:], e.StackSize)
	return int(e.Len)
}
func (e *EntryPoint) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, e.EntryPointCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", e.Command(), err)
	}
	return nil
}
func (e *EntryPoint) String() string {
	return fmt.Sprintf("Entry Point: 0x%016x, Stack Size: %#x", e.EntryOffset, e.StackSize)
}
func (e *EntryPoint) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
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

func (l *DataInCode) LoadSize() uint32 {
	return uint32(binary.Size(l.DataInCodeCmd))
}
func (l *DataInCode) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, l.DataInCodeCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", l.Command(), err)
	}
	return nil
}
func (d *DataInCode) String() string {
	var ents string
	if len(d.Entries) > 0 {
		ents = "\n"
	}
	for _, e := range d.Entries {
		ents += fmt.Sprintf("\toffset: %#08x length: %d kind: %s\n", e.Offset, e.Length, e.Kind)
	}
	ents = strings.TrimSuffix(ents, "\n")
	return fmt.Sprintf(
		"offset=0x%08x-0x%08x size=%5d entries=%d%s",
		d.Offset, d.Offset+d.Size, d.Size, len(d.Entries), ents)
}
func (l *DataInCode) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
}

/*******************************************************************************
 * LC_SOURCE_VERSION
 *******************************************************************************/

// A SourceVersion represents a Mach-O LC_SOURCE_VERSION command.
type SourceVersion struct {
	LoadBytes
	types.SourceVersionCmd
	Version string
}

func (s *SourceVersion) LoadSize() uint32 {
	return uint32(binary.Size(s.SourceVersionCmd))
}
func (s *SourceVersion) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, s.SourceVersionCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", s.Command(), err)
	}
	return nil
}
func (s *SourceVersion) String() string {
	return s.Version
}
func (s *SourceVersion) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
}

/*******************************************************************************
 * LC_DYLIB_CODE_SIGN_DRS Code signing DRs copied from linked dylibs
 *******************************************************************************/

type DylibCodeSignDrs LinkEditData

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

func (e *EncryptionInfo64) LoadSize() uint32 {
	return uint32(binary.Size(e.EncryptionInfo64Cmd))
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
	if err := binary.Write(buf, o, e.EncryptionInfo64Cmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", e.Command(), err)
	}
	return nil
}
func (e *EncryptionInfo64) String() string {
	if e.CryptID == 0 {
		return fmt.Sprintf("offset=0x%09x  size=%#x (not-encrypted yet)", e.Offset, e.Size)
	}
	return fmt.Sprintf("offset=0x%09x  size=%#x CryptID: %#x", e.Offset, e.Size, e.CryptID)
}
func (e *EncryptionInfo64) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
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

func (l *LinkerOption) LoadSize() uint32 {
	return uint32(binary.Size(l.LinkerOptionCmd))
}
func (l *LinkerOption) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, l.LinkerOptionCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", l.Command(), err)
	}
	return nil
}
func (l *LinkerOption) String() string {
	return fmt.Sprintf("Options=%s", strings.Join(l.Options, ","))
}
func (l *LinkerOption) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
}

/*******************************************************************************
 * LC_LINKER_OPTIMIZATION_HINT - linker options in MH_OBJECT files
 *******************************************************************************/

type LinkerOptimizationHint LinkEditData

/*******************************************************************************
 * LC_VERSION_MIN_TVOS
 *******************************************************************************/

// VersionMinTvOS build for AppleTV min OS version
type VersionMinTvOS VersionMin

/*******************************************************************************
 * LC_VERSION_MIN_WATCHOS
 *******************************************************************************/

// VersionMinWatchOS build for Watch min OS version
type VersionMinWatchOS VersionMin

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

func (n *Note) LoadSize() uint32 {
	return uint32(binary.Size(n.NoteCmd))
}
func (n *Note) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, n.NoteCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", n.Command(), err)
	}
	return nil
}
func (n *Note) String() string {
	return fmt.Sprintf("DataOwner=%s, offset=0x%08x-0x%08x size=%5d", n.DataOwner, n.Offset, n.Offset+n.Size, n.Size)
}
func (n *Note) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
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

func (b *BuildVersion) LoadSize() uint32 {
	return uint32(binary.Size(b.BuildVersionCmd))
}
func (b *BuildVersion) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, b.BuildVersionCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", b.Command(), err)
	}
	return nil
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
func (b *BuildVersion) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
}

/*******************************************************************************
 * LC_DYLD_EXPORTS_TRIE
 *******************************************************************************/

// A DyldExportsTrie used with linkedit_data_command, payload is trie
type DyldExportsTrie LinkEditData

/*******************************************************************************
 * LC_DYLD_CHAINED_FIXUPS
 *******************************************************************************/

// A DyldChainedFixups used with linkedit_data_command
type DyldChainedFixups LinkEditData

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

func (l *FilesetEntry) LoadSize() uint32 {
	return uint32(binary.Size(l.FilesetEntryCmd))
}
func (l *FilesetEntry) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, l.FilesetEntryCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", l.Command(), err)
	}
	return nil
}
func (f *FilesetEntry) String() string {
	return fmt.Sprintf("offset=0x%09x addr=0x%016x %s", f.Offset, f.Addr, f.EntryID)
}
func (l *FilesetEntry) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
}

/*******************************************************************************
 * COMMON COMMANDS
 *******************************************************************************/

// A VersionMin represents a Mach-O LC_VERSION_MIN_* command.
type VersionMin struct {
	LoadBytes
	types.VersionMinCmd
	Version string
	Sdk     string
}

func (v *VersionMin) LoadSize() uint32 {
	return uint32(binary.Size(v.VersionMinCmd))
}
func (v *VersionMin) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, v.VersionMinCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", v.Command(), err)
	}
	return nil
}
func (v *VersionMin) String() string {
	return fmt.Sprintf("Version=%s, SDK=%s", v.Version, v.Sdk)
}
func (v *VersionMin) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
}

// A LinkEditData represents a Mach-O linkedit data command.
type LinkEditData struct {
	LoadBytes
	types.LinkEditDataCmd
	Offset uint32
	Size   uint32
}

func (l *LinkEditData) LoadSize() uint32 {
	return uint32(binary.Size(l.LinkEditDataCmd))
}
func (l *LinkEditData) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, l.LinkEditDataCmd); err != nil {
		return fmt.Errorf("failed to write %s to buffer: %v", l.Command(), err)
	}
	return nil
}
func (l *LinkEditData) String() string {
	return fmt.Sprintf("offset=0x%09x  size=%#x", l.Offset, l.Size)
}
func (l *LinkEditData) MarshalJSON() ([]byte, error) {
	panic("not implemented") // TODO: Implement
}
