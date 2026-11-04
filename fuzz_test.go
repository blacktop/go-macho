// Fuzz tests for parsing untrusted Mach-O binaries.
//
// Corpus seeds are intentionally small and structurally varied: real
// (obscured) test binaries from internal/testdata plus synthetic binaries
// that reach the lazy deep-parsers (chained fixups, tries, function starts,
// ObjC/Swift metadata). Run with:
//
//	go test -run=XX -fuzz=FuzzNewFile -fuzztime=5m
//	go test -run=XX -fuzz=FuzzNewFatFile -fuzztime=5m
//
// Minimized crashers found while fuzzing are committed under
// testdata/fuzz/<FuzzName>/ and replayed by plain `go test`.

package macho

import (
	"bytes"
	"encoding/binary"
	"path/filepath"
	"testing"

	"github.com/blacktop/go-macho/internal/obscuretestdata"
	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-macho/types"
)

func to16(s string) [16]byte {
	var b [16]byte
	copy(b[:], s)
	return b
}

// fixupsSeedBlob renders a small LC_DYLD_CHAINED_FIXUPS payload that this
// library can fully parse: one segment with one page whose chain starts at
// offset 0, one import, and one symbol string.
func fixupsSeedBlob() []byte {
	le := binary.LittleEndian
	var starts bytes.Buffer
	// dyld_chain_starts_in_image: seg_count, seg_info_offsets[]
	binary.Write(&starts, le, uint32(1))
	binary.Write(&starts, le, []uint32{8}) // relative offset of segment 0 starts
	// dyld_chain_starts_in_segment for segment 0 (DYLD_CHAINED_PTR_64)
	binary.Write(&starts, le, fixupchains.DyldChainedStartsInSegment{
		Size:          uint32(binary.Size(fixupchains.DyldChainedStartsInSegment{})),
		PageSize:      0x1000,
		PointerFormat: fixupchains.DYLD_CHAINED_PTR_64,
		SegmentOffset: 0,
		PageCount:     1,
	})
	binary.Write(&starts, le, []uint16{0}) // page_starts[0]: chain at page offset 0

	imports := make([]byte, 4) // one DYLD_CHAINED_IMPORT: lib ordinal 1, name offset 0
	le.PutUint32(imports, 1)
	symbols := []byte("\x00_foo\x00")

	startsOff := uint32(binary.Size(fixupchains.DyldChainedFixupsHeader{}))
	importsOff := startsOff + uint32(starts.Len())
	symbolsOff := importsOff + uint32(len(imports))

	var buf bytes.Buffer
	binary.Write(&buf, le, fixupchains.DyldChainedFixupsHeader{
		FixupsVersion: 0,
		StartsOffset:  startsOff,
		ImportsOffset: importsOff,
		SymbolsOffset: symbolsOff,
		ImportsCount:  1,
		ImportsFormat: fixupchains.DC_IMPORT,
		SymbolsFormat: 0,
	})
	buf.Write(starts.Bytes())
	buf.Write(imports)
	buf.Write(symbols)
	return buf.Bytes()
}

// trieSeedBlob renders a valid export trie exporting "_main" and "_foo" at
// vmaddr 0x8000/0x8008.
func trieSeedBlob() []byte {
	var b []byte
	node := func() []byte { return []byte{0x04, 0x00, 0x80, 0x80, 0x04} } // term=4, flags=0, uleb(0x8000)
	root := append(node(), 0x05)
	root = append(root, "_main"...)
	root = append(root, byte(len(root)+1)) // child offset (uleb, < 128)
	child := node()
	b = append(b, root...)
	b = append(b, child...)
	return b
}

// seedArm64Dylib builds a synthetic arm64 dylib exercising the modern load
// command set: segments+sections, symtab/dysymtab, chained fixups, export
// trie, function starts, data-in-code, twolevel hints, dylibs, rpath, main,
// uuid, build version and thread state.
func seedArm64Dylib() []byte {
	le := binary.LittleEndian

	// payload chunks, in fixed order
	symdat := func() []byte {
		var b bytes.Buffer
		binary.Write(&b, le, types.Nlist64{Nlist: types.Nlist{Name: 1, Type: 0x0e, Sect: 1, Desc: 0x0010}, Value: 0x8000})
		binary.Write(&b, le, types.Nlist64{Nlist: types.Nlist{Name: 19, Type: 0x01}, Value: 0})
		return b.Bytes()
	}()
	strtab := []byte("\x00_mh_execute_header\x00_foo\x00")
	dcfData := fixupsSeedBlob()
	trieData := trieSeedBlob()
	funcStarts := []byte{0x40, 0x08, 0x00}
	dice := func() []byte {
		d := make([]byte, 8)
		le.PutUint32(d[0:4], 0x40)
		le.PutUint16(d[4:6], 4)
		le.PutUint16(d[6:8], 1) // DICE_KIND_DATA
		return d
	}()
	indirectSyms := func() []byte {
		d := make([]byte, 8)
		le.PutUint32(d[0:4], 0)
		le.PutUint32(d[4:8], 1)
		return d
	}()
	hints := []types.TwolevelHint{0x00000001, 0x00010002}

	chunks := [][]byte{symdat, strtab, dcfData, trieData, funcStarts, dice, indirectSyms}
	for _, h := range hints {
		var hb [4]byte
		le.PutUint32(hb[:], uint32(h))
		chunks = append(chunks, hb[:])
	}

	const segHdrSize = 72 // binary.Size(types.Segment64{})
	const sectSize = 80   // binary.Size(types.Section64{})

	// The load command block is emitted twice: pass 0 measures it (payload
	// offsets are irrelevant to its length), pass 1 bakes in the real chunk
	// offsets. All commands are fixed-size so both passes agree on length.
	var loadsLen int
	var out []byte
	for pass := 0; pass < 2; pass++ {
		base := uint32(0)
		if pass == 1 {
			base = uint32(types.FileHeaderSize64) + uint32(loadsLen)
		}
		off := func(i int) uint32 {
			o := base
			for j := 0; j < i; j++ {
				o += uint32(len(chunks[j]))
			}
			return o
		}
		size := func(i int) uint32 { return uint32(len(chunks[i])) }

		var l bytes.Buffer
		w := func(v any) {
			if err := binary.Write(&l, le, v); err != nil {
				panic(err)
			}
		}

		// LC_SEGMENT_64 __TEXT (file size patched after assembly)
		w(types.Segment64{
			LoadCmd: types.LC_SEGMENT_64,
			Len:     uint32(segHdrSize + 2*sectSize),
			Name:    to16("__TEXT"),
			Addr:    0,
			Memsz:   0x9000,
			Offset:  0,
			Filesz:  0,
			Maxprot: 5,
			Prot:    5,
			Nsect:   2,
		})
		w(types.Section64{Name: to16("__text"), Seg: to16("__TEXT"), Addr: 0x8000, Size: 0x10, Offset: 0x8000, Align: 2, Flags: 0x80000400})
		w(types.Section64{Name: to16("__cstring"), Seg: to16("__TEXT"), Addr: 0x8010, Size: 0x8, Offset: 0x8010, Align: 0, Flags: 0x2})

		w(types.UUIDCmd{LoadCmd: types.LC_UUID, Len: 24, UUID: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}})
		w(types.BuildVersionCmd{LoadCmd: types.LC_BUILD_VERSION, Len: 24 + 8, Platform: 1, Minos: 0x000C0000, Sdk: 0x000C0000, NumTools: 1})
		w(types.BuildVersionTool{Tool: types.Tool(3), Version: 0x000900}) // TOOL_LD
		w(types.RpathCmd{LoadCmd: types.LC_RPATH, Len: 12 + 8, PathOffset: 12})
		l.WriteString("/lib\x00\x00\x00\x00")
		dylibPath := "/usr/lib/libSystem.B.dylib\x00"
		w(types.DylibCmd{LoadCmd: types.LC_LOAD_DYLIB, Len: 24 + uint32(len(dylibPath)), NameOffset: 24, Timestamp: 2, CurrentVersion: 0x10000, CompatVersion: 0x10000})
		l.WriteString(dylibPath)

		// LC_THREAD: ARM_THREAD_STATE64, all-zero registers
		w(types.ThreadCmd{LoadCmd: types.LC_THREAD, Len: 16 + 68*4})
		w(uint32(6))  // flavor
		w(uint32(68)) // count
		l.Write(make([]byte, 68*4))

		w(types.SymtabCmd{LoadCmd: types.LC_SYMTAB, Len: 24, Symoff: off(0), Nsyms: 2, Stroff: off(1), Strsize: size(1)})
		w(types.DysymtabCmd{
			LoadCmd:        types.LC_DYSYMTAB,
			Len:            80,
			Iundefsym:      1,
			Nundefsym:      1,
			Indirectsymoff: off(6),
			Nindirectsyms:  2,
		})
		w(types.DyldChainedFixupsCmd{LoadCmd: types.LC_DYLD_CHAINED_FIXUPS, Len: 16, Offset: off(2), Size: size(2)})
		w(types.LinkEditDataCmd{LoadCmd: types.LC_DYLD_EXPORTS_TRIE, Len: 16, Offset: off(3), Size: size(3)})
		w(types.LinkEditDataCmd{LoadCmd: types.LC_FUNCTION_STARTS, Len: 16, Offset: off(4), Size: size(4)})
		w(types.LinkEditDataCmd{LoadCmd: types.LC_DATA_IN_CODE, Len: 16, Offset: off(5), Size: size(5)})
		w(types.EntryPointCmd{LoadCmd: types.LC_MAIN, Len: 24, EntryOffset: 0x8000, StackSize: 0})
		// two-level hints are read from the command payload itself
		w(types.TwolevelHintsCmd{LoadCmd: types.LC_TWOLEVEL_HINTS, Len: 16 + 8, Offset: 0, NumHints: 2})
		w([]uint32{0x00000001, 0x00010002})

		if pass == 0 {
			loadsLen = l.Len()
			continue
		}

		var f bytes.Buffer
		binary.Write(&f, le, types.FileHeader{
			Magic:        types.Magic64,
			CPU:          types.CPUArm64,
			Type:         types.MH_DYLIB,
			NCommands:    13,
			SizeCommands: uint32(loadsLen),
		})
		f.Write(l.Bytes())
		for _, c := range chunks {
			f.Write(c)
		}
		out = f.Bytes()
		// patch __TEXT filesz to span the whole image
		le.PutUint64(out[types.FileHeaderSize64+48:types.FileHeaderSize64+56], uint64(len(out)))
	}
	return out
}

// seedI386Exec builds a minimal 32-bit i386 executable with LC_SEGMENT,
// LC_SYMTAB and LC_UNIXTHREAD.
func seedI386Exec() []byte {
	le := binary.LittleEndian

	symdat := func() []byte {
		var b bytes.Buffer
		binary.Write(&b, le, types.Nlist32{Nlist: types.Nlist{Name: 1, Type: 0x0f, Sect: 1}, Value: 0x1000})
		return b.Bytes()
	}()
	strtab := []byte("\x00_start\x00")
	chunks := [][]byte{symdat, strtab}

	var loadsLen int
	var out []byte
	for pass := 0; pass < 2; pass++ {
		base := uint32(0)
		if pass == 1 {
			base = uint32(types.FileHeaderSize32) + uint32(loadsLen)
		}
		off := func(i int) uint32 {
			o := base
			for j := 0; j < i; j++ {
				o += uint32(len(chunks[j]))
			}
			return o
		}

		var l bytes.Buffer
		w := func(v any) {
			if err := binary.Write(&l, le, v); err != nil {
				panic(err)
			}
		}

		w(types.Segment32{
			LoadCmd: types.LC_SEGMENT,
			Len:     uint32(56 + 68), // segment32 + one section32
			Name:    to16("__TEXT"),
			Addr:    0,
			Memsz:   0x2000,
			Offset:  0,
			Filesz:  0x2000,
			Maxprot: 7,
			Prot:    5,
			Nsect:   1,
		})
		w(types.Section32{Name: to16("__text"), Seg: to16("__TEXT"), Addr: 0x1000, Size: 8, Offset: 0x1000, Align: 2, Flags: 0x80000400})
		w(types.SymtabCmd{LoadCmd: types.LC_SYMTAB, Len: 24, Symoff: off(0), Nsyms: 1, Stroff: off(1), Strsize: uint32(len(strtab))})
		w(types.UnixThreadCmd{LoadCmd: types.LC_UNIXTHREAD, Len: 16 + 17*4})
		w(uint32(1))  // i386 thread state
		w(uint32(17)) // count
		l.Write(make([]byte, 17*4))

		if pass == 0 {
			loadsLen = l.Len()
			continue
		}

		var f bytes.Buffer
		// 32-bit headers carry no reserved word on disk (28 bytes)
		f.Write(make([]byte, types.FileHeaderSize32))
		le.PutUint32(f.Bytes()[0:4], uint32(types.Magic32))
		le.PutUint32(f.Bytes()[4:8], uint32(types.CPUI386))
		le.PutUint32(f.Bytes()[8:12], uint32(types.CPUSubtype(3)))
		le.PutUint32(f.Bytes()[12:16], uint32(types.MH_DYLIB))
		le.PutUint32(f.Bytes()[16:20], 3) // ncmds
		le.PutUint32(f.Bytes()[20:24], uint32(loadsLen))
		f.Write(l.Bytes())
		for _, c := range chunks {
			f.Write(c)
		}
		out = f.Bytes()
	}
	return out
}

// seedFat wraps thin images into a fat (universal) binary with 16-byte
// aligned image offsets and distinct architectures.
func seedFat(images ...[]byte) []byte {
	n := len(images)
	cpus := []types.CPU{types.CPUArm64, types.CPUI386, types.CPUAmd64}
	subs := []types.CPUSubtype{0, 3, 3}

	offsets := make([]uint32, n)
	off := uint32(8 + 20*n)
	for i, img := range images {
		offsets[i] = off
		off = (off + uint32(len(img)) + 15) &^ 15
	}

	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(types.MagicFat))
	binary.Write(&buf, binary.BigEndian, uint32(n))
	for i, img := range images {
		binary.Write(&buf, binary.BigEndian, FatArchHeader{
			CPU:    cpus[i%len(cpus)],
			SubCPU: subs[i%len(subs)],
			Offset: offsets[i],
			Size:   uint32(len(img)),
			Align:  4,
		})
	}
	for i, img := range images {
		for buf.Len() < int(offsets[i]) {
			buf.WriteByte(0)
		}
		buf.Write(img)
	}
	return buf.Bytes()
}

// exercise drives the lazy deep-parsers behind File. Calls are gated on the
// presence of the load commands/sections they need so the common
// early-reject path stays fast during fuzzing.
func exercise(t *testing.T, m *File, depth int) {
	t.Helper()
	_ = m.FileTOC.String()

	for _, seg := range m.Segments() {
		_ = seg.String()
	}
	for _, s := range m.Sections {
		_, _ = s.Data()
		_, _ = s.UncompressedSize() // used to panic on malformed __z sections
		_ = s.String()
	}

	if m.Symtab != nil && len(m.Symtab.Syms) > 0 {
		_, _ = m.FindSymbolAddress(m.Symtab.Syms[0].Name)
		_, _ = m.GetCStringAtOffset(int64(m.Symtab.Stroff))
	}

	if m.HasDyldChainedFixups() {
		if dcf, err := m.DyldChainedFixups(); err == nil && dcf != nil {
			if _, err := dcf.Parse(); err == nil {
				_, _ = m.GetBindInfo()
				_, _ = m.GetRebaseInfo()
			}
		}
	} else if m.HasDyldInfoOnly() {
		_, _ = m.GetBindInfo()
		_, _ = m.GetRebaseInfo()
	}

	_, _ = m.GetExports()
	_, _ = m.GetDyldExport("_main")
	_ = m.GetFunctions()
	_, _ = m.GetFunctionVariants()
	_, _ = m.GetFunctionVariantFixups()
	_, _ = m.GetLazyLoadedDylibs()
	_, _ = m.GetEmbeddedInfoPlist()

	if m.Section("__DWARF", "__debug_info") != nil {
		_, _ = m.DWARF()
	}
	if m.Section("__TEXT", "__cstring") != nil {
		_, _ = m.GetCStrings()
	}
	if m.Section("__LLVM", "__bundle") != nil {
		_, _ = m.GetEmbeddedLLVMBitcode()
	}

	// ObjC metadata (anchored on the runtime's class list section)
	if m.Section("__DATA", "__objc_classlist") != nil || m.Section("__DATA_CONST", "__objc_classlist") != nil {
		_, _ = m.GetObjCImageInfo()
		_, _ = m.GetObjCClasses()
		_, _ = m.GetObjCProtocols()
		_, _ = m.GetObjCCategories()
		_, _ = m.GetObjCClassNames()
		_, _ = m.GetObjCMethodNames()
		_, _ = m.GetCFStrings()
		_, _ = m.GetObjCSelectorReferences()
		_, _ = m.GetObjCClassReferences()
	}

	// Swift metadata (anchored on any __swift5 section)
	for _, s := range m.Sections {
		if len(s.Name) >= 8 && s.Name[:8] == "__swift5" {
			_, _ = m.GetSwiftTypes()
			_, _ = m.GetSwiftProtocols()
			_, _ = m.GetSwiftFields()
			_, _ = m.GetSwiftTypeRefs()
			break
		}
	}

	// fileset entries (capped recursion)
	if depth < 2 {
		for _, fs := range m.FileSets() {
			if fe, err := m.GetFileSetFileByName(fs.EntryID); err == nil && fe != nil {
				exercise(t, fe, depth+1)
			}
		}
	}
}

// TestFuzzSeedsAreValid guards against seed rot: every synthetic seed must
// still parse successfully, otherwise the fuzzer would lose coverage of the
// structures the seeds exist to reach.
func TestFuzzSeedsAreValid(t *testing.T) {
	for name, seed := range map[string][]byte{
		"arm64-dylib": seedArm64Dylib(),
		"i386-exec":   seedI386Exec(),
	} {
		m, err := NewFile(bytes.NewReader(seed))
		if err != nil {
			t.Fatalf("seed %s failed to parse: %v", name, err)
		}
		defer m.Close()
		if len(m.Loads) == 0 {
			t.Fatalf("seed %s parsed to zero load commands", name)
		}
		exercise(t, m, 0)
	}

	ff, err := NewFatFile(bytes.NewReader(seedFat(seedArm64Dylib(), seedI386Exec())))
	if err != nil {
		t.Fatalf("fat seed failed to parse: %v", err)
	}
	defer ff.Close()
	if len(ff.Arches) != 2 {
		t.Fatalf("fat seed parsed to %d arches, want 2", len(ff.Arches))
	}
}

func FuzzNewFile(f *testing.F) {
	// real-world binaries (obscured to stay malware-scanner friendly)
	matches, err := filepath.Glob("internal/testdata/*.base64")
	if err != nil {
		f.Fatal(err)
	}
	for _, p := range matches {
		if data, err := obscuretestdata.ReadFile(p); err == nil {
			f.Add(data)
		}
	}

	// synthetic seeds covering structures the real testdata lacks
	f.Add(seedArm64Dylib())
	f.Add(seedI386Exec())
	f.Add([]byte(nil))
	f.Add([]byte{0xcf, 0xfa, 0xed, 0xfe}) // bare magic

	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := NewFile(bytes.NewReader(data))
		if err != nil {
			return
		}
		defer m.Close()
		exercise(t, m, 0)
	})
}

func FuzzNewFatFile(f *testing.F) {
	matches, err := filepath.Glob("internal/testdata/*fat*.base64")
	if err != nil {
		f.Fatal(err)
	}
	for _, p := range matches {
		if data, err := obscuretestdata.ReadFile(p); err == nil {
			f.Add(data)
		}
	}
	f.Add(seedFat(seedArm64Dylib(), seedI386Exec()))
	f.Add(seedFat(seedArm64Dylib()))

	f.Fuzz(func(t *testing.T, data []byte) {
		ff, err := NewFatFile(bytes.NewReader(data))
		if err != nil {
			return
		}
		defer ff.Close()
		for _, arch := range ff.Arches {
			if arch.File != nil {
				exercise(t, arch.File, 0)
			}
		}
	})
}
