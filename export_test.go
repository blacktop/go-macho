package macho

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/blacktop/go-macho/pkg/trie"
	"github.com/blacktop/go-macho/types"
)

func TestPointerAlignPad(t *testing.T) {
	tests := []struct {
		name       string
		currentLen int
		ptrSize    uint64
		want       int
	}{
		{"already aligned 8", 16, 8, 0},
		{"already aligned 4", 12, 4, 0},
		{"off by 1", 1, 8, 7},
		{"off by 4", 4, 8, 4},
		{"off by 7", 7, 8, 1},
		{"zero len", 0, 8, 0},
		{"4-byte align off by 1", 5, 4, 3},
		{"4-byte align off by 3", 7, 4, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pointerAlignPad(tt.currentLen, tt.ptrSize)
			if got != tt.want {
				t.Errorf("pointerAlignPad(%d, %d) = %d, want %d", tt.currentLen, tt.ptrSize, got, tt.want)
			}
			// result should always be aligned
			aligned := (uint64(tt.currentLen) + uint64(got)) % tt.ptrSize
			if aligned != 0 {
				t.Errorf("pointerAlignPad(%d, %d): result %d not aligned (remainder %d)", tt.currentLen, tt.ptrSize, tt.currentLen+got, aligned)
			}
		})
	}
}

func TestPageAlign(t *testing.T) {
	tests := []struct {
		name  string
		off   uint64
		align uint64
		want  uint64
	}{
		{"already aligned", 0x4000, 0x1000, 0x4000},
		{"needs alignment", 0x4001, 0x1000, 0x5000},
		{"zero", 0, 0x1000, 0},
		{"one byte over", 0x1001, 0x1000, 0x2000},
		{"one byte under", 0x0FFF, 0x1000, 0x1000},
		{"16KB align", 0x4001, 0x4000, 0x8000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pageAlign(tt.off, tt.align)
			if got != tt.want {
				t.Errorf("pageAlign(%#x, %#x) = %#x, want %#x", tt.off, tt.align, got, tt.want)
			}
		})
	}
}

func newTextSegmentFile(seg SegmentHeader, sections ...*types.Section) *File {
	seg.LoadCmd = types.LC_SEGMENT_64
	seg.Name = "__TEXT"
	text := &Segment{
		SegmentHeader: seg,
	}
	return &File{
		FileTOC: FileTOC{
			Loads:    loads{text},
			Sections: sections,
		},
	}
}

func newTextSection(addr uint64, offset uint32) *types.Section {
	return &types.Section{
		SectionHeader: types.SectionHeader{
			Name:   "__text",
			Seg:    "__TEXT",
			Addr:   addr,
			Offset: offset,
		},
	}
}

func requireErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("expected error containing %q, got %v", want, err)
	}
}

func TestTextSegmentFirstSectionRelOffUsesVMAddrForCachedImages(t *testing.T) {
	f := newTextSegmentFile(
		SegmentHeader{
			Addr:   0x180000000,
			Offset: 0x3f000000,
			Nsect:  1,
		},
		newTextSection(0x180004000, 0x4000),
	)

	got, err := f.textSegmentFirstSectionRelOff(true)
	if err != nil {
		t.Fatal(err)
	}
	if got != 0x4000 {
		t.Errorf("textSegmentFirstSectionRelOff(true) = %#x, want 0x4000", got)
	}
}

func TestTextSegmentFirstSectionRelOffRejectsInvalidCachedAddress(t *testing.T) {
	f := newTextSegmentFile(
		SegmentHeader{
			Addr:   0x180004000,
			Offset: 0x3f000000,
			Nsect:  1,
		},
		newTextSection(0x180000000, 0x4000),
	)

	_, err := f.textSegmentFirstSectionRelOff(true)
	requireErrorContains(t, err, "precedes segment address")
}

func TestTextSegmentFirstSectionRelOffRejectsInvalidFileOffset(t *testing.T) {
	f := newTextSegmentFile(
		SegmentHeader{
			Addr:   0x100000000,
			Offset: 0x8000,
			Nsect:  1,
		},
		newTextSection(0x100001000, 0x1000),
	)

	_, err := f.textSegmentFirstSectionRelOff(false)
	requireErrorContains(t, err, "precedes segment offset")
}

func TestTextSegmentFirstSectionRelOffRejectsInvalidSectionIndex(t *testing.T) {
	f := newTextSegmentFile(SegmentHeader{
		Addr:      0x100000000,
		Nsect:     1,
		Firstsect: 1,
	})

	_, err := f.textSegmentFirstSectionRelOff(false)
	requireErrorContains(t, err, "out of range")
}

func TestTextSegmentFirstSectionRelOffRejectsHugeSectionIndex(t *testing.T) {
	f := newTextSegmentFile(SegmentHeader{
		Addr:      0x100000000,
		Nsect:     1,
		Firstsect: ^uint32(0),
	})

	_, err := f.textSegmentFirstSectionRelOff(false)
	requireErrorContains(t, err, "out of range")
}

func TestTextSegmentFirstSectionRelOffNoTextSegment(t *testing.T) {
	f := &File{}

	got, err := f.textSegmentFirstSectionRelOff(false)
	if err != nil {
		t.Fatal(err)
	}
	if got != 0 {
		t.Errorf("textSegmentFirstSectionRelOff without __TEXT = %#x, want 0", got)
	}
}

func TestTextSegmentWriteStartRejectsOutOfRangeStart(t *testing.T) {
	_, err := textSegmentWriteStart(0x400000000, 0x2000, 0x10000)
	requireErrorContains(t, err, "exceeds segment data length")
}

func TestTextSegmentWriteStartUsesEndOfLoadsWhenLarger(t *testing.T) {
	got, err := textSegmentWriteStart(0x1000, 0x2000, 0x4000)
	if err != nil {
		t.Fatal(err)
	}
	if got != 0x2000 {
		t.Errorf("textSegmentWriteStart = %#x, want 0x2000", got)
	}
}

func TestSegMapRemap(t *testing.T) {
	m := exportSegMap{
		{
			Name:       "__TEXT",
			Old:        segInfo{Start: 0x10000, End: 0x14000},
			New:        segInfo{Start: 0, End: 0x4000},
			OrigMemsz:  0x4000,
			OrigFilesz: 0x4000,
		},
		{
			Name:       "__DATA",
			Old:        segInfo{Start: 0x20000, End: 0x22000},
			New:        segInfo{Start: 0x4000, End: 0x6000},
			OrigMemsz:  0x3000, // bss makes memsz > filesz
			OrigFilesz: 0x2000,
		},
		{
			Name:       "__LINKEDIT",
			Old:        segInfo{Start: 0x30000, End: 0x34000},
			New:        segInfo{Start: 0x6000, End: 0xA000},
			OrigMemsz:  0x4000,
			OrigFilesz: 0x4000,
		},
	}

	// test Remap
	t.Run("remap __TEXT start", func(t *testing.T) {
		got, err := m.Remap(0x10000)
		if err != nil {
			t.Fatal(err)
		}
		if got != 0 {
			t.Errorf("Remap(0x10000) = %#x, want 0x0", got)
		}
	})
	t.Run("remap __TEXT middle", func(t *testing.T) {
		got, err := m.Remap(0x12000)
		if err != nil {
			t.Fatal(err)
		}
		if got != 0x2000 {
			t.Errorf("Remap(0x12000) = %#x, want 0x2000", got)
		}
	})
	t.Run("remap __DATA start", func(t *testing.T) {
		got, err := m.Remap(0x20000)
		if err != nil {
			t.Fatal(err)
		}
		if got != 0x4000 {
			t.Errorf("Remap(0x20000) = %#x, want 0x4000", got)
		}
	})
	t.Run("remap out of range", func(t *testing.T) {
		_, err := m.Remap(0x50000)
		if err == nil {
			t.Error("Remap(0x50000) should fail for out-of-range offset")
		}
	})

	// test RemapSeg
	t.Run("remap segment __DATA", func(t *testing.T) {
		off, sz, err := m.RemapSeg("__DATA", 0x20000)
		if err != nil {
			t.Fatal(err)
		}
		if off != 0x4000 {
			t.Errorf("RemapSeg offset = %#x, want 0x4000", off)
		}
		if sz != 0x2000 {
			t.Errorf("RemapSeg size = %#x, want 0x2000", sz)
		}
	})

	// test Lookup
	t.Run("lookup __DATA preserves OrigMemsz", func(t *testing.T) {
		smi, ok := m.Lookup("__DATA")
		if !ok {
			t.Fatal("Lookup(__DATA) not found")
		}
		if smi.OrigMemsz != 0x3000 {
			t.Errorf("OrigMemsz = %#x, want 0x3000", smi.OrigMemsz)
		}
		if smi.OrigFilesz != 0x2000 {
			t.Errorf("OrigFilesz = %#x, want 0x2000", smi.OrigFilesz)
		}
	})
	t.Run("lookup nonexistent", func(t *testing.T) {
		_, ok := m.Lookup("__BOGUS")
		if ok {
			t.Error("Lookup(__BOGUS) should return false")
		}
	})
}

func newFunctionVariantLoads(fvOff, ffOff uint32) (*FunctionVariants, *FunctionVariantFixups) {
	fv := &FunctionVariants{
		LinkEditData: LinkEditData{
			LinkEditDataCmd: types.LinkEditDataCmd{LoadCmd: types.LC_FUNCTION_VARIANTS, Offset: fvOff, Size: 0x20},
		},
	}
	ff := &FunctionVariantFixups{
		LinkEditData: LinkEditData{
			LinkEditDataCmd: types.LinkEditDataCmd{LoadCmd: types.LC_FUNCTION_VARIANT_FIXUPS, Offset: ffOff, Size: 0x8},
		},
	}
	return fv, ff
}

func functionVariantSegMap() exportSegMap {
	return exportSegMap{
		{
			Name:       "__LINKEDIT",
			Old:        segInfo{Start: 0x30000, End: 0x40000},
			New:        segInfo{Start: 0x5000, End: 0x15000},
			OrigMemsz:  0x10000,
			OrigFilesz: 0x10000,
		},
	}
}

// On the non-cache path the function-variants linkedit offsets shift with the
// segment, so optimizeLoadCommands must remap them through segMap.
func TestOptimizeLoadCommandsRemapsFunctionVariants(t *testing.T) {
	fv, ff := newFunctionVariantLoads(0x31000, 0x31100)
	f := &File{FileTOC: FileTOC{Loads: loads{fv, ff}}}

	if err := f.optimizeLoadCommands(functionVariantSegMap(), false); err != nil {
		t.Fatal(err)
	}
	// new = New.Start + (off - Old.Start)
	if fv.Offset != 0x6000 {
		t.Errorf("FunctionVariants.Offset = %#x, want 0x6000", fv.Offset)
	}
	if ff.Offset != 0x6100 {
		t.Errorf("FunctionVariantFixups.Offset = %#x, want 0x6100", ff.Offset)
	}
}

// On the in-cache path optimizeLinkedit rewrites the offsets after copying the
// blobs into the rebuilt __LINKEDIT, so optimizeLoadCommands must leave them be.
func TestOptimizeLoadCommandsLeavesFunctionVariantsInCache(t *testing.T) {
	fv, ff := newFunctionVariantLoads(0x31000, 0x31100)
	f := &File{FileTOC: FileTOC{Loads: loads{fv, ff}}}

	if err := f.optimizeLoadCommands(functionVariantSegMap(), true); err != nil {
		t.Fatal(err)
	}
	if fv.Offset != 0x31000 {
		t.Errorf("FunctionVariants.Offset = %#x, want it unchanged (0x31000)", fv.Offset)
	}
	if ff.Offset != 0x31100 {
		t.Errorf("FunctionVariantFixups.Offset = %#x, want it unchanged (0x31100)", ff.Offset)
	}
}

func TestExportIndirectSymbolPool(t *testing.T) {
	for _, magic := range []types.Magic{types.Magic32, types.Magic64} {
		for _, source := range []string{"symtab", "trie"} {
			for _, target := range []string{"_target", ""} {
				t.Run(fmt.Sprintf("%v/%s/target=%q", magic, source, target), func(t *testing.T) {
					indirect := Symbol{Name: "_alias", IndirectName: target, Type: types.N_INDR | types.N_EXT, Value: 0x33b91352}
					section := Symbol{Name: "_section", Type: types.N_SECT, Sect: 1, Desc: 0x20, Value: 0x12345678}
					linkedit := &Segment{SegmentHeader: SegmentHeader{Name: "__LINKEDIT", Offset: 0x1000}}
					f := &File{
						FileTOC:  FileTOC{FileHeader: types.FileHeader{Magic: magic}, ByteOrder: binary.LittleEndian, Loads: loads{linkedit}},
						Symtab:   &Symtab{Syms: []Symbol{indirect, section}},
						Dysymtab: &Dysymtab{},
					}
					if source == "trie" {
						f.Symtab.Syms = []Symbol{section}
						f.Loads = append(f.Loads, &DyldExportsTrie{})
						f.exp = []trie.TrieExport{{Name: indirect.Name, ReExport: target, Address: indirect.Value, Flags: types.EXPORT_SYMBOL_FLAGS_REEXPORT}}
						f.cr = types.NewCustomSectionReader(bytes.NewReader([]byte{0}), nil, 0, 1)
					}
					data, err := f.optimizeLinkedit(nil)
					if err != nil {
						t.Fatal(err)
					}
					if f.Symtab.Nsyms != 2 {
						t.Fatalf("Nsyms = %d, want 2", f.Symtab.Nsyms)
					}
					poolStart := uint64(f.Symtab.Stroff) - linkedit.Offset
					pool := data.Bytes()[poolStart : poolStart+uint64(f.Symtab.Strsize)]
					wantTarget := target
					if source == "trie" && wantTarget == "" {
						wantTarget = indirect.Name
					}
					wantPool := "\x00_section\x00_alias\x00" + wantTarget + "\x00"
					wantPool += strings.Repeat("\x00", pointerAlignPad(len(wantPool), f.pointerSize()))
					if string(pool) != wantPool {
						t.Fatalf("pool = %q, want %q", pool, wantPool)
					}
					entries := bytes.NewReader(data.Bytes()[uint64(f.Symtab.Symoff)-linkedit.Offset : poolStart])
					for i, sym := range []Symbol{section, indirect} {
						var got types.Nlist64
						if f.is64bit() {
							err = binary.Read(entries, binary.LittleEndian, &got)
						} else {
							var entry types.Nlist32
							err = binary.Read(entries, binary.LittleEndian, &entry)
							got = types.Nlist64{Nlist: entry.Nlist, Value: uint64(entry.Value)}
						}
						if err != nil {
							t.Fatal(err)
						}
						wantName := uint32(1)
						if i == 1 {
							wantName += uint32(len(section.Name) + 1)
						}
						wantHeader := types.Nlist{Name: wantName, Type: sym.Type, Sect: sym.Sect, Desc: sym.Desc}
						if got.Nlist != wantHeader {
							t.Fatalf("entry %d header = %+v, want %+v", i, got.Nlist, wantHeader)
						}
						if !sym.Type.IsIndirectSym() {
							if got.Value != sym.Value {
								t.Fatalf("section value = %#x, want %#x", got.Value, sym.Value)
							}
							continue
						}
						if got.Value >= uint64(len(pool)) {
							t.Fatalf("indirect value %#x exceeds pool length %d", got.Value, len(pool))
						}
						name, _, terminated := bytes.Cut(pool[got.Value:], []byte{0})
						if !terminated || string(name) != wantTarget {
							t.Fatalf("indirect target = %q (terminated=%v), want %q", name, terminated, wantTarget)
						}
						if wantTarget != "" && got.Value != uint64(wantName)+uint64(len(sym.Name))+1 {
							t.Fatalf("indirect value = %d, want target immediately after symbol name", got.Value)
						}
						if wantTarget == "" && got.Value != 0 {
							t.Fatalf("unknown target value = %d, want 0", got.Value)
						}
					}
					if f.Dysymtab.Nlocalsym != 1 || f.Dysymtab.Iextdefsym != 1 || f.Dysymtab.Nextdefsym != 1 || f.Dysymtab.Nundefsym != 0 {
						t.Fatalf("unexpected symbol ordering: %+v", f.Dysymtab)
					}
					if source == "symtab" && f.Symtab.Syms[0] != indirect {
						t.Fatal("source indirect symbol was mutated")
					}
				})
			}
		}
		for _, tc := range []struct {
			name       string
			flags      types.ExportFlag
			fromSymtab bool
			wantType   types.NType
		}{
			{name: "absolute", flags: types.EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE, wantType: types.N_ABS | types.N_EXT},
			{name: "thread-local", flags: types.EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL},
			{name: "thread-local-with-symtab", flags: types.EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL, fromSymtab: true, wantType: types.N_SECT | types.N_EXT},
		} {
			t.Run(fmt.Sprintf("%v/trie/%s", magic, tc.name), func(t *testing.T) {
				linkedit := &Segment{SegmentHeader: SegmentHeader{Name: "__LINKEDIT", Offset: 0x1000}}
				f := &File{
					FileTOC: FileTOC{FileHeader: types.FileHeader{Magic: magic}, ByteOrder: binary.LittleEndian, Loads: loads{linkedit, &DyldExportsTrie{}}},
					Symtab:  &Symtab{}, Dysymtab: &Dysymtab{},
					exp: []trie.TrieExport{{Name: "_export", Address: 0x12345678, Flags: tc.flags}},
					cr:  types.NewCustomSectionReader(bytes.NewReader([]byte{0}), nil, 0, 1),
				}
				want := Symbol{Name: "_export", Type: tc.wantType, Value: 0x12345678}
				if tc.fromSymtab {
					want.Sect, want.Desc, want.Value = 3, 0x20, 0x87654321
					f.Symtab.Syms = []Symbol{want}
				}
				data, err := f.optimizeLinkedit(nil)
				if err != nil {
					t.Fatal(err)
				}
				var wantCount uint32
				wantPool := "\x00"
				if tc.wantType != 0 {
					wantCount = 1
					wantPool += want.Name + "\x00"
				}
				if f.Symtab.Nsyms != wantCount || f.Dysymtab.Nextdefsym != wantCount || f.Dysymtab.Nlocalsym != 0 || f.Dysymtab.Nundefsym != 0 {
					t.Fatalf("unexpected symbol counts: symtab=%+v dysymtab=%+v", f.Symtab, f.Dysymtab)
				}
				poolStart := uint64(f.Symtab.Stroff) - linkedit.Offset
				pool := data.Bytes()[poolStart : poolStart+uint64(f.Symtab.Strsize)]
				wantPool += strings.Repeat("\x00", pointerAlignPad(len(wantPool), f.pointerSize()))
				if string(pool) != wantPool {
					t.Fatalf("pool = %q, want %q", pool, wantPool)
				}
				if wantCount == 0 {
					return
				}
				entries := bytes.NewReader(data.Bytes()[uint64(f.Symtab.Symoff)-linkedit.Offset : poolStart])
				var got types.Nlist64
				if f.is64bit() {
					err = binary.Read(entries, binary.LittleEndian, &got)
				} else {
					var entry types.Nlist32
					err = binary.Read(entries, binary.LittleEndian, &entry)
					got = types.Nlist64{Nlist: entry.Nlist, Value: uint64(entry.Value)}
				}
				if err != nil {
					t.Fatal(err)
				}
				wantEntry := types.Nlist64{Nlist: types.Nlist{Name: 1, Type: want.Type, Sect: want.Sect, Desc: want.Desc}, Value: want.Value}
				if got != wantEntry {
					t.Fatalf("entry = %+v, want %+v", got, wantEntry)
				}
				if tc.fromSymtab && f.Symtab.Syms[0] != want {
					t.Fatal("source thread-local symbol was mutated")
				}
			})
		}
	}
}
