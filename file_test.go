// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package macho

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"

	"github.com/appsworld/go-macho/internal/obscuretestdata"
	"github.com/appsworld/go-macho/types"
)

type fileTest struct {
	file        string
	hdr         types.FileHeader
	loads       []interface{}
	sections    []*SectionHeader
	relocations map[string][]Reloc
}

var fileTests = []fileTest{
	{
		"internal/testdata/gcc-386-darwin-exec.base64",
		types.FileHeader{Magic: 0xfeedface, CPU: types.CPU386, SubCPU: 0x3, Type: 0x2, NCommands: 0xc, SizeCommands: 0x3c0, Flags: 0x85, Reserved: 0x1},
		[]interface{}{
			&SegmentHeader{types.LC_SEGMENT, 0x38, "__PAGEZERO", 0x0, 0x1000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			&SegmentHeader{types.LC_SEGMENT, 0xc0, "__TEXT", 0x1000, 0x1000, 0x0, 0x1000, 0x7, 0x5, 0x2, 0x0, 0},
			&SegmentHeader{types.LC_SEGMENT, 0xc0, "__DATA", 0x2000, 0x1000, 0x1000, 0x1000, 0x7, 0x3, 0x2, 0x0, 0x2},
			&SegmentHeader{types.LC_SEGMENT, 0x7c, "__IMPORT", 0x3000, 0x1000, 0x2000, 0x1000, 0x7, 0x7, 0x1, 0x0, 0x4},
			&SegmentHeader{types.LC_SEGMENT, 0x38, "__LINKEDIT", 0x4000, 0x1000, 0x3000, 0x12c, 0x7, 0x1, 0x0, 0x0, 0x5},
			nil, // LC_SYMTAB
			nil, // LC_DYSYMTAB
			nil, // LC_LOAD_DYLINKER
			nil, // LC_UUID
			nil, // LC_UNIXTHREAD
			&Dylib{LoadBytes: LoadBytes(nil), DylibCmd: types.DylibCmd{LoadCmd: 0xc, Len: 0x34, Name: 0x0, Time: 0x0, CurrentVersion: 0x0, CompatVersion: 0x0}, Name: "/usr/lib/libgcc_s.1.dylib", Time: 0x2, CurrentVersion: "1.0.0", CompatVersion: "1.0.0"},
			&Dylib{LoadBytes: LoadBytes(nil), DylibCmd: types.DylibCmd{LoadCmd: 0xc, Len: 0x34, Name: 0x0, Time: 0x0, CurrentVersion: 0x0, CompatVersion: 0x0}, Name: "/usr/lib/libSystem.B.dylib", Time: 0x2, CurrentVersion: "111.1.4", CompatVersion: "1.0.0"},
		},
		[]*SectionHeader{
			{Name: "__text", Seg: "__TEXT", Addr: 0x1f68, Size: 0x88, Offset: 0xf68, Align: 0x2, Reloff: 0x0, Nreloc: 0x0, Flags: 0x80000400, Reserved1: 0x0, Reserved2: 0x0, Reserved3: 0x0, Type: 0x20},
			{Name: "__cstring", Seg: "__TEXT", Addr: 0x1ff0, Size: 0xd, Offset: 0xff0, Align: 0x0, Reloff: 0x0, Nreloc: 0x0, Flags: 0x2, Reserved1: 0x0, Reserved2: 0x0, Reserved3: 0x0, Type: 0x20},
			{Name: "__data", Seg: "__DATA", Addr: 0x2000, Size: 0x14, Offset: 0x1000, Align: 0x2, Reloff: 0x0, Nreloc: 0x0, Flags: 0x0, Reserved1: 0x0, Reserved2: 0x0, Reserved3: 0x0, Type: 0x20},
			{Name: "__dyld", Seg: "__DATA", Addr: 0x2014, Size: 0x1c, Offset: 0x1014, Align: 0x2, Reloff: 0x0, Nreloc: 0x0, Flags: 0x0, Reserved1: 0x0, Reserved2: 0x0, Reserved3: 0x0, Type: 0x20},
			{Name: "__jump_table", Seg: "__IMPORT", Addr: 0x3000, Size: 0xa, Offset: 0x2000, Align: 0x6, Reloff: 0x0, Nreloc: 0x0, Flags: 0x4000008, Reserved1: 0x0, Reserved2: 0x5, Reserved3: 0x0, Type: 0x20}},

		nil,
	},
	{
		"internal/testdata/gcc-amd64-darwin-exec.base64",
		types.FileHeader{Magic: 0xfeedfacf, CPU: types.CPUAmd64, SubCPU: 0x80000003, Type: 0x2, NCommands: 0xb, SizeCommands: 0x568, Flags: 0x85, Reserved: 0x0},
		[]interface{}{
			&SegmentHeader{types.LC_SEGMENT_64, 0x48, "__PAGEZERO", 0x0, 0x100000000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			&SegmentHeader{types.LC_SEGMENT_64, 0x1d8, "__TEXT", 0x100000000, 0x1000, 0x0, 0x1000, 0x7, 0x5, 0x5, 0x0, 0},
			&SegmentHeader{LoadCmd: 0x19, Len: 0x138, Name: "__DATA", Addr: 0x100001000, Memsz: 0x1000, Offset: 0x1000, Filesz: 0x1000, Maxprot: 7, Prot: 3, Nsect: 0x3, Flag: 0x0, Firstsect: 0x5},
			&SegmentHeader{LoadCmd: 0x19, Len: 0x48, Name: "__LINKEDIT", Addr: 0x100002000, Memsz: 0x1000, Offset: 0x2000, Filesz: 0x140, Maxprot: 7, Prot: 1, Nsect: 0x0, Flag: 0x0, Firstsect: 0x8},
			nil, // LC_SYMTAB
			nil, // LC_DYSYMTAB
			nil, // LC_LOAD_DYLINKER
			nil, // LC_UUID
			nil, // LC_UNIXTHREAD
			&Dylib{LoadBytes: LoadBytes(nil), DylibCmd: types.DylibCmd{LoadCmd: 0xc, Len: 0x38, Name: 0x0, Time: 0x0, CurrentVersion: 0x0, CompatVersion: 0x0}, Name: "/usr/lib/libgcc_s.1.dylib", Time: 0x2, CurrentVersion: "1.0.0", CompatVersion: "1.0.0"},
			&Dylib{LoadBytes: LoadBytes(nil), DylibCmd: types.DylibCmd{LoadCmd: 0xc, Len: 0x38, Name: 0x0, Time: 0x0, CurrentVersion: 0x0, CompatVersion: 0x0}, Name: "/usr/lib/libSystem.B.dylib", Time: 0x2, CurrentVersion: "111.1.4", CompatVersion: "1.0.0"},
		},
		[]*SectionHeader{
			{Name: "__text", Seg: "__TEXT", Addr: 0x100000f14, Size: 0x6d, Offset: 0xf14, Align: 0x2, Reloff: 0x0, Nreloc: 0x0, Flags: 0x80000400, Reserved1: 0x0, Reserved2: 0x0, Reserved3: 0x0, Type: 0x40},
			{Name: "__symbol_stub1", Seg: "__TEXT", Addr: 0x100000f81, Size: 0xc, Offset: 0xf81, Align: 0x0, Reloff: 0x0, Nreloc: 0x0, Flags: 0x80000408, Reserved1: 0x0, Reserved2: 0x6, Reserved3: 0x0, Type: 0x40},
			{"__stub_helper", "__TEXT", 0x100000f90, 0x18, 0xf90, 0x2, 0x0, 0x0, 0x0, 0, 0, 0, 0x40},
			{Name: "__cstring", Seg: "__TEXT", Addr: 0x100000fa8, Size: 0xd, Offset: 0xfa8, Align: 0x0, Reloff: 0x0, Nreloc: 0x0, Flags: 0x2, Reserved1: 0x0, Reserved2: 0x0, Reserved3: 0x0, Type: 0x40},
			{"__eh_frame", "__TEXT", 0x100000fb8, 0x48, 0xfb8, 0x3, 0x0, 0x0, 0x6000000b, 0, 0, 0, 0x40},
			{"__data", "__DATA", 0x100001000, 0x1c, 0x1000, 0x3, 0x0, 0x0, 0x0, 0, 0, 0, 0x40},
			{Name: "__dyld", Seg: "__DATA", Addr: 0x100001020, Size: 0x38, Offset: 0x1020, Align: 0x3, Reloff: 0x0, Nreloc: 0x0, Flags: 0x0, Reserved1: 0x0, Reserved2: 0x0, Reserved3: 0x0, Type: 0x40},
			{Name: "__la_symbol_ptr", Seg: "__DATA", Addr: 0x100001058, Size: 0x10, Offset: 0x1058, Align: 0x2, Reloff: 0x0, Nreloc: 0x0, Flags: 0x7, Reserved1: 0x2, Reserved2: 0x0, Reserved3: 0x0, Type: 0x40}},
		nil,
	},
	{
		"internal/testdata/gcc-amd64-darwin-exec-debug.base64",
		types.FileHeader{Magic: 0xfeedfacf, CPU: types.CPUAmd64, SubCPU: 0x80000003, Type: 0xa, NCommands: 0x4, SizeCommands: 0x5a0, Flags: 0, Reserved: 0x0},
		[]interface{}{
			nil, // LC_UUID
			&SegmentHeader{LoadCmd: 0x19, Len: 0x1d8, Name: "__TEXT", Addr: 0x100000000, Memsz: 0x1000, Offset: 0x0, Filesz: 0x0, Maxprot: 7, Prot: 5, Nsect: 0x5, Flag: 0x0, Firstsect: 0x0},
			&SegmentHeader{LoadCmd: 0x19, Len: 0x138, Name: "__DATA", Addr: 0x100001000, Memsz: 0x1000, Offset: 0x0, Filesz: 0x0, Maxprot: 7, Prot: 3, Nsect: 0x3, Flag: 0x0, Firstsect: 0x5},
			&SegmentHeader{LoadCmd: 0x19, Len: 0x278, Name: "__DWARF", Addr: 0x100002000, Memsz: 0x1000, Offset: 0x1000, Filesz: 0x1bc, Maxprot: 7, Prot: 3, Nsect: 0x7, Flag: 0x0, Firstsect: 0x8},
		},
		[]*SectionHeader{
			{"__text", "__TEXT", 0x100000f14, 0x0, 0x0, 0x2, 0x0, 0x0, 0x80000400, 0, 0, 0, 0x40},
			{Name: "__symbol_stub1", Seg: "__TEXT", Addr: 0x100000f81, Size: 0x0, Offset: 0x0, Align: 0x0, Reloff: 0x0, Nreloc: 0x0, Flags: 0x80000408, Reserved1: 0x0, Reserved2: 0x6, Reserved3: 0x0, Type: 0x40},
			{"__stub_helper", "__TEXT", 0x100000f90, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0, 0, 0, 0x40},
			{"__cstring", "__TEXT", 0x100000fa8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0, 0, 0, 0x40},
			{"__eh_frame", "__TEXT", 0x100000fb8, 0x0, 0x0, 0x3, 0x0, 0x0, 0x6000000b, 0, 0, 0, 0x40},
			{"__data", "__DATA", 0x100001000, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0, 0, 0, 0x40},
			{"__dyld", "__DATA", 0x100001020, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0, 0, 0, 0x40},
			{Name: "__la_symbol_ptr", Seg: "__DATA", Addr: 0x100001058, Size: 0x0, Offset: 0x0, Align: 0x2, Reloff: 0x0, Nreloc: 0x0, Flags: 0x7, Reserved1: 0x2, Reserved2: 0x0, Reserved3: 0x0, Type: 0x40},
			{"__debug_abbrev", "__DWARF", 0x100002000, 0x36, 0x1000, 0x0, 0x0, 0x0, 0x0, 0, 0, 0, 0x40},
			{"__debug_aranges", "__DWARF", 0x100002036, 0x30, 0x1036, 0x0, 0x0, 0x0, 0x0, 0, 0, 0, 0x40},
			{"__debug_frame", "__DWARF", 0x100002066, 0x40, 0x1066, 0x0, 0x0, 0x0, 0x0, 0, 0, 0, 0x40},
			{"__debug_info", "__DWARF", 0x1000020a6, 0x54, 0x10a6, 0x0, 0x0, 0x0, 0x0, 0, 0, 0, 0x40},
			{"__debug_line", "__DWARF", 0x1000020fa, 0x47, 0x10fa, 0x0, 0x0, 0x0, 0x0, 0, 0, 0, 0x40},
			{"__debug_pubnames", "__DWARF", 0x100002141, 0x1b, 0x1141, 0x0, 0x0, 0x0, 0x0, 0, 0, 0, 0x40},
			{"__debug_str", "__DWARF", 0x10000215c, 0x60, 0x115c, 0x0, 0x0, 0x0, 0x0, 0, 0, 0, 0x40},
		},
		nil,
	},
	{
		"internal/testdata/clang-386-darwin-exec-with-rpath.base64",
		types.FileHeader{Magic: 0xfeedface, CPU: types.CPU386, SubCPU: 0x3, Type: 0x2, NCommands: 0x10, SizeCommands: 0x42c, Flags: 0x1200085, Reserved: 0x1},
		[]interface{}{
			nil, // LC_SEGMENT
			nil, // LC_SEGMENT
			nil, // LC_SEGMENT
			nil, // LC_SEGMENT
			nil, // LC_DYLD_INFO_ONLY
			nil, // LC_SYMTAB
			nil, // LC_DYSYMTAB
			nil, // LC_LOAD_DYLINKER
			nil, // LC_UUID
			nil, // LC_VERSION_MIN_MACOSX
			nil, // LC_SOURCE_VERSION
			nil, // LC_MAIN
			nil, // LC_LOAD_DYLIB
			&Rpath{LoadBytes: LoadBytes(nil), RpathCmd: types.RpathCmd{LoadCmd: 0x8000001c, Len: 0x18, Path: 0x0}, Path: "/my/rpath"},
			nil, // LC_FUNCTION_STARTS
			nil, // LC_DATA_IN_CODE
		},
		nil,
		nil,
	},
	{
		"internal/testdata/clang-amd64-darwin-exec-with-rpath.base64",
		types.FileHeader{Magic: 0xfeedfacf, CPU: types.CPUAmd64, SubCPU: 0x80000003, Type: 0x2, NCommands: 0x10, SizeCommands: 0x4c8, Flags: 0x200085, Reserved: 0x0},
		[]interface{}{
			nil, // LC_SEGMENT
			nil, // LC_SEGMENT
			nil, // LC_SEGMENT
			nil, // LC_SEGMENT
			nil, // LC_DYLD_INFO_ONLY
			nil, // LC_SYMTAB
			nil, // LC_DYSYMTAB
			nil, // LC_LOAD_DYLINKER
			nil, // LC_UUID
			nil, // LC_VERSION_MIN_MACOSX
			nil, // LC_SOURCE_VERSION
			nil, // LC_MAIN
			nil, // LC_LOAD_DYLIB
			&Rpath{LoadBytes: LoadBytes(nil), RpathCmd: types.RpathCmd{LoadCmd: 0x8000001c, Len: 0x18, Path: 0x0}, Path: "/my/rpath"},
			nil, // LC_FUNCTION_STARTS
			nil, // LC_DATA_IN_CODE
		},
		nil,
		nil,
	},
	{
		"internal/testdata/clang-386-darwin.obj.base64",
		types.FileHeader{Magic: 0xfeedface, CPU: types.CPU386, SubCPU: 0x3, Type: 0x1, NCommands: 0x4, SizeCommands: 0x138, Flags: 0x2000, Reserved: 0x1},
		nil,
		nil,
		map[string][]Reloc{
			"__text": {
				{
					Addr:      0x1d,
					Type:      uint8(types.GENERIC_RELOC_VANILLA),
					Len:       2,
					Pcrel:     true,
					Extern:    true,
					Value:     1,
					Scattered: false,
				},
				{
					Addr:      0xe,
					Type:      uint8(types.GENERIC_RELOC_LOCAL_SECTDIFF),
					Len:       2,
					Pcrel:     false,
					Value:     0x2d,
					Scattered: true,
				},
				{
					Addr:      0x0,
					Type:      uint8(types.GENERIC_RELOC_PAIR),
					Len:       2,
					Pcrel:     false,
					Value:     0xb,
					Scattered: true,
				},
			},
		},
	},
	{
		"internal/testdata/clang-amd64-darwin.obj.base64",
		types.FileHeader{Magic: 0xfeedfacf, CPU: types.CPUAmd64, SubCPU: 0x3, Type: 0x1, NCommands: 0x4, SizeCommands: 0x200, Flags: 0x2000, Reserved: 0x0},
		nil,
		nil,
		map[string][]Reloc{
			"__text": {
				{
					Addr:   0x19,
					Type:   uint8(types.X86_64_RELOC_BRANCH),
					Len:    2,
					Pcrel:  true,
					Extern: true,
					Value:  1,
				},
				{
					Addr:   0xb,
					Type:   uint8(types.X86_64_RELOC_SIGNED),
					Len:    2,
					Pcrel:  true,
					Extern: false,
					Value:  2,
				},
			},
			"__compact_unwind": {
				{
					Addr:   0x0,
					Type:   uint8(types.X86_64_RELOC_UNSIGNED),
					Len:    3,
					Pcrel:  false,
					Extern: false,
					Value:  1,
				},
			},
		},
	},
}

func readerAtFromObscured(name string) (io.ReaderAt, error) {
	b, err := obscuretestdata.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(b), nil
}

func openObscured(name string) (*File, error) {
	ra, err := readerAtFromObscured(name)
	if err != nil {
		return nil, err
	}
	ff, err := NewFile(ra)
	if err != nil {
		return nil, err
	}
	return ff, nil
}

func openFatObscured(name string) (*FatFile, error) {
	ra, err := readerAtFromObscured(name)
	if err != nil {
		return nil, err
	}
	ff, err := NewFatFile(ra)
	if err != nil {
		return nil, err
	}
	return ff, nil
}

func TestOpen(t *testing.T) {
	for i := range fileTests {
		tt := &fileTests[i]

		// Use obscured files to prevent Apple’s notarization service from
		// mistaking them as candidates for notarization and rejecting the entire
		// toolchain.
		// See golang.org/issue/34986
		f, err := openObscured(tt.file)
		if err != nil {
			t.Error(err)
			continue
		}
		if !reflect.DeepEqual(f.FileHeader, tt.hdr) {
			t.Errorf("open %s:\n\thave %#v\n\twant %#v\n", tt.file, f.FileHeader, tt.hdr)
			continue
		}
		for i, l := range f.Loads {
			if len(l.Raw()) < 8 {
				t.Errorf("open %s, command %d:\n\tload command %T don't have enough data\n", tt.file, i, l)
			}
		}
		if tt.loads != nil {
			for i, l := range f.Loads {
				if i >= len(tt.loads) {
					break
				}

				want := tt.loads[i]
				if want == nil {
					continue
				}

				switch l := l.(type) {
				case *Segment:
					have := &l.SegmentHeader
					if !reflect.DeepEqual(have, want) {
						t.Errorf("open %s, command %d:\n\thave %#v\n\twant %#v\n", tt.file, i, have, want)
					}
				case *Dylib:
					have := l
					have.LoadBytes = nil
					if !reflect.DeepEqual(have, want) {
						t.Errorf("open %s, command %d:\n\thave %#v\n\twant %#v\n", tt.file, i, have, want)
					}
				case *Rpath:
					have := l
					have.LoadBytes = nil
					if !reflect.DeepEqual(have, want) {
						t.Errorf("open %s, command %d:\n\thave %#v\n\twant %#v\n", tt.file, i, have, want)
					}
				default:
					t.Errorf("open %s, command %d: unknown load command\n\thave %#v\n\twant %#v\n", tt.file, i, l, want)
				}
			}
			tn := len(tt.loads)
			fn := len(f.Loads)
			if tn != fn {
				t.Errorf("open %s: len(Loads) = %d, want %d", tt.file, fn, tn)
			}
		}

		if tt.sections != nil {
			for i, sh := range f.Sections {
				if i >= len(tt.sections) {
					break
				}
				have := &sh.SectionHeader
				want := tt.sections[i]
				if !reflect.DeepEqual(have, want) {
					t.Errorf("open %s, section %d:\n\thave %#v\n\twant %#v\n", tt.file, i, have, want)
				}
			}
			tn := len(tt.sections)
			fn := len(f.Sections)
			if tn != fn {
				t.Errorf("open %s: len(Sections) = %d, want %d", tt.file, fn, tn)
			}
		}

		if tt.relocations != nil {
			for i, sh := range f.Sections {
				have := sh.Relocs
				want := tt.relocations[sh.Name]
				if !reflect.DeepEqual(have, want) {
					t.Errorf("open %s, relocations in section %d (%s):\n\thave %#v\n\twant %#v\n", tt.file, i, sh.Name, have, want)
				}
			}
		}
	}
}

func TestOpenFailure(t *testing.T) {
	filename := "file.go"    // not a Mach-O file
	_, err := Open(filename) // don't crash
	if err == nil {
		t.Errorf("open %s: succeeded unexpectedly", filename)
	}
}

func TestOpenFat(t *testing.T) {
	ff, err := openFatObscured("internal/testdata/fat-gcc-386-amd64-darwin-exec.base64")
	if err != nil {
		t.Fatal(err)
	}

	if ff.Magic != types.MagicFat {
		t.Errorf("OpenFat: got magic number %#x, want %#x", ff.Magic, types.MagicFat)
	}
	if len(ff.Arches) != 2 {
		t.Errorf("OpenFat: got %d architectures, want 2", len(ff.Arches))
	}

	for i := range ff.Arches {
		arch := &ff.Arches[i]
		ftArch := &fileTests[i]

		if arch.CPU != ftArch.hdr.CPU || arch.SubCPU != ftArch.hdr.SubCPU {
			t.Errorf("OpenFat: architecture #%d got cpu=%#x subtype=%#x, expected cpu=%#x, subtype=%#x", i, arch.CPU, arch.SubCPU, ftArch.hdr.CPU, ftArch.hdr.SubCPU)
		}

		if !reflect.DeepEqual(arch.FileHeader, ftArch.hdr) {
			t.Errorf("OpenFat header:\n\tgot %#v\n\twant %#v\n", arch.FileHeader, ftArch.hdr)
		}
	}
}

func TestOpenFatFailure(t *testing.T) {
	filename := "file.go" // not a Mach-O file
	if _, err := OpenFat(filename); err == nil {
		t.Errorf("OpenFat %s: succeeded unexpectedly", filename)
	}

	filename = "internal/testdata/gcc-386-darwin-exec.base64" // not a fat Mach-O
	ff, err := openFatObscured(filename)
	if err != ErrNotFat {
		t.Errorf("OpenFat %s: got %v, want ErrNotFat", filename, err)
	}
	if ff != nil {
		t.Errorf("OpenFat %s: got %v, want nil", filename, ff)
	}
}

func TestRelocTypeString(t *testing.T) {
	if types.X86_64_RELOC_BRANCH.String() != "X86_64_RELOC_BRANCH" {
		t.Errorf("got %v, want %v", types.X86_64_RELOC_BRANCH.String(), "X86_64_RELOC_BRANCH")
	}
	if types.X86_64_RELOC_BRANCH.GoString() != "macho.X86_64_RELOC_BRANCH" {
		t.Errorf("got %v, want %v", types.X86_64_RELOC_BRANCH.GoString(), "macho.X86_64_RELOC_BRANCH")
	}
}

func TestTypeString(t *testing.T) {
	if types.MH_EXECUTE.String() != "EXECUTE" {
		t.Errorf("got %v, want %v", types.MH_EXECUTE.String(), "EXECUTE")
	}
}

func TestNewFatFile(t *testing.T) {

	f, err := os.Open("/usr/lib/libLeaksAtExit.dylib")
	if err != nil {
		t.Fatal(err)
	}

	fat, err := NewFatFile(f)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(fat.Arches[0].FileTOC.String())

	if fat.Arches[0].UUID().ID != "CCA67965-C1C5-3521-9CC6-BB47C6561696" {
		t.Errorf("macho.UUID() = %s; want test", fat.Arches[0].UUID())
	}
}
