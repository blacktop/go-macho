// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package macho

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/blacktop/go-dwarf"
	"github.com/blacktop/go-macho/internal/obscuretestdata"
	cstypes "github.com/blacktop/go-macho/pkg/codesign/types"
	"github.com/blacktop/go-macho/types"
)

type fileTest struct {
	file        string
	hdr         types.FileHeader
	loads       []any
	sections    []*types.SectionHeader
	relocations map[string][]types.Reloc
}

var fileTests = []fileTest{
	{
		"internal/testdata/gcc-386-darwin-exec.base64",
		types.FileHeader{Magic: 0xfeedface, CPU: types.CPUI386, SubCPU: 0x3, Type: 0x2, NCommands: 0xc, SizeCommands: 0x3c0, Flags: 0x85, Reserved: 0x1},
		[]any{
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
			&LoadDylib{Dylib{LoadBytes: LoadBytes(nil), DylibCmd: types.DylibCmd{LoadCmd: 0xc, Len: 0x34, NameOffset: 0x18, Timestamp: 0x2, CurrentVersion: types.Version(0x10000), CompatVersion: types.Version(0x10000)}, Name: "/usr/lib/libgcc_s.1.dylib"}},
			&LoadDylib{Dylib{LoadBytes: LoadBytes(nil), DylibCmd: types.DylibCmd{LoadCmd: 0xc, Len: 0x34, NameOffset: 0x18, Timestamp: 0x2, CurrentVersion: types.Version(0x6f0104), CompatVersion: types.Version(0x10000)}, Name: "/usr/lib/libSystem.B.dylib"}},
		},
		[]*types.SectionHeader{
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
		[]any{
			&SegmentHeader{types.LC_SEGMENT_64, 0x48, "__PAGEZERO", 0x0, 0x100000000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			&SegmentHeader{types.LC_SEGMENT_64, 0x1d8, "__TEXT", 0x100000000, 0x1000, 0x0, 0x1000, 0x7, 0x5, 0x5, 0x0, 0},
			&SegmentHeader{LoadCmd: 0x19, Len: 0x138, Name: "__DATA", Addr: 0x100001000, Memsz: 0x1000, Offset: 0x1000, Filesz: 0x1000, Maxprot: 7, Prot: 3, Nsect: 0x3, Flag: 0x0, Firstsect: 0x5},
			&SegmentHeader{LoadCmd: 0x19, Len: 0x48, Name: "__LINKEDIT", Addr: 0x100002000, Memsz: 0x1000, Offset: 0x2000, Filesz: 0x140, Maxprot: 7, Prot: 1, Nsect: 0x0, Flag: 0x0, Firstsect: 0x8},
			nil, // LC_SYMTAB
			nil, // LC_DYSYMTAB
			nil, // LC_LOAD_DYLINKER
			nil, // LC_UUID
			nil, // LC_UNIXTHREAD
			&LoadDylib{Dylib{LoadBytes: LoadBytes(nil), DylibCmd: types.DylibCmd{LoadCmd: 0xc, Len: 0x38, NameOffset: 0x18, Timestamp: 0x2, CurrentVersion: types.Version(0x10000), CompatVersion: types.Version(0x10000)}, Name: "/usr/lib/libgcc_s.1.dylib"}},
			&LoadDylib{Dylib{LoadBytes: LoadBytes(nil), DylibCmd: types.DylibCmd{LoadCmd: 0xc, Len: 0x38, NameOffset: 0x18, Timestamp: 0x2, CurrentVersion: types.Version(0x6f0104), CompatVersion: types.Version(0x10000)}, Name: "/usr/lib/libSystem.B.dylib"}},
		},
		[]*types.SectionHeader{
			{Name: "__text", Seg: "__TEXT", Addr: 0x100000f14, Size: 0x6d, Offset: 0xf14, Align: 0x2, Reloff: 0x0, Nreloc: 0x0, Flags: 0x80000400, Reserved1: 0x0, Reserved2: 0x0, Reserved3: 0x0, Type: 0x40},
			{Name: "__symbol_stub1", Seg: "__TEXT", Addr: 0x100000f81, Size: 0xc, Offset: 0xf81, Align: 0x0, Reloff: 0x0, Nreloc: 0x0, Flags: 0x80000408, Reserved1: 0x0, Reserved2: 0x6, Reserved3: 0x0, Type: 0x40},
			{Name: "__stub_helper", Seg: "__TEXT", Addr: 0x100000f90, Size: 0x18, Offset: 0xf90, Align: 0x2, Reloff: 0x0, Nreloc: 0x0, Flags: 0x0, Reserved1: 0, Reserved2: 0, Reserved3: 0, Type: 0x40},
			{Name: "__cstring", Seg: "__TEXT", Addr: 0x100000fa8, Size: 0xd, Offset: 0xfa8, Align: 0x0, Reloff: 0x0, Nreloc: 0x0, Flags: 0x2, Reserved1: 0x0, Reserved2: 0x0, Reserved3: 0x0, Type: 0x40},
			{Name: "__eh_frame", Seg: "__TEXT", Addr: 0x100000fb8, Size: 0x48, Offset: 0xfb8, Align: 0x3, Reloff: 0x0, Nreloc: 0x0, Flags: 0x6000000b, Reserved1: 0, Reserved2: 0, Reserved3: 0, Type: 0x40},
			{Name: "__data", Seg: "__DATA", Addr: 0x100001000, Size: 0x1c, Offset: 0x1000, Align: 0x3, Reloff: 0x0, Nreloc: 0x0, Flags: 0x0, Reserved1: 0, Reserved2: 0, Reserved3: 0, Type: 0x40},
			{Name: "__dyld", Seg: "__DATA", Addr: 0x100001020, Size: 0x38, Offset: 0x1020, Align: 0x3, Reloff: 0x0, Nreloc: 0x0, Flags: 0x0, Reserved1: 0x0, Reserved2: 0x0, Reserved3: 0x0, Type: 0x40},
			{Name: "__la_symbol_ptr", Seg: "__DATA", Addr: 0x100001058, Size: 0x10, Offset: 0x1058, Align: 0x2, Reloff: 0x0, Nreloc: 0x0, Flags: 0x7, Reserved1: 0x2, Reserved2: 0x0, Reserved3: 0x0, Type: 0x40}},
		nil,
	},
	{
		"internal/testdata/gcc-amd64-darwin-exec-debug.base64",
		types.FileHeader{Magic: 0xfeedfacf, CPU: types.CPUAmd64, SubCPU: 0x80000003, Type: 0xa, NCommands: 0x4, SizeCommands: 0x5a0, Flags: 0, Reserved: 0x0},
		[]any{
			nil, // LC_UUID
			&SegmentHeader{LoadCmd: 0x19, Len: 0x1d8, Name: "__TEXT", Addr: 0x100000000, Memsz: 0x1000, Offset: 0x0, Filesz: 0x0, Maxprot: 7, Prot: 5, Nsect: 0x5, Flag: 0x0, Firstsect: 0x0},
			&SegmentHeader{LoadCmd: 0x19, Len: 0x138, Name: "__DATA", Addr: 0x100001000, Memsz: 0x1000, Offset: 0x0, Filesz: 0x0, Maxprot: 7, Prot: 3, Nsect: 0x3, Flag: 0x0, Firstsect: 0x5},
			&SegmentHeader{LoadCmd: 0x19, Len: 0x278, Name: "__DWARF", Addr: 0x100002000, Memsz: 0x1000, Offset: 0x1000, Filesz: 0x1bc, Maxprot: 7, Prot: 3, Nsect: 0x7, Flag: 0x0, Firstsect: 0x8},
		},
		[]*types.SectionHeader{
			{Name: "__text", Seg: "__TEXT", Addr: 0x100000f14, Size: 0x0, Offset: 0x0, Align: 0x2, Reloff: 0x0, Nreloc: 0x0, Flags: 0x80000400, Reserved1: 0, Reserved2: 0, Reserved3: 0, Type: 0x40},
			{Name: "__symbol_stub1", Seg: "__TEXT", Addr: 0x100000f81, Size: 0x0, Offset: 0x0, Align: 0x0, Reloff: 0x0, Nreloc: 0x0, Flags: 0x80000408, Reserved1: 0x0, Reserved2: 0x6, Reserved3: 0x0, Type: 0x40},
			{Name: "__stub_helper", Seg: "__TEXT", Addr: 0x100000f90, Size: 0x0, Offset: 0x0, Align: 0x2, Reloff: 0x0, Nreloc: 0x0, Flags: 0x0, Reserved1: 0, Reserved2: 0, Reserved3: 0, Type: 0x40},
			{Name: "__cstring", Seg: "__TEXT", Addr: 0x100000fa8, Size: 0x0, Offset: 0x0, Align: 0x0, Reloff: 0x0, Nreloc: 0x0, Flags: 0x2, Reserved1: 0, Reserved2: 0, Reserved3: 0, Type: 0x40},
			{Name: "__eh_frame", Seg: "__TEXT", Addr: 0x100000fb8, Size: 0x0, Offset: 0x0, Align: 0x3, Reloff: 0x0, Nreloc: 0x0, Flags: 0x6000000b, Reserved1: 0, Reserved2: 0, Reserved3: 0, Type: 0x40},
			{Name: "__data", Seg: "__DATA", Addr: 0x100001000, Size: 0x0, Offset: 0x0, Align: 0x3, Reloff: 0x0, Nreloc: 0x0, Flags: 0x0, Reserved1: 0, Reserved2: 0, Reserved3: 0, Type: 0x40},
			{Name: "__dyld", Seg: "__DATA", Addr: 0x100001020, Size: 0x0, Offset: 0x0, Align: 0x3, Reloff: 0x0, Nreloc: 0x0, Flags: 0x0, Reserved1: 0, Reserved2: 0, Reserved3: 0, Type: 0x40},
			{Name: "__la_symbol_ptr", Seg: "__DATA", Addr: 0x100001058, Size: 0x0, Offset: 0x0, Align: 0x2, Reloff: 0x0, Nreloc: 0x0, Flags: 0x7, Reserved1: 0x2, Reserved2: 0x0, Reserved3: 0x0, Type: 0x40},
			{Name: "__debug_abbrev", Seg: "__DWARF", Addr: 0x100002000, Size: 0x36, Offset: 0x1000, Align: 0x0, Reloff: 0x0, Nreloc: 0x0, Flags: 0x0, Reserved1: 0, Reserved2: 0, Reserved3: 0, Type: 0x40},
			{Name: "__debug_aranges", Seg: "__DWARF", Addr: 0x100002036, Size: 0x30, Offset: 0x1036, Align: 0x0, Reloff: 0x0, Nreloc: 0x0, Flags: 0x0, Reserved1: 0, Reserved2: 0, Reserved3: 0, Type: 0x40},
			{Name: "__debug_frame", Seg: "__DWARF", Addr: 0x100002066, Size: 0x40, Offset: 0x1066, Align: 0x0, Reloff: 0x0, Nreloc: 0x0, Flags: 0x0, Reserved1: 0, Reserved2: 0, Reserved3: 0, Type: 0x40},
			{Name: "__debug_info", Seg: "__DWARF", Addr: 0x1000020a6, Size: 0x54, Offset: 0x10a6, Align: 0x0, Reloff: 0x0, Nreloc: 0x0, Flags: 0x0, Reserved1: 0, Reserved2: 0, Reserved3: 0, Type: 0x40},
			{Name: "__debug_line", Seg: "__DWARF", Addr: 0x1000020fa, Size: 0x47, Offset: 0x10fa, Align: 0x0, Reloff: 0x0, Nreloc: 0x0, Flags: 0x0, Reserved1: 0, Reserved2: 0, Reserved3: 0, Type: 0x40},
			{Name: "__debug_pubnames", Seg: "__DWARF", Addr: 0x100002141, Size: 0x1b, Offset: 0x1141, Align: 0x0, Reloff: 0x0, Nreloc: 0x0, Flags: 0x0, Reserved1: 0, Reserved2: 0, Reserved3: 0, Type: 0x40},
			{Name: "__debug_str", Seg: "__DWARF", Addr: 0x10000215c, Size: 0x60, Offset: 0x115c, Align: 0x0, Reloff: 0x0, Nreloc: 0x0, Flags: 0x0, Reserved1: 0, Reserved2: 0, Reserved3: 0, Type: 0x40},
		},
		nil,
	},
	{
		"internal/testdata/clang-386-darwin-exec-with-rpath.base64",
		types.FileHeader{Magic: 0xfeedface, CPU: types.CPUI386, SubCPU: 0x3, Type: 0x2, NCommands: 0x10, SizeCommands: 0x42c, Flags: 0x1200085, Reserved: 0x1},
		[]any{
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
			&Rpath{LoadBytes: LoadBytes(nil), RpathCmd: types.RpathCmd{LoadCmd: 0x8000001c, Len: 0x18, PathOffset: 0xc}, Path: "/my/rpath"},
			nil, // LC_FUNCTION_STARTS
			nil, // LC_DATA_IN_CODE
		},
		nil,
		nil,
	},
	{
		"internal/testdata/clang-amd64-darwin-exec-with-rpath.base64",
		types.FileHeader{Magic: 0xfeedfacf, CPU: types.CPUAmd64, SubCPU: 0x80000003, Type: 0x2, NCommands: 0x10, SizeCommands: 0x4c8, Flags: 0x200085, Reserved: 0x0},
		[]any{
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
			&Rpath{LoadBytes: LoadBytes(nil), RpathCmd: types.RpathCmd{LoadCmd: 0x8000001c, Len: 0x18, PathOffset: 0xc}, Path: "/my/rpath"},
			nil, // LC_FUNCTION_STARTS
			nil, // LC_DATA_IN_CODE
		},
		nil,
		nil,
	},
	{
		"internal/testdata/clang-386-darwin.obj.base64",
		types.FileHeader{Magic: 0xfeedface, CPU: types.CPUI386, SubCPU: 0x3, Type: 0x1, NCommands: 0x4, SizeCommands: 0x138, Flags: 0x2000, Reserved: 0x1},
		nil,
		nil,
		map[string][]types.Reloc{
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
		map[string][]types.Reloc{
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
				case *LoadDylib:
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

	if fat.Arches[0].UUID().UUID.String() != "273FB269-0D2F-3A78-9874-09E004F8B069" {
		t.Errorf("macho.UUID() = %s; want test", fat.Arches[0].UUID())
	}
}

var fname string

func init() {
	flag.StringVar(&fname, "file", "", "MachO file to test")
}

func TestNewFile(t *testing.T) {
	f, err := os.Open(fname)

	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			t.Skipf("file %s not found", fname)
		}
		t.Fatal(err)
	}

	got, err := NewFile(f)
	if err != nil {
		t.Fatalf("NewFile() error = %v", err)
		return
	}

	fmt.Println(got.FileTOC.String())

	cs := got.CodeSignature()
	if cs != nil {
		fmt.Println(cs.Requirements[0].Detail)
	}
	if len(cs.LaunchConstraintsSelf) > 0 {
		os.WriteFile("lc_self.bin", cs.LaunchConstraintsSelf, 0644)
		lc, err := cstypes.ParseLaunchContraints(cs.LaunchConstraintsSelf)
		if err != nil {
			t.Fatalf("ParseLaunchContraints() error = %v", err)
		}
		dat, err := json.MarshalIndent(lc, "", "  ")
		if err != nil {
			t.Fatalf("json.MarshalIndent() error = %v", err)
		}
		fmt.Println(string(dat))
	}
	if len(cs.LaunchConstraintsParent) > 0 {
		os.WriteFile("lc_parent.bin", cs.LaunchConstraintsParent, 0644)
		lc, err := cstypes.ParseLaunchContraints(cs.LaunchConstraintsParent)
		if err != nil {
			t.Fatalf("ParseLaunchContraints() error = %v", err)
		}
		dat, err := json.MarshalIndent(lc, "", "  ")
		if err != nil {
			t.Fatalf("json.MarshalIndent() error = %v", err)
		}
		fmt.Println(string(dat))
	}
	if len(cs.LaunchConstraintsResponsible) > 0 {
		os.WriteFile("lc_responsible.bin", cs.LaunchConstraintsResponsible, 0644)
		lc, err := cstypes.ParseLaunchContraints(cs.LaunchConstraintsResponsible)
		if err != nil {
			t.Fatalf("ParseLaunchContraints() error = %v", err)
		}
		dat, err := json.MarshalIndent(lc, "", "  ")
		if err != nil {
			t.Fatalf("json.MarshalIndent() error = %v", err)
		}
		fmt.Println(string(dat))
	}
	if len(cs.LibraryConstraints) > 0 {
		os.WriteFile("lib_constraints.bin", cs.LibraryConstraints, 0644)
		lc, err := cstypes.ParseLaunchContraints(cs.LibraryConstraints)
		if err != nil {
			t.Fatalf("ParseLaunchContraints() error = %v", err)
		}
		dat, err := json.MarshalIndent(lc, "", "  ")
		if err != nil {
			t.Fatalf("json.MarshalIndent() error = %v", err)
		}
		fmt.Println(string(dat))
	}

	d, err := got.DWARF()
	if err != nil {
		t.Fatalf("DWARF() error = %v", err)
	}

	r := d.Reader()

	debugStrSec := got.Section("__DWARF", "__debug_str")
	if debugStrSec == nil {
		t.Fatalf("Section() error = section __DWARF.__debug_str not found")
	}

	names, err := d.DumpNames()
	if err != nil {
		t.Errorf("DWARF.DumpNames() error = %v", err)
	}
	for _, name := range names {
		nameStr, err := got.GetCString(debugStrSec.Addr + uint64(name.StrOffset))
		if err != nil {
			t.Errorf("GetCString() error = %v", err)
		}

		for _, hdata := range name.HashData {
			r.Seek(*hdata[0].(*dwarf.Offset))
			entry, err := r.Next()
			if err != nil {
				t.Fatalf("DWARF.Reader().Next() error = %v", err)
			}

			switch entry.Tag {
			case dwarf.TagInlinedSubroutine:
			case dwarf.TagSubroutineType, dwarf.TagSubprogram:
				ty, _ := d.Type(entry.Offset)
				if ty.(*dwarf.FuncType).FileIndex > 0 {
					fs, err := d.FilesForEntry(entry)
					if err != nil {
						t.Fatalf("DWARF.FilesForEntry() error = %v", err)
					}
					fmt.Printf("TAG: %s, NAME: %s, TYPE: %s\nFILE: %s\n", entry.Tag, nameStr, ty, fs[ty.(*dwarf.FuncType).FileIndex].Name)
				}
			default:
				ty, _ := d.Type(entry.Offset)
				declFile, dOK := entry.Val(dwarf.AttrDeclFile).(int64)
				callFile, cOK := entry.Val(dwarf.AttrCallFile).(int64)
				if dOK || cOK {
					fs, err := d.FilesForEntry(entry)
					if err != nil {
						t.Fatalf("DWARF.FilesForEntry() error = %v", err)
					}
					fmt.Printf("TAG: %s, NAME: %s, TYPE: %s\nFILE: %s\n", entry.Tag, nameStr, ty, fs[declFile+callFile].Name)
				} else {
					fmt.Printf("TAG: %s, NAME: %s, TYPE: %s\n", entry.Tag, nameStr, ty)
				}
			}
		}
	}

	nameSpaces, err := d.DumpNamespaces()
	if err != nil {
		t.Fatalf("DWARF.DumpNamespaces() error = %v", err)
	}
	for _, ns := range nameSpaces {
		nsStr, err := got.GetCString(debugStrSec.Addr + uint64(ns.StrOffset))
		if err != nil {
			t.Errorf("GetCString() error = %v", err)
		}
		for _, hdata := range ns.HashData {
			r.Seek(*hdata[0].(*dwarf.Offset))
			entry, err := r.Next()
			if err != nil {
				t.Fatalf("DWARF.Reader().Next() error = %v", err)
			}

			typ, err := d.Type(entry.Offset)
			if err != nil {
				t.Fatalf("DWARF.Type() error = %v", err)
			}
			fmt.Printf("TAG: %s, NAME: %s, TYPE: %s\n", entry.Tag, nsStr, typ)
		}
	}

	objc, err := d.DumpObjC()
	if err != nil {
		t.Fatalf("DWARF.DumpObjC() error = %v", err)
	}
	for _, oc := range objc {
		nsStr, err := got.GetCString(debugStrSec.Addr + uint64(oc.StrOffset))
		if err != nil {
			t.Errorf("GetCString() error = %v", err)
		}
		fmt.Println(nsStr)
	}

	types, err := d.DumpTypes()
	if err != nil {
		t.Fatalf("DWARF.LookDumpTypesupType() error = %v", err)
	}
	for _, typ := range types {
		typStr, err := got.GetCString(debugStrSec.Addr + uint64(typ.StrOffset))
		if err != nil {
			t.Errorf("GetCString() error = %v", err)
		}
		fmt.Println(typStr)
	}

	off, err := d.LookupType("thread")
	if err != nil {
		t.Fatalf("DWARF.LookupType() error = %v", err)
	}

	r.Seek(off)

	entry, err := r.Next()
	if err != nil {
		t.Fatalf("DWARF.Reader().Next() error = %v", err)
	}

	if entry.Tag == dwarf.TagStructType {
		typ, err := d.Type(entry.Offset)
		if err != nil {
			t.Errorf("DWARF entry.Type() error = %v", err)
		}
		if t1, ok := typ.(*dwarf.StructType); ok {
			if strings.EqualFold(t1.StructName, "thread") {
				if !t1.Incomplete {
					fmt.Println(t1.Defn())
				}
			}
		}
	}
}

func TestNewFileWithSwift(t *testing.T) {
	f, err := os.Open(fname)

	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			t.Skipf("file %s not found", fname)
		}
		t.Fatal(err)
	}

	got, err := NewFile(f)
	if err != nil {
		t.Fatalf("NewFile() error = %v", err)
		return
	}

	if entry, err := got.GetSwiftEntry(); err != nil && !errors.Is(err, ErrSwiftSectionError) {
		t.Fatalf("GetSwiftEntry() error = %v", err)
	} else {
		fmt.Println("GetSwiftEntry" + strings.Repeat("-", 80))
		fmt.Printf("%#x: entry\n", entry)
	}

	if bins, err := got.GetSwiftBuiltinTypes(); err != nil {
		if !errors.Is(err, ErrSwiftSectionError) {
			t.Fatalf("GetSwiftBuiltinTypes() error = %v", err)
		}
	} else {
		fmt.Println("GetSwiftBuiltinTypes" + strings.Repeat("-", 80))
		for _, bin := range bins {
			fmt.Println(bin.Verbose())
		}
	}

	if refStrs, err := got.GetSwiftReflectionStrings(); err != nil && !errors.Is(err, ErrSwiftSectionError) {
		t.Fatalf("GetSwiftReflectionStrings() error = %v", err)
	} else {
		fmt.Println("GetSwiftReflectionStrings" + strings.Repeat("-", 80))
		for addr, refstr := range refStrs {
			fmt.Printf("%#x: %s\n", addr, refstr)
		}
	}

	if fds, err := got.GetSwiftFields(); err != nil && !errors.Is(err, ErrSwiftSectionError) {
		t.Fatalf("GetSwiftFields() error = %v", err)
	} else {
		fmt.Println("GetSwiftFields" + strings.Repeat("-", 80))
		for _, f := range fds {
			fmt.Println(f.Verbose())
		}
	}

	if atyps, err := got.GetSwiftAssociatedTypes(); err != nil && !errors.Is(err, ErrSwiftSectionError) {
		t.Fatalf("GetSwiftAssociatedTypes() error = %v", err)
	} else {
		fmt.Println("GetSwiftAssociatedTypes" + strings.Repeat("-", 80))
		for _, at := range atyps {
			fmt.Println(at.Verbose())
		}
	}

	if typs, err := got.GetColocateTypeDescriptors(); err != nil && !errors.Is(err, ErrSwiftSectionError) {
		t.Fatalf("GetColocateTypeDescriptors() error = %v", err)
	} else {
		fmt.Println("GetColocateTypeDescriptors" + strings.Repeat("-", 80))
		for _, typ := range typs {
			fmt.Println(typ.Verbose())
		}
	}

	if mdatas, err := got.GetColocateMetadata(); err != nil && !errors.Is(err, ErrSwiftSectionError) {
		t.Fatalf("GetColocateMetadata() error = %v", err)
	} else {
		fmt.Println("GetColocateMetadata" + strings.Repeat("-", 80))
		for _, mdat := range mdatas {
			fmt.Println(mdat.Verbose())
		}
	}

	// if refStrs, err := got.GetSwiftTypeRefs(); err != nil && !errors.Is(err, ErrSwiftSectionError) {
	// 	t.Fatalf("GetSwiftTypeRefs() error = %v", err)
	// } else {
	// 	for addr, refstr := range refStrs {
	// 		fmt.Printf("%#x: %s\n", addr, refstr)
	// 	}
	// }

	if typs, err := got.GetSwiftTypes(); err != nil && !errors.Is(err, ErrSwiftSectionError) {
		t.Fatalf("GetSwiftTypes() error = %v", err)
	} else {
		fmt.Println("GetSwiftTypes" + strings.Repeat("-", 80))
		for _, t := range typs {
			fmt.Println(t)
		}
	}

	if prots, err := got.GetSwiftProtocols(); err != nil && !errors.Is(err, ErrSwiftSectionError) {
		t.Fatalf("GetSwiftProtocols() error = %v", err)
	} else {
		fmt.Println("GetSwiftProtocols" + strings.Repeat("-", 80))
		for _, prot := range prots {
			fmt.Println(prot.Verbose())
		}
	}

	if protsconfs, err := got.GetSwiftProtocolConformances(); err != nil && !errors.Is(err, ErrSwiftSectionError) {
		t.Fatalf("GetSwiftProtocolConformances() error = %v", err)
	} else {
		fmt.Println("GetSwiftProtocolConformances" + strings.Repeat("-", 80))
		for _, prot := range protsconfs {
			fmt.Println(prot.Verbose())
		}
	}

	if mpenums, err := got.GetMultiPayloadEnums(); err != nil && !errors.Is(err, ErrSwiftSectionError) {
		t.Fatalf("GetMultiPayloadEnums() error = %v", err)
	} else {
		fmt.Println("GetMultiPayloadEnums" + strings.Repeat("-", 80))
		for _, e := range mpenums {
			fmt.Println(e)
		}
	}

	if clos, err := got.GetSwiftClosures(); err != nil && !errors.Is(err, ErrSwiftSectionError) {
		t.Fatalf("GetSwiftClosures() error = %v", err)
	} else {
		fmt.Println("GetSwiftClosures" + strings.Repeat("-", 80))
		for _, c := range clos {
			fmt.Println(c)
		}
	}

	if rep, err := got.GetSwiftDynamicReplacementInfo(); err != nil && !errors.Is(err, ErrSwiftSectionError) {
		t.Fatalf("GetSwiftDynamicReplacementInfo() error = %v", err)
	} else {
		fmt.Println("GetSwiftDynamicReplacementInfo" + strings.Repeat("-", 80))
		if rep != nil {
			fmt.Println(rep)
		}
	}

	if rep, err := got.GetSwiftDynamicReplacementInfoForOpaqueTypes(); err != nil && !errors.Is(err, ErrSwiftSectionError) {
		t.Fatalf("GetSwiftDynamicReplacementInfoForOpaqueTypes() error = %v", err)
	} else {
		fmt.Println("GetSwiftDynamicReplacementInfoForOpaqueTypes" + strings.Repeat("-", 80))
		if rep != nil {
			fmt.Println(rep)
		}
	}

	if afuncs, err := got.GetSwiftAccessibleFunctions(); err != nil && !errors.Is(err, ErrSwiftSectionError) {
		t.Fatalf("GetSwiftAccessibleFunctions() error = %v", err)
	} else {
		fmt.Println("GetSwiftAccessibleFunctions" + strings.Repeat("-", 80))
		if afuncs != nil {
			fmt.Println(afuncs)
		}
	}
}

func TestNewFileWithObjC(t *testing.T) {
	f, err := os.Open(fname)

	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			t.Skipf("file %s not found", fname)
		}
		t.Fatal(err)
	}

	got, err := NewFile(f)
	if err != nil {
		t.Fatalf("NewFile() error = %v", err)
		return
	}

	if got.HasObjC() {
		fmt.Println("HasPlusLoadMethod: ", got.HasPlusLoadMethod())
		fmt.Println(got.GetObjCToc())

		info, err := got.GetObjCImageInfo()
		if err != nil && !errors.Is(err, ErrObjcSectionNotFound) {
			t.Fatalf("GetObjCImageInfo() error = %v", err)
		}
		fmt.Printf("ObjCImageInfo:\n%s\n\n", info.Flags)

		if cfstrs, err := got.GetCFStrings(); err == nil {
			fmt.Println("CFStrings")
			fmt.Println("---------")
			for _, cfstr := range cfstrs {
				fmt.Printf("%#x: %#v\n", cfstr.Address, cfstr.Name)
			}
		} else {
			t.Errorf(err.Error())
		}

		if meths, err := got.GetObjCMethodLists(); err == nil {
			fmt.Println("_OBJC_INSTANCE_METHODS")
			fmt.Println("----------------------")
			for _, m := range meths {
				fmt.Printf("%#x: (%s) %s [%d]\n", m.ImpVMAddr, m.ReturnType(), m.Name, m.NumberOfArguments())
			}
		} else {
			t.Errorf(err.Error())
		}

		if protos, err := got.GetObjCProtocols(); err == nil {
			for _, proto := range protos {
				fmt.Println(proto.String())
			}
		} else {
			t.Errorf(err.Error())
		}

		if classes, err := got.GetObjCClasses(); err == nil {
			for _, class := range classes {
				fmt.Println(class.Verbose())
			}
		} else {
			t.Errorf(err.Error())
		}

		if nlclasses, err := got.GetObjCNonLazyClasses(); err == nil {
			for _, class := range nlclasses {
				fmt.Println(class.String())
			}
		} else {
			t.Errorf(err.Error())
		}

		if cats, err := got.GetObjCCategories(); err == nil {
			for _, cat := range cats {
				fmt.Println(cat.String())
			}
		} else {
			t.Errorf(err.Error())
		}

		if nlcats, err := got.GetObjCNonLazyCategories(); err == nil {
			for _, cat := range nlcats {
				fmt.Println(cat.String())
			}
		} else {
			t.Errorf(err.Error())
		}

		if selRefs, err := got.GetObjCProtoReferences(); err == nil {
			fmt.Println("@proto refs")
			for off, prot := range selRefs {
				fmt.Printf("%#x -> %#x: %s\n", off, prot.Ptr, prot.Name)
			}
		} else {
			t.Errorf(err.Error())
		}
		if selRefs, err := got.GetObjCClassReferences(); err == nil {
			fmt.Println("@class refs")
			for off, sel := range selRefs {
				fmt.Printf("%#x -> %#x: %s\n", off, sel.ClassPtr, sel.Name)
			}
		} else {
			t.Errorf(err.Error())
		}
		if selRefs, err := got.GetObjCSuperReferences(); err == nil {
			fmt.Println("@super refs")
			for off, sel := range selRefs {
				fmt.Printf("%#x -> %#x: %s\n", off, sel.ClassPtr, sel.SuperClass)
			}
		} else {
			t.Errorf(err.Error())
		}
		if selRefs, err := got.GetObjCSelectorReferences(); err == nil {
			fmt.Println("@selectors refs")
			for off, sel := range selRefs {
				fmt.Printf("%#x -> %#x: %s\n", off, sel.VMAddr, sel.Name)
			}
		} else {
			t.Errorf(err.Error())
		}
		if methods, err := got.GetObjCMethodNames(); err == nil {
			fmt.Printf("\n@methods\n")
			for vmaddr, method := range methods {
				fmt.Printf("%#x: %s\n", vmaddr, method)
			}
		} else {
			t.Errorf(err.Error())
		}
	}
}
