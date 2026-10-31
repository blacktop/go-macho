package macho

import (
	"bytes"
	stdmacho "debug/macho"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-macho/types"
)

func exportAndReopen(
	t *testing.T, f *File, symbols []Symbol, opts ...ExportOption,
) (*File, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "exported")
	if err := f.Export(path, nil, 0, symbols, opts...); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	independent, err := stdmacho.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("debug/macho rejected export: %v", err)
	}
	defer independent.Close()
	got, err := NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { got.Close() })
	headerSize := uint32(types.FileHeaderSize32)
	if independent.Magic == uint32(types.Magic64) {
		headerSize = types.FileHeaderSize64
	}
	if got.HdrSize() != headerSize {
		t.Fatalf("header size=%d, want %d", got.HdrSize(), headerSize)
	}
	// debug/macho validates each record; also require its parsed commands to
	// consume the entire advertised block, including unknown command kinds.
	var commandSize uint64
	for i, load := range independent.Loads {
		size := uint64(len(load.Raw()))
		if size%got.LoadAlign() != 0 {
			t.Fatalf("unaligned load command %d size %#x", i, size)
		}
		commandSize += size
	}
	if commandSize != uint64(independent.Cmdsz) {
		t.Fatalf("load commands occupy %#x bytes, header says %#x", commandSize, independent.Cmdsz)
	}
	return got, data
}

func TestExportLegacyMachORoundTrip(t *testing.T) {
	for _, fixture := range []string{
		"clang-386-darwin-exec-with-rpath.base64",
		"gcc-386-darwin-exec.base64",
		"clang-amd64-darwin-exec-with-rpath.base64",
		"gcc-amd64-darwin-exec.base64",
	} {
		t.Run(fixture, func(t *testing.T) {
			f, err := openObscured(filepath.Join("internal", "testdata", fixture))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			got, first := exportAndReopen(t, f, nil)
			if len(got.Loads) != len(f.Loads) {
				t.Fatalf("got %d commands, want %d", len(got.Loads), len(f.Loads))
			}
			for i, want := range f.Loads {
				if got.Loads[i].Command() != want.Command() {
					t.Fatalf("command %d = %s, want %s", i, got.Loads[i].Command(), want.Command())
				}
				switch want.Command() {
				case types.LC_MAIN, types.LC_UNIXTHREAD, types.LC_LOAD_DYLINKER,
					types.LC_LOAD_DYLIB, types.LC_RPATH:
					if !bytes.Equal(got.Loads[i].Raw(), want.Raw()) {
						t.Errorf("%s changed during export", want.Command())
					}
				}
			}
			_, second := exportAndReopen(t, f, nil)
			if !bytes.Equal(first, second) {
				t.Fatal("repeated export changed the output")
			}
		})
	}
}

func TestExport32BitLinkeditRebuild(t *testing.T) {
	f, err := openObscured(filepath.Join("internal", "testdata", "gcc-386-darwin-exec.base64"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// Exercise the LINKEDIT-rebuilding path with real 32-bit load commands.
	f.Flags |= types.DylibInCache
	got, _ := exportAndReopen(t, f, nil)
	for _, want := range f.Segments() {
		segment := got.Segment(want.Name)
		if segment == nil || segment.Addr != want.Addr {
			t.Errorf("segment %s was replaced or moved", want.Name)
		}
	}
}

func TestExportRejectsPackedIntelImages(t *testing.T) {
	f, err := openObscured(filepath.Join(
		"internal", "testdata", "gcc-amd64-darwin-exec.base64",
	))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	path := filepath.Join(t.TempDir(), "exported")
	refs := []*types.SplitInfoEntry{{Kind: types.DYLD_CACHE_ADJ_V2_POINTER_64}}
	err = f.Export(path, nil, 0, nil, WithReferences(refs))
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("packed Intel export error = %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("unsupported export wrote output: %v", err)
	}
}

func TestExportRejectsLoadCommandsOverlappingText(t *testing.T) {
	for _, overlap := range []bool{false, true} {
		f := splitInfoExportFixture(t, true)
		first := f.HdrSize() + f.SizeCommands + uint32(binary.Size(types.LinkEditDataCmd{}))
		if overlap {
			first -= 8
		}
		section := f.Sections[0]
		section.Offset = first
		section.Addr = f.GetBaseAddress() + uint64(first)
		refs := []*types.SplitInfoEntry{{
			Kind:         types.DYLD_CACHE_ADJ_V2_POINTER_64,
			SourceVmAddr: section.Addr,
			TargetVmAddr: section.Addr + 8,
		}}
		if !overlap {
			exportAndReopen(t, f, nil, WithReferences(refs))
			continue
		}
		path := filepath.Join(t.TempDir(), "exported")
		err := f.Export(path, nil, 0, nil, WithReferences(refs))
		if err == nil || !strings.Contains(err.Error(), "overlap first __TEXT section") {
			t.Fatalf("overlapping export error = %v", err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("overlapping export wrote output: %v", err)
		}
	}
}

func splitInfoExportFixture(t *testing.T, inCache bool) *File {
	t.Helper()
	var textName, linkeditName, sectionName [16]byte
	copy(textName[:], "__TEXT")
	copy(linkeditName[:], "__LINKEDIT")
	copy(sectionName[:], "__const")
	var loads bytes.Buffer
	for _, load := range []any{
		types.Segment64{
			LoadCmd: types.LC_SEGMENT_64, Len: 152, Name: textName,
			Addr: 0x100000, Memsz: 0x4000, Filesz: 0x4000, Nsect: 1,
		},
		types.Section64{
			Name: sectionName, Seg: textName, Addr: 0x100800,
			Size: 16, Offset: 0x800, Align: 3,
		},
		types.Segment64{
			LoadCmd: types.LC_SEGMENT_64, Len: 72, Name: linkeditName,
			Addr: 0x104000, Memsz: 0x4000, Offset: 0x4000, Filesz: 0x4000,
		},
		types.SymtabCmd{LoadCmd: types.LC_SYMTAB, Len: 24, Symoff: 0x4000, Stroff: 0x4000, Strsize: 1},
		types.DysymtabCmd{LoadCmd: types.LC_DYSYMTAB, Len: 80},
		types.SegmentSplitInfoCmd{LoadCmd: types.LC_SEGMENT_SPLIT_INFO, Len: 16, Offset: 0x4010, Size: 8},
	} {
		if err := binary.Write(&loads, binary.LittleEndian, load); err != nil {
			t.Fatal(err)
		}
	}
	header := types.FileHeader{
		Magic: types.Magic64, CPU: types.CPUArm64, Type: types.MH_KEXT_BUNDLE,
		NCommands: 5, SizeCommands: uint32(loads.Len()),
	}
	if inCache {
		header.Flags = types.DylibInCache
	}
	data := make([]byte, 0x8000)
	headerSize := header.Put(data, binary.LittleEndian)
	copy(data[headerSize:], loads.Bytes())
	binary.LittleEndian.PutUint64(data[0x800:], 0x100808)
	data[0x4010] = types.DYLD_CACHE_ADJ_V2_FORMAT
	f, err := NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestExportSplitInfoModes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		inCache bool
		pack    bool
	}{
		{name: "standalone"},
		{name: "cached", inCache: true},
		{name: "reconstructed", inCache: true, pack: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := splitInfoExportFixture(t, tc.inCache)
			var opts []ExportOption
			if tc.pack {
				opts = append(opts, WithReferences([]*types.SplitInfoEntry{{
					Kind:         types.DYLD_CACHE_ADJ_V2_POINTER_64,
					SourceVmAddr: 0x100800,
					TargetVmAddr: 0x100808,
				}}))
			}
			got, data := exportAndReopen(t, f, nil, opts...)
			var split *SplitInfo
			for _, load := range got.Loads {
				if current, ok := load.(*SplitInfo); ok {
					if split != nil {
						t.Fatal("duplicate split-info command")
					}
					split = current
				}
			}
			if tc.inCache && !tc.pack {
				if split != nil {
					t.Fatal("unreconstructed cache split-info was retained")
				}
				return
			}
			if split == nil || uint64(split.Offset)+uint64(split.Size) > uint64(len(data)) {
				t.Fatal("missing or out-of-bounds split-info payload")
			}
			if !tc.pack {
				if !bytes.Equal(data[split.Offset:split.Offset+split.Size], []byte{0x7f, 0, 0, 0, 0, 0, 0, 0}) {
					t.Fatal("standalone split-info payload changed")
				}
				return
			}
			count := 0
			err := got.ForEachV2SplitSegReference(func(
				from, fromOffset, to, toOffset uint64, kind types.SplitInfoKind,
			) {
				count++
				if from != 1 || fromOffset != 0 || to != 1 || toOffset != 8 ||
					kind != types.DYLD_CACHE_ADJ_V2_POINTER_64 {
					t.Errorf("unexpected split reference: %d+%#x -> %d+%#x (%s)",
						from, fromOffset, to, toOffset, kind)
				}
			})
			if err != nil {
				t.Fatal(err)
			}
			if count != 1 {
				t.Fatalf("got %d split references, want 1", count)
			}
		})
	}
}

func TestAddressOnlyBindsSkipsNearbySymbols(t *testing.T) {
	for _, addressOnly := range []bool{false, true} {
		f := splitInfoExportFixture(t, true)
		opts := []ExportOption{WithReferences([]*types.SplitInfoEntry{{
			Kind:         types.DYLD_CACHE_ADJ_V2_POINTER_64,
			SourceVmAddr: 0x100800,
			TargetVmAddr: 0x200010,
		}})}
		if addressOnly {
			opts = append(opts, WithAddressOnlyBinds())
		}
		symbols := []Symbol{{
			Name: "_symbol", Type: types.N_UNDF | types.N_EXT, Value: 0x200000,
		}}
		got, data := exportAndReopen(t, f, symbols, opts...)
		chains, err := got.DyldChainedFixups()
		if err != nil {
			t.Fatal(err)
		}
		if addressOnly {
			if len(chains.Imports) != 0 {
				t.Fatalf("address-only mode guessed imports: %+v", chains.Imports)
			}
			continue
		}
		if len(chains.Imports) != 1 || chains.Imports[0].Name != "_symbol" {
			t.Fatalf("default mode lost nearby-symbol recovery: %+v", chains.Imports)
		}
		bind := fixupchains.DyldChainedPtrArm64eBind{Pointer: binary.LittleEndian.Uint64(data[0x800:])}
		if bind.Bind() != 1 || bind.SignExtendedAddend() != 0x10 {
			t.Fatalf("recovered pointer has bind=%d addend=%d", bind.Bind(), bind.SignExtendedAddend())
		}
	}
}
