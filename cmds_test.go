package macho

import (
	"bytes"
	"encoding/binary"
	"slices"
	"testing"

	"github.com/blacktop/go-macho/types"
)

func TestThreadLoadSize(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, command := range []types.LoadCmd{types.LC_THREAD, types.LC_UNIXTHREAD} {
			for _, states := range [][]types.ThreadState{
				nil,
				{{Flavor: 1, Count: 2, Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}}},
				{{Flavor: 1, Count: 2, Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}}, {Flavor: 2, Count: 2, Data: []byte{8, 7, 6, 5, 4, 3, 2, 1}}},
			} {
				thread := Thread{ThreadCmd: types.ThreadCmd{LoadCmd: command}, Threads: states}
				// LoadSize describes the current payload, including a constructed or edited
				// command whose stored Len and raw bytes have not yet been updated.
				var encoded bytes.Buffer
				if err := thread.Write(&encoded, order); err != nil {
					t.Fatal(err)
				}
				want := uint32(encoded.Len())
				if got := thread.LoadSize(); got != want {
					t.Fatalf("%v %s states=%d: size=%d written=%d", order, command, len(states), got, want)
				}
				thread.Len = want
				encoded.Reset()
				if err := thread.Write(&encoded, order); err != nil {
					t.Fatal(err)
				}
				header := make([]byte, 32)
				for i, value := range []uint32{uint32(types.Magic64), uint32(types.CPUArm64), 0, uint32(types.MH_EXECUTE), 1, want, 0, 0} {
					order.PutUint32(header[i*4:], value)
				}
				f, err := NewFile(bytes.NewReader(append(header, encoded.Bytes()...)))
				if err != nil {
					t.Fatal(err)
				}
				if got := f.Loads[0].LoadSize(); got != want {
					t.Fatalf("parsed %s size=%d want=%d", command, got, want)
				}
				if got := f.FileTOC.LoadSize(); got != want {
					t.Fatalf("TOC size=%d want=%d", got, want)
				}
				_ = f.Close()
			}
		}
	}
}

func TestStringLoadCommandsHonorCmdsize(t *testing.T) {
	commands := []Load{
		&LoadFvmlib{
			LoadFvmLibCmd: types.LoadFvmLibCmd{
				LoadCmd: types.LC_LOADFVMLIB, Len: 28, NameOffset: 20,
			},
			Name: "foo",
		},
		&Ident{IdentCmd: types.IdentCmd{LoadCmd: types.LC_IDENT, Len: 16}, StrTable: []string{"foo"}},
		&FvmFile{
			FvmFileCmd: types.FvmFileCmd{LoadCmd: types.LC_FVMFILE, Len: 20, NameOffset: 16},
			Name:       "foo",
		},
		&SubFramework{
			SubFrameworkCmd: types.SubFrameworkCmd{
				LoadCmd: types.LC_SUB_FRAMEWORK, Len: 20, FrameworkOffset: 12,
			},
			Framework: "foo",
		},
		&SubUmbrella{
			SubUmbrellaCmd: types.SubUmbrellaCmd{
				LoadCmd: types.LC_SUB_UMBRELLA, Len: 20, UmbrellaOffset: 12,
			},
			Umbrella: "foo",
		},
		&SubClient{
			SubClientCmd: types.SubClientCmd{
				LoadCmd: types.LC_SUB_CLIENT, Len: 20, ClientOffset: 12,
			},
			Name: "foo",
		},
		&SubLibrary{
			SubLibraryCmd: types.SubLibraryCmd{
				LoadCmd: types.LC_SUB_LIBRARY, Len: 20, LibraryOffset: 12,
			},
			Library: "foo",
		},
		&Rpath{RpathCmd: types.RpathCmd{LoadCmd: types.LC_RPATH, Len: 20, PathOffset: 12}, Path: "foo"},
		&LinkerOption{
			LinkerOptionCmd: types.LinkerOptionCmd{
				LoadCmd: types.LC_LINKER_OPTION, Len: 20, Count: 1,
			},
			Options: []string{"foo"},
		},
		&FilesetEntry{
			FilesetEntryCmd: types.FilesetEntryCmd{
				LoadCmd: types.LC_FILESET_ENTRY, Len: 40, EntryIdOffset: 32,
			},
			EntryID: "foo",
		},
		&TargetTriple{
			TargetTripleCmd: types.TargetTripleCmd{
				LoadCmd: types.LC_TARGET_TRIPLE, Len: 20, TargetOffset: 12,
			},
			Target: "foo",
		},
		&Dylinker{
			DylinkerCmd: types.DylinkerCmd{
				LoadCmd: types.LC_LOAD_DYLINKER, Len: 20, NameOffset: 12,
			},
			Name: "foo",
		},
	}
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, command := range commands {
			for _, prefix := range []int{0, 4} {
				var buf bytes.Buffer
				buf.Write(make([]byte, prefix))
				if err := command.Write(&buf, order); err != nil {
					t.Fatal(err)
				}
				data := buf.Bytes()[prefix:]
				if want := order.Uint32(data[4:8]); uint64(len(data)) != uint64(want) {
					t.Errorf("%v %s prefix=%d: wrote %d bytes, cmdsize=%d",
						order, command.Command(), prefix, len(data), want)
				}
			}
		}
	}
}

func TestVariableLoadSizeIncludesPadding(t *testing.T) {
	ident := &Ident{StrTable: []string{"abcde"}}
	if got := ident.LoadSize(); got != 16 {
		t.Errorf("LC_IDENT size=%d, want 16", got)
	}
	option := &LinkerOption{Options: []string{"abcd"}}
	if got := option.LoadSize(); got != 24 {
		t.Errorf("LC_LINKER_OPTION size=%d, want 24", got)
	}
}

func TestParsedStringListsRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command any
		payload string
		strings []string
	}{
		{"ident", types.IdentCmd{LoadCmd: types.LC_IDENT, Len: 12}, "abc\x00", []string{"abc"}},
		{"ident-padded", types.IdentCmd{LoadCmd: types.LC_IDENT, Len: 16},
			"abc\x00\x00\x00\x00\x00", []string{"abc"}},
		{"option", types.LinkerOptionCmd{
			LoadCmd: types.LC_LINKER_OPTION, Len: 16, Count: 1,
		}, "abc\x00", []string{"abc"}},
		{"options", types.LinkerOptionCmd{
			LoadCmd: types.LC_LINKER_OPTION, Len: 16, Count: 2,
		}, "a\x00b\x00", []string{"a", "b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var command bytes.Buffer
			if err := binary.Write(&command, binary.LittleEndian, tc.command); err != nil {
				t.Fatal(err)
			}
			command.WriteString(tc.payload)
			header := types.FileHeader{
				Magic: types.Magic32, CPU: types.CPUI386, Type: types.MH_OBJECT,
				NCommands: 1, SizeCommands: uint32(command.Len()),
			}
			data := make([]byte, types.FileHeaderSize32+command.Len())
			header.Put(data, binary.LittleEndian)
			copy(data[types.FileHeaderSize32:], command.Bytes())
			f, err := NewFile(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			switch load := f.Loads[0].(type) {
			case *Ident:
				if !slices.Equal(load.StrTable, tc.strings) {
					t.Fatalf("strings = %q, want %q", load.StrTable, tc.strings)
				}
			case *LinkerOption:
				if load.Count != uint32(len(tc.strings)) || !slices.Equal(load.Options, tc.strings) {
					t.Fatalf("count=%d options=%q, want %q", load.Count, load.Options, tc.strings)
				}
			}
			var rewritten bytes.Buffer
			if err := f.writeLoadCommands(&rewritten, f.Loads); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(rewritten.Bytes(), command.Bytes()) {
				t.Fatal("parsed command changed during serialization")
			}
		})
	}
}

func TestPreboundDylibBitmapRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		size, nameOff, bitsOff uint32
		modules                uint32
		bitmap                 string
		wantError              bool
	}{
		{"tight", 24, 20, 22, 16, "\xff\xfe", false},
		{"gapped", 32, 24, 28, 17, "\x00\xff\x01", false},
		{"empty", 24, 20, 0, 0, "", false},
		{"truncated", 24, 20, 22, 17, "\xff\xfe", true},
		{"bitmap-before-name", 32, 28, 24, 16, "\x00\xff", false},
		{"name-in-header", 24, 4, 22, 16, "\xff\xfe", true},
		{"bitmap-in-header", 24, 20, 16, 8, "\xff", true},
		{"overlap", 24, 20, 21, 8, "\xff", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
				command := make([]byte, tc.size)
				fields := []uint32{
					uint32(types.LC_PREBOUND_DYLIB), tc.size, tc.nameOff, tc.modules, tc.bitsOff,
				}
				for i, value := range fields {
					order.PutUint32(command[i*4:], value)
				}
				if tc.nameOff >= 20 {
					copy(command[tc.nameOff:], "a\x00")
				}
				if tc.bitsOff >= 20 {
					copy(command[tc.bitsOff:], tc.bitmap)
				}
				header := types.FileHeader{
					Magic: types.Magic32, CPU: types.CPUI386, Type: types.MH_EXECUTE,
					NCommands: 1, SizeCommands: tc.size,
				}
				data := make([]byte, types.FileHeaderSize32+len(command))
				header.Put(data, order)
				copy(data[types.FileHeaderSize32:], command)
				f, err := NewFile(bytes.NewReader(data))
				if tc.wantError {
					if err == nil {
						f.Close()
						t.Fatal("accepted truncated module bitmap")
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				load := f.Loads[0].(*PreboundDylib)
				if load.LinkedModulesOffset != tc.bitsOff || load.LinkedModulesBitVector != tc.bitmap {
					t.Fatalf("offset=%d bitmap=%x, want offset=%d bitmap=%x",
						load.LinkedModulesOffset, load.LinkedModulesBitVector, tc.bitsOff, tc.bitmap)
				}
				if size := load.LoadSize(); size != tc.size {
					t.Fatalf("computed command size=%d, want %d", size, tc.size)
				}
				var rewritten bytes.Buffer
				if err := f.writeLoadCommands(&rewritten, f.Loads); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(rewritten.Bytes(), command) {
					t.Fatal("parsed bitmap changed during serialization")
				}
				f.Close()
			}
		})
	}
}

func TestPreboundDylibConstruction(t *testing.T) {
	d := PreboundDylib{
		PreboundDylibCmd:       types.PreboundDylibCmd{NumModules: 16},
		Name:                   "a",
		LinkedModulesBitVector: "\x00\xff",
	}
	if size := d.LoadSize(); size != 24 {
		t.Fatalf("constructed command size=%d, want 24", size)
	}
	for _, size := range []uint32{0, d.LoadSize()} {
		command := d
		command.Len = size
		var buf bytes.Buffer
		if err := command.Write(&buf, binary.LittleEndian); err != nil {
			t.Fatal(err)
		}
		var header types.PreboundDylibCmd
		if err := binary.Read(bytes.NewReader(buf.Bytes()), binary.LittleEndian, &header); err != nil {
			t.Fatal(err)
		}
		if header.LoadCmd != types.LC_PREBOUND_DYLIB || header.Len != 24 ||
			header.NameOffset != 20 || header.LinkedModulesOffset != 22 {
			t.Fatalf("constructed command header: %+v", header)
		}
		if !bytes.Equal(buf.Bytes()[22:24], []byte{0, 0xff}) {
			t.Fatal("constructed command lost its bitmap")
		}
	}
	d.NameOffset = ^uint32(0)
	if d.LoadSize() != ^uint32(0) {
		t.Fatal("overflowing layout did not report the size limit")
	}
	var buf bytes.Buffer
	if err := d.Write(&buf, binary.LittleEndian); err == nil || buf.Len() != 0 {
		t.Fatalf("overflowing layout wrote %d bytes, error=%v", buf.Len(), err)
	}
}

func TestMalformedOptionalCommandsCanBeExcluded(t *testing.T) {
	for _, tc := range []struct {
		cmd     types.LoadCmd
		header  any
		payload string
	}{
		{types.LC_IDENT, types.IdentCmd{LoadCmd: types.LC_IDENT, Len: 12}, "bad!"},
		{types.LC_LINKER_OPTION, types.LinkerOptionCmd{
			LoadCmd: types.LC_LINKER_OPTION, Len: 16, Count: 2,
		}, "abc\x00"},
	} {
		t.Run(tc.cmd.String(), func(t *testing.T) {
			var commands bytes.Buffer
			if err := binary.Write(&commands, binary.LittleEndian, tc.header); err != nil {
				t.Fatal(err)
			}
			commands.WriteString(tc.payload)
			segment := types.Segment32{LoadCmd: types.LC_SEGMENT, Len: 56}
			copy(segment.Name[:], "__TEXT")
			if err := binary.Write(&commands, binary.LittleEndian, segment); err != nil {
				t.Fatal(err)
			}
			header := types.FileHeader{
				Magic: types.Magic32, CPU: types.CPUI386, Type: types.MH_OBJECT,
				NCommands: 2, SizeCommands: uint32(commands.Len()),
			}
			data := make([]byte, types.FileHeaderSize32+commands.Len())
			header.Put(data, binary.LittleEndian)
			copy(data[types.FileHeaderSize32:], commands.Bytes())
			if f, err := NewFile(bytes.NewReader(data)); err == nil {
				f.Close()
				t.Fatal("malformed command was accepted")
			}
			f, err := NewFile(bytes.NewReader(data), FileConfig{
				LoadExcluding: []types.LoadCmd{tc.cmd},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if len(f.Loads) != 1 || f.Segment("__TEXT") == nil {
				t.Fatal("excluding the malformed command lost the segment")
			}
		})
	}
}
