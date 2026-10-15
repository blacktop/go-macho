package objcreader_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/go-macho/types/objc"
)

func protocolBoundsFixture(
	t *testing.T, protocolAddr uint64, protocolSize uint32, zeroFill types.SectionFlag,
) []byte {
	t.Helper()
	name16 := func(s string) (name [16]byte) { copy(name[:], s); return }
	data := make([]byte, 0xd00)
	put := func(offset uint64, value any) { writeLETestData(t, data[offset:], value) }
	sections := []types.Section64{
		{Name: name16("__objc_classlist"), Seg: name16("__DATA"), Addr: 0x1200, Size: 8, Offset: 0x200},
		{Name: name16("__objc_protolist"), Seg: name16("__DATA"), Addr: 0x1208, Size: 8, Offset: 0x208},
	}
	if zeroFill != 0 {
		sections = append(sections, types.Section64{
			Name: name16("__bss"), Seg: name16("__DATA"),
			Addr: protocolAddr, Size: 96, Flags: zeroFill,
		})
	}
	segmentSize := uint32(binary.Size(types.Segment64{}))
	dataSize := segmentSize + uint32(len(sections)*binary.Size(types.Section64{}))
	header := types.FileHeader{
		Magic: types.Magic64, CPU: types.CPUArm64, Type: types.MH_DYLIB,
		NCommands: 2, SizeCommands: dataSize + segmentSize,
	}
	header.Put(data, binary.LittleEndian)
	put(32, types.Segment64{
		LoadCmd: types.LC_SEGMENT_64, Len: dataSize, Name: name16("__DATA"),
		Addr: 0x1000, Memsz: 0x1000, Filesz: 0x500, Nsect: uint32(len(sections)),
	})
	cursor := uint64(32 + segmentSize)
	for _, section := range sections {
		put(cursor, section)
		cursor += uint64(binary.Size(section))
	}
	put(cursor, types.Segment64{
		LoadCmd: types.LC_SEGMENT_64, Len: segmentSize, Name: name16("__LINKEDIT"),
		Addr: 0x5000, Memsz: 0x800, Offset: 0x500, Filesz: 0x800,
	})
	put(0x200, uint64(0x1280))
	put(0x208, protocolAddr)
	put(0x280, objc.SwiftClassMetadata64{
		ObjcClass64: objc.ObjcClass64{DataVMAddrAndFastFlags: 0x12c0},
	})
	put(0x2c0, objc.ClassRO64{Flags: objc.RO_ROOT, NameVMAddr: 0x13e0, BaseProtocolsVMAddr: 0x1330})
	put(0x330, uint64(1))
	put(0x338, protocolAddr)
	put(protocolAddr-0x1000, objc.ProtocolT{NameVMAddr: 0x1400, Size: protocolSize})
	copy(data[0x3e0:], "Ordinary\x00")
	copy(data[0x400:], "ReferencedProtocol\x00")
	return data
}

func TestObjCProtocolFileBounds(t *testing.T) {
	for _, tc := range []struct {
		name          string
		addr          uint64
		size          uint32
		zeroFill      types.SectionFlag
		custom        bool
		customLimit   int64
		want          int
		wantError     bool
		wantRefsError bool
	}{
		{name: "valid", addr: 0x1360, size: 96, want: 1},
		{name: "old short record at boundary", addr: 0x14b8, size: 72, want: 1},
		{name: "zero-fill tail", addr: 0x1580, size: 96, wantRefsError: true},
		{name: "partial prefix", addr: 0x14f8, size: 96, wantError: true},
		{name: "partial optional tail", addr: 0x14b8, size: 96, wantError: true},
		{
			name: "zero-fill section", addr: 0x1360, size: 96, zeroFill: types.Zerofill,
			wantRefsError: true,
		},
		{name: "custom address reader", addr: 0x1580, size: 96, custom: true, want: 1},
		{
			name: "custom unavailable record", addr: 0x1580, size: 96, custom: true, customLimit: 0x580,
			wantRefsError: true,
		},
		{
			name: "custom partial prefix", addr: 0x1580, size: 96, custom: true, customLimit: 0x588,
			wantError: true,
		},
		{
			name: "custom partial optional tail", addr: 0x1580, size: 96, custom: true,
			customLimit: 0x5c8, wantError: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := protocolBoundsFixture(t, tc.addr, tc.size, tc.zeroFill)
			var configs []macho.FileConfig
			if tc.custom {
				vma := &types.VMAddrConverter{VMAddr2Offet: func(addr uint64) (uint64, error) {
					if addr < 0x1000 || addr-0x1000 >= uint64(len(data)) {
						return 0, fmt.Errorf("unmapped address %#x", addr)
					}
					return addr - 0x1000, nil
				}}
				limit := tc.customLimit
				if limit == 0 {
					limit = int64(len(data))
				}
				reader := types.NewCustomSectionReader(bytes.NewReader(data), vma, 0, limit)
				configs = []macho.FileConfig{{CacheReader: reader}}
			}
			f, err := macho.NewFile(bytes.NewReader(data), configs...)
			if err != nil {
				t.Fatal(err)
			}
			protocols, err := f.GetObjCProtocols()
			if (err != nil) != tc.wantError || len(protocols) != tc.want {
				t.Fatalf("protocols=%v err=%v", protocols, err)
			}
			classes, err := f.GetObjCClasses()
			if tc.wantError {
				if err == nil {
					t.Fatalf("accepted truncated protocol: %v", classes)
				}
			} else if err != nil || len(classes) != 1 ||
				classes[0].Name != "Ordinary" || len(classes[0].Protocols) != tc.want {
				t.Fatalf("classes=%v err=%v", classes, err)
			}
			refs, err := f.GetObjCProtoReferences()
			if (err != nil) != (tc.wantError || tc.wantRefsError) || len(refs) != tc.want {
				t.Fatalf("references=%v err=%v", refs, err)
			}
		})
	}
}

func TestObjCProtocolReferenceUnavailable(t *testing.T) {
	data := protocolBoundsFixture(t, 0x1360, 96, 0)
	const unresolved = uint64(1<<63 | 0x1234)
	binary.LittleEndian.PutUint64(data[0x208:], unresolved)
	f, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if protocols, err := f.GetObjCProtocols(); err != nil || len(protocols) != 0 {
		t.Fatalf("protocols=%v err=%v", protocols, err)
	}
	if refs, err := f.GetObjCProtoReferences(); err == nil || len(refs) != 0 {
		t.Fatalf("unavailable reference silently dropped: refs=%v err=%v", refs, err)
	}
}

func TestObjCProtocolListCountBound(t *testing.T) {
	data := protocolBoundsFixture(t, 0x1360, 96, 0)
	binary.LittleEndian.PutUint64(data[0x370:], 0x1340)
	binary.LittleEndian.PutUint64(data[0x340:], ^uint64(0))
	for _, call := range []struct {
		name string
		run  func(*macho.File) error
	}{
		{"protocols", func(f *macho.File) error { _, err := f.GetObjCProtocols(); return err }},
		{"classes", func(f *macho.File) error { _, err := f.GetObjCClasses(); return err }},
	} {
		t.Run(call.name, func(t *testing.T) {
			f, err := macho.NewFile(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			if err := call.run(f); err == nil || !strings.Contains(err.Error(), "count too large") {
				t.Fatalf("count was not rejected: %v", err)
			}
		})
	}
}

func TestObjCClassRecordFileBounds(t *testing.T) {
	for _, tc := range []struct {
		name      string
		addr      uint64
		wantError bool
	}{
		{"forty-byte record at boundary", 0x14d8, false},
		{"zero-fill alias", 0x1580, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := protocolBoundsFixture(t, 0x1360, 96, 0)
			copy(data[tc.addr-0x1000:tc.addr-0x1000+40], data[0x280:0x2a8])
			binary.LittleEndian.PutUint64(data[0x200:], tc.addr)
			for _, call := range []struct {
				name string
				run  func(*macho.File) error
			}{
				{"class", func(f *macho.File) error { _, err := f.GetObjCClass(tc.addr); return err }},
				{"class2", func(f *macho.File) error { _, err := f.GetObjCClass2(tc.addr); return err }},
				{"classes", func(f *macho.File) error { _, err := f.GetObjCClasses(); return err }},
			} {
				t.Run(call.name, func(t *testing.T) {
					f, err := macho.NewFile(bytes.NewReader(data))
					if err != nil {
						t.Fatal(err)
					}
					if err := call.run(f); (err != nil) != tc.wantError {
						t.Fatalf("error=%v, want error=%t", err, tc.wantError)
					}
				})
			}
		})
	}
}
