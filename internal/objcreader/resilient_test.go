package objcreader_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/go-macho/types/objc"
)

// A non-generic Swift subclass whose Objective-C metadata is allocated from a
// resilient pattern. Addresses and names are synthetic; no compiler is needed.
func newResilientObjCTestFile(t *testing.T) (*macho.File, []byte) {
	t.Helper()
	data := make([]byte, 0x2000)
	f := newObjCTestFile(t, data,
		objcSection("__TEXT", "__swift5_types"),
		objcSection("__DATA", "__objc_stublist"))
	put := func(addr uint64, value any) {
		writeLETestData(t, data[addr-0x1000:], value)
	}
	rel := func(from, to uint64) { put(from, int32(int64(to)-int64(from))) }
	str := func(addr uint64, s string) { copy(data[addr-0x1000:], s+"\x00") }
	f.ByteOrder = binary.LittleEndian
	f.Sections[0].Addr, f.Sections[0].Size = 0x1100, 4
	f.Sections[1].Addr, f.Sections[1].Size = 0x2080, 8
	for i, seg := range f.Segments() {
		seg.Addr, seg.Offset = 0x1000+uint64(i)*0x1000, uint64(i)*0x1000
		seg.Memsz, seg.Filesz = 0x1000, 0x1000
	}
	rel(0x1100, 0x1200)
	put(0x1200, uint32(0x20010050)) // class, unique, singleton, resilient superclass
	rel(0x1204, 0x1280)
	rel(0x1208, 0x1400)
	rel(0x1214, 0x1440)
	put(0x121c, uint32(1)) // ObjC resilient class stub present
	rel(0x122c, 0x1300)    // direct superclass descriptor
	rel(0x1230, 0x20a0)
	rel(0x1234, 0x2100)
	rel(0x123c, 0x2200)
	rel(0x1288, 0x1410)
	put(0x1300, uint32(0x50))
	rel(0x1304, 0x1380)
	rel(0x1308, 0x1420)
	rel(0x1388, 0x1430)
	str(0x1400, "Leaf")
	str(0x1410, "Child")
	str(0x1420, "Parent")
	str(0x1430, "Base")
	data[0x440] = 1
	rel(0x1441, 0x1300) // symbolic superclass name
	str(0x1450, "_TtC5Child4Leaf")
	str(0x1470, "performAction")
	str(0x1490, "v16@0:8")
	str(0x14b0, "make")
	str(0x14c0, "title")
	str(0x14d0, "T@\"NSString\",R")
	put(0x2080, uint64(0x2200))
	put(0x2200, uint64(1))
	rel(0x2110, 0x2300)
	rel(0x2114, 0x2400)
	put(0x2300, objc.ClassRO64{
		NameVMAddr: 0x1450, BaseMethodsVMAddr: 0x2500, BasePropertiesVMAddr: 0x2580,
	})
	put(0x2400, objc.ObjcClass64{DataVMAddrAndFastFlags: 0x2480})
	put(0x2480, objc.ClassRO64{Flags: objc.RO_META, NameVMAddr: 0x1450, BaseMethodsVMAddr: 0x2540})
	for _, entry := range []struct{ addr, name uint64 }{{0x2500, 0x1470}, {0x2540, 0x14b0}} {
		put(entry.addr, uint32(24))
		put(entry.addr+4, uint32(1))
		put(entry.addr+8, [3]uint64{entry.name, 0x1490, 0x1500})
	}
	put(0x2580, uint32(16))
	put(0x2584, uint32(1))
	put(0x2588, [2]uint64{0x14c0, 0x14d0})
	return f, data
}

func TestGetObjCResilientClasses(t *testing.T) {
	f, _ := newResilientObjCTestFile(t)
	for i := 0; i < 2; i++ {
		classes, err := f.GetObjCClasses()
		if err != nil {
			t.Fatal(err)
		}
		if len(classes) != 1 {
			t.Fatalf("classes = %d, want 1", len(classes))
		}
		c := classes[0]
		if c.Name != "_TtC5Child4Leaf" || c.SuperClass != "Base.Parent" ||
			!c.IsSwiftStable || c.ClassPtr != 0x2200 {
			t.Fatalf("unexpected class: %+v", c)
		}
		if len(c.InstanceMethods) != 1 || c.InstanceMethods[0].Name != "performAction" {
			t.Fatalf("instance methods: %+v", c.InstanceMethods)
		}
		if len(c.ClassMethods) != 1 || c.ClassMethods[0].Name != "make" {
			t.Fatalf("class methods: %+v", c.ClassMethods)
		}
		if len(c.Props) != 1 || c.Props[0].Name != "title" {
			t.Fatalf("properties: %+v", c.Props)
		}
	}
}

func TestGetObjCResilientClassesInvalid(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		change     func(*macho.File, []byte)
	}{
		{"truncated stub list", "section size", func(f *macho.File, _ []byte) { f.Sections[1].Size = 7 }},
		{"declared-backed stub", "class stub isa", func(f *macho.File, b []byte) {
			f.Segment("__DATA").Filesz, f.Segment("__DATA").Memsz = 0x2000, 0x2000
			binary.LittleEndian.PutUint64(b[0x1080:], 0x2ffc)
		}},
		{"missing pattern", "missing resilient class metadata pattern",
			func(_ *macho.File, b []byte) { binary.LittleEndian.PutUint32(b[0x234:], 0) }},
		{"missing class RO", "missing Objective-C data", func(_ *macho.File, b []byte) {
			binary.LittleEndian.PutUint32(b[0x1110:], 0)
		}},
		{"missing metaclass", "missing Objective-C data", func(_ *macho.File, b []byte) {
			binary.LittleEndian.PutUint32(b[0x1114:], 0)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, b := newResilientObjCTestFile(t)
			tc.change(f, b)
			_, err := f.GetObjCClasses()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestGetObjCClassesSkipsUnavailableStubs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pointer uint64
		change  func(*macho.File, []byte)
	}{
		{name: "null pointer"},
		{name: "uninitialized", pointer: 0x2800},
		{name: "unsupported isa", pointer: 0x2800, change: func(_ *macho.File, b []byte) {
			binary.LittleEndian.PutUint64(b[0x1800:], 2)
		}},
		{name: "unmapped", pointer: 0x5000},
		{name: "zero-fill tail", pointer: 0x3100, change: func(f *macho.File, _ []byte) {
			f.Segment("__DATA").Memsz = 0x2000
		}},
		{name: "zero-fill aliases file data", pointer: 0x2800, change: func(f *macho.File, b []byte) {
			f.Segment("__DATA").Filesz = 0x800
			binary.LittleEndian.PutUint64(b[0x1800:], 1)
		}},
		{name: "stub crosses file backing", pointer: 0x2800, change: func(f *macho.File, b []byte) {
			f.Segment("__DATA").Filesz = 0x804
			binary.LittleEndian.PutUint64(b[0x1800:], 1)
		}},
		{name: "zero-fill section", pointer: 0x2800, change: func(f *macho.File, b []byte) {
			f.AddSection(&types.Section{SectionHeader: types.SectionHeader{
				Seg: "__DATA", Name: "__bss", Addr: 0x2800, Size: 16, Flags: types.Zerofill,
			}})
			binary.LittleEndian.PutUint64(b[0x1800:], 1)
		}},
		{name: "short read", pointer: 0x2fff, change: func(_ *macho.File, b []byte) {
			b[0x1fff] = 1
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, b := issue93SelectionFixture(t)
			binary.LittleEndian.PutUint64(b[0x1080:], tc.pointer)
			if tc.change != nil {
				tc.change(f, b)
			}
			// Unrecognized stubs must not activate Swift descriptor parsing.
			f.Sections[0].Size = 3
			issue93SelectionExpect(t, f, "Ordinary")
			f.Sections[0].Size = 4
			f.Sections[1].Size = 16
			binary.LittleEndian.PutUint64(b[0x1088:], 0x2200)
			issue93SelectionExpect(t, f, "Ordinary", "_TtC5Child4Leaf")
		})
	}
}

func TestGetObjCClassesSkipsUnavailableResilientPatterns(t *testing.T) {
	for _, tc := range []struct {
		name          string
		pattern       uint64
		zeroFillAddr  uint64
		fileSize      uint64
		keepResilient bool
		badSuperclass bool
	}{
		{name: "zero-fill pattern", pattern: 0x2100, zeroFillAddr: 0x2100},
		{
			name: "unavailable pattern and superclass", pattern: 0x2100, zeroFillAddr: 0x2100,
			badSuperclass: true,
		},
		{name: "zero-fill pattern tail", pattern: 0x2100, zeroFillAddr: 0x2110},
		{name: "crosses file backing", pattern: 0x2800, fileSize: 0x810},
		{
			name: "valid class follows unavailable pattern", pattern: 0x2800, zeroFillAddr: 0x2800,
			keepResilient: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, b := issue93SelectionFixture(t)
			put := func(addr uint64, value any) {
				writeLETestData(t, b[addr-0x1000:], value)
			}
			descriptor := uint64(0x1200)
			want := []string{"Ordinary"}
			if tc.keepResilient {
				// Put an unavailable class before the original valid descriptor.
				descriptor = 0x1600
				copy(b[0x600:0x640], b[0x200:0x240])
				f.Sections[0].Size, f.Sections[1].Size = 12, 16
				put(0x1100, int32(0x1600-0x1100))
				put(0x1104, int32(0x1200-0x1104))
				put(0x1108, int32(0x5000-0x1108)) // unrelated unreadable descriptor
				put(0x1614, int32(0x1440-0x1614))
				put(0x163c, int32(0x2220-0x163c))
				put(0x2080, uint64(0x2220))
				put(0x2088, uint64(0x2200))
				put(0x2220, uint64(1))
				want = append(want, "_TtC5Child4Leaf")
			}
			if tc.zeroFillAddr != 0 {
				f.AddSection(&types.Section{SectionHeader: types.SectionHeader{
					Seg: "__DATA", Name: "__bss", Addr: tc.zeroFillAddr, Size: 0x20, Flags: types.Zerofill,
				}})
			}
			if tc.fileSize != 0 {
				f.Segment("__DATA").Filesz = tc.fileSize
			}
			put(descriptor+0x34, int32(int64(tc.pattern)-int64(descriptor+0x34)))
			if tc.badSuperclass {
				put(descriptor+0x14, int32(0x5000-int64(descriptor+0x14)))
			}
			// These readable bytes do not belong to the in-memory pattern.
			put(tc.pattern+16, uint32(0x80000000))
			put(tc.pattern+20, int32(0x2400-int64(tc.pattern+20)))
			issue93SelectionExpect(t, f, want...)
		})
	}
}

func TestGetObjCResilientClassesCustomAddressReader(t *testing.T) {
	for _, cacheReader := range []bool{false, true} {
		name := "section reader"
		if cacheReader {
			name = "cache reader"
		}
		t.Run(name, func(t *testing.T) {
			fixture, b := newResilientObjCTestFile(t)
			// The caller's address reader supplies valid data outside the
			// embedded Mach-O's file-backed segment range.
			fixture.Segment("__DATA").Filesz = 0x100
			header := types.FileHeader{Magic: types.Magic64, CPU: types.CPUArm64, Type: types.MH_EXECUTE}
			header.Put(b, binary.LittleEndian)
			reader := fixtureReader(fixture, b)
			config := macho.FileConfig{SectionReader: reader}
			if cacheReader {
				config = macho.FileConfig{CacheReader: reader}
			}
			f, err := macho.NewFile(bytes.NewReader(b), config)
			if err != nil {
				t.Fatal(err)
			}
			f.FileTOC = fixture.FileTOC
			classes, err := f.GetObjCClasses()
			if err != nil || len(classes) != 1 || classes[0].Name != "_TtC5Child4Leaf" {
				t.Fatalf("classes=%v err=%v", classes, err)
			}
		})
	}
}

func TestGetObjCResilientClassSelection(t *testing.T) {
	t.Run("no stub list", func(t *testing.T) {
		f, _ := newResilientObjCTestFile(t)
		f.Sections[1].Size = 0
		classes, err := f.GetObjCClasses()
		if err != nil || len(classes) != 0 {
			t.Fatalf("classes=%v err=%v", classes, err)
		}
	})
	t.Run("duplicate stub", func(t *testing.T) {
		f, b := newResilientObjCTestFile(t)
		f.Sections[1].Size = 16
		binary.LittleEndian.PutUint64(b[0x1088:], 0x2200)
		classes, err := f.GetObjCClasses()
		if err != nil || len(classes) != 1 {
			t.Fatalf("classes=%v err=%v", classes, err)
		}
	})
	t.Run("missing descriptor stub flag", func(t *testing.T) {
		f, b := newResilientObjCTestFile(t)
		binary.LittleEndian.PutUint32(b[0x21c:], 0)
		classes, err := f.GetObjCClasses()
		if err != nil || len(classes) != 0 {
			t.Fatalf("classes=%v err=%v", classes, err)
		}
	})
}

func TestGetObjCResilientClassLargeTables(t *testing.T) {
	for _, flag := range []uint32{1 << 31, 1 << 30} {
		f, b := newResilientObjCTestFile(t)
		binary.LittleEndian.PutUint32(b[0x200:], 0x20010050|flag)
		countOffset := 0x23c
		if flag == 1<<31 {
			countOffset += 4
		}
		binary.LittleEndian.PutUint32(b[countOffset:], ^uint32(0))
		_, err := f.GetObjCClasses()
		if err == nil || !strings.Contains(err.Error(), "table count too large") {
			t.Fatalf("flag=%#x err=%v", flag, err)
		}
	}
}

func issue93SelectionFixture(t *testing.T) (*macho.File, []byte) {
	t.Helper()
	f, b := newResilientObjCTestFile(t)

	f.AddSection(&types.Section{SectionHeader: types.SectionHeader{
		Seg: "__DATA", Name: "__objc_classlist", Addr: 0x2090, Size: 8,
	}})
	writeLETestData(t, b[0x1090:], uint64(0x2600))
	writeLETestData(t, b[0x1600:], objc.SwiftClassMetadata64{
		ObjcClass64: objc.ObjcClass64{DataVMAddrAndFastFlags: 0x2700},
	})
	writeLETestData(t, b[0x1700:], objc.ClassRO64{Flags: objc.RO_ROOT, NameVMAddr: 0x15a0})
	copy(b[0x5a0:], "Ordinary\x00")
	return f, b
}

func TestObjCClassAddressAlreadyResolved(t *testing.T) {
	const rawBucket = uint64(0x990000)
	for _, call := range []struct {
		name       string
		run        func(*macho.File, uint64) (*objc.Class, error)
		wantBucket uint64
	}{
		{"class", (*macho.File).GetObjCClass, 0x1700},
		{"class2", (*macho.File).GetObjCClass2, rawBucket},
	} {
		t.Run(call.name, func(t *testing.T) {
			f, data := issue93SelectionFixture(t)
			binary.LittleEndian.PutUint64(data[0x1610:], rawBucket)
			f = reopenFixture(t, f, data, macho.FileConfig{
				VMAddrConverter: types.VMAddrConverter{Converter: func(value uint64) uint64 {
					switch value {
					case rawBucket:
						return 0x1700
					case 0x2600:
						return 0x5000
					default:
						return value
					}
				}},
			})
			class, err := call.run(f, 0x2600)
			if err != nil || class.ClassPtr != 0x2600 ||
				class.MethodCacheBuckets != call.wantBucket {
				t.Fatalf("class=%v err=%v", class, err)
			}
		})
	}
}

func issue93SelectionExpect(t *testing.T, f *macho.File, want ...string) {
	t.Helper()
	classes, err := f.GetObjCClasses()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, class := range classes {
		got = append(got, class.Name)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("class names=%v, want %v", got, want)
	}
}

func TestIssue93SelectionUnbackedDescriptorBeforeValid(t *testing.T) {
	f, b := issue93SelectionFixture(t)
	// __DATA's zero-fill tail is mapped by Memsz onto unrelated file bytes.
	// Those bytes resemble a resilient descriptor with a corrupt vtable.
	b = append(b, make([]byte, 0x1000)...)
	f.Segment("__DATA").Memsz = 0x2000
	f.AddSection(&types.Section{SectionHeader: types.SectionHeader{
		Seg: "__DATA", Name: "__bss", Addr: 0x3000, Size: 0x1000, Flags: types.Zerofill,
	}})
	copy(b[0x2100:0x2140], b[0x200:0x240])
	binary.LittleEndian.PutUint32(b[0x2100:], 0xa0010050)
	binary.LittleEndian.PutUint32(b[0x2140:], ^uint32(0))
	f = reopenFixture(t, f, b)
	f.Sections[0].Size = 8
	binary.LittleEndian.PutUint32(b[0x100:], 0x3100-0x1100)
	binary.LittleEndian.PutUint32(b[0x104:], 0x1200-0x1104)
	issue93SelectionExpect(t, f, "Ordinary", "_TtC5Child4Leaf")
}

func TestIssue93SelectionUnbackedTrailerBeforeValid(t *testing.T) {
	for _, vtable := range []bool{false, true} {
		name := "stub relative pointer"
		if vtable {
			name = "vtable count"
		}
		t.Run(name, func(t *testing.T) {
			f, b := issue93SelectionFixture(t)
			copy(b[0x1800:0x1840], b[0x200:0x240])
			unbacked := uint64(0x283c)
			binary.LittleEndian.PutUint32(b[0x183c:], 0xffffd000)
			if vtable {
				unbacked = 0x2840
				binary.LittleEndian.PutUint32(b[0x1800:], 0xa0010050)
				binary.LittleEndian.PutUint32(b[0x1840:], ^uint32(0))
			}
			f.AddSection(&types.Section{SectionHeader: types.SectionHeader{
				Seg: "__DATA", Name: "__bss", Addr: unbacked, Size: 4, Flags: types.Zerofill,
			}})
			f.Sections[0].Size = 8
			binary.LittleEndian.PutUint32(b[0x100:], 0x2800-0x1100)
			binary.LittleEndian.PutUint32(b[0x104:], 0x1200-0x1104)
			issue93SelectionExpect(t, f, "Ordinary", "_TtC5Child4Leaf")
		})
	}
}

func TestIssue93SelectionUnmatchedSingletonPending(t *testing.T) {
	f, b := issue93SelectionFixture(t)
	f.Sections[0].Size = 8
	f.Sections[1].Size = 16
	binary.LittleEndian.PutUint32(b[0x104:], 0x5000-0x1104)
	binary.LittleEndian.PutUint64(b[0x1088:], 0x2220)
	binary.LittleEndian.PutUint64(b[0x1220:], 1)
	issue93SelectionExpect(t, f, "Ordinary", "_TtC5Child4Leaf")
}

type issue93SelectionHighEntryReader struct {
	types.MachoReader
	addr uint64
	rel  uint32
}

func (r *issue93SelectionHighEntryReader) ReadAtAddr(p []byte, addr uint64) (int, error) {
	if addr == r.addr && len(p) == 4 {
		binary.LittleEndian.PutUint32(p, r.rel)
		return len(p), nil
	}
	return r.MachoReader.ReadAtAddr(p, addr)
}

func TestIssue93SelectionTypeRelativeOverflow(t *testing.T) {
	f, data := newResilientObjCTestFile(t)
	f.Sections[0].Addr = ^uint64(0) - 3
	r := &issue93SelectionHighEntryReader{
		MachoReader: fixtureReader(f, data), addr: f.Sections[0].Addr, rel: 0x1204,
	}
	f = reopenFixture(t, f, data, macho.FileConfig{CacheReader: r})
	classes, err := f.GetObjCClasses()
	if err == nil {
		t.Fatalf("overflowed Swift type reference accepted: classes=%v", classes)
	}
}

func TestIssue93SelectionIndirectPointerConvertsOnce(t *testing.T) {
	f, b := issue93SelectionFixture(t)
	binary.LittleEndian.PutUint32(b[0x100:], (0x1600-0x1100)|1)
	binary.LittleEndian.PutUint64(b[0x600:], 0x3300)
	convert := func(value uint64) uint64 {
		switch value {
		case 0x3300:
			return 0x1200
		case 0x1200:
			return 0x5000
		default:
			return value
		}
	}
	f = reopenFixture(t, f, b, macho.FileConfig{
		VMAddrConverter: types.VMAddrConverter{Converter: convert},
	})
	issue93SelectionExpect(t, f, "Ordinary", "_TtC5Child4Leaf")
}

func TestIssue93SelectionTruncatedIndirectPointer(t *testing.T) {
	f, b := issue93SelectionFixture(t)
	binary.LittleEndian.PutUint32(b[0x100:], (0x2ffc-0x1100)|1)
	f.Segment("__DATA").Filesz = 0x2000
	f.Segment("__DATA").Memsz = 0x2000
	if _, err := f.GetObjCClasses(); err == nil {
		t.Fatal("physically truncated indirect pointer must remain an error")
	}
}

func TestIssue93SelectionTruncatedDescriptor(t *testing.T) {
	for _, tc := range []struct {
		name   string
		addr   uint64
		vtable bool
	}{
		{"flags", 0x2ffe, false},
		{"descriptor", 0x2fd6, false},
		{"singleton", 0x2fca, false},
		{"vtable count", 0x2fc0, true},
		{"stub info", 0x2fc2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, data := issue93SelectionFixture(t)
			copy(data[tc.addr-0x1000:], data[0x200:0x240])
			if tc.vtable {
				binary.LittleEndian.PutUint32(data[tc.addr-0x1000:], 0xa0010050)
			}
			binary.LittleEndian.PutUint32(data[0x100:], uint32(tc.addr-0x1100))
			f.Segment("__DATA").Filesz = 0x2000
			f.Segment("__DATA").Memsz = 0x2000
			_, err := f.GetObjCClasses()
			if !errors.Is(err, io.EOF) {
				t.Fatalf("declared-backed short read: %v, want EOF", err)
			}
		})
	}
}

func TestIssue93SelectionPartialStubList(t *testing.T) {
	for _, tc := range []struct {
		name          string
		zeroFill      uint64
		size          uint64
		wantResilient bool
	}{
		{"unbacked first entry", 0x2080, 16, true},
		{"unbacked last entry", 0x2088, 16, true},
		{"partial only entry", 0x2084, 8, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, data := issue93SelectionFixture(t)
			f.Sections[1].Size = tc.size
			binary.LittleEndian.PutUint64(data[0x1088:], 0x2200)
			f.AddSection(&types.Section{SectionHeader: types.SectionHeader{
				Seg: "__DATA", Name: "__bss", Addr: tc.zeroFill,
				Size: 4, Flags: types.Zerofill,
			}})
			want := []string{"Ordinary"}
			if tc.wantResilient {
				want = append(want, "_TtC5Child4Leaf")
			}
			issue93SelectionExpect(t, f, want...)
		})
	}
}

func TestGetObjCClassesSwiftSuperclassFileData(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fileSize uint64
		custom   bool
		wantErr  bool
		wantSkip bool
	}{
		{name: "unbacked control stream", fileSize: 0x800, wantSkip: true},
		{name: "terminator outside file extent", fileSize: 0x80f, wantErr: true},
		{name: "complete control stream", fileSize: 0x810},
		{name: "configured reader", fileSize: 0x800, custom: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, data := issue93SelectionFixture(t)
			f.Segment("__DATA").Filesz = tc.fileSize
			binary.LittleEndian.PutUint32(data[0x214:], 0x2800-0x1214)
			copy(data[0x1800:], "AliasSuperclass\x00")
			if tc.custom {
				f = reopenFixture(t, f, data, macho.FileConfig{
					CacheReader: fixtureReader(f, data),
				})
			}
			classes, err := f.GetObjCClasses()
			if tc.wantSkip {
				if err != nil || len(classes) != 1 || classes[0].Name != "Ordinary" {
					t.Fatalf("classes = %+v, err = %v, want unavailable class skipped", classes, err)
				}
				return
			}
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "swift symbolic control-data decode failed") {
					t.Fatalf("classes = %+v, err = %v, want symbolic control-data error", classes, err)
				}
				return
			}
			if err != nil || len(classes) != 2 || classes[1].SuperClass != "_$sAliasSuperclass" {
				t.Fatalf("classes = %+v, err = %v", classes, err)
			}
		})
	}
}

func TestGetObjCClassesSwiftASCIITypeFileData(t *testing.T) {
	for _, tc := range []struct {
		name string
		addr uint64
		want string
	}{
		{name: "backed string", addr: 0x27f0, want: "Alias.Type"},
		{name: "unbacked string", addr: 0x27ff},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, data := newResilientObjCTestFile(t)
			f.Segment("__DATA").Filesz = 0x800
			binary.LittleEndian.PutUint64(data[0x1330:], 0x2600) // class_ro_t.ivars
			writeLETestData(t, data[0x1600:],
				objc.IvarList{EntSize: uint32(binary.Size(objc.IvarT{})), Count: 1},
				objc.IvarT{NameVMAddr: 0x14c0, TypesVMAddr: tc.addr})
			copy(data[tc.addr-0x1000:], "\x00Alias.Type\x00")
			classes, err := f.GetObjCClasses()
			if err != nil || len(classes) != 1 ||
				len(classes[0].Ivars) != 1 || classes[0].Ivars[0].Type != tc.want {
				t.Fatalf("classes = %+v, err = %v, want ivar type %q", classes, err, tc.want)
			}
		})
	}
}
