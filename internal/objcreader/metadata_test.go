package objcreader_test

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/go-macho/types/objc"
)

func TestObjCMetadataListCountBounds(t *testing.T) {
	for _, tc := range []struct {
		name string
		addr uint64
		run  func(*macho.File, uint64) error
	}{
		{"methods", 0x2500, func(f *macho.File, addr uint64) error {
			_, err := f.GetObjCMethods(addr)
			return err
		}},
		{"ivars", 0x2600, func(f *macho.File, addr uint64) error {
			_, err := f.GetObjCIvars(addr)
			return err
		}},
		{"properties", 0x2580, func(f *macho.File, addr uint64) error {
			_, err := f.GetObjCProperties(addr)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, b := newResilientObjCTestFile(t)
			f = reopenFixture(t, f, b, macho.FileConfig{CacheReader: fixtureReader(f, b)})
			binary.LittleEndian.PutUint32(b[tc.addr-0x1000+4:], ^uint32(0))
			if err := tc.run(f, tc.addr); err == nil || !strings.Contains(err.Error(), "count too large") {
				t.Fatalf("count was not rejected: %v", err)
			}
		})
	}
}

func TestObjCIvarOffsetBacking(t *testing.T) {
	for _, tc := range []struct {
		name      string
		addr      uint64
		zeroFill  bool
		readerEnd int
		want      uint32
		wantError bool
	}{
		{name: "null"},
		{name: "backed", addr: 0x2680, want: 0xfeedbeef},
		{name: "segment zero fill", addr: 0x2800},
		{name: "section zero fill", addr: 0x2680, zeroFill: true},
		{name: "partial backing", addr: 0x27fe, wantError: true},
		{name: "unmapped", addr: 0x5000, wantError: true},
		{name: "unresolved bind", addr: 1<<63 | 0x1234, wantError: true},
		{name: "configured EOF", addr: 0x2800, readerEnd: 0x1800},
		{name: "configured short read", addr: 0x27fe, readerEnd: 0x1800, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, data := newResilientObjCTestFile(t)
			f.Segment("__DATA").Filesz = 0x800
			binary.LittleEndian.PutUint64(data[0x1330:], 0x2600)
			writeLETestData(t, data[0x1600:], objc.IvarList{EntSize: 32, Count: 1},
				objc.IvarT{Offset: tc.addr, NameVMAddr: 0x1570, TypesVMAddr: 0x1590})
			copy(data[0x570:], "ivar\x00")
			copy(data[0x590:], "Q\x00")
			if tc.addr >= 0x1000 && tc.addr <= 0x2ffc {
				binary.LittleEndian.PutUint32(data[tc.addr-0x1000:], 0xfeedbeef)
			}
			if tc.zeroFill {
				f.AddSection(&types.Section{SectionHeader: types.SectionHeader{
					Seg: "__DATA", Name: "__common", Addr: tc.addr,
					Size: 4, Flags: types.Zerofill,
				}})
			}
			if tc.readerEnd != 0 {
				f = reopenFixture(t, f, data, macho.FileConfig{
					CacheReader: fixtureReader(f, data[:tc.readerEnd]),
				})
			}
			classes, err := f.GetObjCClasses()
			if tc.wantError {
				if err == nil {
					t.Fatalf("invalid offset accepted: %v", classes)
				}
				return
			}
			if err != nil || len(classes) != 1 ||
				len(classes[0].Ivars) != 1 || classes[0].Ivars[0].Offset != tc.want {
				t.Fatalf("classes=%v err=%v", classes, err)
			}
		})
	}
}

func TestObjCRelativeSelectorSlotFileBounds(t *testing.T) {
	for _, tc := range []struct {
		name      string
		slot      uint64
		custom    bool
		wantError bool
	}{
		{"backed", 0x1600, false, false},
		{"zero-fill slot", 0x2800, false, true},
		{"custom address reader", 0x2800, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, b := newResilientObjCTestFile(t)
			f.Segment("__DATA").Filesz = 0x800
			if tc.custom {
				f = reopenFixture(t, f, b, macho.FileConfig{CacheReader: fixtureReader(f, b)})
			}
			binary.LittleEndian.PutUint32(b[0x1500:], 1<<31|12)
			binary.LittleEndian.PutUint32(b[0x1508:], uint32(int32(int64(tc.slot)-0x2508)))
			binary.LittleEndian.PutUint32(b[0x150c:], uint32(0xffffef84))
			binary.LittleEndian.PutUint32(b[0x1510:], uint32(0xffffeff0))
			binary.LittleEndian.PutUint64(b[tc.slot-0x1000:], 0x1470)
			classes, err := f.GetObjCClasses()
			if tc.wantError {
				if err == nil {
					t.Fatalf("accepted aliased selector: %v", classes)
				}
			} else if err != nil || len(classes) != 1 ||
				len(classes[0].InstanceMethods) != 1 ||
				classes[0].InstanceMethods[0].Name != "performAction" {
				t.Fatalf("classes=%v err=%v", classes, err)
			}
		})
	}
}

func TestObjCRequiredResourceFileBounds(t *testing.T) {
	type change struct {
		name  string
		patch func([]byte)
	}
	put64 := func(b []byte, addr, value uint64) {
		binary.LittleEndian.PutUint64(b[addr-0x1000:], value)
	}
	put32 := func(b []byte, addr uint64, value uint32) {
		binary.LittleEndian.PutUint32(b[addr-0x1000:], value)
	}
	rel := func(b []byte, from, to uint64) { put32(b, from, uint32(int32(int64(to)-int64(from)))) }
	clone := func(b []byte, from, to, size uint64) {
		copy(b[to-0x1000:to-0x1000+size], b[from-0x1000:from-0x1000+size])
	}
	str := func(b []byte, addr uint64, value string) { copy(b[addr-0x1000:], value+"\x00") }
	write := func(b []byte, addr uint64, value any) {
		writeLETestData(t, b[addr-0x1000:], value)
	}
	protocol := func(b []byte, list, record, name uint64) {
		put64(b, 0x2328, list)
		put64(b, list, 1)
		put64(b, list+8, record)
		write(b, record, objc.ProtocolT{NameVMAddr: name, Size: 96})
		str(b, name, "AliasProtocol")
	}
	ivar := func(b []byte, list, offset uint64) {
		put64(b, 0x2330, list)
		write(b, list, objc.IvarList{EntSize: 32, Count: 1})
		write(b, list+8, objc.IvarT{
			Offset: offset, NameVMAddr: 0x1570, TypesVMAddr: 0x1590,
			AlignmentRaw: 3, Size: 8,
		})
		str(b, 0x1570, "aliasIvar")
		str(b, 0x1590, "Q")
		put32(b, offset, 0xfeedbeef)
	}
	tests := []change{
		{"class-ro", func(b []byte) { clone(b, 0x2300, 0x2800, 72); rel(b, 0x2110, 0x2800) }},
		{"class-ro-tail", func(b []byte) { clone(b, 0x2300, 0x27e0, 72); rel(b, 0x2110, 0x27e0) }},
		{"metaclass", func(b []byte) { clone(b, 0x2400, 0x2800, 40); rel(b, 0x2114, 0x2800) }},
		{"metaclass-ro", func(b []byte) { clone(b, 0x2480, 0x2800, 72); put64(b, 0x2420, 0x2800) }},
		{"class-name", func(b []byte) { put64(b, 0x2318, 0x2800); str(b, 0x2800, "AliasClass") }},
		{"method-list", func(b []byte) { clone(b, 0x2500, 0x2800, 32); put64(b, 0x2320, 0x2800) }},
		{"method-entry-tail", func(b []byte) { clone(b, 0x2500, 0x27f0, 32); put64(b, 0x2320, 0x27f0) }},
		{"method-selector", func(b []byte) { put64(b, 0x2508, 0x2800); str(b, 0x2800, "aliasMethod") }},
		{"method-types", func(b []byte) { put64(b, 0x2510, 0x2800); str(b, 0x2800, "i@:") }},
		{"property-list", func(b []byte) { clone(b, 0x2580, 0x2800, 24); put64(b, 0x2340, 0x2800) }},
		{"property-name", func(b []byte) { put64(b, 0x2588, 0x2800); str(b, 0x2800, "aliasProperty") }},
		{"property-attributes", func(b []byte) { put64(b, 0x2590, 0x2800); str(b, 0x2800, "TQ,R") }},
		{"protocol-list", func(b []byte) { protocol(b, 0x2800, 0x2640, 0x1570) }},
		{"protocol-record", func(b []byte) { protocol(b, 0x2600, 0x2800, 0x1570) }},
		{"protocol-name", func(b []byte) { protocol(b, 0x2600, 0x2640, 0x2800) }},
		{"ivar-list", func(b []byte) { ivar(b, 0x2800, 0x2600) }},
		{"ivar-offset", func(b []byte) { ivar(b, 0x2600, 0x2800) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, b := newResilientObjCTestFile(t)
			f.Segment("__DATA").Filesz = 0x800
			tc.patch(b)
			classes, err := f.GetObjCClasses()
			var expected func(objc.Class) bool
			switch tc.name {
			case "method-selector":
				expected = func(c objc.Class) bool {
					return len(c.InstanceMethods) == 1 &&
						c.InstanceMethods[0].Name == "/* unresolved selector at 0x2800 */"
				}
			case "method-types":
				expected = func(c objc.Class) bool {
					return len(c.InstanceMethods) == 1 &&
						c.InstanceMethods[0].Types == "/* unresolved method types at 0x2800 */"
				}
			case "property-name":
				expected = func(c objc.Class) bool {
					return len(c.Props) == 1 && c.Props[0].Name == `@"SwiftUnresolved_0x2800"`
				}
			case "property-attributes":
				expected = func(c objc.Class) bool {
					return len(c.Props) == 1 && c.Props[0].EncodedAttributes == `@"SwiftUnresolved_0x2800"`
				}
			case "protocol-record":
				expected = func(c objc.Class) bool { return len(c.Protocols) == 0 }
			case "ivar-offset":
				expected = func(c objc.Class) bool { return len(c.Ivars) == 1 && c.Ivars[0].Offset == 0 }
			}
			if expected != nil {
				if err != nil || len(classes) != 1 || !expected(classes[0]) {
					t.Fatalf("classes=%#v err=%v", classes, err)
				}
			} else if err == nil {
				t.Fatalf("required unbacked resource accepted: %#v", classes)
			}
		})
	}
}
