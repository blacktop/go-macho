package objcreader_test

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/go-macho/types/objc"
)

func TestGetObjCIntegerObjectsKeepDistinctRecords(t *testing.T) {
	data := make([]byte, 0x200)
	f := newObjCTestFile(t, data, objcSection("__TEXT", "__objc_intobj"))
	want := []objc.IntObj{{ISA: 1, Number: 17}, {ISA: 2, Number: 29}}
	writeLETestData(t, data[0x100:], want)
	f.Sections[0].Addr, f.Sections[0].Size = 0x100, uint64(binary.Size(want))
	f = reopenFixture(t, f, data, macho.FileConfig{CacheReader: identityReader(data)})
	got, err := f.GetObjCIntegerObjects()
	if err != nil || len(got) != len(want) {
		t.Fatalf("objects=%v error=%v", got, err)
	}
	for i, value := range want {
		addr := uint64(0x100 + i*binary.Size(value))
		if got[addr] == nil || *got[addr] != value {
			t.Fatalf("at %#x got %v, want %+v", addr, got[addr], value)
		}
	}
}

// An in-memory Mach-O model with C literals, os_log, and 64-bit CFString records.
func newCStringSectionFile(t *testing.T) (*macho.File, []byte) {
	t.Helper()
	data := make([]byte, 0x400)
	f := newObjCTestFile(t, data, objcSection("__TEXT", "__cstring"),
		objcSection("__TEXT", "__os_log"), objcSection("__DATA", "__cfstring"))
	literal := "hello\x00\x00bad\x01\x00\x00hello\x00世界 🌍\x00tail"
	copy(data[0x100:], literal)
	copy(data[0x180:], "log\x00unfinished")
	copy(data[0x1a0:], "outside\x00")
	copy(data[0x1c0:], []byte{'A', 0, 0x3d, 0xd8, 0, 0xde})
	f.Sections[0].Addr, f.Sections[0].Size = 0x100, uint64(len(literal))
	f.Sections[0].Flags = types.CstringLiterals
	f.Sections[1].Addr, f.Sections[1].Size = 0x180, 14
	entries := []objc.CFString64Type{
		{Info: objc.CFStringEncodingASCII, Data: 0x100, Length: 5},
		{Info: objc.CFStringEncodingASCII, Data: 0x106},
		{Info: objc.CFStringEncodingASCII, Data: 0x107, Length: 4},
		{Info: objc.CFStringEncodingASCII, Data: 0x1a0, Length: 7},
		{Info: objc.CFStringEncodingUnicode, Data: 0x1c0, Length: 3},
		{Info: objc.CFStringEncodingASCII, Data: 0x102, Length: 1}, // Length does not bound C strings.
	}
	var records bytes.Buffer
	if err := binary.Write(&records, f.ByteOrder, entries); err != nil {
		t.Fatal(err)
	}
	copy(data[0x200:], records.Bytes())
	f.Sections[2].Addr, f.Sections[2].Size = 0x200, uint64(records.Len())
	f = reopenFixture(t, f, data, macho.FileConfig{CacheReader: identityReader(data)})
	return f, data
}

func TestGetCFStringsSectionText(t *testing.T) {
	f, data := newCStringSectionFile(t)
	f.AddSegment(&macho.Segment{SegmentHeader: macho.SegmentHeader{
		LoadCmd: types.LC_SEGMENT_64, Name: "__DATA_CONST",
	}})
	f.AddSection(&types.Section{SectionHeader: types.SectionHeader{
		Seg: "__DATA_CONST", Name: "__cfstring", Addr: 0x300, Size: 64,
	}})
	writeLETestData(t, data[0x300:],
		objc.CFString64Type{Info: objc.CFStringEncodingASCII, Data: 0x180, Length: 3},
		objc.CFString64Type{Info: objc.CFStringEncodingASCII, Data: 0x1a0, Length: 7})
	got, err := f.GetCFStrings()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"hello", "", "bad\x01", "outside", "A😀", "llo", "log", "outside"}
	if len(got) != len(want) {
		t.Fatalf("got %d strings", len(got))
	}
	for i, s := range got {
		addr := 0x200 + uint64(i*32)
		if i >= 6 {
			addr = 0x300 + uint64((i-6)*32)
		}
		if s.Name != want[i] || s.Address != addr {
			t.Fatalf("entry %d: %#v", i, s)
		}
	}
}

func TestGetCFStringsSectionFallback(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*macho.File)
	}{
		{"terminator outside section", func(f *macho.File) { f.Sections[0].Size = 3 }},
		{"unreadable whole section", func(f *macho.File) { f.Sections[0].Size = 0x1000 }},
		{"nonliteral section", func(f *macho.File) { f.Sections[0].Flags = 0 }},
		{"UTF16 inside literal section", func(f *macho.File) { f.Sections[0].Size = 0x100 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _ := newCStringSectionFile(t)
			tc.change(f)
			got, err := f.GetCFStrings()
			if err != nil {
				t.Fatal(err)
			}
			want := []string{"hello", "", "bad\x01", "outside", "A😀", "llo"}
			if len(got) != len(want) {
				t.Fatalf("got %d strings, want %d", len(got), len(want))
			}
			for i, value := range got {
				if value.Name != want[i] {
					t.Fatalf("at %#x got %q, want %q", value.Data, value.Name, want[i])
				}
			}
		})
	}
}

type cstringSectionReadCounter struct {
	types.MachoReader
	sectionReads int
}

func (r *cstringSectionReadCounter) ReadAtAddr(p []byte, addr uint64) (int, error) {
	if addr == 0x100 && len(p) < 0x1000 {
		r.sectionReads++
	}
	return r.MachoReader.ReadAtAddr(p, addr)
}

func TestGetCFStringsSectionReadOnce(t *testing.T) {
	f, data := newCStringSectionFile(t)
	r := &cstringSectionReadCounter{MachoReader: identityReader(data)}
	f = reopenFixture(t, f, data, macho.FileConfig{CacheReader: r})
	for call := 1; call <= 2; call++ {
		if _, err := f.GetCFStrings(); err != nil {
			t.Fatal(err)
		}
		if r.sectionReads != call {
			t.Fatalf("after call %d, section reads = %d", call, r.sectionReads)
		}
	}
}

func TestGetCFStringsSectionErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		addr uint64
		want string
	}{
		{"zero", 0, "unhandled cstring parse case where data is 0"},
		{"unmapped", 0x500,
			"failed to read cfstring: " + macho.ErrCStringNotFound.Error() + " at address 0x500"},
		{"unterminated", 0x3fc,
			"failed to read cfstring: " + macho.ErrCStringNoTerminator.Error() + " at address 0x3fc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, data := newCStringSectionFile(t)
			f.ByteOrder.PutUint64(data[0x210:], tc.addr)
			copy(data[0x3fc:], "tail")
			if _, err := f.GetCFStrings(); err == nil || err.Error() != tc.want {
				t.Fatalf("got %v; want %s", err, tc.want)
			}
		})
	}
}

func TestGetCFStringsBigEndianRecords(t *testing.T) {
	f, data := newCStringSectionFile(t)
	want, err := f.GetCFStrings()
	if err != nil {
		t.Fatal(err)
	}
	var records bytes.Buffer
	for _, s := range want {
		if err := binary.Write(&records, binary.BigEndian, s.CFString64Type); err != nil {
			t.Fatal(err)
		}
	}
	copy(data[0x200:], records.Bytes())
	// Swap the UTF-16 code units along with the record byte order.
	for i := 0x1c0; i < 0x1c6; i += 2 {
		data[i], data[i+1] = data[i+1], data[i]
	}
	f.ByteOrder = binary.BigEndian
	got, err := f.GetCFStrings()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v; want %#v", got, want)
	}
}

func TestGetCStringsSectionText(t *testing.T) {
	f, data := newCStringSectionFile(t)
	got, err := f.GetCStrings()
	want := map[string]map[string]uint64{
		"__TEXT.__cstring": {"hello": 0x10d, "世界 🌍": 0x113},
		"__TEXT.__os_log":  {"log": 0x180},
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, %v; want %#v", got, err, want)
	}
	f = reopenFixture(t, f, data, macho.FileConfig{CacheReader: identityReader(nil)})
	wantErr := "failed to read cstring data in __TEXT.__cstring: EOF"
	if _, err := f.GetCStrings(); err == nil || err.Error() != wantErr {
		t.Fatalf("read error: %v", err)
	}
}
