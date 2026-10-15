package macho

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/blacktop/go-macho/types"
)

// The module at 0x1900 names a parent whose bytes are at file offset 0x1800.
// When __DATA's file extent is shorter than 0x80c, some or all of those bytes
// belong to the following __LINKEDIT segment instead of the parent's address.
func swiftContextFixture(parent, dataFileSize, zeroFillAddr uint64) []byte {
	segmentSize := uint32(binary.Size(types.Segment64{}))
	sectionSize := uint32(binary.Size(types.Section64{}))
	text := Segment{SegmentHeader: SegmentHeader{
		LoadCmd: types.LC_SEGMENT_64, Len: segmentSize + sectionSize, Name: "__TEXT",
		Addr: 0x1000, Memsz: 0x1000, Filesz: 0x1000, Nsect: 1,
	}}
	typesSection := types.Section{SectionHeader: types.SectionHeader{
		Seg: "__TEXT", Name: "__swift5_types", Addr: 0x1800, Offset: 0x800, Size: 4,
	}}
	dataSegment := Segment{SegmentHeader: SegmentHeader{
		LoadCmd: types.LC_SEGMENT_64, Len: segmentSize, Name: "__DATA",
		Addr: 0x2000, Memsz: 0x1000, Offset: 0x1000, Filesz: dataFileSize,
	}}
	zeroFill := types.Section{SectionHeader: types.SectionHeader{
		Seg: "__DATA", Name: "__bss", Addr: zeroFillAddr, Size: 0x10, Flags: types.Zerofill,
	}}
	if zeroFillAddr != 0 {
		dataSegment.Len += sectionSize
		dataSegment.Nsect = 1
	}
	linkedit := Segment{SegmentHeader: SegmentHeader{
		LoadCmd: types.LC_SEGMENT_64, Len: segmentSize, Name: "__LINKEDIT",
		Addr: 0x4000, Memsz: 0x1000, Offset: 0x1000 + dataFileSize, Filesz: 0x1000,
	}}
	header := types.FileHeader{
		Magic: types.Magic64, CPU: types.CPUArm64, Type: types.MH_EXECUTE,
		NCommands: 3, SizeCommands: text.Len + dataSegment.Len + linkedit.Len,
	}
	data := make([]byte, linkedit.Offset+linkedit.Filesz)
	order := binary.LittleEndian
	off := header.Put(data, order)
	off += text.Put64(data[off:], order)
	off += typesSection.Put64(data[off:], order)
	off += dataSegment.Put64(data[off:], order)
	if zeroFillAddr != 0 {
		off += zeroFill.Put64(data[off:], order)
	}
	linkedit.Put64(data[off:], order)
	order.PutUint32(data[0x800:], 0x1900-0x1800)
	order.PutUint32(data[0x900:], 0x40) // unique module context
	order.PutUint32(data[0x904:], uint32(int32(int64(parent)-0x1904)))
	order.PutUint32(data[0x908:], 0x1a00-0x1908)
	copy(data[0xa00:], "Leaf\x00Parent\x00")
	order.PutUint32(data[0x1800:], 0x40)
	order.PutUint32(data[0x1808:], uint32(int32(0x1a05-int64(parent+8))))
	return data
}

func checkSwiftContextParent(t *testing.T, f *File, want string) {
	t.Helper()
	typs, err := f.GetSwiftTypes()
	if err != nil {
		t.Fatal(err)
	}
	if len(typs) != 1 || typs[0].Name != "Leaf" ||
		typs[0].Parent == nil || typs[0].Parent.Name != want {
		t.Fatalf("types = %+v, want Leaf with parent %q", typs, want)
	}
}

func TestGetSwiftTypesParentFileData(t *testing.T) {
	for _, tc := range []struct {
		name         string
		parent       uint64
		fileSize     uint64
		zeroFillAddr uint64
		symbol       bool
		want         string
	}{
		{name: "outside image", parent: 0x5000, fileSize: 0x800},
		{name: "segment zero-fill alias", parent: 0x2800, fileSize: 0x800},
		{name: "descriptor crosses file extent", parent: 0x2800, fileSize: 0x80b},
		{
			name: "last descriptor byte is zero-fill", parent: 0x2800, fileSize: 0x1000,
			zeroFillAddr: 0x280b,
		},
		{name: "complete descriptor", parent: 0x2800, fileSize: 0x80c, want: "Parent"},
		{name: "symbol fallback", parent: 0x2800, fileSize: 0x800, symbol: true, want: "_Parent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := swiftContextFixture(tc.parent, tc.fileSize, tc.zeroFillAddr)
			f, err := NewFile(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			if tc.symbol {
				f.Symtab = &Symtab{Syms: []Symbol{{
					Name: "_Parent", Type: types.N_SECT | types.N_EXT, Value: tc.parent,
				}}}
			}
			checkSwiftContextParent(t, f, tc.want)
		})
	}
}

func swiftIndirectContextFixture(parent, fileSize, zeroFillAddr, pointer uint64) []byte {
	data := swiftContextFixture(parent, fileSize, zeroFillAddr)
	binary.LittleEndian.PutUint64(data[0x1800:], pointer)
	binary.LittleEndian.PutUint32(data[0x940:], 0x40)
	binary.LittleEndian.PutUint32(data[0x948:], 0x1a05-0x1948)
	return data
}

func TestGetSwiftTypesIndirectParentFileData(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fileSize uint64
		bind     bool
		want     string
	}{
		{name: "zero-fill slot", fileSize: 0x800},
		{name: "truncated slot", fileSize: 0x807},
		{name: "backed slot", fileSize: 0x808, want: "Parent"},
		{name: "slot bind fallback", fileSize: 0x800, bind: true, want: "_BoundParent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := swiftIndirectContextFixture(0x2801, tc.fileSize, 0, 0x1940)
			f, err := NewFile(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			if tc.bind {
				f.Loads = append(f.Loads, &DyldInfoOnly{})
				f.binds = types.Binds{{Name: "_BoundParent", Start: 0x2800}}
			}
			checkSwiftContextParent(t, f, tc.want)
		})
	}
}

func TestGetSwiftTypesIndirectParentConvertsOnce(t *testing.T) {
	const rawPointer = 0xfeed00001940
	data := swiftIndirectContextFixture(0x2801, 0x808, 0, rawPointer)
	base, err := NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	vma := types.VMAddrConverter{
		Converter: func(value uint64) uint64 {
			switch value {
			case rawPointer:
				return 0x1940
			case 0x1940:
				return 0x5000
			default:
				return value
			}
		},
		VMAddr2Offet: base.GetOffset,
		Offet2VMAddr: base.GetVMAddress,
	}
	f, err := NewFile(bytes.NewReader(data), FileConfig{VMAddrConverter: vma})
	if err != nil {
		t.Fatal(err)
	}
	checkSwiftContextParent(t, f, "Parent")
}

func newSwiftExternalAddressFile(t *testing.T, data []byte) *File {
	t.Helper()
	base, err := NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	vma := &types.VMAddrConverter{
		Converter: func(addr uint64) uint64 { return addr },
		VMAddr2Offet: func(addr uint64) (uint64, error) {
			if addr >= 0x5000 && addr < 0x5100 {
				return 0x1800 + addr - 0x5000, nil
			}
			return base.GetOffset(addr)
		},
		Offet2VMAddr: base.GetVMAddress,
	}
	reader := types.NewCustomSectionReader(bytes.NewReader(data), vma, 0, int64(len(data)))
	f, err := NewFile(bytes.NewReader(data), FileConfig{CacheReader: reader})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestGetSwiftTypesParentCustomAddressReader(t *testing.T) {
	data := swiftContextFixture(0x5000, 0x800, 0)
	checkSwiftContextParent(t, newSwiftExternalAddressFile(t, data), "Parent")
	data = swiftIndirectContextFixture(0x5001, 0x800, 0, 0x1940)
	checkSwiftContextParent(t, newSwiftExternalAddressFile(t, data), "Parent")
}

func swiftStringTypeRefFixture(fileSize uint64, payload []byte) []byte {
	data := swiftContextFixture(0x2800, fileSize, 0)
	section := types.Section{SectionHeader: types.SectionHeader{
		Seg: "__TEXT", Name: "__swift5_typeref", Addr: 0x1900, Offset: 0x900, Size: 6,
	}}
	section.Put64(data[types.FileHeaderSize64+binary.Size(types.Segment64{}):], binary.LittleEndian)
	// The unsupported 0x03 control byte makes GetSwiftTypeRefs try the
	// relative-string fallback, whose header points at 0x2803.
	binary.LittleEndian.PutUint64(data[0x900:], 0xf03)
	for i := 0x1800; i < len(data); i++ {
		data[i] = 0
	}
	copy(data[0x1803:], payload)
	return data
}

func TestGetSwiftTypeRefsFallbackFileData(t *testing.T) {
	const rawHeader = "\x03\x0f"
	for _, tc := range []struct {
		name            string
		fileSize        uint64
		payload         []byte
		truncatedHeader bool
		symbolic        bool
		want            string
	}{
		{
			name: "backed header unbacked target", fileSize: 0x800, payload: []byte("AliasProperty\x00"),
			want: rawHeader,
		},
		{
			name: "truncated header", fileSize: 0x1000, payload: []byte("AliasProperty\x00"),
			truncatedHeader: true, want: rawHeader,
		},
		{
			name: "terminator outside file extent", fileSize: 0x810,
			payload: []byte("AliasProperty\x00"), want: rawHeader,
		},
		{
			name: "terminator at file boundary", fileSize: 0x811, payload: []byte("AliasProperty\x00"),
			want: "_$sAliasProperty",
		},
		{
			name: "collected string has unbacked tail", fileSize: 0x813,
			payload: []byte("\x03\x00\x00\x00\x00\x00Alias.Type\x00"), want: rawHeader,
		},
		{
			name: "complete collected string", fileSize: 0x814,
			payload: []byte("\x03\x00\x00\x00\x00\x00Alias.Type\x00"), want: "Alias.Type",
		},
		{
			name: "symbolic reference payload", fileSize: 0x1000, payload: []byte{1, 0xfc, 0, 0, 0, 0},
			symbolic: true, want: "Parent",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := swiftStringTypeRefFixture(tc.fileSize, tc.payload)
			if tc.truncatedHeader {
				binary.LittleEndian.PutUint64(data[types.FileHeaderSize64+48:], 0x906)
			}
			if tc.symbolic {
				binary.LittleEndian.PutUint32(data[0x1900:], 0x40)
				nameOffset := int32(0x1a05 - 0x2908)
				binary.LittleEndian.PutUint32(data[0x1908:], uint32(nameOffset))
			}
			f, err := NewFile(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			refs, err := f.GetSwiftTypeRefs()
			if err != nil || len(refs) != 1 || refs[0x1900] != tc.want {
				t.Fatalf("type refs = %q, err = %v, want %q", refs, err, tc.want)
			}
		})
	}
}

func TestGetSwiftTypeRefsFallbackCustomAddressReader(t *testing.T) {
	data := swiftStringTypeRefFixture(0x800, []byte("AliasProperty\x00"))
	binary.LittleEndian.PutUint64(data[0x900:], 0x3703) // target 0x5003
	f := newSwiftExternalAddressFile(t, data)
	refs, err := f.GetSwiftTypeRefs()
	if err != nil || len(refs) != 1 || refs[0x1900] != "_$sAliasProperty" {
		t.Fatalf("type refs = %q, err = %v", refs, err)
	}
}

type swiftBackingReadCounter struct {
	*bytes.Reader
	end     int64
	active  bool
	pastEnd int
}

func (r *swiftBackingReadCounter) ReadAt(p []byte, off int64) (int, error) {
	if r.active && (off < 0 || off > r.end || int64(len(p)) > r.end-off) {
		r.pastEnd++
	}
	return r.Reader.ReadAt(p, off)
}

func TestSwiftSymbolicNameInlineHeaderAtBackingEnd(t *testing.T) {
	data := swiftContextFixture(0x2800, 0x800, 0)
	copy(data[0x17f8:], []byte{0, 0, 0, 0, 'A', 'B', 0, 0})
	reader := &swiftBackingReadCounter{
		Reader: bytes.NewReader(data[:0x1800]), end: 0x1800,
	}
	f, err := NewFile(reader)
	if err != nil {
		t.Fatal(err)
	}
	reader.active = true
	got, err := f.swiftSymbolicName(0x27f8)
	if err != nil || got != "AB" || reader.pastEnd != 0 {
		t.Fatalf("name = %q, err = %v, reads past backing = %d", got, err, reader.pastEnd)
	}
}

func TestGetSwiftTypeRefsFallbackScanLimit(t *testing.T) {
	const scanLimit = 0x1000
	const prefix = "\x03\x00\x00\x00\x00\x00"
	const rawHeader = "\x03\x0f"
	for _, tc := range []struct {
		name       string
		contentLen int
		terminated bool
		wantName   bool
	}{
		{name: "terminator at cap", contentLen: scanLimit, terminated: true, wantName: true},
		{name: "terminator beyond cap", contentLen: scanLimit + 1, terminated: true},
		{name: "unterminated backing end", contentLen: scanLimit},
	} {
		for _, mode := range []string{"standalone", "configured reader"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				name := "Alias." + strings.Repeat("T", tc.contentLen-len(prefix)-6)
				payload := []byte(prefix + name)
				if tc.terminated {
					payload = append(payload, 0)
				}
				fileSize := uint64(0x803 + len(payload))
				data := swiftStringTypeRefFixture(fileSize, payload)
				dataCmd := types.FileHeaderSize64 + binary.Size(types.Segment64{})
				dataCmd += binary.Size(types.Section64{})
				binary.LittleEndian.PutUint64(data[dataCmd+32:], 0x2000)
				data = data[:0x1000+fileSize]
				f, err := NewFile(bytes.NewReader(data))
				if err != nil {
					t.Fatal(err)
				}
				if mode != "standalone" {
					f = newSwiftExternalAddressFile(t, data)
				}
				want := rawHeader
				if tc.wantName {
					want = name
				}
				refs, err := f.GetSwiftTypeRefs()
				if err != nil || len(refs) != 1 || refs[0x1900] != want {
					t.Fatalf("type ref length = %d, err = %v, want length %d",
						len(refs[0x1900]), err, len(want))
				}
			})
		}
	}
}

func TestGetSwiftAccessibleFunctionsKeepsRelativeVMAddresses(t *testing.T) {
	data := swiftContextFixture(0x2800, 0x800, 0)
	section := types.Section{SectionHeader: types.SectionHeader{
		Seg: "__TEXT", Name: "__swift5_acfuncs", Addr: 0x1800, Offset: 0x800, Size: 20,
	}}
	section.Put64(data[types.FileHeaderSize64+binary.Size(types.Segment64{}):],
		binary.LittleEndian)
	for i := 0x800; i < 0x814; i++ {
		data[i] = 0
	}
	binary.LittleEndian.PutUint32(data[0x80c:], 0x1b00-0x180c)
	base, err := NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	vma := types.VMAddrConverter{
		Converter: func(value uint64) uint64 {
			return value + 0x10000
		},
		VMAddr2Offet: base.GetOffset,
		Offet2VMAddr: base.GetVMAddress,
	}
	f, err := NewFile(bytes.NewReader(data), FileConfig{VMAddrConverter: vma})
	if err != nil {
		t.Fatal(err)
	}
	funcs, err := f.GetSwiftAccessibleFunctions()
	if err != nil || len(funcs) != 1 || funcs[0].FunctionAddress != 0x1b00 {
		t.Fatalf("functions = %+v, err = %v", funcs, err)
	}
}

func TestLegacySwiftObjCClassName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
		ok    bool
	}{
		{
			name:  "simple class",
			input: "_TtC4apsd28ClientIdentityMetricReporter",
			want:  "apsd.ClientIdentityMetricReporter",
			ok:    true,
		},
		{
			name:  "nested class",
			input: "_TtCC4apsd20ClientIdentityMetric13FailureMetric",
			want:  "apsd.ClientIdentityMetric.FailureMetric",
			ok:    true,
		},
		{
			name:  "not a legacy swift objc class name",
			input: "NSObject",
			want:  "",
			ok:    false,
		},
		{
			name:  "reject trailing garbage suffix",
			input: "_TtC4apsd28ClientIdentityMetricReporterXX",
			want:  "",
			ok:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := legacySwiftObjCClassName(tt.input)
			if ok != tt.ok {
				t.Fatalf("legacySwiftObjCClassName(%q) ok=%v, want %v", tt.input, ok, tt.ok)
			}
			if got != tt.want {
				t.Fatalf("legacySwiftObjCClassName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSwiftClassLookupNames(t *testing.T) {
	lookup := swiftClassLookupNames("_OBJC_CLASS_$_TtCC4apsd20ClientIdentityMetric13FailureMetric", nil)

	if _, ok := lookup["_OBJC_CLASS_$_TtCC4apsd20ClientIdentityMetric13FailureMetric"]; !ok {
		t.Fatalf("expected lookup to contain original objc class symbol")
	}
	if _, ok := lookup["_TtCC4apsd20ClientIdentityMetric13FailureMetric"]; !ok {
		t.Fatalf("expected lookup to contain objc class symbol without _OBJC_CLASS_$_ prefix")
	}
	if _, ok := lookup["apsd.ClientIdentityMetric.FailureMetric"]; !ok {
		t.Fatalf("expected lookup to contain demangled legacy swift class name")
	}
}
