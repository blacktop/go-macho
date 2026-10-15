package macho

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/blacktop/go-macho/types"
	swiftabi "github.com/blacktop/go-macho/types/swift"
)

func swiftColocatedFixture(
	kind swiftabi.ContextDescriptorKind, generic bool, genericFlags uint16,
	tailBytes int, primary bool,
) ([]byte, int) {
	bodySize := map[swiftabi.ContextDescriptorKind]int{
		swiftabi.CDKindClass: 44, swiftabi.CDKindStruct: 28, swiftabi.CDKindEnum: 28,
		swiftabi.CDKindOpaqueType: 8, swiftabi.CDKindProtocol: 24,
	}[kind]
	data := make([]byte, 0x1000)
	order := binary.LittleEndian
	flags := uint32(kind) | 0x40 // Unique.
	if primary {
		flags |= 0x20
	}
	if generic {
		flags |= 0x80
		headerSize := 16
		if kind == swiftabi.CDKindOpaqueType {
			headerSize = 8
		}
		base := 0x200 + bodySize + headerSize - 8
		order.PutUint16(data[base:], 1) // One key type parameter, no requirements.
		order.PutUint16(data[base+4:], 1)
		order.PutUint16(data[base+6:], genericFlags)
		data[0x200+bodySize+headerSize] = 0x80
		bodySize += headerSize + 4
		if genericFlags&2 != 0 {
			base := 0x200 + bodySize
			order.PutUint16(data[base:], 3) // Two conditional protocols.
			order.PutUint16(data[base+2:], 1)
			order.PutUint16(data[base+4:], 2) // Cumulative requirement counts.
			bodySize += 8 + 2*12
		}
		if genericFlags&4 != 0 {
			order.PutUint32(data[0x200+bodySize:], 1) // One Int value parameter.
			bodySize += 8
		}
	}
	order.PutUint32(data[0x200:], flags)
	order.PutUint32(data[0x204:], 0x1700-0x1204)
	if kind != swiftabi.CDKindOpaqueType {
		order.PutUint32(data[0x208:], 0x1740-0x1208)
	}
	order.PutUint16(data[0x200+bodySize:], 3)
	size := bodySize + tailBytes
	actualSize := bodySize
	if primary {
		actualSize += 2
	}
	if tailBytes == 2 || !primary {
		next := int(Align(uint64(size), 4))
		order.PutUint32(data[0x200+next:], 0x40)
		order.PutUint32(data[0x208+next:], uint32(0x1747-(0x1208+next)))
		size = next + 12
	}
	order.PutUint32(data[0x180:], 0x1200-0x1180)
	order.PutUint32(data[0x700:], 0x40)
	order.PutUint32(data[0x708:], 0x174d-0x1708)
	copy(data[0x740:], "Before\x00After\x00Module\x00")
	segmentSize := uint32(binary.Size(types.Segment64{}))
	sectionSize := uint32(binary.Size(types.Section64{}))
	segment := Segment{SegmentHeader: SegmentHeader{
		LoadCmd: types.LC_SEGMENT_64, Len: segmentSize + 2*sectionSize,
		Name: "__TEXT", Addr: 0x1000, Memsz: 0x1000, Filesz: 0x1000, Nsect: 2,
	}}
	header := types.FileHeader{
		Magic: types.Magic64, CPU: types.CPUArm64, Type: types.MH_DYLIB,
		NCommands: 1, SizeCommands: segment.Len,
	}
	off := header.Put(data, order)
	off += segment.Put64(data[off:], order)
	for _, section := range []types.SectionHeader{
		{Seg: "__TEXT", Name: "__swift5_types", Addr: 0x1180, Offset: 0x180, Size: 4},
		{Seg: "__TEXT", Name: "__constg_swiftt", Addr: 0x1200, Offset: 0x200, Size: uint64(size)},
	} {
		sec := types.Section{SectionHeader: section}
		off += sec.Put64(data[off:], order)
	}
	return data, actualSize
}

func TestSwiftColocatedInvertedProtocols(t *testing.T) {
	for _, tc := range []struct {
		name    string
		kind    swiftabi.ContextDescriptorKind
		generic bool
		flags   uint16
		primary bool
	}{
		{"class", swiftabi.CDKindClass, false, 0, true},
		{"struct", swiftabi.CDKindStruct, false, 0, true},
		{"enum", swiftabi.CDKindEnum, false, 0, true},
		{"opaque", swiftabi.CDKindOpaqueType, false, 0, true},
		{"generic struct", swiftabi.CDKindStruct, true, 0, true},
		{"generic opaque", swiftabi.CDKindOpaqueType, true, 0, true},
		{"conditional and value parameters", swiftabi.CDKindStruct, true, 6, true},
		{"no primary set", swiftabi.CDKindStruct, true, 6, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tail := 0
			if tc.primary {
				tail = 2
			}
			data, size := swiftColocatedFixture(tc.kind, tc.generic, tc.flags, tail, tc.primary)
			for _, colocated := range []bool{false, true} {
				f, err := NewFile(bytes.NewReader(data))
				if err != nil {
					t.Fatal(err)
				}
				var got []swiftabi.Type
				if colocated {
					got, err = f.GetSwiftColocateTypeDescriptors()
				} else {
					got, err = f.GetSwiftTypes()
				}
				if err != nil || len(got) == 0 || got[0].Size != int64(size) {
					t.Fatalf("colocated=%t types=%+v error=%v", colocated, got, err)
				}
				protocols := got[0].InvertedProtocols
				if tc.primary && (protocols == nil || *protocols != 3) ||
					!tc.primary && protocols != nil {
					t.Fatalf("wrong primary protocol set: %v", protocols)
				}
				if colocated && (len(got) != 2 || got[1].Name != "After" ||
					got[1].Address != 0x1200+Align(uint64(size), 4)) {
					t.Fatalf("next descriptor was lost: %+v", got)
				}
			}
		})
	}
}

type swiftAddressOnlyReader struct{ types.MachoReader }

func (r swiftAddressOnlyReader) ReadAt([]byte, int64) (int, error) {
	return 0, errors.New("offset reads select linkedit")
}

func TestSwiftInvertedProtocolsCacheAddressReader(t *testing.T) {
	data, size := swiftColocatedFixture(swiftabi.CDKindStruct, true, 0, 2, true)
	base, err := NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	reader := types.NewCustomSectionReader(bytes.NewReader(data),
		&types.VMAddrConverter{VMAddr2Offet: base.GetOffset}, 0, int64(len(data)))
	f, err := NewFile(bytes.NewReader(data), FileConfig{
		CacheReader: swiftAddressOnlyReader{reader},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.GetSwiftTypes()
	if err != nil || len(got) != 1 || got[0].Size != int64(size) ||
		got[0].InvertedProtocols == nil || *got[0].InvertedProtocols != 3 {
		t.Fatalf("types=%+v error=%v", got, err)
	}
}

func TestSwiftColocatedInvertedProtocolsMalformed(t *testing.T) {
	for _, tail := range []int{0, 1} {
		data, _ := swiftColocatedFixture(swiftabi.CDKindStruct, false, 0, tail, true)
		f, err := NewFile(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.GetSwiftColocateTypeDescriptors()
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("%d trailer bytes: %v", tail, err)
		}
	}
	for _, tc := range []struct {
		flags uint16
		want  string
	}{
		{2, "requirement counts decrease"},
		{4, "exceeds parameter count"},
		{8, "unsupported swift generic context flags"},
	} {
		data, _ := swiftColocatedFixture(swiftabi.CDKindStruct, true, tc.flags, 2, true)
		switch tc.flags {
		case 2:
			binary.LittleEndian.PutUint16(data[0x234:], 0)
		case 4:
			binary.LittleEndian.PutUint32(data[0x230:], 2)
		}
		f, err := NewFile(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.GetSwiftColocateTypeDescriptors()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("generic flags %#x: %v", tc.flags, err)
		}
	}
	data, _ := swiftColocatedFixture(swiftabi.CDKindProtocol, false, 0, 2, true)
	f, err := NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.GetSwiftColocateTypeDescriptors(); err == nil ||
		!strings.Contains(err.Error(), "unsupported type kind") {
		t.Fatalf("protocol accepted an invalid trailer: %v", err)
	}
}
