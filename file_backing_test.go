package macho

import (
	"testing"

	"github.com/blacktop/go-macho/types"
)

func benchmarkFileBacking() *File {
	const (
		base            = uint64(0x100000000)
		segmentSize     = uint64(0x100000)
		sectionSize     = uint64(0x10000)
		segmentCount    = 8
		sectionsPerLoad = 16
	)
	f := new(File)
	for i := 0; i < segmentCount; i++ {
		addr := base + uint64(i)*segmentSize
		seg := &Segment{SegmentHeader: SegmentHeader{
			LoadCmd:   types.LC_SEGMENT_64,
			Addr:      addr,
			Memsz:     segmentSize,
			Offset:    uint64(i) * segmentSize,
			Filesz:    12 * sectionSize,
			Firstsect: uint32(len(f.Sections)),
			Nsect:     sectionsPerLoad,
		}}
		f.Loads = append(f.Loads, seg, &DyldInfoOnly{})
		for j := 0; j < sectionsPerLoad; j++ {
			flags := types.Regular
			if j >= 12 {
				flags = types.Zerofill
			}
			sec := &types.Section{SectionHeader: types.SectionHeader{
				Addr: addr + uint64(j)*sectionSize, Size: sectionSize, Flags: flags,
			}}
			seg.sections = append(seg.sections, sec)
			f.Sections = append(f.Sections, sec)
		}
	}
	return f
}

func TestFileBackingMutableLayout(t *testing.T) {
	const addr = uint64(0x100018008)
	f := benchmarkFileBacking()
	wantSize := func(want uint64) {
		t.Helper()
		if got := f.fileDataSize(addr, 8); got != want {
			t.Fatalf("fileDataSize(%#x, 8) = %d, want %d", addr, got, want)
		}
	}
	wantSize(8)
	seg := f.Loads[0].(*Segment)
	seg.Filesz = 0x1800c
	wantSize(4)
	seg.Filesz = 0xc0000
	f.Loads[0] = &Segment{SegmentHeader: SegmentHeader{Addr: addr, Memsz: 8}}
	wantSize(0)
	f.Loads[0] = seg
	seg.Firstsect, seg.Nsect = ^uint32(0), ^uint32(0)
	zeroFill := &types.Section{SectionHeader: types.SectionHeader{
		Seg: "__OTHER", Addr: addr + 4, Size: 4, Flags: types.Zerofill,
	}}
	f.Sections = append(f.Sections, zeroFill)
	wantSize(4)
	zeroFill.Flags = types.Regular
	wantSize(8)
	zeroFill.Flags = types.ThreadLocalZerofill
	zeroFill.Addr = addr
	wantSize(0)
	f.Sections[len(f.Sections)-1] = &types.Section{}
	wantSize(8)
}

func TestFileBackingOverlappingSegments(t *testing.T) {
	first := &Segment{SegmentHeader: SegmentHeader{
		Addr: 0x1000, Memsz: 0x1000, Offset: 0x200, Filesz: 0x100,
	}}
	second := &Segment{SegmentHeader: SegmentHeader{
		Addr: 0x1000, Memsz: 0x1000, Offset: 0x400, Filesz: 0x200,
	}}
	f := &File{FileTOC: FileTOC{Loads: loads{first, second}}}
	if offset, err := f.getOffset(0x1100); err != nil || offset != 0x300 {
		t.Fatalf("first segment offset = %#x, %v; want 0x300", offset, err)
	}
	if size := f.fileDataSize(0x1100, 8); size != 0 {
		t.Fatalf("first segment BSS size = %d, want 0", size)
	}
	f.Loads[0], f.Loads[1] = f.Loads[1], f.Loads[0]
	if offset, err := f.getOffset(0x1100); err != nil || offset != 0x500 {
		t.Fatalf("reordered segment offset = %#x, %v; want 0x500", offset, err)
	}
	if size := f.fileDataSize(0x1100, 8); size != 8 {
		t.Fatalf("reordered segment size = %d, want 8", size)
	}
}

func BenchmarkFileBacking(b *testing.B) {
	f := benchmarkFileBacking()
	b.Run("GetOffset", func(b *testing.B) {
		b.ReportAllocs()
		var offset uint64
		var err error
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			addr := uint64(0x100018008) + uint64(i&7)*0x100000
			offset, err = f.getOffset(addr)
		}
		if err != nil || offset == 0 {
			b.Fatalf("offset=%#x, err=%v", offset, err)
		}
	})
	for _, tc := range []struct {
		name string
		addr uint64
		max  uint64
		want uint64
	}{
		{"PointerRange", 0x100018008, 8, 8},
		{"CStringPrefix", 0x100018008, 0x1000, 0x1000},
		{"ZeroFillBoundary", 0x1000bfff0, 0x1000, 0x10},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			var size uint64
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				addr := tc.addr + uint64(i&7)*0x100000
				size = f.fileDataSize(addr, tc.max)
			}
			if size != tc.want {
				b.Fatalf("size=%#x, want %#x", size, tc.want)
			}
		})
	}
}
