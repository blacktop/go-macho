package macho

import (
	"strings"
	"testing"

	"github.com/blacktop/go-macho/types"
)

func TestPointerAlignPad(t *testing.T) {
	tests := []struct {
		name       string
		currentLen int
		ptrSize    uint64
		want       int
	}{
		{"already aligned 8", 16, 8, 0},
		{"already aligned 4", 12, 4, 0},
		{"off by 1", 1, 8, 7},
		{"off by 4", 4, 8, 4},
		{"off by 7", 7, 8, 1},
		{"zero len", 0, 8, 0},
		{"4-byte align off by 1", 5, 4, 3},
		{"4-byte align off by 3", 7, 4, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pointerAlignPad(tt.currentLen, tt.ptrSize)
			if got != tt.want {
				t.Errorf("pointerAlignPad(%d, %d) = %d, want %d", tt.currentLen, tt.ptrSize, got, tt.want)
			}
			// result should always be aligned
			aligned := (uint64(tt.currentLen) + uint64(got)) % tt.ptrSize
			if aligned != 0 {
				t.Errorf("pointerAlignPad(%d, %d): result %d not aligned (remainder %d)", tt.currentLen, tt.ptrSize, tt.currentLen+got, aligned)
			}
		})
	}
}

func TestPageAlign(t *testing.T) {
	tests := []struct {
		name  string
		off   uint64
		align uint64
		want  uint64
	}{
		{"already aligned", 0x4000, 0x1000, 0x4000},
		{"needs alignment", 0x4001, 0x1000, 0x5000},
		{"zero", 0, 0x1000, 0},
		{"one byte over", 0x1001, 0x1000, 0x2000},
		{"one byte under", 0x0FFF, 0x1000, 0x1000},
		{"16KB align", 0x4001, 0x4000, 0x8000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pageAlign(tt.off, tt.align)
			if got != tt.want {
				t.Errorf("pageAlign(%#x, %#x) = %#x, want %#x", tt.off, tt.align, got, tt.want)
			}
		})
	}
}

func newTextSegmentFile(seg SegmentHeader, sections ...*types.Section) *File {
	seg.LoadCmd = types.LC_SEGMENT_64
	seg.Name = "__TEXT"
	text := &Segment{
		SegmentHeader: seg,
	}
	return &File{
		FileTOC: FileTOC{
			Loads:    loads{text},
			Sections: sections,
		},
	}
}

func newTextSection(addr uint64, offset uint32) *types.Section {
	return &types.Section{
		SectionHeader: types.SectionHeader{
			Name:   "__text",
			Seg:    "__TEXT",
			Addr:   addr,
			Offset: offset,
		},
	}
}

func requireErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("expected error containing %q, got %v", want, err)
	}
}

func TestTextSegmentFirstSectionRelOffUsesVMAddrForCachedImages(t *testing.T) {
	f := newTextSegmentFile(
		SegmentHeader{
			Addr:   0x180000000,
			Offset: 0x3f000000,
			Nsect:  1,
		},
		newTextSection(0x180004000, 0x4000),
	)

	got, err := f.textSegmentFirstSectionRelOff(true)
	if err != nil {
		t.Fatal(err)
	}
	if got != 0x4000 {
		t.Errorf("textSegmentFirstSectionRelOff(true) = %#x, want 0x4000", got)
	}
}

func TestTextSegmentFirstSectionRelOffRejectsInvalidCachedAddress(t *testing.T) {
	f := newTextSegmentFile(
		SegmentHeader{
			Addr:   0x180004000,
			Offset: 0x3f000000,
			Nsect:  1,
		},
		newTextSection(0x180000000, 0x4000),
	)

	_, err := f.textSegmentFirstSectionRelOff(true)
	requireErrorContains(t, err, "precedes segment address")
}

func TestTextSegmentFirstSectionRelOffRejectsInvalidFileOffset(t *testing.T) {
	f := newTextSegmentFile(
		SegmentHeader{
			Addr:   0x100000000,
			Offset: 0x8000,
			Nsect:  1,
		},
		newTextSection(0x100001000, 0x1000),
	)

	_, err := f.textSegmentFirstSectionRelOff(false)
	requireErrorContains(t, err, "precedes segment offset")
}

func TestTextSegmentFirstSectionRelOffRejectsInvalidSectionIndex(t *testing.T) {
	f := newTextSegmentFile(SegmentHeader{
		Addr:      0x100000000,
		Nsect:     1,
		Firstsect: 1,
	})

	_, err := f.textSegmentFirstSectionRelOff(false)
	requireErrorContains(t, err, "out of range")
}

func TestTextSegmentFirstSectionRelOffRejectsHugeSectionIndex(t *testing.T) {
	f := newTextSegmentFile(SegmentHeader{
		Addr:      0x100000000,
		Nsect:     1,
		Firstsect: ^uint32(0),
	})

	_, err := f.textSegmentFirstSectionRelOff(false)
	requireErrorContains(t, err, "out of range")
}

func TestTextSegmentFirstSectionRelOffNoTextSegment(t *testing.T) {
	f := &File{}

	got, err := f.textSegmentFirstSectionRelOff(false)
	if err != nil {
		t.Fatal(err)
	}
	if got != 0 {
		t.Errorf("textSegmentFirstSectionRelOff without __TEXT = %#x, want 0", got)
	}
}

func TestTextSegmentWriteStartRejectsOutOfRangeStart(t *testing.T) {
	_, err := textSegmentWriteStart(0x400000000, 0x2000, 0x10000)
	requireErrorContains(t, err, "exceeds segment data length")
}

func TestTextSegmentWriteStartUsesEndOfLoadsWhenLarger(t *testing.T) {
	got, err := textSegmentWriteStart(0x1000, 0x2000, 0x4000)
	if err != nil {
		t.Fatal(err)
	}
	if got != 0x2000 {
		t.Errorf("textSegmentWriteStart = %#x, want 0x2000", got)
	}
}

func TestSegMapRemap(t *testing.T) {
	m := exportSegMap{
		{
			Name:       "__TEXT",
			Old:        segInfo{Start: 0x10000, End: 0x14000},
			New:        segInfo{Start: 0, End: 0x4000},
			OrigMemsz:  0x4000,
			OrigFilesz: 0x4000,
		},
		{
			Name:       "__DATA",
			Old:        segInfo{Start: 0x20000, End: 0x22000},
			New:        segInfo{Start: 0x4000, End: 0x6000},
			OrigMemsz:  0x3000, // bss makes memsz > filesz
			OrigFilesz: 0x2000,
		},
		{
			Name:       "__LINKEDIT",
			Old:        segInfo{Start: 0x30000, End: 0x34000},
			New:        segInfo{Start: 0x6000, End: 0xA000},
			OrigMemsz:  0x4000,
			OrigFilesz: 0x4000,
		},
	}

	// test Remap
	t.Run("remap __TEXT start", func(t *testing.T) {
		got, err := m.Remap(0x10000)
		if err != nil {
			t.Fatal(err)
		}
		if got != 0 {
			t.Errorf("Remap(0x10000) = %#x, want 0x0", got)
		}
	})
	t.Run("remap __TEXT middle", func(t *testing.T) {
		got, err := m.Remap(0x12000)
		if err != nil {
			t.Fatal(err)
		}
		if got != 0x2000 {
			t.Errorf("Remap(0x12000) = %#x, want 0x2000", got)
		}
	})
	t.Run("remap __DATA start", func(t *testing.T) {
		got, err := m.Remap(0x20000)
		if err != nil {
			t.Fatal(err)
		}
		if got != 0x4000 {
			t.Errorf("Remap(0x20000) = %#x, want 0x4000", got)
		}
	})
	t.Run("remap out of range", func(t *testing.T) {
		_, err := m.Remap(0x50000)
		if err == nil {
			t.Error("Remap(0x50000) should fail for out-of-range offset")
		}
	})

	// test RemapSeg
	t.Run("remap segment __DATA", func(t *testing.T) {
		off, sz, err := m.RemapSeg("__DATA", 0x20000)
		if err != nil {
			t.Fatal(err)
		}
		if off != 0x4000 {
			t.Errorf("RemapSeg offset = %#x, want 0x4000", off)
		}
		if sz != 0x2000 {
			t.Errorf("RemapSeg size = %#x, want 0x2000", sz)
		}
	})

	// test Lookup
	t.Run("lookup __DATA preserves OrigMemsz", func(t *testing.T) {
		smi, ok := m.Lookup("__DATA")
		if !ok {
			t.Fatal("Lookup(__DATA) not found")
		}
		if smi.OrigMemsz != 0x3000 {
			t.Errorf("OrigMemsz = %#x, want 0x3000", smi.OrigMemsz)
		}
		if smi.OrigFilesz != 0x2000 {
			t.Errorf("OrigFilesz = %#x, want 0x2000", smi.OrigFilesz)
		}
	})
	t.Run("lookup nonexistent", func(t *testing.T) {
		_, ok := m.Lookup("__BOGUS")
		if ok {
			t.Error("Lookup(__BOGUS) should return false")
		}
	})
}
