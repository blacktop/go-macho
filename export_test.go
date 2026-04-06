package macho

import (
	"testing"
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
