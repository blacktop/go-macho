package fixupchains

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// BenchmarkGetFixupAtOffset benchmarks the new direct lookup method
func BenchmarkGetFixupAtOffset(b *testing.B) {
	// Create a mock DyldChainedFixups with a reasonable number of segments/pages
	dcf := &DyldChainedFixups{
		DyldChainedFixupsHeader: DyldChainedFixupsHeader{
			FixupsVersion: 0,
			StartsOffset:  32,
			ImportsOffset: 1000,
			SymbolsOffset: 2000,
			ImportsCount:  10,
			ImportsFormat: DC_IMPORT,
			SymbolsFormat: DC_SFORMAT_UNCOMPRESSED,
		},
		PointerFormat: DYLD_CHAINED_PTR_64,
		Starts: []DyldChainedStarts{
			{
				DyldChainedStartsInSegment: DyldChainedStartsInSegment{
					Size:            40,
					PageSize:        0x4000, // 16KB pages
					PointerFormat:   DYLD_CHAINED_PTR_64,
					SegmentOffset:   0x10000, // Start at 64KB
					MaxValidPointer: 0xFFFFFF,
					PageCount:       100, // 100 pages = 1.6MB segment
				},
				PageStarts: make([]DCPtrStart, 100),
			},
		},
		Imports:        make([]DcfImport, 10),
		fixups:         make(map[uint64]Fixup),
		metadataParsed: true,
		importsParsed:  true,
		chainsParsed:   false,
	}

	// Set up some pages with fixups scattered throughout
	for i := 0; i < 100; i += 10 {
		dcf.Starts[0].PageStarts[i] = DCPtrStart(0x100 + i*4)
	}
	// Set other pages to no fixups
	for i := 0; i < 100; i++ {
		if i%10 != 0 {
			dcf.Starts[0].PageStarts[i] = DYLD_CHAINED_PTR_START_NONE
		}
	}

	// Create mock data for reading
	data := make([]byte, 2*1024*1024) // 2MB
	dcf.r = bytes.NewReader(data)
	dcf.bo = binary.LittleEndian

	// Test offsets - some will have fixups, some won't
	testOffsets := []uint64{
		0x10000 + 0x100,      // First page, has fixup
		0x10000 + 0x4000 + 1, // Second page, no fixup, misaligned
		0x10000 + 0x28000,    // 10th page, has fixup
		0x10000 + 0x4000,     // Second page, no fixup
		0x10000 + 0x50000,    // 20th page, has fixup
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		offset := testOffsets[i%len(testOffsets)]
		_, _ = dcf.GetFixupAtOffset(offset)
	}
}

// BenchmarkLookupByOffsetTraditional benchmarks the traditional method for comparison
func BenchmarkLookupByOffsetTraditional(b *testing.B) {
	// Create a mock with pre-parsed fixups to simulate the traditional approach
	dcf := &DyldChainedFixups{
		Starts: []DyldChainedStarts{
			{
				Fixups: make([]Fixup, 100), // Simulate 100 fixups
			},
		},
	}

	// Add some mock fixups
	for i := 0; i < 100; i++ {
		dcf.Starts[0].Fixups[i] = DyldChainedPtr64Rebase{
			Pointer: 0x1000000000000000,
			Fixup:   uint64(0x10000 + i*0x100),
		}
	}

	testOffsets := []uint64{
		0x10000,      // First fixup
		0x10000 + 50, // Middle fixup
		0x10000 + 99, // Last fixup
		0x20000,      // Non-existent
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		offset := testOffsets[i%len(testOffsets)]
		_, _ = dcf.LookupByOffset(offset)
	}
}
