package fixupchains

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/blacktop/go-macho/types"
)

func TestRebaseRuntimeOffsets(t *testing.T) {
	const base = uint64(0x100000000)
	const target = uint64(0xc158)
	for _, tc := range []struct {
		name   string
		format DCPtrKind
		raw    uint64
	}{
		{"64 virtual address", DYLD_CHAINED_PTR_64, base + target},
		{"64 image offset", DYLD_CHAINED_PTR_64_OFFSET, target},
		{"arm64e virtual address", DYLD_CHAINED_PTR_ARM64E, base + target},
		{"arm64e userland offset", DYLD_CHAINED_PTR_ARM64E_USERLAND, target},
		{"arm64e userland24 offset", DYLD_CHAINED_PTR_ARM64E_USERLAND24, target},
		{"arm64e kernel offset", DYLD_CHAINED_PTR_ARM64E_KERNEL, target},
		{"arm64e firmware address", DYLD_CHAINED_PTR_ARM64E_FIRMWARE, base + target},
		{"arm64e authenticated offset", DYLD_CHAINED_PTR_ARM64E_USERLAND24, 1<<63 | target},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, next := range []uint64{0, 3} {
				raw := tc.raw | next<<51
				var data [8]byte
				binary.LittleEndian.PutUint64(data[:], raw)
				reader := types.NewCustomSectionReader(bytes.NewReader(data[:]), nil, 0, 8)
				dcf := &DyldChainedFixups{
					PointerFormat:  tc.format,
					metadataParsed: true,
					bo:             binary.LittleEndian,
					sr:             reader,
					Starts: []DyldChainedStarts{{
						DyldChainedStartsInSegment: DyldChainedStartsInSegment{
							PointerFormat: tc.format, PageSize: 0x1000, PageCount: 1,
						},
						PageStarts: []DCPtrStart{0},
					}},
				}
				if got, ok := dcf.IsRebase(raw, base); !ok || got != target {
					t.Errorf("IsRebase(%#x) = %#x, %t; want %#x, true", raw, got, ok, target)
				}
				if got, err := dcf.RebaseRaw(0, raw, base); err != nil || got != target {
					t.Errorf("RebaseRaw(%#x) = %#x, %v; want %#x", raw, got, err, target)
				}
				if got, err := dcf.Rebase(0, base); err != nil || got != target {
					t.Errorf("Rebase() for %#x = %#x, %v; want %#x", raw, got, err, target)
				}
			}
		})
	}
}
